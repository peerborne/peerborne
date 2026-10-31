import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
} from 'node:fs';
import { join, relative } from 'node:path';
import { performance } from 'node:perf_hooks';
import {
  projectRoot,
  manifest,
  lsc,
  dafny,
  execute,
  proofPaths,
  requireTools,
  proverEnvironment,
  typescript,
  digestFile,
} from './support.mjs';

const regenerate = process.argv.slice(2).includes('--regen');
if (process.argv.slice(2).some((arg) => arg !== '--regen'))
  throw new Error(
    'Only --regen is supported; partial or skipped verification is not accepted.',
  );
const versions = requireTools();
const ts = typescript();
const options = JSON.parse(
  readFileSync(join(projectRoot, 'lemmascript.json'), 'utf8'),
);
if (
  options['string-semantics'] !== 'javascript-utf16' ||
  options['dafny-library'] !== 'local' ||
  options['proof-dir'] !== 'verification/formal/proofs' ||
  options['run-log'] === false
)
  throw new Error('Unexpected proof model or disabled verification logging');
const listed = readFileSync(join(projectRoot, 'LemmaScript-files.txt'), 'utf8')
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith('#'));
if (
  !manifest.sources.length ||
  JSON.stringify(listed) !==
    JSON.stringify(manifest.sources.map(({ path }) => path))
)
  throw new Error(
    'Proof manifest and LemmaScript file list must match exactly',
  );
const declared = readdirSync(join(projectRoot, 'packages/core/src/policy'))
  .filter((name) => name.endsWith('.ts') && !name.endsWith('.test.ts'))
  .map((name) => `packages/core/src/policy/${name}`)
  .sort();
if (JSON.stringify(declared) !== JSON.stringify([...listed].sort()))
  throw new Error(
    'Every production policy file must have a proof manifest entry',
  );

const directory = join(projectRoot, 'verification/results/formal');
mkdirSync(directory, { recursive: true });
const results = [];
const started = performance.now();
for (const entry of manifest.sources) {
  const source = readFileSync(join(projectRoot, entry.path), 'utf8');
  const syntax = ts.createSourceFile(
    entry.path,
    source,
    ts.ScriptTarget.Latest,
    true,
  );
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    false,
    ts.LanguageVariant.Standard,
    source,
  );
  const annotations = [];
  for (
    let token = scanner.scan();
    token !== ts.SyntaxKind.EndOfFileToken;
    token = scanner.scan()
  ) {
    if (token !== ts.SyntaxKind.SingleLineCommentTrivia) continue;
    const comment = scanner.getTokenText();
    if (/^\/\/@\s+(?:assume|havoc|extern|skip|option)\b/.test(comment))
      throw new Error(
        `Untrusted proof escape or model override in ${entry.path}`,
      );
    if (/^\/\/@\s+verify\s*$/.test(comment))
      annotations.push(scanner.getTokenPos());
  }
  const selected = syntax.statements
    .filter(ts.isFunctionDeclaration)
    .filter(
      (node) =>
        node.body &&
        annotations.some(
          (position) => node.body.pos <= position && position < node.body.end,
        ),
    )
    .map((node) => node.name?.text);
  if (
    JSON.stringify(selected.sort()) !==
    JSON.stringify([...entry.functions].sort())
  )
    throw new Error(`Selected functions drifted in ${entry.path}`);
  if (syntax.statements.some(ts.isImportDeclaration))
    throw new Error(`Verified kernels must be closed: ${entry.path}`);
  const moduleName = entry.path.split('/').at(-1).replace('.ts', '.js');
  if (
    !entry.consumers.length ||
    entry.consumers.some(
      (consumer) =>
        !readFileSync(join(projectRoot, consumer), 'utf8').includes(
          `policy/${moduleName}`,
        ),
    )
  )
    throw new Error(`Production consumers are missing for ${entry.path}`);
  const artifacts = proofPaths(entry.path);
  if (!existsSync(artifacts.proof) || !existsSync(artifacts.generated))
    throw new Error(`Missing reviewed proof artifacts for ${entry.path}`);
  const generatedBefore = digestFile(artifacts.generated);
  const log = join(projectRoot, '.lemmascript/runs.jsonl');
  const oldRecords = existsSync(log) ? readFileSync(log, 'utf8') : '';
  const begin = performance.now();
  const output = execute(
    process.execPath,
    [
      lsc,
      regenerate ? 'regen' : 'check',
      '--backend=dafny',
      '--time-limit=25',
      entry.path,
    ],
    { env: proverEnvironment() },
  );
  process.stdout.write(output);
  if (!regenerate && digestFile(artifacts.generated) !== generatedBefore)
    throw new Error(
      `Generated proof drift in ${entry.path}; review and run verify:formal:regen`,
    );
  const added = readFileSync(log, 'utf8')
    .slice(oldRecords.length)
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const record = added.findLast(
    (item) => item.type === 'verify' && item.file === entry.path,
  );
  const expected = [...entry.verifiedTargets, entry.witness];
  if (
    !record ||
    record.stage !== 'ok' ||
    record.exit !== 0 ||
    record.partial ||
    expected.some((name) => !record.passed.includes(name))
  )
    throw new Error(
      `Incomplete verification or missing non-vacuity witness for ${entry.path}`,
    );
  const auditFile = join(directory, `${entry.path.split('/').at(-1)}.audit.md`);
  const audit = execute(dafny, [
    'audit',
    artifacts.proof,
    '--unicode-char:false',
    '--allow-deprecation',
    '--report-format',
    'md',
    '--report-file',
    auditFile,
  ]);
  if (!/Dafny auditor completed with 0 findings/.test(audit))
    throw new Error(`Unproved assumptions in ${entry.path}:\n${audit}`);
  results.push({
    source: entry.path,
    sourceSha256: digestFile(join(projectRoot, entry.path)),
    proofSha256: digestFile(artifacts.proof),
    generatedSha256: digestFile(artifacts.generated),
    selectedFunctions: entry.functions,
    verifiedMembers: record.passed,
    auditFindings: 0,
    elapsedMs: performance.now() - begin,
    auditReport: relative(projectRoot, auditFile),
  });
  console.log(`${entry.path}: verified, audited, domain witness checked`);
}
const report = {
  ...versions,
  backend: 'dafny',
  sourceRevision: execute('git', ['rev-parse', 'HEAD']).trim(),
  sourceFunctions: results.reduce(
    (sum, result) => sum + result.selectedFunctions.length,
    0,
  ),
  proofModel:
    'Bounded integer arithmetic; JavaScript UTF-16 strings; local collections. Runtime adapters, cryptography, JavaScript engine, scheduling and I/O remain outside the proof.',
  elapsedMs: performance.now() - started,
  results,
};
writeFileSync(
  join(directory, 'report.json'),
  `${JSON.stringify(report, null, 2)}\n`,
);
console.log(
  `Verified ${report.sourceFunctions} production functions with zero audit findings in ${(report.elapsedMs / 1000).toFixed(2)} seconds.`,
);
