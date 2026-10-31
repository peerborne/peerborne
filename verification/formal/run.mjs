import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
} from 'node:fs';
import { join, relative, resolve, dirname } from 'node:path';
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
  options['safe-slice'] !== true ||
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
if (declared.some((path) => !listed.includes(path)))
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
  const comments = new Map();
  const capture = (position) => {
    for (const range of [
      ...(ts.getLeadingCommentRanges(source, position) ?? []),
      ...(ts.getTrailingCommentRanges(source, position) ?? []),
    ]) {
      comments.set(range.pos, range);
    }
  };
  const collect = (node) => {
    capture(node.pos);
    capture(node.end);
    if (ts.isBlock(node)) capture(node.statements.pos);
    ts.forEachChild(node, collect);
  };
  collect(syntax);
  for (const range of comments.values()) {
    const comment = source.slice(range.pos, range.end);
    if (
      /^\/\/@\s*(?:assume|havoc|autohavoc|extern|impure|skip|option)\b/.test(
        comment,
      )
    ) {
      throw new Error(
        `Untrusted proof escape or model override in ${entry.path}`,
      );
    }
  }
  const selected = syntax.statements
    .filter(ts.isFunctionDeclaration)
    .filter((node) => {
      if (!node.body) return false;
      const position = node.body.statements.pos;
      return (ts.getLeadingCommentRanges(source, position) ?? []).some(
        (range) =>
          /^\/\/@\s*verify\s*$/.test(source.slice(range.pos, range.end)),
      );
    })
    .map((node) => node.name?.text);
  if (
    JSON.stringify(selected.sort()) !==
    JSON.stringify([...entry.functions].sort())
  )
    throw new Error(`Selected functions drifted in ${entry.path}`);
  if (
    !entry.consumers.length ||
    entry.consumers.some((consumer) => {
      const consumerSource = ts.createSourceFile(
        consumer,
        readFileSync(join(projectRoot, consumer), 'utf8'),
        ts.ScriptTarget.Latest,
        true,
      );
      return !consumerSource.statements.some((node) => {
        if (!ts.isImportDeclaration(node) && !ts.isExportDeclaration(node))
          return false;
        if (!node.moduleSpecifier || !ts.isStringLiteral(node.moduleSpecifier))
          return false;
        if (ts.isImportDeclaration(node) && node.importClause?.isTypeOnly)
          return false;
        const path = resolve(
          dirname(join(projectRoot, consumer)),
          node.moduleSpecifier.text.replace(/\.js$/, '.ts'),
        );
        return path === resolve(projectRoot, entry.path);
      });
    })
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
  const solverSeeds = [];
  for (const seed of entry.solverSeeds ?? []) {
    if (!Number.isSafeInteger(seed) || seed < 0 || seed > 2147483647)
      throw new Error(`Invalid solver seed for ${entry.path}`);
    const seedStarted = performance.now();
    const output = execute(dafny, [
      'verify',
      '--unicode-char:false',
      '--allow-deprecation',
      '--verification-time-limit:10',
      '--boogie',
      `/randomSeed:${seed}`,
      artifacts.proof,
    ]);
    const verified = output.match(
      /verifier finished with ([1-9]\d*) verified, 0 errors/,
    );
    if (!verified)
      throw new Error(`Incomplete solver-seed check for ${entry.path}`);
    solverSeeds.push({
      seed,
      verifiedObligations: Number(verified[1]),
      elapsedMs: performance.now() - seedStarted,
    });
    console.log(`${entry.path}: solver seed ${seed} verified`);
  }
  results.push({
    source: entry.path,
    sourceSha256: digestFile(join(projectRoot, entry.path)),
    proofSha256: digestFile(artifacts.proof),
    generatedSha256: digestFile(artifacts.generated),
    selectedFunctions: entry.functions,
    verifiedMembers: record.passed,
    auditFindings: 0,
    solverSeeds,
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
    'Bounded exact integer arithmetic, real division/ceiling for sizing and finite-real scalar order, uint64 BigInt epochs, JavaScript UTF-16 strings and local collections. Runtime adapters, cryptography, JavaScript engine, scheduling and I/O remain outside the proof.',
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
