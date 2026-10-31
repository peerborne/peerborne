import {
  mkdtempSync,
  cpSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  projectRoot,
  manifest,
  lsc,
  dafny,
  proofPaths,
  requireTools,
  proverEnvironment,
} from './support.mjs';

requireTools();
const staging = mkdtempSync(join(tmpdir(), 'peerborne-formal-controls-'));
const results = [];
function copyProject(label) {
  const root = join(staging, label);
  mkdirSync(root, { recursive: true });
  cpSync(join(projectRoot, 'lemmascript.json'), join(root, 'lemmascript.json'));
  for (const entry of manifest.sources) {
    const source = join(root, entry.path);
    mkdirSync(dirname(source), { recursive: true });
    cpSync(join(projectRoot, entry.path), source);
    const from = proofPaths(entry.path);
    const to = proofPaths(entry.path, root);
    mkdirSync(dirname(to.proof), { recursive: true });
    cpSync(from.proof, to.proof);
    cpSync(from.generated, to.generated);
  }
  return root;
}
function verify(root, source, regenerate = false) {
  const result = spawnSync(
    process.execPath,
    [
      lsc,
      regenerate ? 'regen' : 'check',
      '--backend=dafny',
      '--time-limit=15',
      source,
    ],
    {
      cwd: root,
      env: proverEnvironment(),
      encoding: 'utf8',
      timeout: 120000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const path = join(root, '.lemmascript/runs.jsonl');
  let records = [];
  try {
    records = readFileSync(path, 'utf8')
      .trim()
      .split(/\r?\n/)
      .map((line) => JSON.parse(line));
  } catch {}
  return {
    ...result,
    record: records.findLast((record) => record.file === source),
  };
}
function requireResult(condition, name, result) {
  if (!condition)
    throw new Error(
      `Verifier control ${name} did not behave as required:\n${result?.stdout ?? ''}${result?.stderr ?? ''}`,
    );
  results.push({
    name,
    passed: true,
    failedMembers: result?.record?.failed ?? [],
  });
  console.log(`${name}: passed`);
}
try {
  const positive = copyProject('positive');
  for (const entry of manifest.sources) {
    const result = verify(positive, entry.path);
    requireResult(
      result.status === 0 &&
        result.record?.stage === 'ok' &&
        result.record.passed.includes(entry.witness),
      `positive/${entry.path}`,
      result,
    );
  }
  const mutations = [
    [
      'budget-overrun',
      'work-budget.ts',
      'if (amount > limit - used) return -1;',
      'if (false) return -1;',
    ],
    [
      'epoch-gap',
      'beekem-transition.ts',
      "if (incoming === current + 1) return 'next';",
      "if (incoming === current + 2) return 'next';",
    ],
    [
      'conflicting-quorum',
      'quorum.ts',
      'if (winner !== -1) return -2;',
      'if (false) return -2;',
    ],
    [
      'authority-equivocation',
      'authority-votes.ts',
      "if (disposition === 'equivocation') equivocating = true;",
      "if (disposition === 'equivocation') equivocating = false;",
    ],
    [
      'vacuous-precondition',
      'work-budget.ts',
      '//@ verify',
      '//@ verify\n  //@ requires false',
    ],
  ];
  for (const [name, file, before, after] of mutations) {
    const root = copyProject(name);
    const source = `packages/core/src/policy/${file}`;
    const path = join(root, source);
    const text = readFileSync(path, 'utf8');
    if (text.split(before).length !== 2)
      throw new Error(`Mutation target drifted: ${name}`);
    writeFileSync(path, text.replace(before, after));
    const result = verify(root, source, true);
    requireResult(
      result.status !== 0 &&
        result.record?.stage === 'verify' &&
        result.record.failed.length > 0,
      name,
      result,
    );
  }
  const drift = copyProject('source-drift');
  const driftSource = 'packages/core/src/policy/work-budget.ts';
  const driftPath = join(drift, driftSource);
  writeFileSync(
    driftPath,
    readFileSync(driftPath, 'utf8').replace(
      'return used + amount;',
      'return used + amount + 1;',
    ),
  );
  const driftResult = verify(drift, driftSource);
  requireResult(
    driftResult.status !== 0 && driftResult.record?.stage === 'diff',
    'stale-generated-code',
    driftResult,
  );
  for (const [name, addition] of [
    ['assume-false', '\nlemma Escape() ensures false { assume false; }\n'],
    ['bodyless-lemma', '\nlemma Escape() ensures false\n'],
    [
      'unproved-import',
      '\nfunction {:axiom} Escape(x: int): int ensures Escape(x) == x\n',
    ],
  ]) {
    const root = copyProject(name);
    const path = proofPaths(
      'packages/core/src/policy/work-budget.ts',
      root,
    ).proof;
    writeFileSync(path, readFileSync(path, 'utf8') + addition);
    const result = spawnSync(
      dafny,
      [
        'audit',
        path,
        '--unicode-char:false',
        '--allow-deprecation',
        '--report-format',
        'md',
        '--report-file',
        join(root, 'audit.md'),
      ],
      { encoding: 'utf8', timeout: 30000 },
    );
    requireResult(
      !/Dafny auditor completed with 0 findings/.test(result.stdout ?? '') &&
        /Dafny auditor completed with [1-9]/.test(result.stdout ?? ''),
      name,
      result,
    );
  }
  const directory = join(projectRoot, 'verification/results/formal');
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    join(directory, 'controls.json'),
    `${JSON.stringify({ results }, null, 2)}\n`,
  );
} finally {
  rmSync(staging, { recursive: true, force: true });
}
