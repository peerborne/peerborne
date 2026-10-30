import { spawn } from 'node:child_process';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { tmpdir } from 'node:os';

const root = fileURLToPath(new URL('../', import.meta.url));
const definitions = [
  ['schema', 'CRDT structural/schema divergence', 'crdt', 'schema'],
  ['history', 'Tombstones, compaction, GC and late join', 'crdt', 'history'],
  ['causal', 'Missing dependencies and orphan flood', 'crdt', 'causal'],
  ['group', 'Membership scalability', 'epochs', 'group'],
  ['epoch-race', 'Ciphertext before epoch transition', 'epochs', 'epochRace'],
  ['offline', 'Long-offline epoch catch-up', 'epochs', 'offline'],
  ['delta', 'Partition rejoin and delta calculation', 'crdt', 'delta'],
];
const external = [
  {
    id: 'webrtc',
    name: '50 concurrent peers over WebRTC',
    command: 'yarn verify:technical:browser --grep webrtc',
  },
  {
    id: 'relay',
    name: 'STUN-disabled cross-NAT Circuit Relay',
    command: 'yarn verify:technical:nat',
  },
  {
    id: 'idb',
    name: '20,000-word paste and IndexedDB batching',
    command: 'yarn verify:technical:browser --grep IndexedDB',
  },
  {
    id: 'cold',
    name: '50 MiB cold-boot document TTI',
    command: 'yarn verify:technical:browser --grep cold',
  },
];
const { values } = parseArgs({
  options: {
    profile: { type: 'string', default: 'smoke' },
    scenario: { type: 'string', multiple: true },
    output: {
      type: 'string',
      default: 'verification/results/node-report.json',
    },
    seed: { type: 'string', default: '186' },
    'budget-ms': { type: 'string', default: '50' },
    'timeout-ms': { type: 'string', default: '900000' },
    strict: { type: 'boolean', default: false },
    list: { type: 'boolean', default: false },
    worker: { type: 'string' },
  },
});

if (!['smoke', 'full'].includes(values.profile))
  throw new Error('profile must be smoke or full');
const seed = Number(values.seed);
const budgetMs = Number(values['budget-ms']);
const timeoutMs = Number(values['timeout-ms']);
if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff)
  throw new Error('seed must be a uint32');
if (!Number.isFinite(budgetMs) || budgetMs <= 0)
  throw new Error('budget-ms must be positive');
if (
  !Number.isSafeInteger(timeoutMs) ||
  timeoutMs <= 0 ||
  timeoutMs > 2147483647
)
  throw new Error('timeout-ms is outside the timer range');
const full = values.profile === 'full';

if (values.list) {
  for (const [id, name] of definitions)
    process.stdout.write(`${id}: ${name}\n`);
  for (const { id, name, command } of external)
    process.stdout.write(`${id}: ${name} (${command})\n`);
} else if (values.worker) {
  const definition = definitions.find(([id]) => id === values.worker);
  if (!definition) throw new Error('unknown worker scenario');
  const original = { ...console };
  const diagnostics = { log: 0, warn: 0, error: 0, debug: 0, info: 0 };
  for (const level of Object.keys(diagnostics))
    console[level] = () => {
      diagnostics[level]++;
    };
  let result;
  try {
    const module = await import(`./scenarios/${definition[2]}.mjs`);
    const observation = await module[definition[3]]({
      full,
      seed,
      budgetMs,
      progress: (message) => process.stderr.write(`${message}\n`),
    });
    result = {
      id: definition[0],
      name: definition[1],
      profile: values.profile,
      seed,
      status: observation.gaps.length ? 'gap' : 'passed',
      ...observation,
      diagnostics,
    };
  } catch (error) {
    result = {
      id: definition[0],
      name: definition[1],
      profile: values.profile,
      seed,
      status: 'failed',
      error: {
        name: error.name,
        message:
          error.code === 'ERR_ASSERTION'
            ? error.message.split('\n')[0]
            : 'Scenario raised an unexpected error; no payload or key material is included.',
      },
      diagnostics,
    };
  } finally {
    Object.assign(console, original);
  }
  await mkdir(dirname(resolve(values.output)), { recursive: true });
  await writeFile(values.output, `${JSON.stringify(result, null, 2)}\n`);
  if (result.status === 'failed') process.exitCode = 1;
} else {
  const wanted = values.scenario ?? definitions.map(([id]) => id);
  for (const id of wanted)
    if (!definitions.some(([known]) => known === id))
      throw new Error(`unknown Node scenario: ${id}`);
  const report = {
    formatVersion: 1,
    profile: values.profile,
    seed,
    budgetMs,
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    determinism:
      'Fixed actors, seeded workload and delivery order; real cryptographic entropy and timing/memory measurements intentionally vary.',
    results: [],
  };
  const output = resolve(root, values.output);
  const save = async () => {
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
  };
  for (const [id] of definitions.filter(([id]) => wanted.includes(id))) {
    const temporary = resolve(
      tmpdir(),
      `peerborne-verification-${process.pid}-${id}.json`,
    );
    const args = [
      '--expose-gc',
      fileURLToPath(import.meta.url),
      '--worker',
      id,
      '--profile',
      values.profile,
      '--seed',
      String(seed),
      '--budget-ms',
      String(budgetMs),
      '--output',
      temporary,
    ];
    process.stdout.write(`Running ${id} (${values.profile})\n`);
    const exit = await new Promise((resolveExit, reject) => {
      const child = spawn(process.execPath, args, {
        cwd: root,
        stdio: ['ignore', 'inherit', 'inherit'],
      });
      let timedOut = false;
      const timeout = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);
      child.once('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
      child.once('exit', (code, signal) => {
        clearTimeout(timeout);
        resolveExit({ code, signal, timedOut });
      });
    });
    let result;
    try {
      result = JSON.parse(await readFile(temporary, 'utf8'));
    } catch {
      result = {
        id,
        status: 'failed',
        error: exit.timedOut
          ? 'Scenario exceeded bounded deadline'
          : 'Worker exited without a report',
        exit,
      };
    }
    if (exit.code !== 0 && result.status !== 'failed')
      result = {
        id,
        status: 'failed',
        error: 'Worker failed after writing its report',
        exit,
      };
    report.results.push(result);
    await save();
    process.stdout.write(
      `${id}: ${result.status}${result.gaps ? ` (${result.gaps.length} unmet guarantees)` : ''}\n`,
    );
  }
  if (!values.scenario) {
    report.results.push(
      ...external.map((scenario) => ({
        ...scenario,
        status: 'not-run',
        reason: 'Requires the separate Chromium or Docker acceptance runner',
      })),
    );
  }
  report.summary = {
    passed: report.results.filter(({ status }) => status === 'passed').length,
    gaps: report.results.filter(({ status }) => status === 'gap').length,
    failed: report.results.filter(({ status }) => status === 'failed').length,
    notRun: report.results.filter(({ status }) => status === 'not-run').length,
  };
  await save();
  process.stdout.write(`Report: ${output}\n`);
  if (
    report.summary.failed ||
    (values.strict && (report.summary.gaps || report.summary.notRun))
  )
    process.exitCode = 1;
}
