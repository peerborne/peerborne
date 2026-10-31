import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { catalog, options, root } from './catalog.mjs';

const { values } = parseArgs({
  options: {
    profile: {
      type: 'string',
      default: process.env.PEERBORNE_VERIFY_PROFILE ?? 'smoke',
    },
    seed: {
      type: 'string',
      default: process.env.PEERBORNE_VERIFY_SEED ?? '9420',
    },
    category: { type: 'string', multiple: true },
    scenario: { type: 'string', multiple: true },
    output: { type: 'string' },
    strict: {
      type: 'boolean',
      default: process.env.PEERBORNE_VERIFY_STRICT === '1',
    },
    list: { type: 'boolean' },
    worker: { type: 'string' },
    'timeout-ms': { type: 'string', default: '900000' },
  },
});
const settings = options({
  PEERBORNE_VERIFY_PROFILE: values.profile,
  PEERBORNE_VERIFY_SEED: values.seed,
  PEERBORNE_VERIFY_STRICT: values.strict ? '1' : '0',
});
const timeout = Number(values['timeout-ms']);
if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 2147483647)
  throw new Error('Invalid timeout');
const available = await catalog();
for (const id of values.scenario ?? [])
  if (!available.some((scenario) => scenario.id === id))
    throw new Error(`Unknown scenario: ${id}`);
for (const category of values.category ?? [])
  if (!available.some((scenario) => scenario.category === category))
    throw new Error(`Unknown category: ${category}`);
const selected = available.filter(
  (scenario) =>
    (!values.scenario || values.scenario.includes(scenario.id)) &&
    (!values.category || values.category.includes(scenario.category)),
);
if (selected.length === 0)
  throw new Error('No scenarios match the requested filters');
const output = resolve(
  root,
  values.output ??
    `verification/results/advanced/${settings.profile}/node-report.json`,
);
const save = async (path, value) => {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
};
if (values.list) {
  for (const { id, runtime, category, name } of selected)
    process.stdout.write(`${category}/${id} [${runtime}]: ${name}\n`);
} else if (values.worker) {
  const definition = available.find(
    ({ id, runtime }) => id === values.worker && runtime === 'node',
  );
  if (!definition) throw new Error('Invalid Node worker');
  const original = { ...console };
  const diagnostics = {};
  for (const level of ['log', 'debug', 'info', 'warn', 'error']) {
    diagnostics[level] = 0;
    console[level] = () => {
      diagnostics[level]++;
    };
  }
  let result;
  try {
    const module = await import(new URL(definition.module, import.meta.url));
    const observation = await module[definition.entry]({
      ...settings,
      progress: (text) => process.stderr.write(`${definition.id}: ${text}\n`),
    });
    if (
      !Array.isArray(observation.gaps) ||
      typeof observation.scope !== 'string'
    )
      throw new Error('Scenario must report its scope and gaps');
    result = {
      ...definition,
      ...settings,
      ...observation,
      status: observation.gaps.length ? 'gap' : 'passed',
      diagnostics,
    };
  } catch (error) {
    result = {
      ...definition,
      ...settings,
      status: 'failed',
      error: {
        name: error.name,
        assertion: error.code === 'ERR_ASSERTION' ? error.operator : undefined,
        location: error.stack
          ?.split('\n')
          .find((line) => line.includes('/verification/advanced/'))
          ?.trim(),
      },
      diagnostics,
    };
  } finally {
    Object.assign(console, original);
  }
  await save(output, result);
  if (result.status === 'failed') process.exitCode = 1;
} else {
  const report = {
    formatVersion: 1,
    suite: 'advanced',
    ...settings,
    determinism:
      'Fixed seeds, actor IDs, boundary values and delivery schedules. Real crypto entropy, timing, memory and native network behavior vary.',
    results: [],
  };
  const temporary = await mkdtemp(join(tmpdir(), 'peerborne-advanced-'));
  try {
    for (const definition of selected) {
      if (definition.runtime === 'browser') {
        report.results.push({
          ...definition,
          ...settings,
          status: 'not-run',
          command: `yarn verify:advanced:browser --grep ${definition.id}`,
        });
        continue;
      }
      const file = join(temporary, `${definition.id}.json`);
      process.stdout.write(`Running ${definition.id} (${settings.profile})\n`);
      const outcome = await new Promise((resolveExit, reject) => {
        const child = spawn(
          process.execPath,
          [
            '--expose-gc',
            fileURLToPath(import.meta.url),
            '--worker',
            definition.id,
            '--profile',
            settings.profile,
            '--seed',
            String(settings.seed),
            '--output',
            file,
            ...(values.strict ? ['--strict'] : []),
          ],
          { cwd: root, stdio: ['ignore', 'inherit', 'inherit'] },
        );
        let timedOut = false;
        const timer = setTimeout(() => {
          timedOut = true;
          child.kill('SIGKILL');
        }, timeout);
        child.once('error', (error) => {
          clearTimeout(timer);
          reject(error);
        });
        child.once('exit', (code, signal) => {
          clearTimeout(timer);
          resolveExit({ code, signal, timedOut });
        });
      });
      let result;
      try {
        result = JSON.parse(await readFile(file, 'utf8'));
      } catch {
        result = {
          ...definition,
          ...settings,
          status: 'failed',
          error: outcome.timedOut
            ? 'Bounded worker deadline exceeded'
            : 'Worker exited without a report',
        };
      }
      if (outcome.code !== 0 && result.status !== 'failed')
        result = {
          ...definition,
          ...settings,
          status: 'failed',
          error: 'Worker exited unsuccessfully after reporting',
        };
      report.results.push(result);
      await save(output, report);
      process.stdout.write(`${definition.id}: ${result.status}\n`);
    }
    await save(output, report);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
  if (
    report.results.some(
      ({ status }) =>
        status === 'failed' || (values.strict && status !== 'passed'),
    )
  )
    process.exitCode = 1;
  process.stdout.write(`Report: ${output}\n`);
}
