import { readdir, readFile, stat, mkdir, writeFile } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
  options: {
    directory: { type: 'string', default: 'verification/results' },
    output: {
      type: 'string',
      default: 'verification/results/combined-report.json',
    },
    profile: { type: 'string', default: 'full' },
    strict: { type: 'boolean', default: false },
  },
});
if (!['full', 'smoke'].includes(values.profile))
  throw new Error('profile must be smoke or full');
const ids = [
  'schema',
  'history',
  'causal',
  'group',
  'epoch-race',
  'offline',
  'webrtc',
  'relay',
  'delta',
  'idb',
  'cold',
];
const output = resolve(values.output);
const newest = new Map();
const topologies = new Map();
async function visit(directory) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  for (const entry of entries.sort((left, right) =>
    left.name.localeCompare(right.name),
  )) {
    const file = join(directory, entry.name);
    if (entry.isDirectory()) await visit(file);
    else if (entry.name.endsWith('.json') && resolve(file) !== output) {
      let document;
      try {
        document = JSON.parse(await readFile(file, 'utf8'));
      } catch {
        continue;
      }
      if (document.selection) continue;
      const candidates = document.results ?? [document];
      for (const candidate of candidates) {
        if (!ids.includes(candidate.id) || candidate.status === 'not-run')
          continue;
        if ((candidate.profile ?? document.profile) !== values.profile)
          continue;
        const timestamp = (await stat(file)).mtimeMs;
        if (candidate.id === 'webrtc' && candidate.metrics?.topology) {
          const topology = candidate.metrics.topology;
          if (timestamp > (topologies.get(topology)?.timestamp ?? -1)) {
            topologies.set(topology, {
              timestamp,
              result: { ...candidate, sourceReport: file },
            });
          }
        }
        if (timestamp <= (newest.get(candidate.id)?.timestamp ?? -1)) continue;
        newest.set(candidate.id, {
          timestamp,
          result: { ...candidate, sourceReport: file },
        });
      }
    }
  }
}
await visit(resolve(values.directory));
const results = ids.map(
  (id) => newest.get(id)?.result ?? { id, status: 'not-run' },
);
const report = {
  formatVersion: 1,
  profile: values.profile,
  selection:
    'Newest matching-profile report per scenario; source paths retained. Check topology and scope before interpreting results.',
  results,
  topologyComparisons: [...topologies.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, value]) => value.result),
};
await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
for (const result of results)
  process.stdout.write(`${result.id}: ${result.status}\n`);
process.stdout.write(`Report: ${output}\n`);
if (
  results.some(({ status }) => status === 'failed') ||
  (values.strict && results.some(({ status }) => status !== 'passed'))
)
  process.exitCode = 1;
