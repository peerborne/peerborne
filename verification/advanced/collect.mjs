import { readdir, readFile, stat, mkdir, writeFile } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import { catalog, options, root } from './catalog.mjs';

const { values } = parseArgs({
  options: {
    profile: {
      type: 'string',
      default: process.env.PEERBORNE_VERIFY_PROFILE ?? 'smoke',
    },
    directory: { type: 'string', default: 'verification/results/advanced' },
    output: { type: 'string' },
    strict: { type: 'boolean', default: false },
  },
});
options({ PEERBORNE_VERIFY_PROFILE: values.profile });
const definitions = await catalog();
const output = resolve(
  root,
  values.output ??
    `verification/results/advanced/${values.profile}/combined-report.json`,
);
const newest = new Map();
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
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await visit(path);
    else if (entry.name.endsWith('.json') && path !== output) {
      let document;
      try {
        document = JSON.parse(await readFile(path, 'utf8'));
      } catch {
        continue;
      }
      if (document.selection) continue;
      const timestamp = (await stat(path)).mtimeMs;
      for (const result of document.results ?? [document]) {
        if (
          !definitions.some(({ id }) => id === result.id) ||
          (result.profile ?? document.profile) !== values.profile ||
          result.status === 'not-run'
        )
          continue;
        if (timestamp > (newest.get(result.id)?.timestamp ?? -1))
          newest.set(result.id, {
            timestamp,
            result: { ...result, sourceReport: path },
          });
      }
    }
  }
}
await visit(resolve(root, values.directory));
const results = definitions.map(
  (definition) =>
    newest.get(definition.id)?.result ?? { ...definition, status: 'not-run' },
);
const report = {
  formatVersion: 1,
  suite: 'advanced',
  profile: values.profile,
  selection:
    'Latest matching-profile observation per catalog ID; inspect the scope of each result.',
  results,
};
await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
for (const { id, status } of results)
  process.stdout.write(`${id}: ${status}\n`);
if (
  results.some(
    ({ status }) =>
      status === 'failed' || (values.strict && status !== 'passed'),
  )
)
  process.exitCode = 1;
