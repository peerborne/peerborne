import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export const root = fileURLToPath(new URL('../../', import.meta.url));
export const resultsDirectory = new URL(
  '../results/advanced/',
  import.meta.url,
);

export async function catalog() {
  const directory = new URL('./catalog/', import.meta.url);
  const scenarios = [];
  const seen = new Set();
  for (const file of (await readdir(directory)).sort()) {
    if (!file.endsWith('.json')) continue;
    const group = JSON.parse(await readFile(new URL(file, directory), 'utf8'));
    for (const scenario of group.scenarios) {
      if (!/^[a-z][a-z0-9-]+$/.test(scenario.id) || seen.has(scenario.id))
        throw new Error('Invalid or duplicate scenario ID');
      if (!['node', 'browser'].includes(scenario.runtime))
        throw new Error('Invalid scenario runtime');
      if (
        scenario.runtime === 'node' &&
        !/^\.\/node\/[a-z-]+\.mjs$/.test(scenario.module)
      )
        throw new Error('Invalid scenario module');
      seen.add(scenario.id);
      scenarios.push({ ...scenario, category: group.category });
    }
  }
  return scenarios;
}

export function options(environment = process.env) {
  const profile = environment.PEERBORNE_VERIFY_PROFILE ?? 'smoke';
  const seed = Number(environment.PEERBORNE_VERIFY_SEED ?? 9420);
  if (!['smoke', 'full'].includes(profile))
    throw new Error('profile must be smoke or full');
  if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff)
    throw new Error('seed must be a uint32');
  return {
    profile,
    full: profile === 'full',
    seed,
    strict: environment.PEERBORNE_VERIFY_STRICT === '1',
  };
}
