import { spawnSync } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const reports = fileURLToPath(new URL('../results/release/', import.meta.url));

export async function auditConsumer(consumer, name, productionOnly) {
  const result = spawnSync(
    'npm',
    [
      'audit',
      '--json',
      '--audit-level=high',
      ...(productionOnly ? ['--omit=dev'] : []),
    ],
    {
      cwd: consumer,
      encoding: 'utf8',
      env: { ...process.env, NODE_AUTH_TOKEN: undefined, NPM_TOKEN: undefined },
    },
  );
  if (result.error) throw result.error;
  let audit;
  try {
    audit = JSON.parse(result.stdout);
  } catch {
    throw new Error('npm did not return a dependency audit');
  }
  if (!audit.metadata?.vulnerabilities)
    throw new Error('Dependency audit did not complete');
  await mkdir(reports, { recursive: true });
  const advisories = Object.entries(audit.vulnerabilities ?? {}).map(
    ([name, vulnerability]) => ({
      name,
      severity: vulnerability.severity,
      advisories: vulnerability.via
        .filter((value) => typeof value !== 'string')
        .map(({ title, url, range }) => ({ title, url, range })),
    }),
  );
  await writeFile(
    resolve(reports, `${name}.json`),
    `${JSON.stringify({ scope: productionOnly ? 'installed release packages' : 'external browser applications and build tools', counts: audit.metadata.vulnerabilities, advisories }, null, 2)}\n`,
  );
  console.log(
    `Dependency audit (${name}): ${JSON.stringify(audit.metadata.vulnerabilities)}`,
  );
  if (result.status !== 0)
    throw new Error(
      'Release consumer has high or critical dependency advisories',
    );
}
