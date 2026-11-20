import { spawnSync } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const reports = fileURLToPath(new URL('../results/release/', import.meta.url));
const severities = ['info', 'low', 'moderate', 'high', 'critical'];

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function incompleteAudit() {
  return new Error(
    'Dependency audit did not complete with a consistent report',
  );
}

export function inspectConsumerAudit(result, productionOnly) {
  if (result.error || result.signal || !Number.isSafeInteger(result.status))
    throw incompleteAudit();
  let audit;
  try {
    audit = JSON.parse(result.stdout);
  } catch {
    throw incompleteAudit();
  }
  if (
    audit?.auditReportVersion !== 2 ||
    audit.error !== undefined ||
    !isRecord(audit.vulnerabilities) ||
    !isRecord(audit.metadata?.vulnerabilities)
  )
    throw incompleteAudit();

  const advertised = audit.metadata.vulnerabilities;
  const counts = Object.fromEntries(
    severities.map((severity) => [severity, 0]),
  );
  const advisories = Object.entries(audit.vulnerabilities).map(
    ([name, finding]) => {
      if (
        !isRecord(finding) ||
        !severities.includes(finding.severity) ||
        !Array.isArray(finding.via)
      )
        throw incompleteAudit();
      counts[finding.severity]++;
      return {
        name,
        severity: finding.severity,
        advisories: finding.via
          .filter((value) => typeof value !== 'string')
          .map((value) => {
            if (
              !isRecord(value) ||
              typeof value.title !== 'string' ||
              typeof value.url !== 'string' ||
              typeof value.range !== 'string'
            )
              throw incompleteAudit();
            const { title, url, range } = value;
            return { title, url, range };
          }),
      };
    },
  );
  counts.total = advisories.length;
  if (
    Object.keys(advertised).length !== severities.length + 1 ||
    Object.entries(counts).some(
      ([severity, count]) => advertised[severity] !== count,
    )
  )
    throw incompleteAudit();

  const blocked = productionOnly
    ? counts.total > 0
    : counts.high > 0 || counts.critical > 0;
  return {
    scope: productionOnly
      ? 'installed release packages'
      : 'external browser applications and build tools',
    counts,
    advisories,
    failure: blocked
      ? productionOnly
        ? 'Release consumer has production dependency advisories'
        : 'Release consumer has high or critical dependency advisories'
      : result.status !== 0
        ? 'Dependency audit failed'
        : undefined,
  };
}

export async function auditConsumer(consumer, name, productionOnly) {
  const result = spawnSync(
    'npm',
    [
      'audit',
      '--json',
      productionOnly ? '--audit-level=info' : '--audit-level=high',
      ...(productionOnly ? ['--omit=dev'] : []),
    ],
    {
      cwd: consumer,
      encoding: 'utf8',
      env: { ...process.env, NODE_AUTH_TOKEN: undefined, NPM_TOKEN: undefined },
    },
  );
  const { failure, ...report } = inspectConsumerAudit(result, productionOnly);
  await mkdir(reports, { recursive: true });
  await writeFile(
    resolve(reports, `${name}.json`),
    `${JSON.stringify(report, null, 2)}\n`,
  );
  console.log(`Dependency audit (${name}): ${JSON.stringify(report.counts)}`);
  if (failure) throw new Error(failure);
}
