import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectConsumerAudit } from './audit.mjs';

const severities = ['info', 'low', 'moderate', 'high', 'critical'];

function auditReport(counts) {
  const vulnerabilities = Object.fromEntries(
    severities.flatMap((severity, index) =>
      Array.from({ length: counts[index] }, (_, number) => [
        `fixture-${severity}-${number}`,
        { severity, via: ['fixture-advisory'] },
      ]),
    ),
  );
  return {
    auditReportVersion: 2,
    vulnerabilities,
    metadata: {
      vulnerabilities: {
        ...Object.fromEntries(
          severities.map((severity, index) => [severity, counts[index]]),
        ),
        total: Object.keys(vulnerabilities).length,
      },
    },
  };
}

function outcome(report, status = 0) {
  return { status, stdout: JSON.stringify(report) };
}

test('all production findings block release and application checks keep their high threshold', () => {
  for (let state = 0; state < 3 ** severities.length; state++) {
    const counts = severities.map(
      (_, index) => Math.floor(state / 3 ** index) % 3,
    );
    const report = auditReport(counts);
    for (const productionOnly of [true, false]) {
      const inspected = inspectConsumerAudit(outcome(report), productionOnly);
      const relevant = productionOnly ? counts : counts.slice(3);
      assert.equal(inspected.failure !== undefined, relevant.some(Boolean));
      assert.deepEqual(inspected.counts, report.metadata.vulnerabilities);
      assert.equal(
        inspected.advisories.length,
        report.metadata.vulnerabilities.total,
      );
    }
  }
});

test('a failed or interrupted npm audit never produces an accepted decision', () => {
  const clean = outcome(auditReport([0, 0, 0, 0, 0]));
  const incomplete = { ...clean, stdout: '{' };
  for (const productionOnly of [true, false]) {
    for (const result of [
      incomplete,
      { ...clean, status: null, signal: 'SIGTERM' },
      { ...clean, error: new Error('spawn error') },
      { ...clean, status: undefined },
    ])
      assert.throws(
        () => inspectConsumerAudit(result, productionOnly),
        /did not complete/u,
      );
    for (const status of [1, 2, 127])
      assert.equal(
        inspectConsumerAudit({ ...clean, status }, productionOnly).failure,
        'Dependency audit failed',
      );
  }
});

test('rejects incomplete or inconsistent npm audit JSON even when npm exits zero', () => {
  const variants = [
    (report) => {
      report.auditReportVersion = 3;
    },
    (report) => {
      report.error = { code: 'unavailable' };
    },
    (report) => {
      delete report.vulnerabilities;
    },
    (report) => {
      delete report.metadata.vulnerabilities.low;
    },
    (report) => {
      report.metadata.vulnerabilities.low = '1';
    },
    (report) => {
      report.metadata.vulnerabilities.low = 0;
    },
    (report) => {
      report.metadata.vulnerabilities.total = 0;
    },
    (report) => {
      report.metadata.vulnerabilities.unknown = 0;
    },
    (report) => {
      report.vulnerabilities['fixture-low-0'].severity = 'unknown';
    },
    (report) => {
      report.vulnerabilities['fixture-low-0'].via = null;
    },
    (report) => {
      report.vulnerabilities['fixture-low-0'].via = [null];
    },
  ];
  for (const modify of variants) {
    const report = auditReport([0, 1, 0, 0, 0]);
    modify(report);
    for (const productionOnly of [true, false])
      assert.throws(
        () => inspectConsumerAudit(outcome(report), productionOnly),
        /did not complete/u,
      );
  }
});

test('production findings remain reportable when npm returns a failure status', () => {
  const report = auditReport([0, 1, 0, 0, 0]);
  const advisory = {
    title: 'Fixture advisory',
    url: 'https://example.org/advisory',
    range: '<1.0.0',
  };
  report.vulnerabilities['fixture-low-0'].via.push({
    ...advisory,
    extra: 'discarded',
  });
  const inspected = inspectConsumerAudit(outcome(report, 1), true);
  assert.match(inspected.failure, /production dependency advisories/u);
  assert.deepEqual(inspected.advisories, [
    { name: 'fixture-low-0', severity: 'low', advisories: [advisory] },
  ]);
});
