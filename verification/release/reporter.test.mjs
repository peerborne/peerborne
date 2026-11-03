import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import ReleaseReporter from './reporter.mjs';

test('release diagnostics redact bare invitation fragments and URL fragments through every reporter entry point', (context) => {
  const chunks = [];
  const token = 'synthetic_invitation_token-123';
  const message =
    [
      `Received: "#invite=${token}"`,
      `Received: \u001b[31m"#invite=${token}"\u001b[39m`,
      `Relative URL: /note#invite=${token}`,
      `Full URL: https://example.test/note#invite=${token}`,
      'Other fragment: https://example.test/#private-fragment',
    ].join('\n') + '\n';
  const write = (chunk) => {
    chunks.push(String(chunk));
    return true;
  };
  context.mock.method(process.stdout, 'write', write);
  context.mock.method(process.stderr, 'write', write);
  try {
    const reporter = new ReleaseReporter();
    reporter.onStdOut(message);
    reporter.onStdErr(message);
    reporter.onError({ message });
    reporter.onTestEnd(
      { titlePath: () => ['fragment scrubbing'], expectedStatus: 'passed' },
      { status: 'failed', duration: 1, retry: 0, errors: [{ message }] },
    );
  } finally {
    context.mock.restoreAll();
  }
  assert.equal(chunks.length, 5);
  for (const diagnostic of chunks.slice(0, 3).concat(chunks[4])) {
    assert.equal(diagnostic.includes(token), false);
    assert.equal(diagnostic.includes('private-fragment'), false);
    assert.match(diagnostic, /Received: "#invite=\[redacted\]"/u);
    assert.match(diagnostic, /https:\/\/example.test\/note#\[redacted\]/u);
  }
});

test('split stdout/stderr fragments remain private until a complete diagnostic can be redacted', (context) => {
  const report = mkdtempSync(join(tmpdir(), 'peerborne-reporter-'));
  const previous = process.env.PEERBORNE_RELEASE_REPORT_DIRECTORY;
  const chunks = [];
  const token = 'synthetic_chunked_invitation';
  const reporter = new ReleaseReporter();
  const write = (chunk) => {
    chunks.push(String(chunk));
    return true;
  };
  process.env.PEERBORNE_RELEASE_REPORT_DIRECTORY = report;
  context.mock.method(process.stdout, 'write', write);
  context.mock.method(process.stderr, 'write', write);
  let evidence;
  try {
    reporter.onStdOut('Received: #inv');
    reporter.onStdOut(`ite=${token.slice(0, 8)}`);
    reporter.onStdErr('Error: #invite=');
    reporter.onStdErr(token);
    assert.equal(chunks.length, 0);
    reporter.onStdOut(`${token.slice(8)}\n`);
    reporter.onEnd({ status: 'failed' });
    evidence = readFileSync(join(report, 'browser.json'), 'utf8');
  } finally {
    context.mock.restoreAll();
    if (previous === undefined)
      delete process.env.PEERBORNE_RELEASE_REPORT_DIRECTORY;
    else process.env.PEERBORNE_RELEASE_REPORT_DIRECTORY = previous;
    rmSync(report, { recursive: true, force: true });
  }
  assert.deepEqual(chunks, [
    'Received: #invite=[redacted]\n',
    'Error: #invite=[redacted]',
  ]);
  assert.equal(evidence.includes(token), false);
  assert.deepEqual(JSON.parse(evidence), { status: 'failed', results: [] });
});
