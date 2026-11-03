import assert from 'node:assert/strict';
import test from 'node:test';
import ReleaseReporter from './reporter.mjs';

test('release diagnostics redact bare invitation fragments and URL fragments through every reporter entry point', (context) => {
  const chunks = [];
  const token = 'synthetic_invitation_token-123';
  const message = [
    `Received: "#invite=${token}"`,
    `Received: \u001b[31m"#invite=${token}"\u001b[39m`,
    `Relative URL: /note#invite=${token}`,
    `Full URL: https://example.test/note#invite=${token}`,
    'Other fragment: https://example.test/#private-fragment',
  ].join('\n');
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
