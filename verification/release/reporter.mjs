import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

function redact(message) {
  return message.replace(/https?:\/\/[^\s<>"']+/gu, (url) =>
    url.replace(/#.*/u, '#[redacted]'),
  );
}

export default class ReleaseReporter {
  results = [];
  onStdOut(chunk) {
    process.stdout.write(redact(String(chunk)));
  }
  onStdErr(chunk) {
    process.stderr.write(redact(String(chunk)));
  }
  onTestEnd(test, result) {
    const name = test.titlePath().filter(Boolean).join(' / ');
    this.results.push({
      name,
      status: result.status,
      expectedStatus: test.expectedStatus,
      durationMs: result.duration,
      retry: result.retry,
    });
    console.log(`${result.status}: ${name}`);
    for (const error of result.errors)
      console.error(
        redact(error.message ?? 'Release browser assertion failed'),
      );
  }
  onError(error) {
    console.error(
      redact(error.message ?? 'Release browser infrastructure failed'),
    );
  }
  onEnd(result) {
    const path = resolve(
      process.env.PEERBORNE_RELEASE_REPORT_DIRECTORY,
      'browser.json',
    );
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      `${JSON.stringify({ status: result.status, results: this.results }, null, 2)}\n`,
    );
  }
}
