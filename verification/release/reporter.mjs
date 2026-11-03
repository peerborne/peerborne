import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

function redact(message) {
  return message
    .replace(/#invite=[A-Za-z0-9_-]+/gu, '#invite=[redacted]')
    .replace(/https?:\/\/[^\s<>"']+/gu, (url) =>
      url.replace(/#.*/u, '#[redacted]'),
    );
}

export default class ReleaseReporter {
  results = [];
  pending = { stdout: '', stderr: '' };
  writeDiagnostic(stream, chunk) {
    this.pending[stream] += String(chunk);
    const end = this.pending[stream].lastIndexOf('\n') + 1;
    if (end === 0) return;
    process[stream].write(redact(this.pending[stream].slice(0, end)));
    this.pending[stream] = this.pending[stream].slice(end);
  }
  onStdOut(chunk) {
    this.writeDiagnostic('stdout', chunk);
  }
  onStdErr(chunk) {
    this.writeDiagnostic('stderr', chunk);
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
    for (const stream of ['stdout', 'stderr']) {
      if (this.pending[stream])
        process[stream].write(redact(this.pending[stream]));
      this.pending[stream] = '';
    }
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
