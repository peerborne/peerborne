import { defineConfig } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const { ports } = JSON.parse(
  readFileSync(process.env.PEERBORNE_RELEASE_CONFIGURATION, 'utf8'),
);
process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1';
const browsers = (process.env.PEERBORNE_RELEASE_BROWSERS ?? 'chromium').split(
  ',',
);
for (const name of browsers)
  if (!['chromium', 'firefox', 'webkit'].includes(name))
    throw new Error('Unknown release acceptance browser');

export default defineConfig({
  testDir: '../../e2e',
  forbidOnly: Boolean(process.env.CI),
  maxFailures: process.env.CI ? 1 : 0,
  workers: 1,
  timeout: 180_000,
  expect: { timeout: 60_000 },
  reporter: [['./reporter.mjs']],
  use: { trace: 'off', screenshot: 'off', video: 'off' },
  projects: browsers.flatMap((browserName) => [
    {
      name: `${browserName}-integrations`,
      testMatch: 'integrations.spec.ts',
      use: { browserName, baseURL: `http://127.0.0.1:${ports.integrations}` },
    },
    {
      name: `${browserName}-note`,
      testMatch: [
        'peerborne-note.spec.ts',
        'peerborne-note-live.spec.ts',
        'release-recovery.spec.ts',
      ],
      use: { browserName, baseURL: `http://127.0.0.1:${ports.note}/` },
    },
  ]),
  webServer: {
    command: 'node verification/release/serve.mjs',
    cwd: fileURLToPath(new URL('../../', import.meta.url)),
    url: `http://127.0.0.1:${ports.control}/ready`,
    timeout: 180_000,
    stdout: 'pipe',
    stderr: 'pipe',
    reuseExistingServer: false,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
  },
});
