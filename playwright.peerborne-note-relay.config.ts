import { defineConfig, devices } from '@playwright/test';

process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1';
process.env.PEERBORNE_NOTE_LIVE_URL = 'http://127.0.0.1:4179/';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'peerborne-note-live.spec.ts',
  forbidOnly: Boolean(process.env.CI),
  fullyParallel: false,
  workers: 1,
  reporter: 'line',
  timeout: 180_000,
  expect: { timeout: 60_000 },
  use: {
    baseURL: 'http://127.0.0.1:4179/',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node e2e/start-note-relay.mjs',
    port: 4179,
    timeout: 90_000,
    reuseExistingServer: false,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 },
  },
});
