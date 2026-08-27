import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.PEERBORNE_NOTE_LIVE_URL;
if (!baseURL || !/^https:\/\/[^/]+\/$/u.test(baseURL)) {
  throw new Error(
    'PEERBORNE_NOTE_LIVE_URL must be an HTTPS origin ending in a slash',
  );
}

export default defineConfig({
  testDir: './e2e',
  testMatch: 'peerborne-note-live.spec.ts',
  forbidOnly: Boolean(process.env.CI),
  fullyParallel: false,
  workers: 1,
  reporter: 'line',
  timeout: 180_000,
  expect: { timeout: 60_000 },
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
