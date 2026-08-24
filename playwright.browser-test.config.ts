import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'browser-test.spec.ts',
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:4175',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'yarn workspace @peerborne/browser-test vite preview --host 127.0.0.1 --port 4175',
    port: 4175,
    timeout: 30_000,
    reuseExistingServer: false,
  },
});
