import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'peerborne-note.spec.ts',
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:4176',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command:
      'yarn workspace @peerborne/peerborne-note vite preview --host 127.0.0.1 --port 4176',
    port: 4176,
    timeout: 30_000,
    reuseExistingServer: false,
  },
});
