import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'password-manager.spec.ts',
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'yarn workspace @peerborne/password-manager vite preview --host 127.0.0.1 --port 4173',
    port: 4173,
    timeout: 30_000,
    reuseExistingServer: false,
  },
});
