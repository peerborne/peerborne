import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'wiki-swarm.spec.ts',
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:4174',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'yarn workspace @peerborne/wiki-swarm vite preview --host 127.0.0.1 --port 4174',
    port: 4174,
    timeout: 30_000,
    reuseExistingServer: false,
  },
});
