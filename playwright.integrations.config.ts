import { defineConfig, devices } from '@playwright/test';
import cases from './e2e/integration-cases.json';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'integrations.spec.ts',
  timeout: 45_000,
  workers: 2,
  fullyParallel: true,
  reporter: 'line',
  use: {
    ...devices['Desktop Chrome'],
    baseURL: 'http://127.0.0.1:4190',
    trace: 'on-first-retry',
  },
  webServer: [
    {
      command:
        'yarn workspace @peerborne/integration-examples preview --port 4190',
      port: 4190,
      reuseExistingServer: false,
    },
    ...cases.ssr.map(({ workspace, port }) => ({
      command: `yarn workspace ${workspace} preview${workspace.endsWith('nextjs-starter') ? ` --port ${port}` : ''}`,
      env: { PORT: String(port) },
      port,
      reuseExistingServer: false,
    })),
  ],
});
