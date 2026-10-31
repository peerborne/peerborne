import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './nat',
  testMatch: '*.spec.ts',
  timeout: 300_000,
  workers: 1,
  retries: 0,
  reporter: 'line',
  outputDir: './results/nat',
  use: { trace: 'off', screenshot: 'off', video: 'off' },
});
