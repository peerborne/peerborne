import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './browser',
  testMatch: '*.spec.ts',
  timeout: 900_000,
  expect: { timeout: 30_000 },
  workers: 1,
  retries: 0,
  reporter: 'line',
  outputDir: `./results/browser-${process.env.PEERBORNE_VERIFY_PROFILE ?? 'smoke'}-${process.env.PEERBORNE_VERIFY_TOPOLOGY ?? 'mesh'}`,
  use: {
    baseURL: 'http://127.0.0.1:4187',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
    launchOptions: { args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command:
      'yarn workspace @peerborne/browser-test exec vite --config ../../verification/browser/vite.config.mjs --host 127.0.0.1 --port 4187 --strictPort',
    url: 'http://127.0.0.1:4187',
    timeout: 60_000,
    reuseExistingServer: false,
  },
});
