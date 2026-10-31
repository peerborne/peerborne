import { defineConfig, devices } from '@playwright/test';
import { root } from './catalog.mjs';

export default defineConfig({
  testDir: './browser',
  testMatch: '*.spec.ts',
  timeout: 900_000,
  workers: 1,
  retries: 0,
  reporter: 'line',
  outputDir: `../results/advanced/browser-${process.env.PEERBORNE_VERIFY_PROFILE ?? 'smoke'}`,
  use: {
    baseURL: 'http://127.0.0.1:4188',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
    launchOptions: {
      args: [
        '--disable-features=WebRtcHideLocalIpsWithMdns',
        '--enable-precise-memory-info',
        ...(process.env.PEERBORNE_VERIFY_NETEM === 'isolated'
          ? ['--allow-loopback-in-peer-connection']
          : []),
      ],
    },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    cwd: root,
    command:
      'yarn workspace @peerborne/browser-test exec vite --config ../../verification/advanced/browser/vite.config.mjs --host 127.0.0.1 --port 4188 --strictPort',
    url: 'http://127.0.0.1:4188',
    timeout: 60000,
    reuseExistingServer: false,
  },
});
