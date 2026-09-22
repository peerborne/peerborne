import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

export async function waitForRemoteChromium(
  endpoint,
  { timeoutMs = 120_000, pollIntervalMs = 1_000 } = {},
) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    try {
      const browser = await chromium.connect(endpoint, {
        timeout: Math.max(1, Math.min(5_000, deadline - performance.now())),
      });
      await browser.close();
      return;
    } catch {
      const remaining = deadline - performance.now();
      if (remaining > 0) await delay(Math.min(pollIntervalMs, remaining));
    }
  }
  throw new Error(`Remote Chromium did not become ready within ${timeoutMs}ms`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const endpoints = process.argv.slice(2);
  if (endpoints.length === 0) {
    console.error('Provide at least one remote Playwright WebSocket endpoint');
    process.exitCode = 1;
  } else {
    await Promise.all(endpoints.map(async (endpoint, index) => {
      try {
        await waitForRemoteChromium(endpoint);
        console.log(`Remote Chromium ${index + 1} is ready`);
      } catch (error) {
        console.error(`Remote Chromium ${index + 1}: ${error.message}`);
        process.exitCode = 1;
      }
    }));
  }
}
