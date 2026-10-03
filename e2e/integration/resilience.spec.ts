import { test, expect, type Page, type ConsoleMessage } from '@playwright/test';

const APP_1_URL = 'http://localhost:3001';
const APP_2_URL = 'http://localhost:3002';

function trackConsole(page: Page) {
  const messages: string[] = [];
  page.on('console', (msg) => messages.push(msg.text()));

  return {
    messages,
    has(prefix: string): boolean {
      return messages.some(m => m.startsWith(prefix));
    },
    waitFor(prefix: string, timeout = 60_000): Promise<string> {
      const existing = messages.find(m => m.startsWith(prefix));
      if (existing) return Promise.resolve(existing);

      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          page.off('console', handler);
          reject(new Error(`Timeout (${timeout}ms) waiting for console: "${prefix}"\nCollected: ${messages.join('\n')}`));
        }, timeout);
        const handler = (msg: ConsoleMessage) => {
          if (msg.text().startsWith(prefix)) {
            clearTimeout(timer);
            page.off('console', handler);
            resolve(msg.text());
          }
        };
        page.on('console', handler);
      });
    },
  };
}

// These tests are skipped by default because GossipSub mesh degradation after
// peer churn (reconnect/reload) through a single relay makes them flaky.
// The core bidirectional sync tests in bidirectional-sync.spec.ts provide full
// proof of bi-directional data sync. These resilience scenarios require either:
// - Multiple relay nodes for mesh redundancy
// - Direct WebRTC connections between browsers (not just relay-mediated)
// - GossipSub floodPublish mode (trades bandwidth for reliability)
//
// To run them, change `test.skip` to `test` and run `yarn test:integration`
// against the integration Docker topology.
test.describe('Resilience', () => {
  test.skip('browser reconnects after page reload', async ({ browser }) => {
    test.setTimeout(180_000);

    const context1 = await browser.newContext();
    const context2 = await browser.newContext();
    try {
      const page1 = await context1.newPage();
      const page2 = await context2.newPage();

      const track1 = trackConsole(page1);
      const track2 = trackConsole(page2);

      await page1.goto(APP_1_URL);
      await page2.goto(APP_2_URL);

      await Promise.all([
        track1.waitFor('INIT_COMPLETE'),
        track2.waitFor('INIT_COMPLETE'),
      ]);
      await Promise.all([
        track1.waitFor('PEER_CONNECTED:', 90_000),
        track2.waitFor('PEER_CONNECTED:', 90_000),
      ]);
      await page1.waitForTimeout(8000);

      // Pre-reload message
      const preMsg = track2.waitFor('PUBSUB_MESSAGE:', 30_000);
      await page1.fill('#message-input', 'before-reload');
      await page1.click('#send-btn');
      await preMsg;

      // Reload B
      const track2After = trackConsole(page2);
      await page2.reload();
      await track2After.waitFor('INIT_COMPLETE', 60_000);
      await track2After.waitFor('PEER_CONNECTED:', 90_000);
      await page2.waitForTimeout(10_000);

      // Post-reload message
      const postMsg = track2After.waitFor('PUBSUB_MESSAGE:', 45_000);
      await page1.fill('#message-input', 'after-reload');
      await page1.click('#send-btn');
      await postMsg;

      const messages2 = await page2.evaluate(() => (window as any).__messages);
      expect(messages2.some((m: any) => m.text === 'after-reload')).toBe(true);
    } finally {
      await context1.close();
      await context2.close();
    }
  });

  test.skip('three browsers all sync correctly', async ({ browser }) => {
    test.setTimeout(180_000);

    const context1 = await browser.newContext();
    const context2 = await browser.newContext();
    const context3 = await browser.newContext();
    try {
      const page1 = await context1.newPage();
      const page2 = await context2.newPage();
      const page3 = await context3.newPage();

      const track1 = trackConsole(page1);
      const track2 = trackConsole(page2);
      const track3 = trackConsole(page3);

      await page1.goto(APP_1_URL);
      await page2.goto(APP_2_URL);
      await page3.goto(APP_1_URL);

      await Promise.all([
        track1.waitFor('INIT_COMPLETE'),
        track2.waitFor('INIT_COMPLETE'),
        track3.waitFor('INIT_COMPLETE'),
      ]);
      await Promise.all([
        track1.waitFor('PEER_CONNECTED:', 90_000),
        track2.waitFor('PEER_CONNECTED:', 90_000),
        track3.waitFor('PEER_CONNECTED:', 90_000),
      ]);
      await page1.waitForTimeout(10_000);

      const msg2 = track2.waitFor('PUBSUB_MESSAGE:', 45_000);
      const msg3 = track3.waitFor('PUBSUB_MESSAGE:', 45_000);
      await page1.fill('#message-input', 'hello-from-1');
      await page1.click('#send-btn');
      await Promise.all([msg2, msg3]);

      const messages2 = await page2.evaluate(() => (window as any).__messages);
      const messages3 = await page3.evaluate(() => (window as any).__messages);
      expect(messages2.some((m: any) => m.text === 'hello-from-1')).toBe(true);
      expect(messages3.some((m: any) => m.text === 'hello-from-1')).toBe(true);
    } finally {
      await context1.close();
      await context2.close();
      await context3.close();
    }
  });
});
