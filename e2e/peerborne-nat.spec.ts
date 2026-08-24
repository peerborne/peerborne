import { chromium, expect, test, type Browser, type Page } from '@playwright/test';
import { webcrypto } from 'node:crypto';

const endpoints = [
  process.env.BROWSER_A_WS ?? 'ws://127.0.0.1:3101/',
  process.env.BROWSER_B_WS ?? 'ws://127.0.0.1:3102/',
];

async function waitForDocument(page: Page, path: string, key: string, value: unknown) {
  await expect.poll(
    () => page.evaluate(
      ([p, k]) => (window as any).__PEERBORNE_TEST__?.state().documents[p]?.document?.[k],
      [path, key],
    ),
    { timeout: 30_000, intervals: [250, 500, 1_000] },
  ).toEqual(value);
}

test('real Peerborne document loads across two NAT-isolated Chromium processes', async () => {
  const pair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'],
  ) as CryptoKeyPair;
  const identity = {
    privateKey: await webcrypto.subtle.exportKey('jwk', pair.privateKey),
    publicKey: await webcrypto.subtle.exportKey('jwk', pair.publicKey),
  };

  const browsers: Browser[] = [];
  try {
    browsers.push(await chromium.connect(endpoints[0]));
    browsers.push(await chromium.connect(endpoints[1]));
    const contexts = await Promise.all(browsers.map((browser) => browser.newContext()));
    const pages = await Promise.all(contexts.map((context) => context.newPage()));
    const diagnostics = pages.map(() => [] as string[]);
    pages.forEach((page, index) => {
      page.on('console', (message) => diagnostics[index].push(`console:${message.type()}: ${message.text()}`));
      page.on('pageerror', (error) => diagnostics[index].push(`pageerror: ${error.message}`));
    });
    await Promise.all(pages.map((page) => page.addInitScript(
      (injected) => { (window as any).__PEERBORNE_TEST_IDENTITY__ = injected; },
      identity,
    )));
    await Promise.all(pages.map((page) => page.goto('http://localhost:8080')));
    try {
      await Promise.all(pages.map(async (page) => {
        await page.waitForFunction(
          () => Boolean((window as any).__PEERBORNE_TEST__), undefined,
          { timeout: 15_000 },
        );
        await page.waitForFunction(
          () => Boolean((window as any).__PEERBORNE_TEST__?.state().node), undefined,
          { timeout: 90_000 },
        );
      }));
    } catch (error) {
      throw new Error(`Peerborne initialization failed:\n${diagnostics.map(
        (messages, index) => `browser ${index + 1}:\n${messages.join('\n')}`,
      ).join('\n')}\n${String(error)}`);
    }

    await Promise.all(pages.map((page) => expect.poll(
      () => page.evaluate(() => (window as any).__PEERBORNE_TEST__.circuitAddress()),
      { timeout: 90_000, intervals: [250, 500, 1_000] },
    ).not.toBeUndefined()));

    const path = `/nat-proof-${Date.now()}`;
    await pages[0].evaluate((p) => (window as any).__PEERBORNE_TEST__.open(p), path);
    await pages[0].evaluate((p) => (window as any).__PEERBORNE_TEST__.change(p, 'fromA', 'alice'), path);

    // Dial A's circuit-relay address explicitly. Besides removing peer
    // discovery timing from the database assertion, requiring p2p-circuit in
    // the selected address proves this connection cannot be a direct LAN path.
    await expect.poll(
      () => pages[0].evaluate(() =>
        (window as any).__PEERBORNE_TEST__.circuitAddress(),
      ),
      { timeout: 90_000, intervals: [500, 1_000] },
    ).not.toBeUndefined();
    const address = await pages[0].evaluate(() =>
      (window as any).__PEERBORNE_TEST__.circuitAddress(),
    );
    expect(address).toContain('/p2p-circuit/');
    await expect.poll(
      () => pages[1].evaluate(async (target) => {
        try {
          await (window as any).__PEERBORNE_TEST__.connect([target]);
          return true;
        } catch {
          return false;
        }
      }, address),
      { timeout: 90_000, intervals: [1_000, 2_000] },
    ).toBe(true);

    try {
      // This is one user on two computers. Restore the user's document
      // keychain out of band, as a real device restore/key-sync mechanism
      // must do; the document history itself is still fetched over the relay.
      const documentKey = await pages[0].evaluate(
        (p) => (window as any).__PEERBORNE_TEST__.exportDocumentKey(p), path,
      );
      await pages[1].evaluate(
        ([p, saved]) => (window as any).__PEERBORNE_TEST__.openWithDocumentKey(p, saved),
        [path, documentKey] as const,
      );
      await waitForDocument(pages[1], path, 'fromA', 'alice');
    } catch (error) {
      throw new Error(`Document convergence failed:\n${diagnostics.map(
        (messages, index) => `browser ${index + 1}:\n${messages.join('\n')}`,
      ).join('\n')}\n${String(error)}`);
    }
  } finally {
    await Promise.all(browsers.map((browser) => browser.close().catch(() => undefined)));
  }
});
