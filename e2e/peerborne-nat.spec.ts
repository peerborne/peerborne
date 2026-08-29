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

test('distinct identities accept an invitation and converge bidirectionally across NAT', async () => {
  const identities = await Promise.all([0, 1].map(async () => {
    const pair = await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'],
    ) as CryptoKeyPair;
    return {
      privateKey: await webcrypto.subtle.exportKey('jwk', pair.privateKey),
      publicKey: await webcrypto.subtle.exportKey('jwk', pair.publicKey),
    };
  }));
  expect(identities[0].publicKey.x).not.toBe(identities[1].publicKey.x);

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
    await Promise.all(pages.map((page, index) => page.addInitScript(
      (injected) => { (window as any).__PEERBORNE_TEST_IDENTITY__ = injected; },
      identities[index],
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

    try {
      // No pre-connect: acceptInvitation() must dial the founder from the
      // signed circuit rendezvous address carried by the offer.
      const encodedOffer = await pages[0].evaluate(
        (p) => (window as any).__PEERBORNE_TEST__.createInvitation(p),
        path,
      );
      const offerText = Buffer.from(encodedOffer).toString('utf8');
      expect(offerText).toContain('peerborne.invitation.offer');
      expect(offerText).not.toMatch(/privateKey|documentKey|sealedWelcome/i);

      await pages[1].evaluate(
        (offer) => (window as any).__PEERBORNE_TEST__.acceptInvitation(offer),
        encodedOffer,
      );
      await waitForDocument(pages[1], path, 'fromA', 'alice');

      // Initial retrieval alone does not prove the live GossipSub path. Make
      // fresh changes after both replicas are open and require convergence in
      // each direction over the existing relay-only connection.
      await pages[0].evaluate(
        (p) => (window as any).__PEERBORNE_TEST__.change(p, 'liveFromA', 'alice-live'),
        path,
      );
      await waitForDocument(pages[1], path, 'liveFromA', 'alice-live');

      await pages[1].evaluate(
        (p) => (window as any).__PEERBORNE_TEST__.change(p, 'liveFromB', 'bob-live'),
        path,
      );
      await waitForDocument(pages[0], path, 'liveFromB', 'bob-live');

      // Exercise the other public role on a separate document. The recipient
      // must decrypt/read the bootstrap while remaining absent from the writer
      // ACL, and a real document mutation must reject locally.
      const readerPath = `/nat-reader-proof-${Date.now()}`;
      await pages[0].evaluate(
        (p) => (window as any).__PEERBORNE_TEST__.open(p),
        readerPath,
      );
      await pages[0].evaluate(
        (p) => (window as any).__PEERBORNE_TEST__.change(
          p,
          'founderOnly',
          'readable',
        ),
        readerPath,
      );
      const readerOffer = await pages[0].evaluate(
        (p) => (window as any).__PEERBORNE_TEST__.createInvitation(p, 'reader'),
        readerPath,
      );
      await pages[1].evaluate(
        (offer) => (window as any).__PEERBORNE_TEST__.acceptInvitation(offer),
        readerOffer,
      );
      await waitForDocument(
        pages[1],
        readerPath,
        'founderOnly',
        'readable',
      );
      expect(await pages[1].evaluate(
        (p) => (window as any).__PEERBORNE_TEST__.writerCount(p),
        readerPath,
      )).toBe(1);
      const readerWrite = await pages[1].evaluate(async (p) => {
        try {
          await (window as any).__PEERBORNE_TEST__.change(
            p,
            'forbidden',
            true,
          );
          return { accepted: true, message: '' };
        } catch (error) {
          return {
            accepted: false,
            message: error instanceof Error ? error.message : String(error),
          };
        }
      }, readerPath);
      expect(readerWrite.accepted).toBe(false);
      expect(readerWrite.message).toMatch(/does not have write permissions/);
    } catch (error) {
      throw new Error(`Document convergence failed:\n${diagnostics.map(
        (messages, index) => `browser ${index + 1}:\n${messages.join('\n')}`,
      ).join('\n')}\n${String(error)}`);
    }
  } finally {
    await Promise.all(browsers.map((browser) => browser.close().catch(() => undefined)));
  }
});
