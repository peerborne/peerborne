import {
  test,
  expect,
  chromium,
  type Page,
  type BrowserContext,
} from '@playwright/test';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, dirname, join } from 'node:path';
import { catalog, options } from '../catalog.mjs';

const settings = options();
const definition = (await catalog()).find(
  (item) => item.id === 'storage-eviction',
);
const call = (page: Page, method: string, args: any[] = []): Promise<any> =>
  page.evaluate(
    async ({ method, args }) => {
      const path = '/eviction.mjs';
      return (await import(path))[method](...args);
    },
    { method, args },
  );
async function link(source: Page, target: Page) {
  const offer = await call(source, 'offer');
  const answer = await call(target, 'answer', [offer]);
  await call(source, 'accept', [answer]);
  await Promise.all([call(source, 'opened'), call(target, 'opened')]);
}

if (definition)
  test(`${definition.id}: ${definition.name}`, async ({ browser }, info) => {
    const profile = await mkdtemp(join(tmpdir(), 'peerborne-eviction-'));
    const authorityContext = await browser.newContext({
      baseURL: 'http://127.0.0.1:4188',
    });
    const authority = await authorityContext.newPage();
    let victimContext: BrowserContext | undefined;
    const launch = async () => {
      victimContext = await chromium.launchPersistentContext(profile, {
        headless: true,
        baseURL: 'http://127.0.0.1:4188',
        args: ['--disable-features=WebRtcHideLocalIpsWithMdns'],
      });
      const page = victimContext.pages()[0] ?? (await victimContext.newPage());
      await page.goto('/');
      return page;
    };
    const output = resolve(
      info.config.rootDir,
      '../../results/advanced',
      settings.profile,
      `${definition.id}-report.json`,
    );
    let reported = false;
    const save = async (result: any) => {
      await mkdir(dirname(output), { recursive: true });
      await writeFile(
        output,
        `${JSON.stringify({ ...definition, ...settings, ...result }, null, 2)}\n`,
      );
      await info.attach(`${definition.id}-report.json`, {
        path: output,
        contentType: 'application/json',
      });
      reported = true;
    };
    try {
      await authority.goto('/');
      let victim = await launch();
      const original = await call(victim, 'victimIdentity');
      expect(original.privateKeyExtractable).toBe(false);
      const bootstrap = await call(authority, 'authorityStart', [
        original.publicKey,
        settings,
      ]);
      await call(victim, 'enroll', [bootstrap]);
      await link(authority, victim);
      await call(authority, 'sendSnapshot');
      await expect
        .poll(async () => (await call(victim, 'status')).applied, {
          timeout: 30000,
        })
        .toBe(1);
      const enrolled = await call(victim, 'persist', [bootstrap]);
      expect(enrolled.counter).toBe(bootstrap.changes - 1);
      expect(enrolled.receivedBlocks).toBeGreaterThan(0);
      await call(victim, 'close');
      await call(authority, 'disconnect');
      await victimContext!.close();

      victim = await launch();
      const baseline = await call(victim, 'restore', [bootstrap.path]);
      expect(baseline.fingerprint).toBe(original.fingerprint);
      expect(baseline.restored).toBe(true);
      expect(baseline.counter).toBe(enrolled.counter);
      await victimContext!.setOffline(true);
      await call(victim, 'disconnect');
      await call(victim, 'closeStorage');
      const cdp = await victimContext!.newCDPSession(victim);
      await cdp.send('Storage.clearDataForOrigin', {
        origin: 'http://127.0.0.1:4188',
        storageTypes: 'indexeddb',
      });
      const databasesAfterEviction = await victim.evaluate(
        async () => (await indexedDB.databases()).length,
      );
      expect(databasesAfterEviction).toBe(0);
      await victimContext!.close();

      victim = await launch();
      const after = await call(victim, 'restore', [bootstrap.path]);
      expect(after.persistedManifestPresent).toBe(false);
      expect(after.restored).toBe(false);
      expect(after.counter).toBeNull();
      await link(authority, victim);
      await call(authority, 'sendSnapshot');
      await expect
        .poll(async () => (await call(victim, 'status')).rejected, {
          timeout: 30000,
        })
        .toBe(1);
      const recovered = await call(victim, 'status');
      const survivor = await call(authority, 'status');
      expect(recovered.applied).toBe(0);
      expect(survivor.counter).toBe(enrolled.counter);
      const identityPreserved = after.fingerprint === original.fingerprint;
      const gaps = [
        ...(!identityPreserved
          ? [
              'The shipped example identity store lives in IndexedDB. Complete eviction loses the non-extractable private key; getOrCreateIdentity silently creates a new identity rather than preserving an independent secure-storage identity.',
            ]
          : []),
        'An automatic authenticated rejoin/snapshot recovery path after losing identity and document keys is not established. An authoritative peer retains state, but its encrypted snapshot cannot repair missing authorization/key material by itself. The harness does not restore lost keys or supply a synthetic automatic recovery feature.',
        'The baseline snapshot boot manifest and native RTC block carrier are fixtures; only the example identity store, document crypto/ingress and IndexedDB are production components. Programmatic Chromium eviction does not prove iOS Safari OS eviction behavior.',
      ];
      await save({
        scope:
          'Real persistent Chromium profile restarted twice, shipped Peerborne Note non-extractable identity storage, actual IndexedDB removal while offline, native RTC encrypted snapshot transfers and a separate surviving authoritative context. No old identity/key material is re-injected after eviction.',
        metrics: {
          baselineIdentitySurvivedRestart: true,
          baselineEncryptedSnapshotRestored: true,
          databasesAfterEviction,
          identityPreserved,
          privateKeyNonExtractable: !after.privateKeyExtractable,
          persistedDocumentStateMissing: true,
          emptyStateOpenRejected: after.emptyOpenRejected,
          identityApiReturnedReplacement: !identityPreserved,
          automaticRecoveryObserved: recovered.applied > 0,
          encryptedSnapshotRejectedWithoutKeys: recovered.rejected === 1,
          authoritativeStateIntact: survivor.counter === enrolled.counter,
          preEvictionTransportBlocks: enrolled.receivedBlocks,
          postEvictionTransportBlocks: recovered.receivedBlocks,
          browserProfileRestarts: 2,
        },
        gaps,
        status: gaps.length ? 'gap' : 'passed',
      });
      if (settings.strict)
        expect(gaps, 'strict acceptance rejects missing guarantees').toEqual(
          [],
        );
    } catch (error) {
      if (!reported)
        await save({
          scope:
            'Persistent-profile storage eviction workload did not complete.',
          metrics: {},
          gaps: [],
          status: 'failed',
        });
      throw error;
    } finally {
      await Promise.allSettled([call(authority, 'close')]);
      await victimContext?.close();
      await authorityContext.close();
      await rm(profile, { recursive: true, force: true });
    }
  });
