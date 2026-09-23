import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import { loadAdvertisementHash } from './load-advertisement-hash.js';
import { tipsHash } from './tips-hash.js';

const commitments = () => ({
  version: 1 as const,
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'group',
  epoch: 1n,
  treeHash: new Uint8Array(32).fill(2),
  confirmedTranscriptHash: new Uint8Array(32).fill(3),
});

describe('loadAdvertisementHash', () => {
  test('preserves the legacy tips hash exactly without commitments', async () => {
    expect(await loadAdvertisementHash('/doc', ['b', 'a'])).toEqual(
      await tipsHash(['b', 'a']),
    );
  });

  test('binds security commitments and document identity', async () => {
    const securityCommitments = commitments();
    const manifest = new Uint8Array(32).fill(4);
    expect(
      await loadAdvertisementHash('/a', ['cid'], securityCommitments, manifest),
    ).not.toEqual(
      await loadAdvertisementHash('/b', ['cid'], securityCommitments, manifest),
    );
  });

  test('binds the complete V4 response manifest and rejects its omission', async () => {
    const securityCommitments = commitments();
    const first = new Uint8Array(32).fill(4);
    const second = new Uint8Array(32).fill(5);
    await expect(
      loadAdvertisementHash('/doc', ['cid'], securityCommitments, first),
    ).resolves.not.toEqual(
      await loadAdvertisementHash('/doc', ['cid'], securityCommitments, second),
    );
    await expect(
      (loadAdvertisementHash as any)('/doc', ['cid'], securityCommitments),
    ).rejects.toThrow(/response manifest/);
  });

  test('detaches the V4 response manifest before the security-state digest yields', async () => {
    const manifest = new Uint8Array(32).fill(4);
    const pending = loadAdvertisementHash(
      '/doc',
      ['cid'],
      commitments(),
      manifest,
    );
    manifest.fill(9);

    await expect(pending).resolves.toEqual(
      await loadAdvertisementHash(
        '/doc',
        ['cid'],
        commitments(),
        new Uint8Array(32).fill(4),
      ),
    );
  });

  test('accepts cross-realm manifest hashes and rejects shared backing', async () => {
    const crossRealm = runInNewContext(
      'new Uint8Array(32).fill(4)',
    ) as Uint8Array;
    expect(crossRealm instanceof Uint8Array).toBe(false);
    await expect(
      loadAdvertisementHash('/doc', ['cid'], commitments(), crossRealm),
    ).resolves.toHaveLength(32);

    if (typeof SharedArrayBuffer !== 'undefined') {
      await expect(
        loadAdvertisementHash(
          '/doc',
          ['cid'],
          commitments(),
          new Uint8Array(new SharedArrayBuffer(32)),
        ),
      ).rejects.toThrow(/response manifest hash/);
    }
  });

  test('captures commitment fields without invoking live property reads', async () => {
    let propertyReads = 0;
    const stable = commitments();
    const guarded = new Proxy(stable, {
      get() {
        propertyReads++;
        throw new Error('commitment property reads must not run');
      },
    });

    await expect(
      loadAdvertisementHash(
        '/doc',
        ['cid'],
        guarded,
        new Uint8Array(32).fill(4),
      ),
    ).resolves.toEqual(
      await loadAdvertisementHash(
        '/doc',
        ['cid'],
        stable,
        new Uint8Array(32).fill(4),
      ),
    );
    expect(propertyReads).toBe(0);
  });
});
