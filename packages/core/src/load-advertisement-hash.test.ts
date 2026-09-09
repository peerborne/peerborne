import { describe, expect, test } from '@jest/globals';
import { loadAdvertisementHash } from './load-advertisement-hash.js';
import { tipsHash } from './tips-hash.js';

describe('loadAdvertisementHash', () => {
  test('preserves the legacy tips hash exactly without commitments', async () => {
    expect(await loadAdvertisementHash('/doc', ['b', 'a'])).toEqual(
      await tipsHash(['b', 'a']),
    );
  });

  test('binds security commitments and document identity', async () => {
    const commitments = {
      version: 1 as const,
      controlHead: new Uint8Array(32).fill(1),
      groupId: 'group',
      epoch: 1n,
      treeHash: new Uint8Array(32).fill(2),
      confirmedTranscriptHash: new Uint8Array(32).fill(3),
    };
    const manifest = new Uint8Array(32).fill(4);
    expect(
      await loadAdvertisementHash('/a', ['cid'], commitments, manifest),
    ).not.toEqual(
      await loadAdvertisementHash('/b', ['cid'], commitments, manifest),
    );
  });

  test('binds the complete V4 response manifest and rejects its omission', async () => {
    const commitments = {
      version: 1 as const,
      controlHead: new Uint8Array(32).fill(1),
      groupId: 'group',
      epoch: 1n,
      treeHash: new Uint8Array(32).fill(2),
      confirmedTranscriptHash: new Uint8Array(32).fill(3),
    };
    const first = new Uint8Array(32).fill(4);
    const second = new Uint8Array(32).fill(5);
    await expect(
      loadAdvertisementHash('/doc', ['cid'], commitments, first),
    ).resolves.not.toEqual(
      await loadAdvertisementHash('/doc', ['cid'], commitments, second),
    );
    await expect(
      (loadAdvertisementHash as any)('/doc', ['cid'], commitments),
    ).rejects.toThrow(/response manifest/);
  });
});
