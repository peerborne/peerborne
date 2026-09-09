import { describe, expect, jest, test } from '@jest/globals';
import { loadAdvertisementHash } from './load-advertisement-hash.js';
import { LoadQuorumFailedError } from './load-quorum.js';
import { runLoadQuorum } from './load-quorum-orchestrator.js';
import {
  captureTrustedLoadSecurityCommitments,
  loadSecurityCommitmentsEqual,
  LoadSecurityCommitments,
} from './load-security-state.js';

const bytes = (fill: number) => new Uint8Array(32).fill(fill);
const tuple = (
  overrides: Partial<LoadSecurityCommitments> = {},
): LoadSecurityCommitments => ({
  version: 1,
  controlHead: bytes(1),
  groupId: 'group-a',
  epoch: 10n,
  treeHash: bytes(2),
  confirmedTranscriptHash: bytes(3),
  ...overrides,
});

interface PeerAdvertisement {
  id: string;
  signerAuthority: string;
  commitments: LoadSecurityCommitments;
  frontier: readonly string[];
}

async function trustedProbe(
  peer: PeerAdvertisement,
  trusted: LoadSecurityCommitments,
) {
  if (!loadSecurityCommitmentsEqual(trusted, peer.commitments)) return null;
  return {
    hash: await loadAdvertisementHash(
      '/doc',
      peer.frontier,
      peer.commitments,
      new Uint8Array(32).fill(4),
    ),
    signerAuthority: peer.signerAuthority,
  };
}

describe('trusted V4 security tuple quorum primitives', () => {
  test('rejects a Byzantine quorum agreeing on a different rollback tuple', async () => {
    const trusted = tuple();
    const rollback = tuple({ epoch: 9n, treeHash: bytes(9) });
    const peers: PeerAdvertisement[] = ['a', 'b', 'c'].map((id) => ({
      id,
      signerAuthority: `writer-${id}`,
      commitments: rollback,
      frontier: ['cid-rollback'],
    }));

    const err = await runLoadQuorum({
      peers,
      peerIdOf: (peer) => peer.id,
      probeFn: (peer) => trustedProbe(peer, trusted),
      documentPath: '/doc',
      config: { enabled: true, k: 3, q: 2 },
    }).catch((error: unknown) => error);

    expect(err).toBeInstanceOf(LoadQuorumFailedError);
    expect((err as LoadQuorumFailedError).respondingCount).toBe(0);
  });

  test('does not co-tally mixed remote security tuples', async () => {
    const trusted = tuple();
    const peers: PeerAdvertisement[] = [
      {
        id: 'trusted',
        signerAuthority: 'writer-a',
        commitments: tuple(),
        frontier: ['cid'],
      },
      {
        id: 'rollback',
        signerAuthority: 'writer-b',
        commitments: tuple({ epoch: 9n }),
        frontier: ['cid'],
      },
      {
        id: 'fork',
        signerAuthority: 'writer-c',
        commitments: tuple({ confirmedTranscriptHash: bytes(8) }),
        frontier: ['cid'],
      },
    ];

    await expect(
      runLoadQuorum({
        peers,
        peerIdOf: (peer) => peer.id,
        probeFn: (peer) => trustedProbe(peer, trusted),
        documentPath: '/doc',
        config: { enabled: true, k: 3, q: 2 },
      }),
    ).rejects.toMatchObject({
      reason: 'insufficient-responses',
      respondingCount: 1,
    });
  });

  test('uses one captured resolver snapshot despite later resolver mutation', async () => {
    const mutable = tuple();
    const resolver = jest.fn(async () => mutable);
    const trusted = await captureTrustedLoadSecurityCommitments('/doc', resolver);
    mutable.epoch = 1n;
    mutable.treeHash.fill(7);

    const peers: PeerAdvertisement[] = ['a', 'b'].map((id) => ({
      id,
      signerAuthority: `writer-${id}`,
      commitments: tuple(),
      frontier: ['cid'],
    }));
    const result = await runLoadQuorum({
      peers,
      peerIdOf: (peer) => peer.id,
      probeFn: (peer) => trustedProbe(peer, trusted),
      documentPath: '/doc',
      config: { enabled: true, k: 2, q: 2 },
    });

    expect(resolver).toHaveBeenCalledTimes(1);
    expect('ok' in result && result.ok).toBe(true);
  });

  test.each(['full-document', 'snapshot']) (
    'distinguishes an untrusted tuple for a %s candidate',
    (_candidateKind) => {
      expect(
        loadSecurityCommitmentsEqual(tuple(), tuple({ groupId: 'attacker' })),
      ).toBe(false);
    },
  );
});
