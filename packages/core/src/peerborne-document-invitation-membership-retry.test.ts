import { describe, expect, jest, test } from '@jest/globals';

import {
  crdtReaderChangeNode,
  crdtWriterChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import {
  assertAcceptedInvitationMembershipTopology,
  InvitationMembershipQueue,
} from './invitation-membership.js';
import { PeerborneDocument } from './peerborne-document.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Reject: 'reject' } }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

type MembershipChange =
  | { readonly add: string }
  | { readonly snapshot: readonly string[] };

type Role = 'reader' | 'editor';

type FailurePoint =
  | 'reader publication'
  | 'writer publication'
  | 'bootstrap signature';

const documentPath = '/invitation-membership-retry';
const founderWriterCid = 'founder-writer-cid';

class StagedMembershipACL {
  readonly members: Set<string>;
  readonly current = jest.fn(
    (): MembershipChange => ({ snapshot: [...this.members] }),
  );

  constructor(members: readonly string[]) {
    this.members = new Set(members);
  }

  async check(identity: string): Promise<boolean> {
    return this.members.has(identity);
  }

  async users(): Promise<string[]> {
    return [...this.members];
  }

  async prepareAdd(identity: string) {
    const changes: MembershipChange = { add: identity };
    const commit = () => {
      this.members.add(identity);
    };
    return { changes, commit, claimCommit: () => ({ finalize: commit }) };
  }
}

async function kemKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  )) as CryptoKeyPair;
}

async function rawPublicKey(keyPair: CryptoKeyPair): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey),
  );
}

async function founderDocument(publish: ReturnType<typeof jest.fn>) {
  const founderKem = await kemKeyPair();
  const readers = new StagedMembershipACL([]);
  const writers = new StagedMembershipACL(['founder']);
  const bootstrapMessages: any[] = [];
  let nextCid = 0;
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    _userPublicKey: 'founder',
    _createdLocally: true,
    _historyVisibility: 'full_history',
    _bootstrapLoadApplicationState: 'pristine',
    _bootstrapLoadApplicationRevision: 0,
    _mutationQueue: new InvitationMembershipQueue(),
    _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
    _readers: readers,
    _writers: writers,
    _kemKeyPair: founderKem,
    _kemPublicKeyRaw: await rawPublicKey(founderKem),
    _beekemInitialized: false,
    _beekem: null,
    _readerKemPublicKeys: new Map(),
    _readerLeafIndices: new Map(),
    _beekemWelcomeByLeaf: new Map(),
    _readerPublicationsInFlight: 0,
    _writerPublicationsInFlight: 0,
    _writerMutationsInFlight: 0,
    _writerKeysVersion: 0,
    _cachedWriterKeys: null,
    _hashes: new Set([founderWriterCid]),
    _referencedAncestors: new Set(),
    _recentTips: [{ cid: founderWriterCid, kind: crdtWriterChangeNode }],
    _lastSyncMessage: {
      documentId: documentPath,
      changeId: founderWriterCid,
      changes: { kind: crdtWriterChangeNode, change: { add: 'founder' } },
    },
    _putBlock: jest.fn(async () => `membership-cid-${++nextCid}`),
    _signAsWriter: jest.fn(async () => 'AQ=='),
    _signAsWriterUnconditional: jest.fn(async () => 'AQ=='),
    _localHandlers: {},
    _keychain: {
      current: jest.fn(async () => [new Uint8Array(32).fill(1), { key: 1 }]),
    },
    _changesSerializer: {
      serializeChanges: jest.fn(() => new Uint8Array([7])),
    },
    _syncMessageSerializer: {
      serializeSyncMessage: jest.fn((message: any) => {
        if (message.signatureContext === 'invitation-bootstrap-v1') {
          bootstrapMessages.push(structuredClone(message));
        }
        return new Uint8Array([3]);
      }),
    },
    _authProvider: {
      serializePublicKey: jest.fn(async (identity: string) => identity),
      deserializePublicKey: jest.fn(async (identity: string) => identity),
      encrypt: jest.fn(async (plaintext: Uint8Array) => ({
        nonce: new Uint8Array(12),
        data: new Uint8Array(plaintext.byteLength + 16),
      })),
    },
    _topic: '/topic',
    swarm: { heliaNode: { libp2p: { services: { pubsub: { publish } } } } },
    _prepareInvitationBootstrapCapacity: jest.fn(async () => ({
      keychainChanges: { keychain: 1 },
      serializedBootstrapBaselineBytes: 0,
      welcomeWithoutBeeKEMBytes: 0,
    })),
  }) as any;
  return { document, readers, writers, bootstrapMessages };
}

/** Rebuild recipient membership from the signed bootstrap change tree only. */
function membershipFromBootstrap(message: any): {
  readers: string[];
  writers: string[];
  snapshots: number;
} {
  const inline = new Map<string, CRDTChangeNode<MembershipChange>>();
  const deferred = new Set<string>();
  const pending: [string, CRDTChangeNode<MembershipChange>][] = [
    [message.changeId, message.changes],
  ];
  while (pending.length > 0) {
    const [cid, node] = pending.pop()!;
    if (node.change === undefined) {
      deferred.add(cid);
    } else {
      inline.set(cid, node);
    }
    if (node.children) {
      pending.push(...Object.entries(node.children));
    }
  }
  for (const cid of deferred) {
    expect(inline.has(cid)).toBe(true);
  }

  const readers = new Set<string>();
  const writers = new Set<string>();
  let snapshots = 0;
  for (const node of inline.values()) {
    const change = node.change!;
    if (!('add' in change)) {
      snapshots++;
      continue;
    }
    if (node.kind === crdtReaderChangeNode) readers.add(change.add);
    if (node.kind === crdtWriterChangeNode) writers.add(change.add);
  }
  return { readers: [...readers], writers: [...writers], snapshots };
}

const cases: readonly [FailurePoint, Role][] = [
  ['reader publication', 'reader'],
  ['reader publication', 'editor'],
  ['writer publication', 'editor'],
  ['bootstrap signature', 'reader'],
  ['bootstrap signature', 'editor'],
];

describe('exact invitation retry after a partial failure', () => {
  test.each(cases)(
    'converges from the committed ACL deltas after a %s failure (%s)',
    async (failure, role) => {
      const publish = jest.fn<() => Promise<void>>(async () => undefined);
      const { document, readers, writers, bootstrapMessages } =
        await founderDocument(publish);
      const failingPublication =
        failure === 'reader publication'
          ? 1
          : failure === 'writer publication'
            ? 2
            : 0;
      let publications = 0;
      publish.mockImplementation(async () => {
        if (++publications === failingPublication) {
          throw new Error('publication rejected');
        }
      });
      if (failure === 'bootstrap signature') {
        document._signAsWriterUnconditional.mockRejectedValueOnce(
          new Error('bootstrap signing failed'),
        );
      }
      const recipientKem = await rawPublicKey(await kemKeyPair());

      await expect(
        document.buildInvitationBootstrap('recipient', recipientKem, role),
      ).rejects.toThrow(
        failure === 'bootstrap signature'
          ? 'bootstrap signing failed'
          : 'publication rejected',
      );
      expect(readers.members.has('recipient')).toBe(
        failure !== 'reader publication',
      );
      expect(document._bootstrapLoadApplicationState).toBe('pristine');

      const retry = await document.buildInvitationBootstrap(
        'recipient',
        recipientKem,
        role,
      );

      expect(retry.welcomeEpochId).toEqual(new Uint8Array(32).fill(1));
      expect(retry.sealedWelcome.byteLength).toBeGreaterThan(0);
      expect(retry.encryptedBootstrap.byteLength).toBeGreaterThan(0);
      expect([...readers.members]).toEqual(['recipient']);
      expect([...writers.members]).toEqual(
        role === 'editor' ? ['founder', 'recipient'] : ['founder'],
      );

      const bootstrap = membershipFromBootstrap(bootstrapMessages.at(-1));
      expect(() =>
        assertAcceptedInvitationMembershipTopology(
          {
            issuer: 'founder',
            recipient: 'recipient',
            readers: bootstrap.readers,
            writers: bootstrap.writers,
          },
          role,
        ),
      ).not.toThrow();
    },
  );
});
