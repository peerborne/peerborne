import { describe, expect, jest, test } from '@jest/globals';

import {
  crdtDocumentChangeNode,
  crdtWriterChangeNode,
  type CRDTChangeNodeKind,
} from './crdt-change-node.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
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
jest.mock('./ecies.js', () => ({
  ECIES_P256_PUBLIC_KEY_LENGTH: 65,
  eciesOpen: jest.fn(),
  eciesSeal: jest.fn(async () => new Uint8Array([9])),
  importEciesPublicKey: jest.fn(async (raw: Uint8Array) => ({
    raw: new Uint8Array(raw),
  })),
}));
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

const mockedEcies = require('./ecies.js');

type ACLChange = {
  readonly operation: 'add' | 'remove';
  readonly publicKey: string;
  readonly sequence: number;
};

class StagedWriterACL {
  readonly directAdds = jest.fn();
  readonly directRemoves = jest.fn();
  prepareAddCalls = 0;
  prepareRemoveCalls = 0;
  private _revision = 0;
  private _sequence = 0;

  constructor(
    readonly members: Set<string>,
    private readonly _events?: string[],
  ) {}

  async add(): Promise<never> {
    this.directAdds();
    throw new Error('direct writer addition must not be used');
  }

  async remove(): Promise<never> {
    this.directRemoves();
    throw new Error('direct writer removal must not be used');
  }

  async prepareAdd(publicKey: string) {
    this.prepareAddCalls++;
    return this._prepare(publicKey, 'add');
  }

  async prepareRemove(publicKey: string) {
    this.prepareRemoveCalls++;
    return this._prepare(publicKey, 'remove');
  }

  private _prepare(publicKey: string, operation: 'add' | 'remove') {
    const baseRevision = this._revision;
    const changes: ACLChange = {
      operation,
      publicKey,
      sequence: ++this._sequence,
    };
    const acl = this;
    return {
      changes,
      committed: false,
      commit() {
        if (this.committed) throw new Error('prepared change already committed');
        if (acl._revision !== baseRevision) throw new Error('stale ACL change');
        this.committed = true;
        acl._events?.push(`commit:${operation}`);
        const hadMember = acl.members.has(publicKey);
        if (operation === 'add') {
          acl.members.add(publicKey);
        } else {
          acl.members.delete(publicKey);
        }
        if (hadMember !== acl.members.has(publicKey)) acl._revision++;
      },
    };
  }

  current(): ACLChange {
    return { operation: 'add', publicKey: 'snapshot', sequence: 0 };
  }

  merge(changes: ACLChange): void {
    if (changes.operation === 'add') {
      this.members.add(changes.publicKey);
    } else {
      this.members.delete(changes.publicKey);
    }
    this._revision++;
  }

  async check(publicKey: string): Promise<boolean> {
    return this.members.has(publicKey);
  }

  async users(): Promise<string[]> {
    return [...this.members];
  }
}

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), fields);
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function publicationHarness(
  writers: StagedWriterACL,
  publish: ReturnType<typeof jest.fn>,
  hashes: string[],
) {
  const initialLastSyncMessage = {
    documentId: '/writer-publication',
    changeId: 'parent-cid',
    changes: {
      kind: crdtDocumentChangeNode,
      change: { prior: true },
    },
  };
  const initialRecentTips = [
    { cid: 'parent-cid', kind: crdtDocumentChangeNode },
    { cid: 'remote-tip-cid', kind: crdtDocumentChangeNode },
  ];
  const serializedMessages: any[] = [];
  const keychain = {
    current: jest.fn(async () => [new Uint8Array([1]), { key: true }]),
    add: jest.fn(async () => [
      new Uint8Array([2]),
      { key: 'rotated' },
      { keychain: 'changes' },
    ]),
  };
  const distributeKeyUpdate = jest.fn(async () => undefined);
  const readers = new Set(['candidate']);
  let nextHash = 0;
  const document = fakeDocument({
    documentPath: '/writer-publication',
    _document: { stable: true },
    _writers: writers,
    _readers: {
      check: jest.fn(async (publicKey: string) => readers.has(publicKey)),
      users: jest.fn(async () => [...readers]),
    },
    _mutationQueue: new InvitationMembershipQueue(),
    _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
    _writerMutationsInFlight: 0,
    _writerPublicationsInFlight: 0,
    _writerKeysVersion: 0,
    _cachedWriterKeys: ['cached-owner'],
    _hashes: new Set(['parent-cid', 'remote-tip-cid']),
    _referencedAncestors: new Set(['older-ancestor-cid']),
    _recentTips: initialRecentTips.map((tip) => ({ ...tip })),
    _lastSyncMessage: initialLastSyncMessage,
    _putBlock: jest.fn(async () => hashes[nextHash++]!),
    _signAsWriter: jest.fn(async () => 'signature'),
    _syncMessageSerializer: {
      serializeSyncMessage: jest.fn((message: unknown) => {
        serializedMessages.push(structuredClone(message));
        return new Uint8Array([3]);
      }),
    },
    _keychain: keychain,
    _authProvider: {
      serializePublicKey: jest.fn(async (publicKey: string) => publicKey),
      deserializePublicKey: jest.fn(async (serialized: string) => serialized),
      encrypt: jest.fn(async () => ({
        nonce: new Uint8Array([4]),
        data: new Uint8Array([5]),
      })),
    },
    _topic: '/topic',
    swarm: {
      heliaNode: {
        libp2p: { services: { pubsub: { publish } } },
      },
    },
    _localHandlers: {},
    _maybeCompact: jest.fn(async () => undefined),
    _documentChangeCount: 0,
    _changesSinceSnapshot: 0,
    _distributeKeyUpdate: distributeKeyUpdate,
  });
  return {
    document,
    initialLastSyncMessage,
    initialRecentTips,
    serializedMessages,
    keychain,
    distributeKeyUpdate,
    readers,
  };
}

function childCids(message: any): string[] {
  return Object.keys(message.changes?.children ?? {});
}

describe('writer ACL publication boundary', () => {
  test('rolls back DAG bookkeeping when the post-publication commit rejects', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const originalPrepareAdd = writers.prepareAdd.bind(writers);
    let preparation = 0;
    writers.prepareAdd = jest.fn(async (publicKey: string) => {
      const prepared = await originalPrepareAdd(publicKey);
      preparation++;
      if (preparation !== 1) return prepared;
      return {
        ...prepared,
        commit: () => {
          throw new Error('stale writer commit');
        },
      };
    });
    const publish = jest.fn(async () => undefined);
    const {
      document,
      initialLastSyncMessage,
      initialRecentTips,
      serializedMessages,
    } = publicationHarness(
      writers,
      publish,
      ['rejected-commit-cid', 'committed-retry-cid'],
    );

    await expect(document.addWriter('candidate')).rejects.toThrow(
      'stale writer commit',
    );

    expect(writers.members).toEqual(new Set(['owner']));
    expect(document._hashes).not.toContain('rejected-commit-cid');
    expect(document._referencedAncestors).toEqual(
      new Set(['older-ancestor-cid']),
    );
    expect(document._recentTips).toEqual(initialRecentTips);
    expect(document._lastSyncMessage).toBe(initialLastSyncMessage);

    await expect(document.addWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    expect(document._hashes).toContain('committed-retry-cid');
    expect(serializedMessages).toHaveLength(2);
    expect(childCids(serializedMessages[1])).not.toContain(
      'rejected-commit-cid',
    );
  });

  test('invalidates a writer lookup at the synchronous commit boundary', async () => {
    const writers = new StagedWriterACL(
      new Set(['owner', 'candidate']),
    );
    const publishStarted = deferred<void>();
    const publication = deferred<void>();
    const firstLookupStarted = deferred<void>();
    const releaseFirstLookup = deferred<void>();
    const handlerReadStarted = deferred<void>();
    const releaseHandlerRead = deferred<void>();
    let firstLookup = true;
    writers.users = jest.fn(async () => {
      if (!firstLookup) return [...writers.members];
      firstLookup = false;
      const captured = [...writers.members];
      firstLookupStarted.resolve();
      await releaseFirstLookup.promise;
      return captured;
    });
    const publish = jest.fn(() => {
      publishStarted.resolve();
      return publication.promise;
    });
    const { document } = publicationHarness(
      writers,
      publish,
      ['committed-removal-cid'],
    );
    document._readers.users = jest.fn(async () => {
      handlerReadStarted.resolve();
      await releaseHandlerRead.promise;
      return [];
    });
    document._localHandlers = { observer: () => undefined };

    const removal = document.removeWriter('candidate');
    await publishStarted.promise;
    const lookup = document._getWriterKeys();
    await firstLookupStarted.promise;

    publication.resolve();
    await handlerReadStarted.promise;
    expect(writers.members).toEqual(new Set(['owner']));

    releaseFirstLookup.resolve();
    await expect(lookup).resolves.toEqual(['owner']);

    releaseHandlerRead.resolve();
    await expect(removal).resolves.toBeUndefined();
    expect(writers.users.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  test('a rejected writer addition rolls back DAG bookkeeping and retries cleanly', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error('publication rejected'))
      .mockResolvedValueOnce(undefined);
    const {
      document,
      initialLastSyncMessage,
      initialRecentTips,
      serializedMessages,
    } = publicationHarness(
      writers,
      publish,
      ['rejected-add-cid', 'committed-add-cid'],
    );

    await expect(document.addWriter('candidate')).rejects.toThrow(
      'publication rejected',
    );

    expect(writers.members).toEqual(new Set(['owner']));
    expect(document._hashes).toEqual(
      new Set(['parent-cid', 'remote-tip-cid']),
    );
    expect(document._referencedAncestors).toEqual(
      new Set(['older-ancestor-cid']),
    );
    expect(document._recentTips).toEqual(initialRecentTips);
    expect(document._lastSyncMessage).toBe(initialLastSyncMessage);

    await expect(document.addWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    expect(writers.prepareAddCalls).toBe(2);
    expect(writers.directAdds).not.toHaveBeenCalled();
    expect(document._hashes).not.toContain('rejected-add-cid');
    expect(document._hashes).toContain('committed-add-cid');
    expect(serializedMessages).toHaveLength(2);
    expect(childCids(serializedMessages[1])).not.toContain('rejected-add-cid');
    expect(childCids(serializedMessages[1])).toEqual(
      expect.arrayContaining(['parent-cid', 'remote-tip-cid']),
    );
  });

  test('does not serve a staged writer grant while encryption is pending', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const encryptionStarted = deferred<void>();
    const pendingEncryption = deferred<{
      nonce: Uint8Array;
      data: Uint8Array;
    }>();
    let encryptionCall = 0;
    const encrypt = jest.fn(() => {
      encryptionCall++;
      if (encryptionCall === 1) {
        encryptionStarted.resolve();
        return pendingEncryption.promise;
      }
      return Promise.resolve({
        nonce: new Uint8Array([4]),
        data: new Uint8Array([5]),
      });
    });
    const {
      document,
      initialLastSyncMessage,
      serializedMessages,
    } = publicationHarness(
      writers,
      publish,
      ['uncommitted-writer-cid', 'committed-retry-cid'],
    );
    document.swarm.config = { enableSigning: true };
    document._authProvider.encrypt = encrypt;
    document._authProvider.verify = jest.fn(async () => true);
    document._encoder = new TextEncoder();
    document._keychainChangesForVisibility = jest.fn(async () => ({
      visible: true,
    }));
    document._latestSnapshot = {
      lastChangeNodeCID: 'snapshot-boundary',
      state: { stable: true },
      signature: new Uint8Array([1]),
    };
    const loadSink = jest.fn(async () => undefined);
    const snapshotSink = jest.fn(async () => undefined);

    const addition = document.addWriter('candidate');
    const additionResult = expect(addition).rejects.toThrow(
      'encryption rejected',
    );
    await encryptionStarted.promise;

    const loadResponse = document.handleLoadRequestData(
      { documentId: '/writer-publication', signature: 'AA==' },
      { sink: loadSink },
    );
    const snapshotResponse = document.handleSnapshotLoadRequestData(
      { documentId: '/writer-publication', signature: 'AA==' },
      { sink: snapshotSink },
    );

    await Promise.resolve();
    expect(loadSink).not.toHaveBeenCalled();
    expect(snapshotSink).not.toHaveBeenCalled();

    pendingEncryption.reject(new Error('encryption rejected'));
    await additionResult;
    await expect(loadResponse).resolves.toBeUndefined();
    await expect(snapshotResponse).resolves.toBeUndefined();

    expect(loadSink).toHaveBeenCalledWith([expect.any(Uint8Array)]);
    expect(snapshotSink).toHaveBeenCalledWith([expect.any(Uint8Array)]);
    expect(serializedMessages).toHaveLength(3);
    for (const served of serializedMessages.slice(1)) {
      expect(served.changeId).toBe('parent-cid');
      expect(served.changes.change).toEqual({ prior: true });
      expect(JSON.stringify(served)).not.toContain('uncommitted-writer-cid');
    }
    expect(document._lastSyncMessage).toBe(initialLastSyncMessage);
    expect(publish).not.toHaveBeenCalled();

    await expect(document.addWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    expect(publish).toHaveBeenCalledTimes(1);
    expect(childCids(serializedMessages.at(-1))).not.toContain(
      'uncommitted-writer-cid',
    );
  });

  test('a rejected writer removal stays authorized and retries without leaking its node', async () => {
    const writers = new StagedWriterACL(new Set(['owner', 'candidate']));
    const publish = jest
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error('publication rejected'))
      .mockResolvedValueOnce(undefined);
    const {
      document,
      serializedMessages,
      keychain,
      distributeKeyUpdate,
    } = publicationHarness(
      writers,
      publish,
      ['rejected-remove-cid', 'committed-remove-cid'],
    );

    await expect(document.removeWriter('candidate')).rejects.toThrow(
      'publication rejected',
    );

    expect(writers.members).toContain('candidate');
    expect(keychain.add).not.toHaveBeenCalled();
    expect(distributeKeyUpdate).not.toHaveBeenCalled();

    await expect(document.removeWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).not.toContain('candidate');
    expect(writers.prepareRemoveCalls).toBe(2);
    expect(writers.directRemoves).not.toHaveBeenCalled();
    expect(document._hashes).not.toContain('rejected-remove-cid');
    expect(document._hashes).toContain('committed-remove-cid');
    expect(childCids(serializedMessages[1])).not.toContain(
      'rejected-remove-cid',
    );
    expect(keychain.current).toHaveBeenCalledTimes(2);
    expect(keychain.add).not.toHaveBeenCalled();
    expect(distributeKeyUpdate).not.toHaveBeenCalled();
    expect(await document._readers.check('candidate')).toBe(true);
  });

  test('writer downgrade never enters the fallible key-rotation path', async () => {
    const writers = new StagedWriterACL(new Set(['owner', 'candidate']));
    const publish = jest.fn(async () => undefined);
    const { document, keychain, distributeKeyUpdate, readers } =
      publicationHarness(writers, publish, ['writer-downgrade-cid']);
    keychain.add.mockRejectedValue(new Error('keychain unavailable'));

    await expect(document.removeWriter('candidate')).resolves.toBeUndefined();
    await expect(document.removeWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner']));
    expect(readers).toContain('candidate');
    expect(keychain.current).toHaveBeenCalledTimes(1);
    expect(keychain.add).not.toHaveBeenCalled();
    expect(distributeKeyUpdate).not.toHaveBeenCalled();
    expect(publish).toHaveBeenCalledTimes(1);
  });

  test('rejects removal of a writer without explicit reader authorization', async () => {
    const writers = new StagedWriterACL(new Set(['owner', 'candidate']));
    const publish = jest.fn(async () => undefined);
    const { document, keychain, distributeKeyUpdate, readers } =
      publicationHarness(writers, publish, ['must-not-publish']);
    readers.delete('candidate');

    await expect(document.removeWriter('candidate')).rejects.toThrow(
      /must remain explicitly authorized as a reader/,
    );

    expect(writers.members).toContain('candidate');
    expect(writers.prepareRemoveCalls).toBe(0);
    expect(publish).not.toHaveBeenCalled();
    expect(keychain.current).not.toHaveBeenCalled();
    expect(keychain.add).not.toHaveBeenCalled();
    expect(distributeKeyUpdate).not.toHaveBeenCalled();
  });

  test.each([
    {
      operation: 'addWriter',
      initialWriters: ['owner'],
      expectedWriters: ['owner', 'candidate'],
    },
    {
      operation: 'removeWriter',
      initialWriters: ['owner', 'candidate'],
      expectedWriters: ['owner'],
    },
  ] as const)(
    '$operation snapshots a mutable identity before waiting for the queue',
    async ({ operation, initialWriters, expectedWriters }) => {
      const writers = new StagedWriterACL(new Set(initialWriters));
      const originalPrepareAdd = writers.prepareAdd.bind(writers);
      const originalPrepareRemove = writers.prepareRemove.bind(writers);
      writers.check = jest.fn(async (key: any) =>
        writers.members.has(typeof key === 'string' ? key : key.id),
      );
      (writers as any).prepareAdd = jest.fn((key: any) =>
        originalPrepareAdd(typeof key === 'string' ? key : key.id),
      );
      (writers as any).prepareRemove = jest.fn((key: any) =>
        originalPrepareRemove(typeof key === 'string' ? key : key.id),
      );
      const publish = jest.fn(async () => undefined);
      const { document, readers } = publicationHarness(
        writers,
        publish,
        ['stable-identity-cid'],
      );
      document._readers.check = jest.fn(async (key: any) =>
        readers.has(typeof key === 'string' ? key : key.id),
      );
      document._authProvider.serializePublicKey = jest.fn((key: any) => {
        const captured = typeof key === 'string' ? key : key.id;
        return Promise.resolve(captured);
      });
      document._authProvider.deserializePublicKey = jest.fn(
        async (serialized: string) => ({ id: serialized }),
      );
      const queueEntered = deferred<void>();
      const releaseQueue = deferred<void>();
      const priorMutation = document._mutationQueue.run(async () => {
        queueEntered.resolve();
        await releaseQueue.promise;
      });
      await queueEntered.promise;
      const callerIdentity = { id: 'candidate' };

      const transition = document[operation](callerIdentity);
      callerIdentity.id = 'attacker';
      releaseQueue.resolve();
      await priorMutation;
      await expect(transition).resolves.toBeUndefined();

      expect(writers.members).toEqual(new Set(expectedWriters));
      expect(writers.members).not.toContain('attacker');
      expect(publish).toHaveBeenCalledTimes(1);
    },
  );

  test('supports an immutable writer removal without identity codecs', async () => {
    const writers = new StagedWriterACL(new Set(['owner', 'candidate']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['primitive-writer-cid'],
    );
    delete document._authProvider.serializePublicKey;
    delete document._authProvider.deserializePublicKey;

    await expect(document.removeWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner']));
    expect(publish).toHaveBeenCalledTimes(1);
  });

  test('preserves an existing-writer no-op without identity codecs', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['must-not-publish'],
    );
    delete document._authProvider.serializePublicKey;
    delete document._authProvider.deserializePublicKey;

    await expect(document.addWriter('owner')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner']));
    expect(writers.prepareAddCalls).toBe(0);
    expect(publish).not.toHaveBeenCalled();
  });

  test('supports an immutable writer addition without identity codecs', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['primitive-add-cid'],
    );
    delete document._authProvider.serializePublicKey;
    delete document._authProvider.deserializePublicKey;

    await expect(document.addWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    expect(writers.prepareAddCalls).toBe(1);
    expect(publish).toHaveBeenCalledTimes(1);
  });

  test('rejects a mutable writer mutation without identity codecs', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['must-not-publish'],
    );
    delete document._authProvider.serializePublicKey;
    delete document._authProvider.deserializePublicKey;

    await expect(
      document.addWriter({ id: 'candidate' }),
    ).rejects.toThrow(/requires AuthProvider.serializePublicKey/);

    expect(writers.members).toEqual(new Set(['owner']));
    expect(writers.prepareAddCalls).toBe(0);
    expect(publish).not.toHaveBeenCalled();
  });

  test('rejects an aliasing deserializer for a mutable writer identity', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['must-not-publish'],
    );
    const callerIdentity = { id: 'candidate' };
    document._authProvider.serializePublicKey = jest.fn(
      async (key: { id: string }) => key.id,
    );
    document._authProvider.deserializePublicKey = jest.fn(
      async () => callerIdentity,
    );

    await expect(document.addWriter(callerIdentity)).rejects.toThrow(
      /return a detached identity/,
    );

    expect(writers.members).toEqual(new Set(['owner']));
    expect(publish).not.toHaveBeenCalled();
  });

  test('snapshots invitation identity and KEM inputs before queueing', async () => {
    const queue = new InvitationMembershipQueue();
    const blockerStarted = deferred<void>();
    const releaseBlocker = deferred<void>();
    const blocker = queue.run(async () => {
      blockerStarted.resolve();
      await releaseBlocker.promise;
    });
    await blockerStarted.promise;

    type Identity = { profile: { id: string } };
    const owner: Identity = { profile: { id: 'owner' } };
    const readers: Identity[] = [];
    const writers: Identity[] = [owner];
    const serializedIdentities: string[] = [];
    const serializePublicKey = jest.fn((key: Identity) => {
      const serialized = key.profile.id;
      serializedIdentities.push(serialized);
      return Promise.resolve(serialized);
    });
    const deserializePublicKey = jest.fn(async (serialized: string) => ({
      profile: { id: serialized },
    }));
    const readerAclAdd = jest.fn((reader: Identity) => readers.push(reader));
    const writerAclAdd = jest.fn((writer: Identity) => writers.push(writer));
    const originalKem = new Uint8Array(65).fill(4);
    const expectedKem = new Uint8Array(originalKem);
    const document = fakeDocument({
      documentPath: '/writer-publication',
      _createdLocally: true,
      _historyVisibility: 'full_history',
      _userPublicKey: owner,
      _mutationQueue: queue,
      _authProvider: {
        serializePublicKey,
        deserializePublicKey,
        encrypt: jest.fn(async () => ({
          nonce: new Uint8Array([2]),
          data: new Uint8Array([3]),
        })),
      },
      _readers: {
        users: jest.fn(async () => [...readers]),
        current: jest.fn(() => ({ readers: true })),
      },
      _writers: {
        users: jest.fn(async () => [...writers]),
        current: jest.fn(() => ({ writers: true })),
      },
      _prepareInvitationBootstrapCapacity: jest.fn(async () => ({
        keychainChanges: new Uint8Array([5]),
        serializedBootstrapBaselineBytes: 0,
        welcomeWithoutBeeKEMBytes: 0,
      })),
      _addReaderUnlocked: jest.fn(
        async (
          reader: Identity,
          kem: Uint8Array,
          _broadcast: boolean,
          beginMutation: () => void,
        ) => {
          beginMutation();
          readerAclAdd(reader);
          expect(kem).toEqual(expectedKem);
          return {
            leafIndex: 2,
            pathKeys: [],
            treeNodePublicKeys: [],
            treeHash: new Uint8Array([6]),
          };
        },
      ),
      _addWriterUnlocked: jest.fn(
        async (writer: Identity, beginMutation: () => void) => {
          beginMutation();
          writerAclAdd(writer);
        },
      ),
      _makeChange: jest.fn(async () => undefined),
      _keychain: {
        current: jest.fn(async () => [new Uint8Array(32), { key: true }]),
      },
      _changesSerializer: {
        serializeChanges: jest.fn(() => new Uint8Array([7])),
      },
      _createSyncMessage: jest.fn(() => ({
        documentId: '/writer-publication',
      })),
      _signAsWriterUnconditional: jest.fn(async () => 'AA=='),
      _syncMessageSerializer: {
        serializeSyncMessage: jest.fn(() => new Uint8Array([8])),
      },
    });
    mockedEcies.importEciesPublicKey.mockClear();
    mockedEcies.eciesSeal.mockClear();
    const reader: Identity = { profile: { id: 'candidate' } };

    const bootstrap = document.buildInvitationBootstrap(
      reader,
      originalKem,
      'editor',
    );
    reader.profile.id = 'mutated';
    originalKem.fill(8);
    releaseBlocker.resolve();

    await expect(bootstrap).resolves.toEqual({
      welcomeEpochId: new Uint8Array(32),
      sealedWelcome: new Uint8Array([9]),
      encryptedBootstrap: expect.any(Uint8Array),
    });
    await blocker;

    expect(readerAclAdd).toHaveBeenCalledWith({
      profile: { id: 'candidate' },
    });
    expect(readerAclAdd.mock.calls[0]![0]).not.toBe(reader);
    expect(writerAclAdd).toHaveBeenCalledWith({
      profile: { id: 'candidate' },
    });
    expect(
      document._prepareInvitationBootstrapCapacity,
    ).toHaveBeenCalledWith({ profile: { id: 'candidate' } });
    expect(serializedIdentities).toContain('candidate');
    expect(serializedIdentities).not.toContain('mutated');
    expect(mockedEcies.importEciesPublicKey).toHaveBeenCalledWith(expectedKem);
    expect(mockedEcies.eciesSeal).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      { raw: expectedKem },
    );
  });

  test('an out-of-queue remote writer merge fails closed during publication and can be retried', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const remoteChange: ACLChange = {
      operation: 'add',
      publicKey: 'remote-writer',
      sequence: 99,
    };
    let document: any;
    const publish = jest.fn(async () => {
      await expect(document._mergeWriters(remoteChange)).rejects.toThrow(
        /staged local writer publication is in flight.*Retry the sync/s,
      );
      expect(writers.members).toEqual(new Set(['owner']));
    });
    ({ document } = publicationHarness(
      writers,
      publish,
      ['committed-local-add-cid'],
    ));

    await expect(document.addWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    await expect(
      document._mergeWriters(remoteChange),
    ).resolves.toBeUndefined();
    expect(writers.members).toEqual(
      new Set(['owner', 'candidate', 'remote-writer']),
    );
  });

  test('queued remote ACL and DAG bookkeeping run after rejected-publication rollback', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publishStarted = deferred<void>();
    const publication = deferred<void>();
    const publish = jest.fn(() => {
      publishStarted.resolve();
      return publication.promise;
    });
    const { document } = publicationHarness(
      writers,
      publish,
      ['rejected-local-add-cid'],
    );
    const remoteLastSyncMessage = {
      documentId: '/writer-publication',
      changeId: 'remote-writer-cid',
      changes: {
        kind: crdtWriterChangeNode,
        change: {
          operation: 'add',
          publicKey: 'remote-writer',
          sequence: 100,
        },
      },
    };

    const localAdd = document.addWriter('candidate');
    await publishStarted.promise;
    let remoteRan = false;
    const queuedRemote = document._mutationQueue.run(async () => {
      remoteRan = true;
      await document._mergeWriters(remoteLastSyncMessage.changes.change);
      document._hashes.add('remote-writer-cid');
      document._referencedAncestors.add('remote-parent-cid');
      document._trackTip('remote-writer-cid', crdtWriterChangeNode);
      document._lastSyncMessage = remoteLastSyncMessage;
    });

    await Promise.resolve();
    expect(remoteRan).toBe(false);

    publication.reject(new Error('publication rejected'));
    await expect(localAdd).rejects.toThrow('publication rejected');
    await queuedRemote;

    expect(remoteRan).toBe(true);
    expect(writers.members).toEqual(new Set(['owner', 'remote-writer']));
    expect(document._hashes).toEqual(
      new Set(['parent-cid', 'remote-tip-cid', 'remote-writer-cid']),
    );
    expect(document._referencedAncestors).toEqual(
      new Set(['older-ancestor-cid', 'remote-parent-cid']),
    );
    expect(document._recentTips).toContainEqual({
      cid: 'remote-writer-cid',
      kind: crdtWriterChangeNode,
    });
    expect(document._lastSyncMessage).toBe(remoteLastSyncMessage);
  });

  test.each([
    {
      operation: 'addWriter',
      initialMembers: ['owner'],
      expectedAtPublish: ['owner'],
      expectedAtHandler: ['owner', 'candidate'],
      commitEvent: 'commit:add',
    },
    {
      operation: 'removeWriter',
      initialMembers: ['owner', 'candidate'],
      expectedAtPublish: ['owner', 'candidate'],
      expectedAtHandler: ['owner'],
      commitEvent: 'commit:remove',
    },
  ])(
    '$operation commits after publish, exposes committed writers to handlers, and reports handler throws',
    async ({
      operation,
      initialMembers,
      expectedAtPublish,
      expectedAtHandler,
      commitEvent,
    }) => {
      const events: string[] = [];
      const writers = new StagedWriterACL(
        new Set(initialMembers),
        events,
      );
      const publish = jest.fn(async () => {
        events.push(`publish:${[...writers.members].join(',')}`);
        expect([...writers.members]).toEqual(expectedAtPublish);
      });
      const { document } = publicationHarness(
        writers,
        publish,
        [`committed-${operation}-cid`],
      );
      const handlerError = new Error('observer failed');
      document._localHandlers = {
        throwingObserver: (
          _current: unknown,
          _readers: string[],
          observedWriters: string[],
          hashes: string[],
        ) => {
          events.push(`handler:${observedWriters.join(',')}`);
          expect(observedWriters).toEqual(expectedAtHandler);
          expect(hashes).toEqual([`committed-${operation}-cid`]);
          throw handlerError;
        },
      };
      const consoleError = jest
        .spyOn(console, 'error')
        .mockImplementation(() => undefined);

      try {
        await expect(document[operation]('candidate')).resolves.toBeUndefined();
        expect(consoleError).toHaveBeenCalledWith(
          expect.stringContaining('not a retryable ACL publication failure'),
          handlerError,
        );
      } finally {
        consoleError.mockRestore();
      }

      expect(events).toEqual([
        `publish:${expectedAtPublish.join(',')}`,
        commitEvent,
        `handler:${expectedAtHandler.join(',')}`,
      ]);
    },
  );

  test('observes an asynchronous handler rejection without delaying the committed operation', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['async-observer-cid'],
    );
    const handlerStarted = deferred<void>();
    const handlerResult = deferred<void>();
    const rejectionLogged = deferred<void>();
    const handlerError = new Error('asynchronous observer failed');
    document._localHandlers = {
      asynchronousObserver: () => {
        handlerStarted.resolve();
        return handlerResult.promise;
      },
    };
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => rejectionLogged.resolve());

    try {
      const addition = document.addWriter('candidate');
      await handlerStarted.promise;
      await expect(addition).resolves.toBeUndefined();
      expect(writers.members).toContain('candidate');

      handlerResult.reject(handlerError);
      await rejectionLogged.promise;

      expect(consoleError).toHaveBeenCalledWith(
        expect.stringContaining('not a retryable ACL publication failure'),
        handlerError,
      );
    } finally {
      consoleError.mockRestore();
    }
  });

  test('releases the membership queue before a handler awaits a queued API', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['handler-add-cid', 'handler-remove-cid'],
    );
    const handlerFinished = deferred<void>();
    document._localHandlers = {
      reentrantObserver: async () => {
        delete document._localHandlers.reentrantObserver;
        await document.removeWriter('candidate');
        handlerFinished.resolve();
      },
    };

    let timeout: ReturnType<typeof setTimeout> | undefined;
    const result = await Promise.race([
      document.addWriter('candidate').then(() => 'completed'),
      new Promise<string>((resolve) => {
        timeout = setTimeout(() => resolve('timed out'), 1000);
      }),
    ]);
    if (timeout) clearTimeout(timeout);

    expect(result).toBe('completed');
    await handlerFinished.promise;
    expect(writers.members).toEqual(new Set(['owner']));
    expect(publish).toHaveBeenCalledTimes(2);
  });

  test.each([
    ['addition', 'addWriter', ['owner'], 'prepareAdd'],
    ['removal', 'removeWriter', ['owner', 'candidate'], 'prepareRemove'],
  ] as const)(
    'fails closed when the writer ACL lacks staged %s support',
    async (_caseName, operation, initialMembers, prepareMethod) => {
      const writers = new StagedWriterACL(new Set(initialMembers));
      Object.defineProperty(writers, prepareMethod, { value: undefined });
      const publish = jest.fn(async () => undefined);
      const { document } = publicationHarness(
        writers,
        publish,
        ['must-not-publish'],
      );

      await expect(document[operation]('candidate')).rejects.toThrow(
        /does not support the staged .+ required for safe publication/,
      );
      expect(publish).not.toHaveBeenCalled();
      expect(writers.members).toEqual(new Set(initialMembers));
    },
  );

  test('ordinary document changes retain their existing handler error behavior', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['ordinary-document-cid'],
    );
    document._localHandlers = {
      throwingObserver: () => {
        throw new Error('ordinary observer failed');
      },
    };

    await expect(
      document._makeChange(
        { operation: 'add', publicKey: 'not-an-acl-op', sequence: 1 },
        crdtDocumentChangeNode as CRDTChangeNodeKind,
      ),
    ).rejects.toThrow('ordinary observer failed');
  });
});
