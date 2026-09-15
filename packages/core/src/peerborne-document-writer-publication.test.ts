import { describe, expect, jest, test } from '@jest/globals';

import { ACLOperationInProgressError } from './acl.js';
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
  const readers = new Set(['candidate']);
  let nextHash = 0;
  const document = fakeDocument({
    documentPath: '/writer-publication',
    _document: { stable: true },
    _userPublicKey: 'owner',
    _writers: writers,
    _readers: {
      check: jest.fn(async (publicKey: string) => readers.has(publicKey)),
      users: jest.fn(async () => [...readers]),
    },
    _beekemInitialized: true,
    _beekem: {
      findLeafByPublicKey: jest.fn(async () => 2),
    },
    _readerKemPublicKeys: new Map([
      ['candidate', new Uint8Array(65).fill(7)],
    ]),
    _readerLeafIndices: new Map([['candidate', 2]]),
    _mutationQueue: new InvitationMembershipQueue(),
    _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
    _writerMutationsInFlight: 0,
    _writerPublicationsInFlight: 0,
    _writerKeysVersion: 0,
    _cachedWriterKeys: ['cached-owner'],
    _bootstrapLoadApplicationState: 'pristine',
    _bootstrapLoadApplicationRevision: 0,
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
  });
  return {
    document,
    initialLastSyncMessage,
    initialRecentTips,
    serializedMessages,
    keychain,
    readers,
  };
}

function childCids(message: any): string[] {
  return Object.keys(message.changes?.children ?? {});
}

describe('writer ACL publication boundary', () => {
  test('reader removal queued behind a promotion preserves the writer reader row', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publicationStarted = deferred<void>();
    const releasePublication = deferred<void>();
    const publish = jest.fn(async () => {
      publicationStarted.resolve();
      await releasePublication.promise;
    });
    const { document, readers } = publicationHarness(
      writers, publish, ['promoted-cid'],
    );
    const rotate = jest.fn(async () => {
      throw new Error('rotation must not start');
    });
    document._beekem.removeMember = rotate;
    const promotion = document.addWriter('candidate');
    await publicationStarted.promise;
    const removal = document.removeReader('candidate');
    const rejected = expect(removal).rejects.toThrow(
      /still an authorized writer.*removeWriter/s,
    );
    releasePublication.resolve();
    await promotion;
    await rejected;
    expect(writers.members).toContain('candidate');
    expect(readers).toContain('candidate');
    expect(rotate).not.toHaveBeenCalled();
    expect(publish).toHaveBeenCalledTimes(1);
  });

  test('poisons the document when a post-publication ACL commit is indeterminate', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const originalPrepareAdd = writers.prepareAdd.bind(writers);
    writers.prepareAdd = jest.fn(async (publicKey: string) => {
      const prepared = await originalPrepareAdd(publicKey);
      return {
        ...prepared,
        commit: () => {
          writers.members.add(publicKey);
          throw new Error('indeterminate writer commit');
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
      ['rejected-commit-cid'],
    );

    await expect(document.addWriter('candidate')).rejects.toThrow(
      'indeterminate writer commit',
    );

    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    expect(document._hashes).not.toContain('rejected-commit-cid');
    expect(document._referencedAncestors).toEqual(
      new Set(['older-ancestor-cid']),
    );
    expect(document._recentTips).toEqual(initialRecentTips);
    expect(document._lastSyncMessage).toBe(initialLastSyncMessage);
    expect(serializedMessages).toHaveLength(1);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    document._markBootstrapStateApplicationPending();
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(() => document._markBootstrapStateApplicationComplete()).toThrow(
      /requires pending state/,
    );
    await expect(
      document._completeBootstrapStateApplicationUnlocked(),
    ).rejects.toThrow(/requires pending state/);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(() => document.document).toThrow(/discard this document instance/);
    await expect(document.getWriters()).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(document.addWriter('another-writer')).rejects.toThrow(
      /discard this document instance/,
    );
    await expect(
      document.sync(
        {
          documentId: '/writer-publication',
          changeId: 'poison-bypass-cid',
          changes: {
            kind: crdtDocumentChangeNode,
            change: { attackerControlled: true },
          },
        },
        false,
      ),
    ).rejects.toThrow(/indeterminate authorization state/);
    expect(document._hashes).toEqual(
      new Set(['parent-cid', 'remote-tip-cid']),
    );
    expect(document._lastSyncMessage).toBe(initialLastSyncMessage);
    const sink = jest.fn(async () => undefined);
    const consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);
    try {
      await document.handleLoadRequestData(
        { documentId: '/writer-publication', signature: 'AA==' },
        { sink },
      );
    } finally {
      consoleError.mockRestore();
    }
    expect(sink).toHaveBeenCalledWith([]);
  });

  test.each([
    ['a non-undefined value', () => 'unexpected commit result'],
    [
      'a rejected native Promise',
      () => Promise.reject(new Error('asynchronous writer commit')),
    ],
  ] as const)(
    'poisons and rolls back when a staged writer commit returns %s',
    async (_caseName, commitResult) => {
      const writers = new StagedWriterACL(new Set(['owner']));
      const originalPrepareAdd = writers.prepareAdd.bind(writers);
      (writers as any).prepareAdd = jest.fn(async (publicKey: string) => {
        const prepared = await originalPrepareAdd(publicKey);
        return {
          ...prepared,
          commit: (() => commitResult()) as () => void,
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
        ['invalid-commit-result-cid'],
      );

      await expect(document.addWriter('candidate')).rejects.toThrow(
        /Writer ACL staged commit finalizer must return undefined/,
      );

      expect(writers.members).toEqual(new Set(['owner']));
      expect(document._hashes).not.toContain('invalid-commit-result-cid');
      expect(document._referencedAncestors).toEqual(
        new Set(['older-ancestor-cid']),
      );
      expect(document._recentTips).toEqual(initialRecentTips);
      expect(document._lastSyncMessage).toBe(initialLastSyncMessage);
      expect(serializedMessages).toHaveLength(1);
      expect(publish).toHaveBeenCalledTimes(1);
      expect(document._bootstrapLoadApplicationState).toBe('poisoned');
    },
  );

  test('observes a rejected native-Promise commit without invoking its own then accessor', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const originalPrepareAdd = writers.prepareAdd.bind(writers);
    const thenGetter = jest.fn(() => {
      writers.members.add('attacker');
      throw new Error('native Promise then accessor was invoked');
    });
    let rejectionRan = false;
    (writers as any).prepareAdd = jest.fn(async (publicKey: string) => {
      const prepared = await originalPrepareAdd(publicKey);
      return {
        ...prepared,
        commit: (() => {
          const rejected = Promise.resolve().then(() => {
            rejectionRan = true;
            throw new Error('rejected asynchronous writer commit');
          });
          Object.defineProperty(rejected, 'then', { get: thenGetter });
          return rejected;
        }) as () => void,
      };
    });
    const publish = jest.fn(async () => undefined);
    const { document, initialLastSyncMessage } = publicationHarness(
      writers,
      publish,
      ['rejected-native-promise-commit-cid'],
    );

    await expect(document.addWriter('candidate')).rejects.toThrow(
      /Writer ACL staged commit finalizer must return undefined/,
    );
    await Promise.resolve();
    await Promise.resolve();

    expect(rejectionRan).toBe(true);
    expect(thenGetter).not.toHaveBeenCalled();
    expect(writers.members).toEqual(new Set(['owner']));
    expect(writers.members).not.toContain('attacker');
    expect(document._hashes).not.toContain(
      'rejected-native-promise-commit-cid',
    );
    expect(document._lastSyncMessage).toBe(initialLastSyncMessage);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test('rejects a custom-thenable writer commit result without assimilating it', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const originalPrepareAdd = writers.prepareAdd.bind(writers);
    const then = jest.fn(() => {
      throw new Error('custom writer commit thenable was assimilated');
    });
    const thenGetter = jest.fn(() => then);
    const thenable = {};
    Object.defineProperty(thenable, 'then', { get: thenGetter });
    (writers as any).prepareAdd = jest.fn(async (publicKey: string) => {
      const prepared = await originalPrepareAdd(publicKey);
      return {
        ...prepared,
        commit: (() => thenable) as () => void,
      };
    });
    const publish = jest.fn(async () => undefined);
    const { document, initialLastSyncMessage } = publicationHarness(
      writers,
      publish,
      ['thenable-commit-result-cid'],
    );

    await expect(document.addWriter('candidate')).rejects.toThrow(
      /Writer ACL staged commit finalizer must return undefined/,
    );

    expect(thenGetter).not.toHaveBeenCalled();
    expect(then).not.toHaveBeenCalled();
    expect(writers.members).toEqual(new Set(['owner']));
    expect(document._hashes).not.toContain('thenable-commit-result-cid');
    expect(document._lastSyncMessage).toBe(initialLastSyncMessage);
    expect(document._bootstrapLoadApplicationState).toBe('poisoned');
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

  test('requires explicit reader authorization before writer promotion', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document, readers } = publicationHarness(
      writers,
      publish,
      ['must-not-publish'],
    );
    readers.delete('candidate');

    await expect(document.addWriter('candidate')).rejects.toThrow(
      /must first be added to the explicit readers ACL.*BeeKEM leaf/i,
    );

    expect(writers.members).toEqual(new Set(['owner']));
    expect(writers.prepareAddCalls).toBe(0);
    expect(publish).not.toHaveBeenCalled();
  });

  test('promotes a reader and later downgrades the same identity', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document, readers } = publicationHarness(
      writers,
      publish,
      ['promote-reader-cid', 'downgrade-writer-cid'],
    );

    await expect(document.addWriter('candidate')).resolves.toBeUndefined();
    expect(writers.members).toEqual(new Set(['owner', 'candidate']));

    await expect(document.removeWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner']));
    expect(readers).toContain('candidate');
    expect(writers.prepareAddCalls).toBe(1);
    expect(writers.prepareRemoveCalls).toBe(1);
    expect(publish).toHaveBeenCalledTimes(2);
  });

  test.each([
    ['addition', 'addWriter', ['owner'], 'prepareAdd', ['owner', 'candidate']],
    [
      'removal',
      'removeWriter',
      ['owner', 'candidate'],
      'prepareRemove',
      ['owner'],
    ],
  ] as const)(
    'retries staged writer %s preparation after an ACL conflict settles',
    async (
      _transition,
      operation,
      initialMembers,
      prepareMethod,
      expectedMembers,
    ) => {
      const writers = new StagedWriterACL(new Set(initialMembers));
      const originalPrepare = writers[prepareMethod].bind(writers);
      const conflictObserved = deferred<void>();
      const settlement = deferred<void>();
      let firstAttempt = true;
      const prepare = jest.fn((publicKey: string) => {
        if (firstAttempt) {
          firstAttempt = false;
          conflictObserved.resolve();
          throw new ACLOperationInProgressError(
            `${prepareMethod} conflict`,
            settlement.promise,
          );
        }
        return originalPrepare(publicKey);
      });
      (writers as any)[prepareMethod] = prepare;
      const publish = jest.fn(async () => undefined);
      const { document } = publicationHarness(
        writers,
        publish,
        [`retried-${operation}-cid`],
      );

      const transition = document[operation]('candidate');
      await conflictObserved.promise;
      expect(publish).not.toHaveBeenCalled();

      settlement.resolve();
      await expect(transition).resolves.toBeUndefined();

      expect(prepare).toHaveBeenCalledTimes(2);
      expect(writers.members).toEqual(new Set(expectedMembers));
      expect(publish).toHaveBeenCalledTimes(1);
    },
  );

  test('captures the writer preparation method and receiver across conflict retries', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const conflictObserved = deferred<void>();
    const settlement = deferred<void>();
    const replacementPrepareAdd = jest.fn(() => {
      throw new Error('replacement preparation must not run');
    });
    let attempts = 0;
    const capturedPrepareAdd = jest.fn(function (
      this: StagedWriterACL,
      publicKey: string,
    ) {
      expect(this).toBe(writers);
      if (attempts++ === 0) {
        conflictObserved.resolve();
        throw new ACLOperationInProgressError(
          'captured prepareAdd conflict',
          settlement.promise,
        );
      }
      return StagedWriterACL.prototype.prepareAdd.call(this, publicKey);
    });
    Object.defineProperty(writers, 'prepareAdd', {
      configurable: true,
      writable: true,
      value: capturedPrepareAdd,
    });
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['captured-prepare-add-cid'],
    );

    const addition = document.addWriter('candidate');
    await conflictObserved.promise;
    (writers as any).prepareAdd = replacementPrepareAdd;
    settlement.resolve();
    await expect(addition).resolves.toBeUndefined();

    expect(capturedPrepareAdd).toHaveBeenCalledTimes(2);
    expect(replacementPrepareAdd).not.toHaveBeenCalled();
    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    expect(publish).toHaveBeenCalledTimes(1);
  });

  test.each([
    {
      transition: 'addition',
      operation: 'addWriter',
      initialMembers: ['owner'],
      acl: 'writers',
      expectedMembers: ['owner', 'candidate'],
    },
    {
      transition: 'removal',
      operation: 'removeWriter',
      initialMembers: ['owner', 'candidate'],
      acl: 'readers',
      expectedMembers: ['owner'],
    },
  ] as const)(
    'retries the $transition admission check after an ACL conflict settles',
    async ({ operation, initialMembers, acl, expectedMembers }) => {
      const writers = new StagedWriterACL(new Set(initialMembers));
      const publish = jest.fn(async () => undefined);
      const { document } = publicationHarness(
        writers,
        publish,
        [`retried-${operation}-check-cid`],
      );
      const checkedAcl = acl === 'writers' ? writers : document._readers;
      const originalCheck = checkedAcl.check.bind(checkedAcl);
      const conflictObserved = deferred<void>();
      const settlement = deferred<void>();
      let firstAttempt = true;
      checkedAcl.check = jest.fn((publicKey: string) => {
        if (firstAttempt) {
          firstAttempt = false;
          conflictObserved.resolve();
          throw new ACLOperationInProgressError(
            `${acl} check conflict`,
            settlement.promise,
          );
        }
        return originalCheck(publicKey);
      });

      const transition = document[operation]('candidate');
      await conflictObserved.promise;
      expect(publish).not.toHaveBeenCalled();

      settlement.resolve();
      await expect(transition).resolves.toBeUndefined();

      expect(checkedAcl.check).toHaveBeenCalledTimes(2);
      expect(writers.members).toEqual(new Set(expectedMembers));
      expect(publish).toHaveBeenCalledTimes(1);
    },
  );

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
    expect(await document._readers.check('candidate')).toBe(true);
  });

  test('writer downgrade never enters the fallible key-rotation path', async () => {
    const writers = new StagedWriterACL(new Set(['owner', 'candidate']));
    const publish = jest.fn(async () => undefined);
    const { document, keychain, readers } =
      publicationHarness(writers, publish, ['writer-downgrade-cid']);
    keychain.add.mockRejectedValue(new Error('keychain unavailable'));

    await expect(document.removeWriter('candidate')).resolves.toBeUndefined();
    await expect(document.removeWriter('candidate')).resolves.toBeUndefined();

    expect(writers.members).toEqual(new Set(['owner']));
    expect(readers).toContain('candidate');
    expect(keychain.current).toHaveBeenCalledTimes(1);
    expect(keychain.add).not.toHaveBeenCalled();
    expect(publish).toHaveBeenCalledTimes(1);
  });

  test('rejects removal of a writer without explicit reader authorization', async () => {
    const writers = new StagedWriterACL(new Set(['owner', 'candidate']));
    const publish = jest.fn(async () => undefined);
    const { document, keychain, readers } =
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

  test('snapshots the local identity before queued writer removal', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document, readers } = publicationHarness(
      writers,
      publish,
      ['must-not-publish'],
    );
    const localIdentity = { id: 'owner' };
    const capturedLocalEncodings: string[] = [];
    document._userPublicKey = localIdentity;
    document._authProvider.serializePublicKey = jest.fn((key: any) => {
      const serialized = typeof key === 'string' ? key : key.id;
      if (key === localIdentity) capturedLocalEncodings.push(serialized);
      return Promise.resolve(serialized);
    });
    document._authProvider.deserializePublicKey = jest.fn(
      async (serialized: string) => serialized,
    );
    readers.add('owner');
    const queueEntered = deferred<void>();
    const releaseQueue = deferred<void>();
    const priorMutation = document._mutationQueue.run(async () => {
      queueEntered.resolve();
      await releaseQueue.promise;
    });
    await queueEntered.promise;

    const removal = document.removeWriter('owner');
    localIdentity.id = 'attacker';
    releaseQueue.resolve();
    await priorMutation;

    await expect(removal).rejects.toThrow(/Cannot remove the local writer/);
    expect(capturedLocalEncodings).toEqual(['owner']);
    expect(writers.members).toEqual(new Set(['owner']));
    expect(writers.prepareRemoveCalls).toBe(0);
    expect(publish).not.toHaveBeenCalled();
  });

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

  test('does not let an existing-writer no-op bless malformed membership', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const publish = jest.fn(async () => undefined);
    const { document } = publicationHarness(
      writers,
      publish,
      ['must-not-publish'],
    );
    delete document._authProvider.serializePublicKey;
    delete document._authProvider.deserializePublicKey;

    await expect(document.addWriter('owner')).rejects.toThrow(
      /must first be added to the explicit readers ACL/,
    );

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
          serializedReader: string,
          kem: Uint8Array,
          _broadcast: boolean,
          beginMutation: () => void,
        ) => {
          beginMutation();
          readerAclAdd(reader);
          expect(serializedReader).toBe('candidate');
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
        async (
          writer: Identity,
          beginMutation: () => void,
          stableIdentity: boolean,
          serializedWriter: string,
        ) => {
          beginMutation();
          expect(stableIdentity).toBe(true);
          expect(serializedWriter).toBe('candidate');
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
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
  });

  test.each(['readers', 'writers'] as const)(
    'poisons the document when a custom %s merge mutates and then throws',
    async (aclKind) => {
      const writers = new StagedWriterACL(new Set(['owner']));
      const publish = jest.fn(async () => undefined);
      const { document, readers } = publicationHarness(
        writers,
        publish,
        ['must-not-publish'],
      );
      const failure = new Error(`indeterminate ${aclKind} merge`);
      if (aclKind === 'readers') {
        document._readers.merge = jest.fn(() => {
          readers.add('injected-member');
          throw failure;
        });
      } else {
        writers.merge = jest.fn(() => {
          writers.members.add('injected-member');
          throw failure;
        });
      }

      await expect(
        aclKind === 'readers'
          ? document._mergeReaders({ remote: true })
          : document._mergeWriters({ remote: true }),
      ).rejects.toBe(failure);

      expect(
        aclKind === 'readers'
          ? readers.has('injected-member')
          : writers.members.has('injected-member'),
      ).toBe(true);
      expect(document._bootstrapLoadApplicationState).toBe('poisoned');
      expect(() => document.document).toThrow(/discard this document instance/);
      await expect(document.getReaders()).rejects.toThrow(
        /discard this document instance/,
      );
      await expect(document.getWriters()).rejects.toThrow(
        /discard this document instance/,
      );
      await expect(
        document.sync({ documentId: '/writer-publication' }),
      ).rejects.toThrow(/discard this document instance/);
    },
  );

  test.each(['readers', 'writers'] as const)(
    'retries a certified %s merge conflict without poisoning the document',
    async (aclKind) => {
      const writers = new StagedWriterACL(new Set(['owner']));
      const publish = jest.fn(async () => undefined);
      const { document, readers } = publicationHarness(
        writers,
        publish,
        ['must-not-publish'],
      );
      const settlement = Promise.resolve();
      let attempts = 0;
      const merge = jest.fn(() => {
        if (attempts++ === 0) {
          throw new ACLOperationInProgressError(
            `${aclKind} merge conflict`,
            settlement,
          );
        }
        if (aclKind === 'readers') {
          readers.add('remote-member');
        } else {
          writers.members.add('remote-member');
        }
      });
      if (aclKind === 'readers') {
        document._readers.merge = merge;
        document._schedulePendingWelcomeDrain = jest.fn();
      } else {
        writers.merge = merge;
      }

      await expect(
        aclKind === 'readers'
          ? document._mergeReaders({ remote: true })
          : document._mergeWriters({ remote: true }),
      ).resolves.toBeUndefined();

      expect(merge).toHaveBeenCalledTimes(2);
      expect(document._bootstrapLoadApplicationState).toBe('pristine');
    },
  );

  test('rechecks publication exclusion after a writer merge conflict settles', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const mergeObserved = deferred<void>();
    const settlement = deferred<void>();
    const publishObserved = deferred<void>();
    const publication = deferred<void>();
    const originalMerge = writers.merge.bind(writers);
    let firstAttempt = true;
    writers.merge = jest.fn((changes: ACLChange) => {
      if (firstAttempt) {
        firstAttempt = false;
        mergeObserved.resolve();
        throw new ACLOperationInProgressError(
          'writer merge conflict',
          settlement.promise,
        );
      }
      originalMerge(changes);
    });
    const publish = jest.fn(() => {
      publishObserved.resolve();
      return publication.promise;
    });
    const { document } = publicationHarness(
      writers,
      publish,
      ['local-writer-cid'],
    );
    const remoteChange: ACLChange = {
      operation: 'add',
      publicKey: 'remote-writer',
      sequence: 101,
    };

    const remoteMerge = document._mergeWriters(remoteChange);
    await mergeObserved.promise;
    const localAddition = document.addWriter('candidate');
    await publishObserved.promise;
    settlement.resolve();

    await expect(remoteMerge).rejects.toThrow(
      /staged local writer publication is in flight/,
    );
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
    expect(writers.members).toEqual(new Set(['owner']));

    publication.resolve();
    await expect(localAddition).resolves.toBeUndefined();
    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    expect(writers.merge).toHaveBeenCalledTimes(1);
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
      const handlerSecret = 'decrypted-observer-secret';
      const handlerError = { secret: handlerSecret };
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
        );
        expect(consoleError).toHaveBeenCalledTimes(1);
        expect(consoleError.mock.calls[0]).toHaveLength(1);
        expect(JSON.stringify(consoleError.mock.calls)).not.toContain(
          handlerSecret,
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
    const handlerSecret = 'decrypted-asynchronous-observer-secret';
    const handlerError = { secret: handlerSecret };
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
      );
      expect(consoleError).toHaveBeenCalledTimes(1);
      expect(consoleError.mock.calls[0]).toHaveLength(1);
      expect(JSON.stringify(consoleError.mock.calls)).not.toContain(
        handlerSecret,
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
    'rejects an accessor-backed staged writer %s capability without invoking it',
    async (_caseName, operation, initialMembers, prepareMethod) => {
      const writers = new StagedWriterACL(new Set(initialMembers));
      const accessor = jest.fn(() => {
        throw new Error('writer preparation accessor was invoked');
      });
      Object.defineProperty(writers, prepareMethod, {
        configurable: true,
        get: accessor,
      });
      const publish = jest.fn(async () => undefined);
      const { document } = publicationHarness(
        writers,
        publish,
        ['must-not-publish'],
      );

      await expect(document[operation]('candidate')).rejects.toThrow(
        /Writer ACL prepare(?:Add|Remove) must be a data property/,
      );

      expect(accessor).not.toHaveBeenCalled();
      expect(publish).not.toHaveBeenCalled();
      expect(writers.members).toEqual(new Set(initialMembers));
      expect(document._bootstrapLoadApplicationState).toBe('pristine');
    },
  );

  test.each([
    ['addition', 'addWriter', ['owner'], 'prepareAdd', 'changes'],
    [
      'addition',
      'addWriter',
      ['owner'],
      'prepareAdd',
      'commit',
    ],
    [
      'removal',
      'removeWriter',
      ['owner', 'candidate'],
      'prepareRemove',
      'changes',
    ],
    [
      'removal',
      'removeWriter',
      ['owner', 'candidate'],
      'prepareRemove',
      'commit',
    ],
  ] as const)(
    'rejects an accessor-backed prepared writer %s %s field without invoking it',
    async (
      _caseName,
      operation,
      initialMembers,
      prepareMethod,
      preparedField,
    ) => {
      const writers = new StagedWriterACL(new Set(initialMembers));
      const originalPrepare = writers[prepareMethod].bind(writers);
      const accessor = jest.fn(() => {
        throw new Error('prepared writer field accessor was invoked');
      });
      (writers as any)[prepareMethod] = jest.fn(
        async (publicKey: string) => {
          const prepared = await originalPrepare(publicKey);
          Object.defineProperty(prepared, preparedField, {
            configurable: true,
            get: accessor,
          });
          return prepared;
        },
      );
      const publish = jest.fn(async () => undefined);
      const { document } = publicationHarness(
        writers,
        publish,
        ['must-not-publish'],
      );

      await expect(document[operation]('candidate')).rejects.toThrow(
        /Prepared writer ACL (?:addition|removal) (?:changes|commit) must be a data property/,
      );

      expect(accessor).not.toHaveBeenCalled();
      expect(publish).not.toHaveBeenCalled();
      expect(writers.members).toEqual(new Set(initialMembers));
      expect(document._bootstrapLoadApplicationState).toBe('pristine');
    },
  );

  test('uses the captured staged writer commit method with its original receiver', async () => {
    const writers = new StagedWriterACL(new Set(['owner']));
    const originalPrepareAdd = writers.prepareAdd.bind(writers);
    const publishStarted = deferred<void>();
    const publication = deferred<void>();
    let retainedPrepared: Record<string, unknown> | undefined;
    const capturedCommit = jest.fn(function (this: object) {
      expect(this).toBe(retainedPrepared);
      writers.members.add('candidate');
    });
    (writers as any).prepareAdd = jest.fn(async (publicKey: string) => {
      const prepared = await originalPrepareAdd(publicKey);
      Object.defineProperty(prepared, 'commit', {
        configurable: true,
        writable: true,
        value: capturedCommit,
      });
      retainedPrepared = prepared;
      return prepared;
    });
    const publish = jest.fn(() => {
      publishStarted.resolve();
      return publication.promise;
    });
    const { document } = publicationHarness(
      writers,
      publish,
      ['captured-writer-commit-cid'],
    );

    const addition = document.addWriter('candidate');
    await publishStarted.promise;
    const replacementCommit = jest.fn(() => {
      throw new Error('replacement commit must not run');
    });
    Object.defineProperty(retainedPrepared!, 'commit', {
      configurable: true,
      writable: true,
      value: replacementCommit,
    });
    publication.resolve();
    await expect(addition).resolves.toBeUndefined();

    expect(capturedCommit).toHaveBeenCalledTimes(1);
    expect(replacementCommit).not.toHaveBeenCalled();
    expect(writers.members).toEqual(new Set(['owner', 'candidate']));
    expect(document._bootstrapLoadApplicationState).toBe('pristine');
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
