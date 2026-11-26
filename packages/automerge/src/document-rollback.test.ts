import { describe, expect, jest, test } from '@jest/globals';
import {
  change,
  clone,
  from,
  getChanges,
  load,
  save,
  getMissingDeps,
  type Change,
} from '@automerge/automerge';
import {
  ACLMergeRejectedError,
  CRDTActorBindings,
  PeerborneDocument,
  createCRDTActorNonce,
  deriveCRDTActorDigest,
  encodeCRDTChangeAuthor,
  mergeCompactionConfig,
} from '@peerborne/core';
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
} from './peerborne-automerge.js';

type Log = { log: string[] };

const KEY_ID_BYTES = 32;
const NONCE_BYTES = 12;
const provider = new AutomergeProvider<Log>();
const genesis = from<Log>({ log: [] }, { actor: '01' });
const PATH = '/automerge-rollback';
const bare = (changes: Change[]) => provider.actorBinding.detach(changes)[1];

async function authoredRemote(entry: string): Promise<Change[]> {
  const registration = { signer: 'remote', nonce: createCRDTActorNonce() };
  const actor = provider.actorBinding.actorFromDigest(
    await deriveCRDTActorDigest(PATH, registration),
  );
  const remote = change(clone(genesis, { actor }), push(entry));
  return provider.actorBinding.attach(
    getChanges(genesis, remote),
    encodeCRDTChangeAuthor({
      ...registration,
      registrationSignature: new Uint8Array(),
      signature: new Uint8Array(),
    }),
  );
}

function automergeDocument(): any {
  const serializer = new AutomergeJSONSerializer();
  let blocks = 0;
  const document: any = Object.assign(
    Object.create(PeerborneDocument.prototype),
    {
      documentPath: PATH,
      _userPublicKey: 'writer',
      _actorBindings: new CRDTActorBindings(),
      _changeAuthorKeys: new Map(),
      _reservedActors: new Map(),
      _changesSerializer: serializer,
      _document: clone(genesis, { actor: '02' }),
      _crdtProvider: provider,
      _syncMessageSerializer: serializer,
      _mutationQueue: {
        run: (operation: () => Promise<unknown>) => operation(),
      },
      _ensureCurrentUserCanWrite: jest.fn(async () => undefined),
      _inTransaction: false,
      _committing: false,
      _pendingChangeFns: [],
      _hashes: new Set<string>(),
      _referencedAncestors: new Set<string>(),
      _recentTips: [],
      _documentChangeCount: 0,
      _changesSinceSnapshot: 0,
      _compactionConfig: mergeCompactionConfig({}),
      _snapshotUnsupported: false,
      _compactionInProgress: false,
      _putBlock: jest.fn(async () => `change-cid-${++blocks}`),
      _signAsWriter: jest.fn(async () => 'AQ=='),
      _keychain: {
        current: jest.fn(async () => [
          new Uint8Array(KEY_ID_BYTES).fill(1),
          { key: 1 },
        ]),
      },
      _authProvider: {
        serializePublicKey: async () => 'writer',
        encrypt: jest.fn(async (plaintext: Uint8Array) => ({
          nonce: new Uint8Array(NONCE_BYTES),
          data: plaintext,
        })),
      },
      _topic: '/topic',
      swarm: {
        config: { enableSigning: false },
        unregisterDocument: jest.fn(),
        heliaNode: {
          libp2p: {
            services: {
              pubsub: {
                publish: jest.fn(async (_topic: string, frame: Uint8Array) => {
                  document.frames.push(frame);
                }),
              },
            },
          },
        },
      },
      _localHandlers: {},
      _fireOrDeferRemoteUpdateHandlers: jest.fn(async () => undefined),
      getReaders: jest.fn(async () => []),
      getWriters: async () => [],
      frames: [] as Uint8Array[],
    },
  );
  return document;
}

function publishedChange(document: any, index: number): Change[] {
  const frame: Uint8Array = document.frames[index];
  return bare(
    document._syncMessageSerializer.deserializeSyncMessage(
      frame.subarray(KEY_ID_BYTES + NONCE_BYTES),
    ).changes.change,
  );
}

function push(entry: string) {
  return (doc: Log) => {
    doc.log.push(entry);
  };
}

async function batch(document: any, entry: string): Promise<void> {
  document.startChange();
  document.addChange(push(entry));
  await document.endChange();
}

// G holds A's a2, which waits for B's b1, in Automerge's queue.
function queuedRemoteChange() {
  const b1 = getChanges(
    genesis,
    change(clone(genesis, { actor: '07' }), push('b1')),
  );
  const withB1 = provider.remoteChange(clone(genesis, { actor: '08' }), b1);
  const a2 = getChanges(withB1, change(withB1, push('a2')));
  const queued = provider.remoteChange(clone(genesis, { actor: '02' }), a2);
  expect(getMissingDeps(queued, [])).toHaveLength(1);
  return { queued, b1 };
}

// Automerge rejects every remote change and snapshot merge into an outdated
// document, as the sync paths apply them.
function applyRemoteChangeAndSnapshot(document: any): void {
  const remote = change(clone(genesis, { actor: '05' }), push('probe'));
  document._document = provider.remoteChange(
    document._document,
    getChanges(genesis, remote),
  );
  document._document = provider.applySnapshot(
    document._document,
    provider.getSnapshot(remote),
  );
  expect(document._document.log).toContain('probe');
}

describe('an Automerge transaction that fails', () => {
  test.each([
    ['storing the block', (document: any) => document._putBlock],
    ['signing the frame', (document: any) => document._signAsWriter],
    ['encrypting the frame', (document: any) => document._authProvider.encrypt],
    [
      'publishing the frame',
      (document: any) => document.swarm.heliaNode.libp2p.services.pubsub.publish,
    ],
  ])(
    'before publication, while %s, rolls back to a writable document',
    async (_step, failingStep) => {
      const document = automergeDocument();
      const failure = new Error('commit failed');
      failingStep(document).mockRejectedValueOnce(failure);

      document.startChange();
      document.addChange(push('lost'));
      await expect(document.endChange()).rejects.toBe(failure);
      const discarded = bare(document._putBlock.mock.calls[0][0]);
      expect(document._document.log).toEqual([]);
      expect(document._hashes.size).toBe(0);
      expect(document._recentTips).toEqual([]);
      expect(document._lastSyncMessage).toBeUndefined();
      expect(document._inTransaction).toBe(false);

      await document.change(push('next'));
      await batch(document, 'batched');
      expect(document._document.log).toEqual(['next', 'batched']);
      expect(load<Log>(save(document._document)).log).toEqual([
        'next',
        'batched',
      ]);

      // A peer may hold the discarded change after an ambiguous publish. The
      // replica's later changes must not reuse its actor sequence number.
      let peer = provider.remoteChange(
        clone(genesis, { actor: '06' }),
        discarded,
      );
      for (let index = 0; index < document.frames.length; index++) {
        peer = provider.remoteChange(peer, publishedChange(document, index));
      }
      expect([...peer.log].sort()).toEqual(['batched', 'lost', 'next']);
      applyRemoteChangeAndSnapshot(document);
    },
  );

  test.each([
    [
      'a local update handler throws',
      (document: any, failure: Error) => {
        document._localHandlers.broken = () => {
          throw failure;
        };
      },
    ],
    [
      'getReaders() rejects',
      (document: any, failure: Error) => {
        document._localHandlers.observer = () => undefined;
        document.getReaders.mockRejectedValueOnce(failure);
      },
    ],
  ])(
    'after publication, when %s, keeps the published change and its bookkeeping',
    async (_case, fail) => {
      const document = automergeDocument();
      const failure = new Error('observer failed');
      fail(document, failure);

      document.startChange();
      document.addChange(push('published'));
      await expect(document.endChange()).rejects.toBe(failure);
      expect(document.frames).toHaveLength(1);
      expect(document._document.log).toEqual(['published']);
      const publishedId = document._lastSyncMessage.changeId;
      expect(document._hashes.has(publishedId)).toBe(true);
      expect(document._recentTips.map(({ cid }: any) => cid)).toEqual([
        publishedId,
      ]);
      expect(document._inTransaction).toBe(false);
      expect(document._committing).toBe(false);

      delete document._localHandlers.broken;
      await document.change(push('next'));
      expect(document._document.log).toEqual(['published', 'next']);
      expect(
        Object.keys(document._lastSyncMessage.changes.children),
      ).toEqual([publishedId]);
      applyRemoteChangeAndSnapshot(document);
    },
  );
});

describe('a remote sync whose ACL entry throws after a document entry', () => {
  const remoteTree = async () => ({
    kind: 'document' as const,
    change: await authoredRemote('remote'),
    children: {
      'writer-cid': { kind: 'writer' as const, change: [] as Change[] },
    },
  });

  test.each([
    [
      'the ACL merge is rejected',
      (document: any) => {
        document._mergeWriters = jest.fn(async () => {
          throw new ACLMergeRejectedError(new Error('rejected'));
        });
        return {};
      },
      ACLMergeRejectedError,
    ],
    [
      'the sync is cancelled during the ACL merge',
      (document: any) => {
        let cancelled = false;
        document._mergeWriters = jest.fn(async () => {
          cancelled = true;
        });
        return {
          assertStillActive: () => {
            if (cancelled) throw new Error('cancelled');
          },
        };
      },
      Error,
    ],
  ])(
    'rolls back to a writable document when %s',
    async (_case, prepare, expected) => {
      const document = automergeDocument();
      const options = prepare(document);
      const tree = await remoteTree();

      await expect(
        document._syncDocumentChanges('remote-cid', tree, options),
      ).rejects.toBeInstanceOf(expected);
      expect(document._document.log).toEqual([]);
      expect(document._hashes.has('remote-cid')).toBe(false);
      expect(document._fireOrDeferRemoteUpdateHandlers).not.toHaveBeenCalled();

      await document.change(push('local'));
      expect(document._document.log).toEqual(['local']);

      document._mergeWriters = jest.fn(async () => undefined);
      await document._syncDocumentChanges('remote-cid', tree);
      expect(document._hashes.has('remote-cid')).toBe(true);
      expect(document._fireOrDeferRemoteUpdateHandlers).toHaveBeenCalledWith([
        'remote-cid',
        'writer-cid',
      ]);
      expect([...document._document.log].sort()).toEqual(['local', 'remote']);
      applyRemoteChangeAndSnapshot(document);
    },
  );
});

describe('a rollback while Automerge holds changes waiting for dependencies', () => {
  test('cloneDocument() declines, because a clone would drop the queue', () => {
    const { queued, b1 } = queuedRemoteChange();
    const outdated = queued;
    const live = provider.localChange(queued, '', push('g1'))[0];

    expect(provider.cloneDocument(outdated)).toBeUndefined();
    const synced = provider.remoteChange(live, b1);
    expect(synced.log).toContain('a2');
    expect(provider.cloneDocument(synced)?.log).toEqual(synced.log);
  });

  test('a transaction that fails before publication retires the instance', async () => {
    const document = automergeDocument();
    const { queued, b1 } = queuedRemoteChange();
    document._document = queued;
    const failure = new Error('commit failed');
    document._putBlock.mockRejectedValueOnce(failure);

    document.startChange();
    document.addChange(push('lost'));
    const error: any = await document
      .endChange()
      .catch((reason: unknown) => reason);
    expect(error.message).toMatch(/could not be rolled back/);
    expect(error.cause).toBe(failure);
    await expect(document.change(push('next'))).rejects.toThrow(
      /could not be rolled back/,
    );
    expect(() => document.document).toThrow(/could not be rolled back/);
    expect(document.frames).toHaveLength(0);
    // The retained document still holds the queued change.
    expect(provider.remoteChange(document._document, b1).log).toContain('a2');
  });

  test('a sync whose ACL entry throws keeps the applied entries and the queue', async () => {
    const document = automergeDocument();
    const { queued, b1 } = queuedRemoteChange();
    document._document = queued;
    document._mergeWriters = jest.fn(async () => {
      throw new ACLMergeRejectedError(new Error('rejected'));
    });
    await expect(
      document._syncDocumentChanges('remote-cid', {
        kind: 'document',
        change: await authoredRemote('remote'),
        children: { 'writer-cid': { kind: 'writer', change: [] } },
      }),
    ).rejects.toBeInstanceOf(ACLMergeRejectedError);
    expect(document._hashes.has('remote-cid')).toBe(false);
    expect(document._document.log).toEqual(['remote']);

    await document.change(push('local'));
    const synced = provider.remoteChange(document._document, b1);
    expect([...synced.log].sort()).toEqual(['a2', 'b1', 'local', 'remote']);
  });
});
