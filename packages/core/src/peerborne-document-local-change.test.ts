import { describe, expect, jest, test } from '@jest/globals';
import { mergeCompactionConfig } from './compaction-config.js';
import { crdtDocumentChangeNode } from './crdt-change-node.js';
import { PartialLocalChangeError } from './crdt-provider.js';
import { JSONSerializer } from './json-serializer.js';
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

type Edit = (document: string[]) => void;

const inPlaceProvider = {
  localChange(
    document: string[],
    _message: string,
    edit: Edit,
  ): [string[], string[]] {
    const before = document.length;
    try {
      edit(document);
    } catch (error) {
      if (document.length === before) throw error;
      throw new PartialLocalChangeError(
        error,
        document,
        document.slice(before),
      );
    }
    return [document, document.slice(before)];
  },
};

function fakeDocument(): any {
  const document: any = Object.assign(
    Object.create(PeerborneDocument.prototype),
    {
      documentPath: '/local-change',
      _document: [] as string[],
      _crdtProvider: inPlaceProvider,
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
      published: [] as string[][],
    },
  );
  document._makeChange = jest.fn(async (changes: string[]) => {
    document.published.push(changes);
    document._hashes.add(`cid-${document._hashes.size}`);
  });
  return document;
}

const KEY_ID_BYTES = 32;
const NONCE_BYTES = 12;

const copyingProvider = {
  localChange(
    document: string[],
    _message: string,
    edit: Edit,
  ): [string[], string[]] {
    const next = [...document];
    edit(next);
    return [next, next.slice(document.length)];
  },
};

function publishingDocument(crdtProvider: object = inPlaceProvider): any {
  const serializer = new JSONSerializer<string[]>();
  let blocks = 0;
  const document: any = Object.assign(
    Object.create(PeerborneDocument.prototype),
    {
      documentPath: '/local-change',
      _userPublicKey: 'writer',
      _document: [] as string[],
      _crdtProvider: crdtProvider,
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
      _syncMessageSerializer: serializer,
      _authProvider: {
        encrypt: jest.fn(async (plaintext: Uint8Array) => ({
          nonce: new Uint8Array(NONCE_BYTES),
          data: plaintext,
        })),
      },
      _topic: '/topic',
      swarm: {
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
      getReaders: async () => [],
      getWriters: async () => [],
      _closeDocument: jest.fn(async () => undefined),
      _deliveryFailureHandlers: {},
      _remoteHandlers: {},
      handled: [] as string[][],
      undelivered: [] as { changeId: string; error: unknown }[],
      frames: [] as Uint8Array[],
    },
  );
  document._localHandlers = {
    probe: (current: string[]) => {
      document.handled.push([...current]);
    },
  };
  document.subscribeDeliveryFailures('probe', (failure: any) => {
    document.undelivered.push(failure);
  });
  return document;
}

function publishedChange(document: any, index: number): unknown {
  const frame: Uint8Array = document.frames[index];
  const message = document._syncMessageSerializer.deserializeSyncMessage(
    frame.subarray(KEY_ID_BYTES + NONCE_BYTES),
  );
  return message.changes.change;
}

async function rejection(promise: Promise<unknown>): Promise<any> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected the change to reject');
}

describe('local changes whose change function throws', () => {
  test('change() publishes the partial in-place edit and rethrows the original error', async () => {
    const document = fakeDocument();
    const failure = new Error('validation');

    await expect(
      document.change((doc: string[]) => {
        doc.push('partial');
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(document.published).toEqual([['partial']]);

    await document.change((doc: string[]) => doc.push('next'));
    expect(document.published).toEqual([['partial'], ['next']]);
    expect(document._document).toEqual(['partial', 'next']);
  });

  test('change() publishes nothing when the function throws before editing', async () => {
    const document = fakeDocument();
    const failure = new Error('rejected');

    await expect(
      document.change(() => {
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(document._makeChange).not.toHaveBeenCalled();
  });

  test('endChange() publishes the partial batch, keeps its history and ends the transaction', async () => {
    const document = fakeDocument();
    const failure = new Error('validation');
    document.startChange();
    document.addChange((doc: string[]) => doc.push('first'));
    document.addChange((doc: string[]) => {
      doc.push('second');
      throw failure;
    });

    await expect(document.endChange()).rejects.toBe(failure);
    expect(document.published).toEqual([['first', 'second']]);
    expect([...document._hashes]).toEqual(['cid-0']);
    expect(document._inTransaction).toBe(false);
    expect(document._committing).toBe(false);

    document.startChange();
    document.addChange((doc: string[]) => doc.push('third'));
    await document.endChange();
    expect(document.published).toEqual([['first', 'second'], ['third']]);
  });
});

describe('committing the partial edit of a throwing change function', () => {
  test('change() signs, publishes, notifies and counts the partial edit, and the next change builds on it', async () => {
    const document = publishingDocument();
    const failure = new Error('validation');

    await expect(
      document.change((doc: string[]) => {
        doc.push('partial');
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(document._putBlock).toHaveBeenCalledWith(
      ['partial'],
      crdtDocumentChangeNode,
    );
    expect(document._signAsWriter).toHaveBeenCalledTimes(1);
    expect(document.frames).toHaveLength(1);
    expect(publishedChange(document, 0)).toEqual(['partial']);
    expect(document.handled).toEqual([['partial']]);
    expect(document._documentChangeCount).toBe(1);
    expect(document._changesSinceSnapshot).toBe(1);
    const partialId = document._lastSyncMessage.changeId;
    expect(document._hashes.has(partialId)).toBe(true);

    await document.change((doc: string[]) => doc.push('next'));
    expect(publishedChange(document, 1)).toEqual(['next']);
    expect(
      document._lastSyncMessage.changes.children[partialId].change,
    ).toEqual(['partial']);
    expect(document._documentChangeCount).toBe(2);
  });

  test('change() rethrows the change function error, keeps the partial edit and reports it undelivered when publishing fails', async () => {
    const document = publishingDocument();
    const failure = new Error('validation');
    const offline = new Error('offline');
    document.swarm.heliaNode.libp2p.services.pubsub.publish.mockRejectedValueOnce(
      offline,
    );

    await expect(
      document.change((doc: string[]) => {
        doc.push('partial');
        throw failure;
      }),
    ).rejects.toBe(failure);
    const partialId = document._lastSyncMessage.changeId;
    expect(document._hashes.has(partialId)).toBe(true);
    expect(document.undelivered).toEqual([
      { documentPath: '/local-change', changeId: partialId, error: offline },
    ]);
    expect(document.handled).toEqual([['partial']]);

    await document.change((doc: string[]) => doc.push('next'));
    expect(document.frames).toHaveLength(1);
    expect(
      document._lastSyncMessage.changes.children[partialId].change,
    ).toEqual(['partial']);
  });

  test('change() rejects with both errors when a local handler fails after publication', async () => {
    const document = publishingDocument();
    const failure = new Error('validation');
    const observer = new Error('observer');
    document._localHandlers.broken = () => {
      throw observer;
    };

    const error = await rejection(
      document.change((doc: string[]) => {
        doc.push('partial');
        throw failure;
      }),
    );
    expect(error).toBeInstanceOf(AggregateError);
    expect([...error.errors]).toEqual([failure, observer]);
    expect(document.frames).toHaveLength(1);
  });

  test('endChange() rethrows the change function error, keeps the partial batch and ends the transaction when publishing fails', async () => {
    const document = publishingDocument();
    const failure = new Error('validation');
    const offline = new Error('offline');
    document.swarm.heliaNode.libp2p.services.pubsub.publish.mockRejectedValueOnce(
      offline,
    );
    document.startChange();
    document.addChange((doc: string[]) => {
      doc.push('partial');
      throw failure;
    });

    await expect(document.endChange()).rejects.toBe(failure);
    expect(document._hashes.size).toBe(1);
    expect(document._lastSyncMessage.changes.change).toEqual(['partial']);
    expect(document.undelivered).toHaveLength(1);
    expect(document.undelivered[0].error).toBe(offline);
    expect(document._inTransaction).toBe(false);
    expect(document._committing).toBe(false);
  });
});

describe('a local change that fails before publication', () => {
  const beforeTheTree: [string, (document: any) => any][] = [
    ['storing the block', (document) => document._putBlock],
    ['signing the frame', (document) => document._signAsWriter],
  ];
  const inTheTree: [string, (document: any) => any][] = [
    ['encrypting the frame', (document) => document._authProvider.encrypt],
    [
      'publishing the frame',
      (document) => document.swarm.heliaNode.libp2p.services.pubsub.publish,
    ],
  ];
  const entries: [string, (document: any, edit: Edit) => Promise<void>][] = [
    ['change()', (document, edit) => document.change(edit)],
    [
      'endChange()',
      (document, edit) => {
        document.startChange();
        document.addChange(edit);
        return document.endChange();
      },
    ],
  ];
  const cases = (steps: [string, (document: any) => any][]) =>
    entries.flatMap(([entry, commit]) =>
      steps.map(
        ([step, failingStep]) => [entry, step, commit, failingStep] as const,
      ),
    );

  async function committedOnce(provider: object) {
    const document = publishingDocument(provider);
    await document.change((doc: string[]) => doc.push('accepted'));
    return {
      document,
      hashes: [...document._hashes],
      tree: document._lastSyncMessage,
      tips: [...document._recentTips],
      ancestors: [...document._referencedAncestors],
    };
  }

  test.each(cases(beforeTheTree))(
    'in %s while %s, an in-place provider retires the instance',
    async (_entry, _step, commit, failingStep) => {
      const { document, hashes, tree, tips, ancestors } =
        await committedOnce(inPlaceProvider);
      const failure = new Error('commit failed');
      failingStep(document).mockRejectedValueOnce(failure);

      const error = await rejection(
        commit(document, (doc: string[]) => doc.push('lost')),
      );
      expect(error.message).toMatch(/could not be rolled back/);
      expect(error.cause).toBe(failure);
      expect([...document._hashes]).toEqual(hashes);
      expect(document._lastSyncMessage).toBe(tree);
      expect(document._recentTips).toEqual(tips);
      expect([...document._referencedAncestors]).toEqual(ancestors);
      expect(document._documentChangeCount).toBe(1);
      expect(document._inTransaction).toBe(false);
      expect(document.handled).toEqual([['accepted']]);
      expect(document._closeDocument).toHaveBeenCalledTimes(1);
      await expect(
        document.change((doc: string[]) => doc.push('next')),
      ).rejects.toThrow(/could not be rolled back/);
      expect(() => document.startChange()).toThrow(/could not be rolled back/);
    },
  );

  test.each(cases(beforeTheTree))(
    'in %s while %s, a provider that returns a new document restores the earlier one',
    async (_entry, _step, commit, failingStep) => {
      const { document, hashes, tree, tips } =
        await committedOnce(copyingProvider);
      const accepted = document._document;
      const failure = new Error('commit failed');
      failingStep(document).mockRejectedValueOnce(failure);

      await expect(
        commit(document, (doc: string[]) => doc.push('lost')),
      ).rejects.toBe(failure);
      expect(document._document).toBe(accepted);
      expect([...document._hashes]).toEqual(hashes);
      expect(document._lastSyncMessage).toBe(tree);
      expect(document._recentTips).toEqual(tips);
      expect(document._closeDocument).not.toHaveBeenCalled();

      await commit(document, (doc: string[]) => doc.push('next'));
      expect(document._document).toEqual(['accepted', 'next']);
      expect(publishedChange(document, document.frames.length - 1)).toEqual([
        'next',
      ]);
      expect(Object.keys(document._lastSyncMessage.changes.children)).toEqual([
        tree.changeId,
      ]);
    },
  );

  test.each(
    cases(inTheTree).flatMap((entry) => [
      [...entry, 'an in-place provider', inPlaceProvider] as const,
      [
        ...entry,
        'a provider that returns a new document',
        copyingProvider,
      ] as const,
    ]),
  )(
    'in %s while %s, %s resolves, keeps the change and reports it undelivered',
    async (_entry, _step, commit, failingStep, _name, provider) => {
      const { document, tree } = await committedOnce(provider);
      const failure = new Error('PublishError.NoPeersSubscribedToTopic');
      failingStep(document).mockRejectedValueOnce(failure);

      await commit(document, (doc: string[]) => doc.push('kept'));
      const keptId = document._lastSyncMessage.changeId;
      expect(keptId).not.toBe(tree.changeId);
      expect(document._hashes.has(keptId)).toBe(true);
      expect(document._document).toEqual(['accepted', 'kept']);
      expect(document._documentChangeCount).toBe(2);
      expect(document._inTransaction).toBe(false);
      expect(document.undelivered).toEqual([
        { documentPath: '/local-change', changeId: keptId, error: failure },
      ]);
      expect(Object.isFrozen(document.undelivered[0])).toBe(true);
      expect(document.handled).toEqual([['accepted'], ['accepted', 'kept']]);
      expect(document._closeDocument).not.toHaveBeenCalled();

      await commit(document, (doc: string[]) => doc.push('next'));
      expect(document.frames).toHaveLength(2);
      const delivered = document._syncMessageSerializer.deserializeSyncMessage(
        document.frames[1].subarray(KEY_ID_BYTES + NONCE_BYTES),
      );
      expect(delivered.changes.change).toEqual(['next']);
      expect(delivered.changes.children[keptId].change).toEqual(['kept']);
      expect(
        Object.keys(delivered.changes.children[keptId].children),
      ).toContain(tree.changeId);
      expect(document.undelivered).toHaveLength(1);
    },
  );

  test('a throwing delivery failure handler does not fail the change, and unsubscribe removes handlers', async () => {
    const { document } = await committedOnce(inPlaceProvider);
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      document.subscribeDeliveryFailures('broken', () => {
        throw new Error('handler');
      });
      const { publish } = document.swarm.heliaNode.libp2p.services.pubsub;
      publish.mockRejectedValueOnce(new Error('offline'));
      await document.change((doc: string[]) => doc.push('kept'));
      expect(document.undelivered).toHaveLength(1);
      expect(error).toHaveBeenCalledWith(
        '[/local-change] a delivery failure handler failed.',
      );

      document.unsubscribe('broken');
      document.unsubscribe('probe');
      publish.mockRejectedValueOnce(new Error('offline'));
      await document.change((doc: string[]) => doc.push('again'));
      expect(document.undelivered).toHaveLength(1);
      expect(error).toHaveBeenCalledTimes(1);
    } finally {
      error.mockRestore();
    }
  });
});
