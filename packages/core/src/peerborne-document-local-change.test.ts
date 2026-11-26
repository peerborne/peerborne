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

function publishingDocument(): any {
  const serializer = new JSONSerializer<string[]>();
  let blocks = 0;
  const document: any = Object.assign(
    Object.create(PeerborneDocument.prototype),
    {
      documentPath: '/local-change',
      _userPublicKey: 'writer',
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
      handled: [] as string[][],
      frames: [] as Uint8Array[],
    },
  );
  document._localHandlers = {
    probe: (current: string[]) => {
      document.handled.push([...current]);
    },
  };
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

  test('change() rejects with both errors when publishing the partial edit fails', async () => {
    const document = publishingDocument();
    const failure = new Error('validation');
    const offline = new Error('offline');
    document.swarm.heliaNode.libp2p.services.pubsub.publish.mockRejectedValueOnce(
      offline,
    );

    const error = await rejection(
      document.change((doc: string[]) => {
        doc.push('partial');
        throw failure;
      }),
    );
    expect(error).toBeInstanceOf(AggregateError);
    expect(error.errors).toHaveLength(2);
    expect(error.errors[0]).toBe(failure);
    expect(error.errors[1]).toBe(offline);
    expect(document.handled).toEqual([]);
    expect(document._documentChangeCount).toBe(0);
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

  test('endChange() rejects with both errors, rolls back and ends the transaction when publishing fails', async () => {
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

    const error = await rejection(document.endChange());
    expect(error).toBeInstanceOf(AggregateError);
    expect(error.errors[0]).toBe(failure);
    expect(error.errors[1]).toBe(offline);
    expect(document._hashes.size).toBe(0);
    expect(document._lastSyncMessage).toBeUndefined();
    expect(document._inTransaction).toBe(false);
    expect(document._committing).toBe(false);
  });
});
