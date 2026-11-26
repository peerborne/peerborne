import { describe, expect, jest, test } from '@jest/globals';
import { PartialLocalChangeError } from './crdt-provider.js';
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
