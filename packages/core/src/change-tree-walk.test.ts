import { describe, expect, jest, test } from '@jest/globals';

import {
  collectBoundedChangeTree,
  MAX_CHANGE_TREE_NODES,
} from './change-tree-walk.js';
import { collectChangeTreeCidsForPinning } from './change-tree-pinning.js';
import {
  type CRDTChangeNode,
  crdtChangeNodeDeferred,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import { PeerborneDocument } from './peerborne-document.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock(
  'multiformats',
  () => ({
    CID: class {
      static parse(value: string) {
        if (value === 'not-a-cid') throw new TypeError('malformed CID');
        return { toString: () => value };
      }
    },
  }),
  { virtual: true },
);
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

type Change = Uint8Array;
type Node = CRDTChangeNode<Change>;

function chain(length: number, leafKind = crdtDocumentChangeNode): Node {
  const root: Node = { kind: crdtDocumentChangeNode };
  let cursor = root;
  for (let index = 1; index < length; index++) {
    const child: Node = {
      kind: index === length - 1 ? leafKind : crdtDocumentChangeNode,
    };
    cursor.children = { [`cid-${index}`]: child };
    cursor = child;
  }
  return root;
}

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), fields);
}

describe('bounded iterative change-tree consumers', () => {
  test('walks a deeply nested accepted legacy tree without recursion', () => {
    expect(collectBoundedChangeTree('root', chain(10_000))).toHaveLength(
      10_000,
    );
  });

  test('rejects a tree over the aggregate node budget', () => {
    expect(() =>
      collectBoundedChangeTree('root', chain(MAX_CHANGE_TREE_NODES + 1)),
    ).toThrow(/exceeds/);
  });

  test('pinning preflight validates every CID before returning work', () => {
    const rootCid =
      'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
    const tree: Node = {
      kind: crdtDocumentChangeNode,
      children: {
        'not-a-cid': { kind: crdtDocumentChangeNode },
      },
    };
    expect(() => collectChangeTreeCidsForPinning(rootCid, tree)).toThrow(
      /malformed CID/,
    );
  });

  test('pinning preflight is stack-safe and rejects deferred trees', () => {
    expect(collectChangeTreeCidsForPinning('root', chain(10_000))).toHaveLength(
      10_000,
    );
    expect(() =>
      collectChangeTreeCidsForPinning('root', {
        kind: crdtDocumentChangeNode,
        children: crdtChangeNodeDeferred,
      }),
    ).toThrow(/deferred/);
  });

  test('ACL pre-pass does not partially mutate on an over-budget tree', () => {
    const mergeReaders = jest.fn();
    const mergeWriters = jest.fn();
    const root = chain(MAX_CHANGE_TREE_NODES + 1);
    root.kind = crdtWriterChangeNode;
    root.change = new Uint8Array([1]);
    const document = fakeDocument({
      _mergeReaders: mergeReaders,
      _mergeWriters: mergeWriters,
    });

    expect(() => document._applyACLFromTree(root)).toThrow(/exceeds/);
    expect(mergeReaders).not.toHaveBeenCalled();
    expect(mergeWriters).not.toHaveBeenCalled();
  });

  test('ACL pre-pass does not partially mutate before a cyclic child fails', () => {
    const mergeReaders = jest.fn();
    const mergeWriters = jest.fn();
    const root: Node = {
      kind: crdtWriterChangeNode,
      change: new Uint8Array([1]),
    };
    root.children = { self: root };
    const document = fakeDocument({
      _mergeReaders: mergeReaders,
      _mergeWriters: mergeWriters,
    });

    expect(() => document._applyACLFromTree(root)).toThrow(/cycles/);
    expect(mergeReaders).not.toHaveBeenCalled();
    expect(mergeWriters).not.toHaveBeenCalled();
  });

  test('ACL pre-pass rejects accessors without invoking them or mutating', () => {
    const mergeReaders = jest.fn();
    const mergeWriters = jest.fn();
    const childrenGetter = jest.fn(() => ({}));
    const root: Node = {
      kind: crdtWriterChangeNode,
      change: new Uint8Array([1]),
    };
    Object.defineProperty(root, 'children', {
      enumerable: true,
      get: childrenGetter,
    });
    const document = fakeDocument({
      _mergeReaders: mergeReaders,
      _mergeWriters: mergeWriters,
    });

    expect(() => document._applyACLFromTree(root)).toThrow(/data properties/);
    expect(childrenGetter).not.toHaveBeenCalled();
    expect(mergeReaders).not.toHaveBeenCalled();
    expect(mergeWriters).not.toHaveBeenCalled();
  });

  test('ACL pre-pass does not partially mutate conflicting CID aliases', () => {
    const mergeReaders = jest.fn();
    const mergeWriters = jest.fn();
    const root: Node = {
      kind: crdtDocumentChangeNode,
      children: {
        left: {
          kind: crdtDocumentChangeNode,
          children: {
            shared: {
              kind: crdtWriterChangeNode,
              change: new Uint8Array([1]),
            },
          },
        },
        right: {
          kind: crdtDocumentChangeNode,
          children: {
            shared: {
              kind: crdtReaderChangeNode,
              change: new Uint8Array([2]),
            },
          },
        },
      },
    };
    const document = fakeDocument({
      _mergeReaders: mergeReaders,
      _mergeWriters: mergeWriters,
    });

    expect(() => document._applyACLFromTree(root)).toThrow(
      /conflicting descriptions/,
    );
    expect(mergeReaders).not.toHaveBeenCalled();
    expect(mergeWriters).not.toHaveBeenCalled();
  });

  test('ACL pre-pass reaches a deep membership leaf exactly once', () => {
    const mergeReaders = jest.fn();
    const mergeWriters = jest.fn();
    const root = chain(10_000, crdtReaderChangeNode);
    let leaf = root;
    while (leaf.children) {
      leaf = Object.values(leaf.children)[0]!;
    }
    leaf.change = new Uint8Array([7]);
    const document = fakeDocument({
      _mergeReaders: mergeReaders,
      _mergeWriters: mergeWriters,
    });

    expect(() => document._applyACLFromTree(root)).not.toThrow();
    expect(mergeReaders).toHaveBeenCalledTimes(1);
    expect(mergeWriters).not.toHaveBeenCalled();
  });

  test('pruning leaves an over-budget cached tree untouched', () => {
    const root = chain(MAX_CHANGE_TREE_NODES + 1);
    const originalChildren = root.children;
    const document = fakeDocument({
      documentPath: '/bounded-prune',
      _lastSyncMessage: {
        documentId: '/bounded-prune',
        changeId: 'root',
        changes: root,
      },
    });

    expect(() => document._pruneChanges(1)).toThrow(/exceeds/);
    expect(root.children).toBe(originalChildren);
  });
});
