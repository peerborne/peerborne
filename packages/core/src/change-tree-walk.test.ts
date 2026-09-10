import { describe, expect, jest, test } from '@jest/globals';

import {
  collectBoundedChangeTree,
  MAX_CHANGE_TREE_DEPTH,
  MAX_CHANGE_TREE_NODES,
  snapshotBoundedChangeTree,
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
        return {
          toString: () =>
            value === 'non-canonical-cid' ? 'canonical-cid' : value,
        };
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

function overNodeBudgetTree(): Node {
  const children: Record<string, Node> = {};
  for (let index = 0; index < MAX_CHANGE_TREE_NODES; index++) {
    children[`cid-${index}`] = { kind: crdtDocumentChangeNode };
  }
  return { kind: crdtDocumentChangeNode, children };
}

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), fields);
}

describe('bounded iterative change-tree consumers', () => {
  test('walks a tree at the serialization-safe depth limit', () => {
    expect(
      collectBoundedChangeTree('root', chain(MAX_CHANGE_TREE_DEPTH)),
    ).toHaveLength(MAX_CHANGE_TREE_DEPTH);
  });

  test('rejects a tree beyond the serialization-safe depth limit', () => {
    expect(() =>
      collectBoundedChangeTree('root', chain(MAX_CHANGE_TREE_DEPTH + 1)),
    ).toThrow(/maximum depth/);
  });

  test('returns a detached, frozen structural snapshot', () => {
    const child: Node = { kind: crdtDocumentChangeNode };
    const root: Node = {
      kind: crdtDocumentChangeNode,
      children: { child },
    };

    const snapshot = snapshotBoundedChangeTree('root', root).root;
    const snapshotChildren = snapshot.children as Record<string, Node>;

    expect(snapshot).not.toBe(root);
    expect(snapshotChildren).not.toBe(root.children);
    expect(snapshotChildren.child).not.toBe(child);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshotChildren)).toBe(true);
    expect(Object.isFrozen(snapshotChildren.child)).toBe(true);
  });

  test('rejects a tree over the aggregate node budget', () => {
    expect(() =>
      collectBoundedChangeTree('root', overNodeBudgetTree()),
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
      /canonical CID/,
    );
  });

  test('pinning preflight is stack-safe and rejects deferred trees', () => {
    expect(
      collectChangeTreeCidsForPinning(
        'root',
        chain(MAX_CHANGE_TREE_DEPTH),
      ),
    ).toHaveLength(MAX_CHANGE_TREE_DEPTH);
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
    const root = overNodeBudgetTree();
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

  test('ACL pre-pass reaches a maximum-depth membership leaf exactly once', () => {
    const mergeReaders = jest.fn();
    const mergeWriters = jest.fn();
    const root = chain(MAX_CHANGE_TREE_DEPTH, crdtReaderChangeNode);
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
    const root = overNodeBudgetTree();
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

  test.each([
    [
      'root',
      'not-a-cid',
      { kind: crdtWriterChangeNode, change: new Uint8Array([1]) },
    ],
    [
      'non-canonical root',
      'non-canonical-cid',
      { kind: crdtWriterChangeNode, change: new Uint8Array([1]) },
    ],
    [
      'inline child',
      'root',
      {
        kind: crdtDocumentChangeNode,
        children: {
          'not-a-cid': {
            kind: crdtWriterChangeNode,
            change: new Uint8Array([2]),
          },
        },
      },
    ],
    [
      'deferred child',
      'root',
      {
        kind: crdtDocumentChangeNode,
        children: {
          'not-a-cid': {
            kind: crdtDocumentChangeNode,
            children: crdtChangeNodeDeferred,
          },
        },
      },
    ],
  ] as const)(
    'rejects a malformed %s CID before changing any sync state',
    async (_caseName, changeId, changes) => {
      const initialDocument = { unchanged: true };
      const initialLastSyncMessage = {
        documentId: '/cid-preflight',
        changeId: 'prior',
        changes: { kind: crdtDocumentChangeNode },
      };
      const mergeKeychain = jest.fn();
      const mergeReaders = jest.fn();
      const mergeWriters = jest.fn();
      const remoteChange = jest.fn();
      const document = fakeDocument({
        documentPath: '/cid-preflight',
        _isSigningEnabled: () => false,
        _keychain: { merge: mergeKeychain },
        _mergeReaders: mergeReaders,
        _mergeWriters: mergeWriters,
        _crdtProvider: { remoteChange },
        _document: initialDocument,
        _hashes: new Set(['prior']),
        _referencedAncestors: new Set(['prior-parent']),
        _recentTips: [{ cid: 'prior', kind: crdtDocumentChangeNode }],
        _lastSyncMessage: initialLastSyncMessage,
        _documentChangeCount: 7,
        _changesSinceSnapshot: 3,
        _latestSnapshot: undefined,
      });

      await expect(
        document._syncUnlocked(
          {
            documentId: '/cid-preflight',
            changeId,
            changes,
            keychainChanges: new Uint8Array([9]),
            snapshot: {
              state: new Uint8Array([8]),
              lastChangeNodeCID: 'prior',
              timestamp: 1,
              compactedCount: 1,
              signature: new Uint8Array(),
            },
          },
          false,
        ),
      ).rejects.toThrow(/canonical CID/);

      expect(mergeKeychain).not.toHaveBeenCalled();
      expect(mergeReaders).not.toHaveBeenCalled();
      expect(mergeWriters).not.toHaveBeenCalled();
      expect(remoteChange).not.toHaveBeenCalled();
      expect(document._document).toBe(initialDocument);
      expect(document._hashes).toEqual(new Set(['prior']));
      expect(document._referencedAncestors).toEqual(
        new Set(['prior-parent']),
      );
      expect(document._recentTips).toEqual([
        { cid: 'prior', kind: crdtDocumentChangeNode },
      ]);
      expect(document._lastSyncMessage).toBe(initialLastSyncMessage);
      expect(document._documentChangeCount).toBe(7);
      expect(document._changesSinceSnapshot).toBe(3);
      expect(document._latestSnapshot).toBeUndefined();
    },
  );

  test('pruning uses one detached tree view and never partially mutates proxies', () => {
    let sourceMutationObserved = false;
    const firstChildren = {
      'cid-first-leaf': { kind: crdtDocumentChangeNode } as Node,
    };
    const firstTarget: Node = {
      kind: crdtDocumentChangeNode,
      children: firstChildren,
    };
    const first = new Proxy(firstTarget, {
      deleteProperty(target, property) {
        if (property === 'children') sourceMutationObserved = true;
        return Reflect.deleteProperty(target, property);
      },
    });
    const secondChildren = {
      'cid-second-leaf': { kind: crdtDocumentChangeNode } as Node,
    };
    const secondTarget: Node = {
      kind: crdtDocumentChangeNode,
      children: secondChildren,
    };
    const second = new Proxy(secondTarget, {
      get(target, property, receiver) {
        if (property === 'children' && sourceMutationObserved) {
          return { 'cid-invalid-after-mutation': null };
        }
        return Reflect.get(target, property, receiver);
      },
    });
    const root: Node = {
      kind: crdtDocumentChangeNode,
      children: {
        'cid-first': first,
        'cid-second': second,
      },
    };
    const document = fakeDocument({
      documentPath: '/stable-prune',
      _lastSyncMessage: {
        documentId: '/stable-prune',
        changeId: 'root',
        changes: root,
      },
    });
    const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);

    try {
      expect(document._pruneChanges(2)).toEqual(
        new Set(['cid-first-leaf', 'cid-second-leaf']),
      );
      expect(sourceMutationObserved).toBe(false);
      expect(firstTarget.children).toBe(firstChildren);
      expect(secondTarget.children).toBe(secondChildren);
      expect(document._lastSyncMessage.changes).not.toBe(root);
      const retained = document._lastSyncMessage.changes.children as Record<
        string,
        Node
      >;
      expect(retained['cid-first'].children).toBeUndefined();
      expect(retained['cid-second'].children).toBeUndefined();
    } finally {
      log.mockRestore();
    }
  });
});
