import { expect, jest, test } from '@jest/globals';
import { snapshotBoundedChangeTree } from './change-tree-walk.js';
import type { CRDTChangeNode } from './crdt-change-node.js';
import type { CRDTSyncMessage } from './crdt-sync-message.js';
import { boundSyncMessage } from './gossip-frame.js';
import { JSONSerializer } from './json-serializer.js';
import {
  mergeRemoteSyncTree,
  validateRemoteSyncTreeAliases,
} from './merkle-cross-links.js';

type Node = CRDTChangeNode<string>;
type Message = CRDTSyncMessage<string>;

const serializer = new JSONSerializer<string>();
const serialize = (message: Message) =>
  serializer.serializeSyncMessage(message);
const sign = jest.fn(async (message: Message) => {
  expect(message.signature).toBeUndefined();
  return `sig:${serialize(message).byteLength}`;
});

/** A linear history c<count-1> -> ... -> c0, newest first. */
function chain(count: number, payload: (index: number) => string): Message {
  let node: Node | undefined;
  for (let index = 0; index < count; index++) {
    const next: Node = { kind: 'document', change: payload(index) };
    if (node !== undefined) next.children = { [`c${index - 1}`]: node };
    node = next;
  }
  return {
    documentId: '/doc',
    signatureContext: 'ordinary-sync-v1',
    changeId: `c${count - 1}`,
    changes: node,
    signature: 'original',
  };
}

function inline(message: Message): Record<string, boolean> {
  const result: Record<string, boolean> = {};
  const pending: [string | undefined, Node][] = [
    [message.changeId, message.changes!],
  ];
  while (pending.length > 0) {
    const [id, node] = pending.pop()!;
    result[id!] = node.change !== undefined;
    if (node.children) pending.push(...Object.entries(node.children));
  }
  return result;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

test('a message that fits is returned unchanged and is not re-signed', async () => {
  sign.mockClear();
  const message = chain(3, () => 'x');
  const bounded = await boundSyncMessage(message, 4096, serialize, sign);
  expect(bounded?.message).toBe(message);
  expect(bounded?.deferredChanges).toBe(0);
  expect(bounded?.bytes).toEqual(serialize(message));
  expect(sign).not.toHaveBeenCalled();
});

test('an oversized history sends the oldest payloads by CID and keeps the newest inline', async () => {
  sign.mockClear();
  const message = deepFreeze(chain(8, () => 'x'.repeat(1000)));
  const limit = 4000;
  const bounded = (await boundSyncMessage(message, limit, serialize, sign))!;
  expect(bounded.bytes.byteLength).toBeLessThanOrEqual(limit);
  expect(bounded.message.signature).toMatch(/^sig:/);
  expect(sign).toHaveBeenCalledTimes(1);
  const shape = inline(bounded.message);
  expect(Object.keys(shape)).toHaveLength(8);
  expect(shape.c7).toBe(true);
  expect(shape.c0).toBe(false);
  const kept = Object.values(shape).filter(Boolean).length;
  expect(kept).toBeGreaterThan(1);
  expect(bounded.deferredChanges).toBe(8 - kept);
  // Payloads are dropped from the oldest end only.
  for (let index = 7; index > 0; index--) {
    if (!shape[`c${index}`]) expect(shape[`c${index - 1}`]).toBe(false);
  }
  expect(inline(message).c0).toBe(true);

  const decoded = serializer.deserializeSyncMessage(bounded.bytes);
  expect(serialize(decoded)).toEqual(bounded.bytes);
  validateRemoteSyncTreeAliases(decoded.changeId, decoded.changes!);
  snapshotBoundedChangeTree(decoded.changeId, decoded.changes!);
  const entries = mergeRemoteSyncTree(
    decoded.changeId,
    decoded.changes!,
    undefined,
    new Set(),
  );
  expect(entries.map(([id]) => id).sort()).toEqual(
    Array.from({ length: 8 }, (_, index) => `c${index}`).sort(),
  );
  for (const [id, , change] of entries)
    expect(change !== undefined).toBe(shape[id]);
});

test('aliases of one CID are deferred together and ACL payloads stay inline', async () => {
  const shared: Node = { kind: 'document', change: 'y'.repeat(2000) };
  const acl: Node = { kind: 'writer', change: 'w'.repeat(500) };
  const message: Message = {
    documentId: '/doc',
    signatureContext: 'ordinary-sync-v1',
    changeId: 'root',
    signature: 'original',
    changes: {
      kind: 'document',
      change: 'r',
      children: {
        near: { kind: 'document', change: 'n', children: { shared } },
        acl: {
          kind: 'document',
          change: 'm',
          children: {
            deep: {
              kind: 'document',
              change: 'd',
              children: { writer: acl, shared },
            },
          },
        },
      },
    },
  };
  const bounded = (await boundSyncMessage(message, 1600, serialize, sign))!;
  const decoded = serializer.deserializeSyncMessage(bounded.bytes);
  expect(() =>
    validateRemoteSyncTreeAliases(decoded.changeId, decoded.changes!),
  ).not.toThrow();
  const children = decoded.changes!.children as Record<string, Node>;
  const near = children.near.children as Record<string, Node>;
  const deep = (children.acl.children as Record<string, Node>).deep;
  expect(near.shared.change).toBeUndefined();
  expect((deep.children as Record<string, Node>).shared.change).toBeUndefined();
  expect((deep.children as Record<string, Node>).writer.change).toBe(
    acl.change,
  );
});

test('a mixed inline and deferred description of one CID is still rejected by receivers', () => {
  expect(() =>
    validateRemoteSyncTreeAliases('root', {
      kind: 'document',
      change: 'r',
      children: {
        a: {
          kind: 'document',
          children: { x: { kind: 'document', change: 'x' } },
        },
        b: {
          kind: 'document',
          change: 'b',
          children: {
            a: {
              kind: 'document',
              change: 'a',
              children: { x: { kind: 'document', change: 'x' } },
            },
          },
        },
      },
    }),
  ).toThrow('conflicting descriptions');
});

test('a root payload above the limit is sent by CID with the history structure intact', async () => {
  const message = chain(3, (index) => (index === 2 ? 'z'.repeat(5000) : 's'));
  const bounded = (await boundSyncMessage(message, 1000, serialize, sign))!;
  expect(bounded.deferredChanges).toBe(3);
  expect(inline(bounded.message)).toEqual({ c2: false, c1: false, c0: false });
  const decoded = serializer.deserializeSyncMessage(bounded.bytes);
  const entries = mergeRemoteSyncTree(
    decoded.changeId,
    decoded.changes!,
    undefined,
    new Set(['c0']),
  );
  expect(entries).toEqual([
    ['c2', 'document', undefined],
    ['c1', 'document', undefined],
  ]);
});

test('the snapshot is kept and a tree that cannot fit is reported', async () => {
  const message: Message = {
    ...chain(4, () => 'p'.repeat(400)),
    snapshot: {
      state: 'S'.repeat(300),
      lastChangeNodeCID: 'c0',
      signature: 'snap',
    } as unknown as Message['snapshot'],
  };
  const bounded = (await boundSyncMessage(message, 1200, serialize, sign))!;
  expect(bounded.message.snapshot).toBe(message.snapshot);
  expect(bounded.deferredChanges).toBeGreaterThan(0);
  await expect(
    boundSyncMessage(message, 400, serialize, sign),
  ).resolves.toBeUndefined();
  await expect(
    boundSyncMessage(
      {
        documentId: '/doc',
        signatureContext: 'ordinary-sync-v1',
        keychainChanges: 'k'.repeat(500),
      },
      100,
      serialize,
      sign,
    ),
  ).resolves.toBeUndefined();
});
