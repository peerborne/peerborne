import { describe, expect, test } from '@jest/globals';
import type { CRDTChangeNode } from './crdt-change-node.js';
import { MAX_MERKLE_DAG_DEPTH } from './merkle-dag-serialization.js';
import {
  MAX_LOAD_RESPONSE_MANIFEST_EDGES,
  MAX_LOAD_RESPONSE_MANIFEST_ID_BYTES,
  MAX_LOAD_RESPONSE_MANIFEST_NODES,
  MAX_LOAD_RESPONSE_MANIFEST_OCCURRENCES,
  MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES,
  loadResponseManifestHash,
} from './load-response-manifest.js';
import {
  collectAllCidsInTree,
  collectReferencedAncestors,
  computeServedFrontier,
  mergeRemoteSyncTree,
  stripInlineChanges,
  treeContainsCid,
} from './merkle-cross-links.js';

const node = (
  overrides: Partial<CRDTChangeNode<unknown>> = {},
): CRDTChangeNode<unknown> => ({
  kind: 'document',
  ...overrides,
});

const textEncoder = new TextEncoder();
const serializeChange = (change: unknown) =>
  textEncoder.encode(JSON.stringify(change));
const hash = (input: Parameters<typeof loadResponseManifestHash>[0]) =>
  loadResponseManifestHash({ serializeChange, ...input });

describe('loadResponseManifestHash', () => {
  test('is canonical across child insertion order', async () => {
    const first = node({
      children: {
        B: node({ kind: 'reader', children: false }),
        A: node({ kind: 'writer', change: { acl: true } }),
      },
    });
    const second = node({
      children: {
        A: node({ kind: 'writer', change: { acl: true } }),
        B: node({ kind: 'reader', children: false }),
      },
    });

    await expect(hash({ changeId: 'ROOT', changes: first })).resolves.toEqual(
      await hash({ changeId: 'ROOT', changes: second }),
    );
  });

  test.each([
    [
      'root identity',
      { changeId: 'OTHER', changes: node() },
    ],
    [
      'node kind',
      { changeId: 'ROOT', changes: node({ kind: 'writer' }) },
    ],
    [
      'directed edges',
      {
        changeId: 'ROOT',
        changes: node({
          children: { A: node({ children: { B: node() } }) },
        }),
      },
    ],
    [
      'deferred child marker',
      { changeId: 'ROOT', changes: node({ children: false }) },
    ],
    [
      'inline change marker',
      { changeId: 'ROOT', changes: node({ change: { value: 1 } }) },
    ],
    [
      'encryption key identity',
      { changeId: 'ROOT', changes: node({ keyID: 'epoch-b' }) },
    ],
  ])('binds %s', async (_name, changed) => {
    const baseline = {
      changeId: 'ROOT',
      changes: node({
        keyID: 'epoch-a',
        children: { A: node(), B: node() },
      }),
    };
    await expect(hash(changed)).resolves.not.toEqual(await hash(baseline));
  });

  test('binds canonical inline change bytes, not only their presence', async () => {
    const baseline = await hash({
      changeId: 'ROOT',
      changes: node({ change: { value: 1 } }),
    });
    const substituted = await hash({
      changeId: 'ROOT',
      changes: node({ change: { value: 2 } }),
    });
    expect(substituted).not.toEqual(baseline);
  });

  test('fails closed when an inline change has no canonical serializer', async () => {
    await expect(
      loadResponseManifestHash({
        changeId: 'ROOT',
        changes: node({ change: { value: 1 } }),
      }),
    ).rejects.toThrow(/requires serializeChange/);
  });

  test('copies serialized inline bytes before hashing', async () => {
    const serialized = new Uint8Array([1, 2, 3]);
    const pending = hash({
      changeId: 'ROOT',
      changes: node({ change: { value: 1 } }),
      serializeChange: () => serialized,
    });
    serialized.fill(9);
    await expect(pending).resolves.toEqual(
      await hash({
        changeId: 'ROOT',
        changes: node({ change: { value: 1 } }),
        serializeChange: () => new Uint8Array([1, 2, 3]),
      }),
    );
  });

  test('binds snapshot bytes and every applied snapshot metadata field', async () => {
    const baseline = {
      snapshot: {
        stateBytes: new Uint8Array([1, 2, 3]),
        lastChangeNodeCID: 'SNAP',
        compactedCount: 4,
        timestamp: 5,
      },
    };
    const baselineHash = await hash(baseline);
    for (const changed of [
      { ...baseline.snapshot, stateBytes: new Uint8Array([1, 2, 4]) },
      { ...baseline.snapshot, lastChangeNodeCID: 'OTHER' },
      { ...baseline.snapshot, compactedCount: 3 },
      { ...baseline.snapshot, timestamp: 6 },
    ]) {
      await expect(hash({ snapshot: changed })).resolves.not.toEqual(
        baselineHash,
      );
    }
  });

  test('binds keychain presence and serialized bytes', async () => {
    const absent = await hash({});
    const first = await hash({
      keychainChangesBytes: new Uint8Array([1, 2, 3]),
    });
    const second = await hash({
      keychainChangesBytes: new Uint8Array([1, 2, 4]),
    });
    expect(first).not.toEqual(absent);
    expect(second).not.toEqual(first);
  });

  test('rejects a lone surrogate before UTF-8 canonicalization', async () => {
    await expect(
      hash({ changeId: '\ud800', changes: node() }),
    ).rejects.toThrow(/well-formed UTF-16/);
  });

  test('rejects conflicting descriptions of one CID', async () => {
    await expect(
      hash({
        changeId: 'ROOT',
        changes: node({
          children: {
            A: node({ kind: 'document' }),
            B: node({
              children: { A: node({ kind: 'writer' }) },
            }),
          },
        }),
      }),
    ).rejects.toThrow(/conflicting descriptions/);
  });

  test.each(['alias-first', 'canonical-first'] as const)(
    'rejects a conflicting repeated-CID subtree in %s child order',
    async (order) => {
      const canonical = node({
        children: {
          SHARED: node({
            children: { C: node({ kind: 'document' }) },
          }),
        },
      });
      const conflictingAlias = node({
        children: {
          SHARED: node({
            children: { C: node({ kind: 'writer' }) },
          }),
        },
      });
      const children: Record<string, CRDTChangeNode<unknown>> = {};
      if (order === 'alias-first') {
        children.Z = conflictingAlias;
        children.A = canonical;
      } else {
        children.A = canonical;
        children.Z = conflictingAlias;
      }

      await expect(
        hash({ changeId: 'ROOT', changes: node({ children }) }),
      ).rejects.toThrow(/conflicting descriptions.*C/);
    },
  );

  test.each(['attacker-first', 'canonical-first'] as const)(
    'rejects substituted inline bytes for one repeated CID in %s order',
    async (order) => {
      const canonical = node({
        children: { SHARED: node({ change: { value: 'canonical' } }) },
      });
      const attacker = node({
        children: { SHARED: node({ change: { value: 'attacker' } }) },
      });
      const children =
        order === 'attacker-first'
          ? { A: attacker, Z: canonical }
          : { A: canonical, Z: attacker };

      await expect(
        hash({ changeId: 'ROOT', changes: node({ children }) }),
      ).rejects.toThrow(/conflicting descriptions.*SHARED/);
    },
  );

  test('accepts identical full representations of a shared CID', async () => {
    const shared = () =>
      node({
        children: {
          C: node({ kind: 'reader', children: { LEAF: node() } }),
        },
      });
    const first = node({
      children: {
        A: node({ children: { SHARED: shared() } }),
        Z: node({ children: { SHARED: shared() } }),
      },
    });
    const second = node({
      children: {
        Z: node({ children: { SHARED: shared() } }),
        A: node({ children: { SHARED: shared() } }),
      },
    });

    await expect(hash({ changeId: 'ROOT', changes: first })).resolves.toEqual(
      await hash({ changeId: 'ROOT', changes: second }),
    );
  });

  test.each(['sparse-first', 'full-first'] as const)(
    'reconciles a sparse cross-link with its full CID description in %s order',
    async (order) => {
      const sparseBranch = node({
        children: { SHARED: node() },
      });
      const fullBranch = node({
        children: {
          SHARED: node({
            keyID: 'epoch-a',
            change: { value: 'shared' },
            children: { PARENT: node({ change: { value: 'parent' } }) },
          }),
        },
      });
      const children: Record<string, CRDTChangeNode<unknown>> = {};
      if (order === 'sparse-first') {
        children.A = sparseBranch;
        children.Z = fullBranch;
      } else {
        children.A = fullBranch;
        children.Z = sparseBranch;
      }

      const actual = await hash({
        changeId: 'ROOT',
        changes: node({ children }),
      });
      const reversed = await hash({
        changeId: 'ROOT',
        changes: node({
          children: {
            A: order === 'sparse-first' ? fullBranch : sparseBranch,
            Z: order === 'sparse-first' ? sparseBranch : fullBranch,
          },
        }),
      });
      expect(actual).toEqual(reversed);
    },
  );

  test.each(['sparse-first', 'full-first'] as const)(
    'rejects incompatible sparse/full metadata in %s order',
    async (order) => {
      const sparse = node({ kind: 'reader', keyID: 'epoch-a' });
      const full = node({
        kind: 'reader',
        keyID: 'epoch-b',
        change: { value: 'shared' },
      });
      const first = node({ children: { SHARED: sparse } });
      const second = node({ children: { SHARED: full } });
      const children =
        order === 'sparse-first'
          ? { A: first, Z: second }
          : { A: second, Z: first };

      await expect(
        hash({ changeId: 'ROOT', changes: node({ children }) }),
      ).rejects.toThrow(/conflicting descriptions.*SHARED/);
    },
  );

  test('rejects cycles instead of canonicalizing an ambiguous graph', async () => {
    const root = node();
    const child = node();
    root.children = { CHILD: child };
    child.children = { ROOT: root };
    await expect(hash({ changeId: 'ROOT', changes: root })).rejects.toThrow(
      /cycle/,
    );
  });

  test('bounds node count before hashing', async () => {
    const children: Record<string, CRDTChangeNode<unknown>> = {};
    for (let index = 0; index < MAX_LOAD_RESPONSE_MANIFEST_NODES; index++) {
      children[`N${index}`] = node();
    }
    await expect(
      hash({ changeId: 'ROOT', changes: node({ children }) }),
    ).rejects.toThrow(/exceeds .* nodes/);
  });

  test('rejects depth 513 without exhausting the call stack', async () => {
    const root = node();
    let cursor = root;
    for (let index = 1; index <= MAX_MERKLE_DAG_DEPTH; index++) {
      const child = node();
      cursor.children = { [`N${index}`]: child };
      cursor = child;
    }

    await expect(
      hash({ changeId: 'ROOT', changes: root }),
    ).rejects.toThrow(
      new RegExp(`exceeds ${MAX_MERKLE_DAG_DEPTH} tree depth`),
    );
  });

  test('processes depth 512 through every security traversal without recursive stack growth', async () => {
    const root = node({ change: { index: 0 } });
    let cursor = root;
    let lastCid = 'ROOT';
    for (let index = 1; index < MAX_MERKLE_DAG_DEPTH; index++) {
      const child = node({ change: { index } });
      lastCid = `N${index}`;
      cursor.children = { [lastCid]: child };
      cursor = child;
    }

    await expect(
      hash({ changeId: 'ROOT', changes: root }),
    ).resolves.toHaveLength(32);
    expect(computeServedFrontier('ROOT', root, undefined)).toEqual(['ROOT']);
    expect(
      collectReferencedAncestors('ROOT', root, new Set<string>()).size,
    ).toBe(MAX_MERKLE_DAG_DEPTH - 1);
    expect(treeContainsCid('ROOT', root, lastCid)).toBe(true);
    expect(collectAllCidsInTree('ROOT', root)).toHaveLength(
      MAX_MERKLE_DAG_DEPTH,
    );
    expect(
      mergeRemoteSyncTree('ROOT', root, undefined, new Set()),
    ).toHaveLength(MAX_MERKLE_DAG_DEPTH);

    stripInlineChanges(root);
    expect(root.change).toBeUndefined();
    expect(cursor.change).toBeUndefined();
  });

  test('bounds directed edge count even with a small shared node set', async () => {
    const leafCount = 128;
    const parentCount =
      Math.floor(MAX_LOAD_RESPONSE_MANIFEST_EDGES / leafCount) + 1;
    const children: Record<string, CRDTChangeNode<unknown>> = {};
    for (let parent = 0; parent < parentCount; parent++) {
      const sharedLeaves: Record<string, CRDTChangeNode<unknown>> = {};
      for (let leaf = 0; leaf < leafCount; leaf++) {
        sharedLeaves[`L${leaf}`] = node();
      }
      children[`P${parent}`] = node({ children: sharedLeaves });
    }
    await expect(
      hash({ changeId: 'ROOT', changes: node({ children }) }),
    ).rejects.toThrow(/exceeds .* edges/);
  });

  test('bounds validation work across repeated full CID occurrences', async () => {
    const sharedChildren: Record<string, CRDTChangeNode<unknown>> = {};
    for (let index = 0; index < 128; index++) {
      sharedChildren[`L${index}`] = node();
    }
    const shared = node({ children: sharedChildren });
    const parents: Record<string, CRDTChangeNode<unknown>> = {};
    const parentCount =
      Math.floor(MAX_LOAD_RESPONSE_MANIFEST_OCCURRENCES / 128) + 1;
    for (let index = 0; index < parentCount; index++) {
      parents[`P${index}`] = node({ children: { SHARED: shared } });
    }

    await expect(
      hash({ changeId: 'ROOT', changes: node({ children: parents }) }),
    ).rejects.toThrow(/exceeds .* (node occurrences|traversed edges)/);
  });

  test('bounds every serialized CID/key identifier', async () => {
    const oversized = 'x'.repeat(MAX_LOAD_RESPONSE_MANIFEST_ID_BYTES + 1);
    await expect(
      hash({ changeId: oversized, changes: node() }),
    ).rejects.toThrow(/UTF-8 bytes/);
    await expect(
      hash({ changeId: 'ROOT', changes: node({ keyID: oversized }) }),
    ).rejects.toThrow(/UTF-8 bytes/);
  });

  test('bounds serialized snapshot and keychain payload bytes', async () => {
    const oversized = new Uint8Array(
      MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES + 1,
    );
    await expect(
      hash({
        snapshot: {
          stateBytes: oversized,
          lastChangeNodeCID: 'SNAP',
          compactedCount: 1,
          timestamp: 1,
        },
      }),
    ).rejects.toThrow(/snapshot state exceeds/);
    await expect(
      hash({ keychainChangesBytes: oversized }),
    ).rejects.toThrow(/keychain changes exceed/);
    await expect(
      hash({
        changeId: 'ROOT',
        changes: node({ change: { oversized: true } }),
        serializeChange: () => oversized,
      }),
    ).rejects.toThrow(/inline changes exceed/);
  });
});
