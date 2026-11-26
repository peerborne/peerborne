import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';
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
const hash = (input: Parameters<typeof loadResponseManifestHash>[0]) =>
  loadResponseManifestHash(input);
const signedSnapshot = (
  overrides: Record<string, unknown> = {},
): Parameters<typeof loadResponseManifestHash>[0]['snapshot'] =>
  ({
    stateBytes: new Uint8Array([1, 2, 3]),
    lastChangeNodeCID: 'SNAP',
    compactedCount: 4,
    timestamp: 5,
    signature: new Uint8Array([7]),
    ...overrides,
  }) as Parameters<typeof loadResponseManifestHash>[0]['snapshot'];

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
      'a deferred child in place of a leaf',
      {
        changeId: 'ROOT',
        changes: node({
          children: { A: node({ children: false }), B: node() },
        }),
      },
    ],
  ])('binds %s', async (_name, changed) => {
    const baseline = {
      changeId: 'ROOT',
      changes: node({
        children: { A: node(), B: node() },
      }),
    };
    await expect(hash(changed)).resolves.not.toEqual(await hash(baseline));
  });

  test('encodes node descriptors as kind and child edges', async () => {
    const u32 = (value: number): number[] => [
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    ];
    const encodeString = (value: string): number[] => {
      const bytes = [...textEncoder.encode(value)];
      return [...u32(bytes.length), ...bytes];
    };
    const expected = new Uint8Array([
      ...textEncoder.encode('peerborne/load-response-manifest/v2\0'),
      2,
      ...encodeString('ROOT'),
      ...u32(2),
      ...u32(1),
      ...encodeString('A'),
      2,
      0,
      ...u32(0),
      ...encodeString('ROOT'),
      0,
      2,
      ...u32(1),
      ...encodeString('A'),
      0,
      0,
    ]);
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', expected),
    );

    await expect(
      hash({
        changeId: 'ROOT',
        changes: node({
          change: { value: 1 },
          children: { A: node({ kind: 'writer' }) },
        }),
      }),
    ).resolves.toEqual(digest);
  });

  test('agrees across inline and stripped copies of one change tree', async () => {
    const authored = () =>
      node({
        change: { value: 'head' },
        children: {
          PARENT: node({
            change: { value: 'parent' },
            children: { WRITER: node({ kind: 'writer', change: { acl: 1 } }) },
          }),
          CROSS: node(),
        },
      });
    const replica = stripInlineChanges(authored())!;
    expect(replica.change).toBeUndefined();

    await expect(hash({ changeId: 'ROOT', changes: replica })).resolves.toEqual(
      await hash({ changeId: 'ROOT', changes: authored() }),
    );
  });

  test('does not bind inline payloads, which quorum-bound loads discard', async () => {
    const digests = await Promise.all(
      [{ value: 1 }, { value: 2 }, undefined].map((change) =>
        hash({ changeId: 'ROOT', changes: node({ change }) }),
      ),
    );
    expect(digests[1]).toEqual(digests[0]);
    expect(digests[2]).toEqual(digests[0]);
  });

  test('never reads or serializes inline payloads', async () => {
    const change = new Proxy(
      {},
      {
        get() {
          throw new Error('inline payload must not be read');
        },
        ownKeys() {
          throw new Error('inline payload must not be enumerated');
        },
      },
    );
    await expect(
      hash({ changeId: 'ROOT', changes: node({ change }) }),
    ).resolves.toEqual(await hash({ changeId: 'ROOT', changes: node() }));
  });

  test('snapshots the complete tree before the first digest yields', async () => {
    const originalChild = node({ kind: 'reader' });
    const originalRoot = node({ children: { CHILD: originalChild } });
    const pending = hash({ changeId: 'ROOT', changes: originalRoot });
    originalChild.kind = 'writer';
    originalRoot.children = { ATTACKER: node() };

    await expect(pending).resolves.toEqual(
      await hash({
        changeId: 'ROOT',
        changes: node({ children: { CHILD: node({ kind: 'reader' }) } }),
      }),
    );
  });

  test('rejects change-tree accessors without invoking them', async () => {
    let getterCalls = 0;
    const changes = node();
    Object.defineProperty(changes, 'children', {
      enumerable: true,
      get() {
        getterCalls++;
        return { ATTACKER: node() };
      },
    });

    await expect(hash({ changeId: 'ROOT', changes })).rejects.toThrow(
      /data properties/,
    );
    expect(getterCalls).toBe(0);
  });

  test('binds snapshot presence, state bytes and boundary', async () => {
    const baselineHash = await hash({ snapshot: signedSnapshot() });
    await expect(hash({})).resolves.not.toEqual(baselineHash);
    for (const changed of [
      signedSnapshot({ stateBytes: new Uint8Array([1, 2, 4]) }),
      signedSnapshot({ stateBytes: new Uint8Array([1, 2, 3, 0]) }),
      signedSnapshot({ stateBytes: new Uint8Array(0) }),
      signedSnapshot({ lastChangeNodeCID: 'OTHER' }),
      signedSnapshot({ lastChangeNodeCID: '' }),
    ]) {
      await expect(hash({ snapshot: changed })).resolves.not.toEqual(
        baselineHash,
      );
    }
  });

  test('agrees across writers that signed their own snapshot of one state', async () => {
    const authored = await hash({ snapshot: signedSnapshot() });
    for (const resigned of [
      signedSnapshot({ signature: new Uint8Array([8, 9]) }),
      signedSnapshot({ timestamp: 6 }),
      signedSnapshot({ compactedCount: 3 }),
      {
        stateBytes: new Uint8Array([1, 2, 3]),
        lastChangeNodeCID: 'SNAP',
      },
    ]) {
      await expect(hash({ snapshot: resigned })).resolves.toEqual(authored);
    }
  });

  test('rejects a missing or non-byte snapshot state and boundary', async () => {
    await expect(
      hash({
        snapshot: { lastChangeNodeCID: 'SNAP' } as unknown as Parameters<
          typeof hash
        >[0]['snapshot'],
      }),
    ).rejects.toThrow(/stateBytes must be an enumerable own data property/);
    await expect(
      hash({
        snapshot: { stateBytes: new Uint8Array([1]) } as unknown as Parameters<
          typeof hash
        >[0]['snapshot'],
      }),
    ).rejects.toThrow(
      /lastChangeNodeCID must be an enumerable own data property/,
    );
    await expect(
      hash({
        snapshot: signedSnapshot({
          stateBytes: 'state' as unknown as Uint8Array,
        }),
      }),
    ).rejects.toThrow(/snapshot state .* not an unshared Uint8Array/);
    await expect(
      hash({ snapshot: signedSnapshot({ lastChangeNodeCID: 7 }) }),
    ).rejects.toThrow(/lastChangeNodeCID/);
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

  test('snapshots snapshot and keychain bytes before the first digest yields', async () => {
    const stateBytes = new Uint8Array([1, 2, 3]);
    const keychainChangesBytes = new Uint8Array([4, 5, 6]);
    const snapshot = { stateBytes, lastChangeNodeCID: 'SNAP' };
    const pending = hash({ snapshot, keychainChangesBytes });

    stateBytes.fill(9);
    snapshot.lastChangeNodeCID = 'OTHER';
    keychainChangesBytes.fill(9);

    await expect(pending).resolves.toEqual(
      await hash({
        snapshot: {
          stateBytes: new Uint8Array([1, 2, 3]),
          lastChangeNodeCID: 'SNAP',
        },
        keychainChangesBytes: new Uint8Array([4, 5, 6]),
      }),
    );
  });

  test('uses own descriptor snapshots without Proxy property reads', async () => {
    const stable = {
      snapshot: {
        stateBytes: new Uint8Array([1, 2, 3]),
        lastChangeNodeCID: 'SNAP',
        compactedCount: 1,
        timestamp: 2,
        signature: new Uint8Array([7]),
      },
      keychainChangesBytes: new Uint8Array([4, 5, 6]),
    };
    let inputReads = 0;
    let snapshotReads = 0;
    const snapshot = new Proxy(stable.snapshot, {
      get() {
        snapshotReads++;
        throw new Error('snapshot property read must not run');
      },
    });
    const input = new Proxy({ ...stable, snapshot }, {
      get() {
        inputReads++;
        throw new Error('input property read must not run');
      },
    });

    await expect(loadResponseManifestHash(input)).resolves.toEqual(
      await hash(stable),
    );
    expect(inputReads).toBe(0);
    expect(snapshotReads).toBe(0);
  });

  test('does not consult an inherited setter while capturing input fields', async () => {
    const input = {
      snapshot: {
        stateBytes: new Uint8Array([1, 2, 3]),
        lastChangeNodeCID: 'SNAP',
        compactedCount: 1,
        timestamp: 2,
        signature: new Uint8Array([7]),
      },
    };
    const descriptor = Object.getOwnPropertyDescriptor(
      Object.prototype,
      'snapshot',
    );
    let setterCalls = 0;
    let pending: Promise<Uint8Array> | undefined;
    try {
      Object.defineProperty(Object.prototype, 'snapshot', {
        configurable: true,
        set() {
          setterCalls++;
        },
      });
      pending = loadResponseManifestHash(input);
    } finally {
      if (descriptor === undefined) {
        delete (Object.prototype as Record<string, unknown>).snapshot;
      } else {
        Object.defineProperty(Object.prototype, 'snapshot', descriptor);
      }
    }

    expect(setterCalls).toBe(0);
    await expect(pending).resolves.toEqual(
      await loadResponseManifestHash(input),
    );
  });

  test('rejects accessors that could synthesize a mixed-time manifest', async () => {
    const stateBytes = new Uint8Array([1]);
    const keychainChangesBytes = new Uint8Array([4]);
    let getterCalls = 0;
    const snapshot = {
      stateBytes,
      compactedCount: 1,
      timestamp: 2,
      signature: new Uint8Array([7]),
    } as Record<string, unknown>;
    Object.defineProperty(snapshot, 'lastChangeNodeCID', {
      enumerable: true,
      get() {
        getterCalls++;
        stateBytes[0] = 9;
        return 'SNAP';
      },
    });
    const input = { snapshot } as Record<string, unknown>;
    Object.defineProperty(input, 'keychainChangesBytes', {
      enumerable: true,
      get() {
        getterCalls++;
        keychainChangesBytes[0] = 9;
        return keychainChangesBytes;
      },
    });

    await expect(
      loadResponseManifestHash(
        input as unknown as Parameters<typeof loadResponseManifestHash>[0],
      ),
    ).rejects.toThrow(/own data property/);
    expect(getterCalls).toBe(0);
    expect(stateBytes).toEqual(new Uint8Array([1]));
    expect(keychainChangesBytes).toEqual(new Uint8Array([4]));

    await expect(
      hash({
        snapshot:
          snapshot as unknown as Parameters<typeof hash>[0]['snapshot'],
      }),
    ).rejects.toThrow(/own data property/);
    expect(getterCalls).toBe(0);
  });

  test('accepts cross-realm payload bytes but rejects shared backing', async () => {
    const crossRealm = runInNewContext(
      'new Uint8Array([1, 2, 3])',
    ) as Uint8Array;
    expect(crossRealm instanceof Uint8Array).toBe(false);
    const crossRealmInput = runInNewContext(
      `({
        snapshot: {
          stateBytes: bytes,
          lastChangeNodeCID: 'SNAP',
          compactedCount: 1,
          timestamp: 2,
          signature: new Uint8Array([7]),
        },
        keychainChangesBytes: bytes,
      })`,
      { bytes: crossRealm },
    ) as Parameters<typeof loadResponseManifestHash>[0];
    await expect(
      loadResponseManifestHash(crossRealmInput),
    ).resolves.toHaveLength(32);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(new SharedArrayBuffer(3));
      await expect(hash({ keychainChangesBytes: shared })).rejects.toThrow(
        /unshared Uint8Array/,
      );
    }
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

  test.each(['inline-first', 'stripped-first'] as const)(
    'reconciles inline and stripped copies of one repeated CID in %s order',
    async (order) => {
      const inline = node({
        children: { SHARED: node({ change: { value: 'shared' } }) },
      });
      const stripped = node({ children: { SHARED: node() } });
      const children =
        order === 'inline-first'
          ? { A: inline, Z: stripped }
          : { A: stripped, Z: inline };
      const sharedLeaf = () => node({ children: { SHARED: node() } });

      await expect(
        hash({ changeId: 'ROOT', changes: node({ children }) }),
      ).resolves.toEqual(
        await hash({
          changeId: 'ROOT',
          changes: node({ children: { A: sharedLeaf(), Z: sharedLeaf() } }),
        }),
      );
    },
  );

  test.each(['deferred-first', 'explicit-first'] as const)(
    'rejects deferred and explicit children for one repeated CID in %s order',
    async (order) => {
      const deferred = node({
        children: { SHARED: node({ children: false }) },
      });
      const explicit = node({
        children: { SHARED: node({ children: { PARENT: node() } }) },
      });
      const children =
        order === 'deferred-first'
          ? { A: deferred, Z: explicit }
          : { A: explicit, Z: deferred };

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
    'rejects a sparse cross-link whose kind conflicts with the full description in %s order',
    async (order) => {
      const sparse = node({ kind: 'reader' });
      const full = node({
        kind: 'writer',
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

  test('bounds every serialized CID', async () => {
    const oversized = 'x'.repeat(MAX_LOAD_RESPONSE_MANIFEST_ID_BYTES + 1);
    await expect(
      hash({ changeId: oversized, changes: node() }),
    ).rejects.toThrow(/UTF-8 bytes/);
    await expect(
      hash({
        changeId: 'ROOT',
        changes: node({ children: { [oversized]: node() } }),
      }),
    ).rejects.toThrow(/UTF-8 bytes/);
  });

  test('bounds serialized snapshot and keychain payload bytes', async () => {
    const oversized = new Uint8Array(
      MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES + 1,
    );
    await expect(
      hash({ snapshot: signedSnapshot({ stateBytes: oversized }) }),
    ).rejects.toThrow(/snapshot state exceeds/);
    await expect(
      hash({ keychainChangesBytes: oversized }),
    ).rejects.toThrow(/keychain changes exceed/);
  });
});
