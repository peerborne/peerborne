import { describe, expect, test } from '@jest/globals';
import {
  MAX_CHANGE_TREE_DEPTH,
  MAX_CHANGE_TREE_EDGES,
  MAX_CHANGE_TREE_NODES,
} from './change-tree-walk.js';
import { snapshotSyncMessageForContext, syncMessageMatchesSnapshot } from './sync-message-context.js';

describe('sync message wire-context separation', () => {
  test.each([
    ['ordinary-sync-v1', { documentId: '/doc', changes: {}, signature: 'sig' }],
    [
      'document-publish-v1',
      { documentId: '/doc', changes: {}, signature: 'sig' },
    ],
    [
      'load-response-v3',
      {
        documentId: '/doc',
        changes: {},
        keychainChanges: {},
        tips: ['cid'],
        signature: 'sig',
      },
    ],
    [
      'tip-advertisement-v1',
      { documentId: '/doc', tipsHash: new Uint8Array(32), signature: 'sig' },
    ],
    [
      'load-response-v4',
      {
        documentId: '/doc',
        changes: {},
        keychainChanges: {},
        tips: ['cid'],
        loadSecurityState: { controlHead: 'head', groupEpoch: '1' },
        loadChallenge: new Uint8Array(32),
        signature: 'sig',
      },
    ],
    [
      'security-advertisement-v1',
      {
        documentId: '/doc',
        tipsHash: new Uint8Array(32),
        loadSecurityState: { controlHead: 'head', groupEpoch: '1' },
        loadChallenge: new Uint8Array(32),
        signature: 'sig',
      },
    ],
    [
      'invitation-bootstrap-v1',
      {
        documentId: '/doc',
        changes: {},
        keychainChanges: {},
        tips: ['cid'],
        signature: 'sig',
      },
    ],
    [
      'beekem-welcome-v1',
      {
        documentId: '/doc',
        welcomeEpochId: new Uint8Array(32),
        welcomeRecipient: 'reader',
        welcomeRecipientKemPublicKey: new Uint8Array(65),
        eciesSealed: new Uint8Array([1]),
        signature: 'sig',
      },
    ],
    [
      'beekem-path-update-v1',
      {
        documentId: '/doc',
        pathUpdate: {},
        pathUpdateEpochId: new Uint8Array(32),
        signature: 'sig',
      },
    ],
    [
      'key-update-v2',
      { documentId: '/doc', keychainChanges: {}, signature: 'sig' },
    ],
  ] as const)('accepts the %s allowlist', (context, message) => {
    expect(snapshotSyncMessageForContext(message, context)).toEqual(message);
  });

  test.each([
    ['ordinary-sync-v1', { keychainChanges: {} }],
    ['ordinary-sync-v1', { welcomeEpochId: new Uint8Array(32) }],
    ['ordinary-sync-v1', { pathUpdate: {} }],
    ['ordinary-sync-v1', { tipsHash: new Uint8Array(32) }],
    ['document-publish-v1', { snapshot: {} }],
    ['document-publish-v1', { keychainChanges: {} }],
    ['load-response-v3', { tipsHash: new Uint8Array(32) }],
    ['load-response-v3', { loadSecurityState: {} }],
    ['load-response-v4', { welcomeEpochId: new Uint8Array(32) }],
    ['tip-advertisement-v1', { tips: ['cid'] }],
    ['tip-advertisement-v1', { loadSecurityState: {} }],
    ['security-advertisement-v1', { changes: {} }],
    ['invitation-bootstrap-v1', { eciesSealed: new Uint8Array([1]) }],
    ['beekem-welcome-v1', { keychainChanges: {} }],
    ['beekem-path-update-v1', { keychainChanges: {} }],
    ['key-update-v2', { welcomeEpochId: new Uint8Array(32) }],
  ] as const)(
    'rejects a cross-context field in %s',
    (context, extra) => {
      expect(() =>
        snapshotSyncMessageForContext(
          { documentId: '/doc', ...extra },
          context,
        ),
      ).toThrow(/unexpected field|non-canonical fields/);
    },
  );

  test('rejects unknown undefined and symbol fields from custom serializers', () => {
    expect(() =>
      snapshotSyncMessageForContext(
        { documentId: '/doc', extension: undefined },
        'ordinary-sync-v1',
      ),
    ).toThrow(/unexpected field/);

    const symbolMessage = { documentId: '/doc' } as Record<
      PropertyKey,
      unknown
    >;
    symbolMessage[Symbol('extension')] = true;
    expect(() =>
      snapshotSyncMessageForContext(symbolMessage, 'ordinary-sync-v1'),
    ).toThrow(/symbol/);
  });

  test('does not trust a later replacement of Reflect.ownKeys', () => {
    const original = Reflect.ownKeys;
    Reflect.ownKeys = (() => ['documentId']) as typeof Reflect.ownKeys;
    try {
      expect(() =>
        snapshotSyncMessageForContext(
          { documentId: '/doc', keychainChanges: {} },
          'ordinary-sync-v1',
        ),
      ).toThrow(/unexpected field/);
    } finally {
      Reflect.ownKeys = original;
    }
  });

  test('rejects accessor-backed messages without invoking accessors', () => {
    let reads = 0;
    const message = { documentId: '/doc' };
    Object.defineProperty(message, 'changes', {
      enumerable: true,
      get() {
        reads += 1;
        return {};
      },
    });

    expect(() =>
      snapshotSyncMessageForContext(message, 'ordinary-sync-v1'),
    ).toThrow(/data properties/);
    expect(reads).toBe(0);
  });

  test('deeply detaches nested objects and byte arrays', () => {
    const changes = {
      nested: { value: 1 },
      bytes: new Uint8Array([2, 3]),
    };
    const snapshot = snapshotSyncMessageForContext(
      { documentId: '/doc', changes },
      'ordinary-sync-v1',
    );

    changes.nested.value = 9;
    changes.bytes.fill(9);

    expect(snapshot.changes).toEqual({
      nested: { value: 1 },
      bytes: new Uint8Array([2, 3]),
    });
  });

  test('rejects nested accessors without invoking them', () => {
    let reads = 0;
    const changes = {};
    Object.defineProperty(changes, 'payload', {
      enumerable: true,
      get() {
        reads += 1;
        return new Uint8Array([1]);
      },
    });

    expect(() =>
      snapshotSyncMessageForContext(
        { documentId: '/doc', changes },
        'ordinary-sync-v1',
      ),
    ).toThrow(/data properties/);
    expect(reads).toBe(0);
  });

  test('detaches the maximum accepted shallow change tree', () => {
    const children: Record<string, { kind: 'document' }> = {};
    for (let index = 1; index < MAX_CHANGE_TREE_NODES; index++) {
      children[`cid-${index}`] = { kind: 'document' };
    }

    const snapshot = snapshotSyncMessageForContext(
      {
        documentId: '/doc',
        changes: { kind: 'document' as const, children },
      },
      'ordinary-sync-v1',
    );

    expect(Object.keys(snapshot.changes!.children!)).toHaveLength(
      MAX_CHANGE_TREE_NODES - 1,
    );
  });

  test('does not impose the generic snapshotter array-length limit', () => {
    const changes = Array.from(
      { length: 65_537 },
      () => new Uint8Array([1]),
    );

    const snapshot = snapshotSyncMessageForContext(
      {
        documentId: '/doc',
        snapshot: {
          state: changes,
          lastChangeNodeCID: 'cid',
          compactedCount: 1,
          signature: new Uint8Array([1]),
          timestamp: 1,
        },
      },
      'ordinary-sync-v1',
    );

    expect(snapshot.snapshot!.state).toHaveLength(changes.length);
    expect(snapshot.snapshot!.state).not.toBe(changes);
  });

  test('rejects arrays above the sync-message structural budget', () => {
    const values = new Array(MAX_CHANGE_TREE_EDGES + 1).fill(0);

    expect(() =>
      snapshotSyncMessageForContext(
        {
          documentId: '/doc',
          snapshot: { state: values },
        },
        'ordinary-sync-v1',
      ),
    ).toThrow(/invalid array/);
  });

  test('rejects alias expansion above the sync-message object budget', () => {
    const aliased = { nested: {} };
    const values = new Array(MAX_CHANGE_TREE_EDGES).fill(aliased);

    expect(() =>
      snapshotSyncMessageForContext(
        {
          documentId: '/doc',
          snapshot: { state: values },
        },
        'ordinary-sync-v1',
      ),
    ).toThrow(/detached objects/);
  });

  test('rejects nesting above the sync-message depth budget', () => {
    const state: Record<string, unknown> = {};
    let cursor = state;
    for (let depth = 0; depth < 2 * MAX_CHANGE_TREE_DEPTH + 17; depth++) {
      const child: Record<string, unknown> = {};
      cursor.child = child;
      cursor = child;
    }

    expect(() =>
      snapshotSyncMessageForContext(
        {
          documentId: '/doc',
          snapshot: { state },
        },
        'ordinary-sync-v1',
      ),
    ).toThrow(/maximum depth/);
  });
});

test('snapshot comparison rejects different array lengths even without enumerable entries', () => {
  expect(syncMessageMatchesSnapshot(
    { documentId: '/doc', changes: new Array(2) } as any,
    { documentId: '/doc', changes: [] },
    'ordinary-sync-v1',
  )).toBe(false);
});
