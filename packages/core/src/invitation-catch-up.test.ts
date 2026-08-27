import { describe, expect, jest, test } from '@jest/globals';

import {
  assertInvitationCidsInstalled,
  collectInvitationCidsToInstall,
  syncInvitationMessageCompletely,
  withIssuerPinnedInvitationStream,
} from './invitation-catch-up.js';
import { MAX_INVITATION_MESSAGE_BYTES } from './invitation-wire.js';
import { crdtDocumentChangeNode } from './crdt-change-node.js';
import { readUint8Iterable } from './utils.js';

describe('invitation catch-up', () => {
  test('requires every advertised bootstrap and catch-up CID', () => {
    const expected = ['root', 'inline-child', 'deferred-child'];

    expect(() =>
      assertInvitationCidsInstalled(
        expected,
        new Set(expected),
        'bootstrap',
      ),
    ).not.toThrow();
    expect(() =>
      assertInvitationCidsInstalled(
        expected,
        new Set(['root', 'inline-child']),
        'catch-up',
      ),
    ).toThrow(/1 of 3 advertised CIDs were not installed/);
  });

  test.each(['bootstrap', 'catch-up'] as const)(
    'rejects an incomplete %s after sync returns success',
    async (phase) => {
      const installed = new Set<string>();
      const message = {
        documentId: '/invitation-completeness',
        changeId: 'root-cid',
        changes: {
          kind: crdtDocumentChangeNode,
          children: {
            'deferred-child-cid': { kind: crdtDocumentChangeNode },
          },
        },
      };

      await expect(
        syncInvitationMessageCompletely(
          message,
          installed,
          async () => {
            installed.add('root-cid');
            return true;
          },
          phase,
        ),
      ).rejects.toThrow(/1 of 2 advertised CIDs were not installed/);
    },
  );

  test.each(['bootstrap', 'catch-up'] as const)(
    'rejects an inline %s tree without its root CID before sync',
    async (phase) => {
      const sync = jest.fn(async () => true);

      await expect(
        syncInvitationMessageCompletely(
          {
            documentId: '/missing-invitation-root',
            changes: {
              kind: crdtDocumentChangeNode,
              change: ['inline-root-change'],
            },
          },
          new Set(),
          sync,
          phase,
        ),
      ).rejects.toThrow(/missing its root CID/);
      expect(sync).not.toHaveBeenCalled();
    },
  );

  test('accepts CIDs retrieved by sync or installed by bootstrap', async () => {
    const message = {
      documentId: '/invitation-completeness',
      changeId: 'root-cid',
      changes: {
        kind: crdtDocumentChangeNode,
        children: {
          'deferred-child-cid': { kind: crdtDocumentChangeNode },
        },
      },
    };
    const retrieved = new Set<string>();
    await expect(
      syncInvitationMessageCompletely(
        message,
        retrieved,
        async () => {
          retrieved.add('root-cid');
          retrieved.add('deferred-child-cid');
          return true;
        },
        'catch-up',
      ),
    ).resolves.toBe(true);

    const alreadyInstalled = new Set(['root-cid', 'deferred-child-cid']);
    await expect(
      syncInvitationMessageCompletely(
        message,
        alreadyInstalled,
        async () => true,
        'catch-up',
      ),
    ).resolves.toBe(true);
  });

  test('preserves an ordinary sync rejection', async () => {
    await expect(
      syncInvitationMessageCompletely(
        {
          documentId: '/invitation-completeness',
          changeId: 'root-cid',
          changes: { kind: crdtDocumentChangeNode },
        },
        new Set(),
        async () => false,
        'bootstrap',
      ),
    ).resolves.toBe(false);
  });

  test('stops only below an applied snapshot boundary', () => {
    const tree = {
      kind: crdtDocumentChangeNode,
      children: {
        'snapshot-boundary': {
          kind: crdtDocumentChangeNode,
          children: {
            'covered-ancestor': { kind: crdtDocumentChangeNode },
          },
        },
        'installed-head': {
          kind: crdtDocumentChangeNode,
          children: {
            'installed-ancestor': { kind: crdtDocumentChangeNode },
          },
        },
        'post-snapshot-head': {
          kind: crdtDocumentChangeNode,
          children: {
            'missing-post-snapshot': { kind: crdtDocumentChangeNode },
          },
        },
      },
    };

    expect(
      collectInvitationCidsToInstall(
        'root-cid',
        tree,
        new Set(['snapshot-boundary']),
      ),
    ).toEqual([
      'root-cid',
      'snapshot-boundary',
      'installed-head',
      'installed-ancestor',
      'post-snapshot-head',
      'missing-post-snapshot',
    ]);
  });

  test('accepts an expanded tree covered by a snapshot boundary', async () => {
    const installed = new Set<string>();
    const message = {
      documentId: '/snapshot-invitation',
      changeId: 'snapshot-boundary',
      changes: {
        kind: crdtDocumentChangeNode,
        children: {
          'covered-ancestor': { kind: crdtDocumentChangeNode },
        },
      },
      snapshot: {
        lastChangeNodeCID: 'snapshot-boundary',
        state: {},
        compactedCount: 1,
        signature: new Uint8Array([1]),
        timestamp: 1,
      },
    };

    await expect(
      syncInvitationMessageCompletely(
        message,
        installed,
        async () => {
          installed.add('snapshot-boundary');
          return true;
        },
        'bootstrap',
        { isSnapshotApplied: () => true },
      ),
    ).resolves.toBe(true);
    expect(installed.has('covered-ancestor')).toBe(false);
  });

  test('does not trust an unapplied snapshot boundary in the hash set', async () => {
    const installed = new Set<string>();
    const message = {
      documentId: '/invalid-snapshot-invitation',
      changeId: 'snapshot-boundary',
      changes: {
        kind: crdtDocumentChangeNode,
        children: {
          'missing-covered-ancestor': { kind: crdtDocumentChangeNode },
        },
      },
      snapshot: {
        lastChangeNodeCID: 'snapshot-boundary',
        state: {},
        compactedCount: 1,
        signature: new Uint8Array([1]),
        timestamp: 1,
      },
    };

    await expect(
      syncInvitationMessageCompletely(
        message,
        installed,
        async () => {
          installed.add('snapshot-boundary');
          return true;
        },
        'bootstrap',
        { isSnapshotApplied: () => false },
      ),
    ).rejects.toThrow(/1 of 2 advertised CIDs were not installed/);
  });

  test('uses an explicitly proven pre-existing snapshot boundary', async () => {
    const installed = new Set(['snapshot-boundary']);
    const message = {
      documentId: '/equal-catch-up-snapshot',
      changeId: 'snapshot-boundary',
      changes: {
        kind: crdtDocumentChangeNode,
        children: {
          'covered-ancestor': { kind: crdtDocumentChangeNode },
        },
      },
      snapshot: {
        lastChangeNodeCID: 'snapshot-boundary',
        state: {},
        compactedCount: 1,
        signature: new Uint8Array([1]),
        timestamp: 1,
      },
    };

    await expect(
      syncInvitationMessageCompletely(
        message,
        installed,
        async () => true,
        'catch-up',
        {
          provenSnapshotBoundariesBeforeSync: new Set([
            'snapshot-boundary',
          ]),
          isSnapshotApplied: () => false,
        },
      ),
    ).resolves.toBe(true);
  });

  test('does not let a preinstalled partial root hide its missing child', async () => {
    const installed = new Set(['root-cid']);

    await expect(
      syncInvitationMessageCompletely(
        {
          documentId: '/partial-preinstalled-root',
          changeId: 'root-cid',
          changes: {
            kind: crdtDocumentChangeNode,
            children: {
              'missing-child-cid': { kind: crdtDocumentChangeNode },
            },
          },
        },
        installed,
        async () => true,
        'catch-up',
      ),
    ).rejects.toThrow(/1 of 2 advertised CIDs were not installed/);
  });

  test('loads directly from the signed founder endpoint without ordinary quorum', async () => {
    const founderAddress = '/ip4/127.0.0.1/tcp/4001';
    const issuerPublicKey = { id: 'founder' };
    const rawStream = {
      close: jest.fn(async () => {}),
      closeRead: jest.fn(async () => {}),
      abort: jest.fn((_error: Error) => {}),
      send: jest.fn(() => true),
      onDrain: jest.fn(async () => {}),
      async *[Symbol.asyncIterator]() {},
    };
    const dialProtocol = jest.fn(async () => rawStream);
    const ordinaryLoad = jest.fn(async () => {
      throw new Error('default quorum would reject the founder-only cohort');
    });
    const loadAndVerify = jest.fn(async (_stream: unknown) => {
      expect(issuerPublicKey).toEqual({ id: 'founder' });
      return true;
    });

    await expect(
      withIssuerPinnedInvitationStream(
        founderAddress,
        async (address, signal) => {
          expect(address).toBe(founderAddress);
          expect(signal.aborted).toBe(false);
          return dialProtocol();
        },
        loadAndVerify,
      ),
    ).resolves.toBe(true);
    expect(ordinaryLoad).not.toHaveBeenCalled();
    expect(dialProtocol).toHaveBeenCalledTimes(1);
    expect(loadAndVerify).toHaveBeenCalledWith(rawStream);
    expect(rawStream.close).toHaveBeenCalledTimes(1);
    expect(rawStream.closeRead).toHaveBeenCalledTimes(1);
    expect(rawStream.abort).not.toHaveBeenCalled();
  });

  test('aborts and closes a stalled founder stream at the deadline', async () => {
    const never = new Promise<boolean>(() => {});
    const rawStream = {
      close: jest.fn(async () => {}),
      abort: jest.fn((_error: Error) => {}),
    };
    let observedSignal: AbortSignal | undefined;

    await expect(
      withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async (_address, signal) => {
          observedSignal = signal;
          return rawStream;
        },
        async () => never,
        1,
      ),
    ).rejects.toThrow(/deadline exceeded/);

    expect(observedSignal?.aborted).toBe(true);
    expect(rawStream.abort).toHaveBeenCalledTimes(1);
    expect(rawStream.close).not.toHaveBeenCalled();
  });

  test('aborts an over-cap founder response and does not retain the stream', async () => {
    const rawStream = {
      close: jest.fn(async () => {}),
      abort: jest.fn((_error: Error) => {}),
      source: (async function* () {
        yield new Uint8Array(MAX_INVITATION_MESSAGE_BYTES);
        yield new Uint8Array(1);
      })(),
    };

    await expect(
      withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => rawStream,
        (stream) =>
          readUint8Iterable(
            stream.source,
            MAX_INVITATION_MESSAGE_BYTES,
          ),
      ),
    ).rejects.toThrow(/maximum allowed size/i);

    expect(rawStream.abort).toHaveBeenCalledTimes(1);
    expect(rawStream.close).not.toHaveBeenCalled();
  });

  test('aborts a stream that opens only after its deadline', async () => {
    let resolveOpen!: (stream: {
      close: () => Promise<void>;
      abort: (error: Error) => void;
    }) => void;
    const delayedOpen = new Promise<{
      close: () => Promise<void>;
      abort: (error: Error) => void;
    }>((resolve) => {
      resolveOpen = resolve;
    });
    const rawStream = {
      close: jest.fn(async () => {}),
      abort: jest.fn((_error: Error) => {}),
    };
    const operation = jest.fn(async () => true);

    await expect(
      withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => delayedOpen,
        operation,
        1,
      ),
    ).rejects.toThrow(/deadline exceeded/);

    resolveOpen(rawStream);
    await Promise.resolve();
    await Promise.resolve();

    expect(operation).not.toHaveBeenCalled();
    expect(rawStream.abort).toHaveBeenCalledTimes(1);
    expect(rawStream.close).not.toHaveBeenCalled();
  });
});
