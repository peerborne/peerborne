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
    expect(loadAndVerify).toHaveBeenCalledWith(
      rawStream,
      expect.any(AbortSignal),
      expect.any(Function),
    );
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

  test('preserves the operation error when stream abort cleanup throws', async () => {
    const terminalError = new Error('terminal authenticated-load failure');
    const rawStream = {
      close: jest.fn(async () => {}),
      abort: jest.fn(() => {
        throw new Error('transport cleanup failure');
      }),
    };

    await expect(
      withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => rawStream,
        async () => {
          throw terminalError;
        },
      ),
    ).rejects.toBe(terminalError);
    expect(rawStream.abort).toHaveBeenCalledTimes(1);
  });

  test('bounds successful stream cleanup and falls back to reset', async () => {
    jest.useFakeTimers();
    const rawStream = {
      close: jest.fn(async () => new Promise<void>(() => {})),
      closeRead: jest.fn(async () => new Promise<void>(() => {})),
      abort: jest.fn((_error: Error) => {}),
    };

    try {
      const loading = withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => rawStream,
        async () => true,
        10,
      );
      await jest.advanceTimersByTimeAsync(11);

      await expect(loading).resolves.toBe(true);
      expect(rawStream.close).toHaveBeenCalledTimes(1);
      expect(rawStream.closeRead).toHaveBeenCalledTimes(1);
      expect(rawStream.abort).toHaveBeenCalledTimes(1);
      expect(rawStream.abort.mock.calls[0][0].message).toBe(
        'Invitation stream cleanup timed out',
      );
    } finally {
      jest.useRealTimers();
    }
  });

  test('resets a successful stream when graceful cleanup rejects', async () => {
    const rawStream = {
      close: jest.fn(async () => {
        throw new Error('close failed');
      }),
      closeRead: jest.fn(async () => new Promise<void>(() => {})),
      abort: jest.fn((_error: Error) => {}),
    };

    await expect(
      withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => rawStream,
        async () => true,
      ),
    ).resolves.toBe(true);
    expect(rawStream.close).toHaveBeenCalledTimes(1);
    expect(rawStream.closeRead).toHaveBeenCalledTimes(1);
    expect(rawStream.abort).toHaveBeenCalledTimes(1);
    const cleanupError = rawStream.abort.mock.calls[0][0];
    expect(cleanupError.message).toBe('Invitation stream cleanup failed');
    expect((cleanupError.cause as Error).message).toBe('close failed');
  });

  test('forwards deadline cancellation through late response verification', async () => {
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    let mutated = false;
    let operationSettled!: () => void;
    const settled = new Promise<void>((resolve) => {
      operationSettled = resolve;
    });
    const rawStream = {
      close: jest.fn(async () => {}),
      abort: jest.fn((_error: Error) => {}),
    };

    await expect(
      withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => rawStream,
        async (_stream, signal) => {
          await released;
          try {
            if (signal.aborted) throw signal.reason;
            mutated = true;
            return true;
          } finally {
            operationSettled();
          }
        },
        1,
      ),
    ).rejects.toThrow(/deadline exceeded/);

    release();
    await settled;
    expect(mutated).toBe(false);
    expect(rawStream.abort).toHaveBeenCalledTimes(1);
  });

  test('awaits an admitted state mutation after disarming the stream deadline', async () => {
    jest.useFakeTimers();
    let mutationEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      mutationEntered = resolve;
    });
    let releaseMutation!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseMutation = resolve;
    });
    const rawStream = {
      close: jest.fn(async () => {}),
      abort: jest.fn((_error: Error) => {}),
    };
    let observedSignal: AbortSignal | undefined;

    try {
      const loading = withIssuerPinnedInvitationStream(
        '/ip4/127.0.0.1/tcp/4001',
        async () => rawStream,
        async (_stream, signal, admitStateMutation) => {
          observedSignal = signal;
          admitStateMutation();
          mutationEntered();
          await released;
          return true;
        },
        1,
      );
      await entered;
      await jest.advanceTimersByTimeAsync(2);

      expect(observedSignal?.aborted).toBe(false);
      expect(rawStream.abort).not.toHaveBeenCalled();
      expect(rawStream.close).not.toHaveBeenCalled();
      releaseMutation();
      await expect(loading).resolves.toBe(true);
      expect(rawStream.close).toHaveBeenCalledTimes(1);
    } finally {
      releaseMutation();
      jest.useRealTimers();
    }
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
