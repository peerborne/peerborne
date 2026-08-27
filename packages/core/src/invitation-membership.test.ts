import { describe, expect, test } from '@jest/globals';
import {
  crdtChangeNodeDeferred,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import {
  assertAcceptedInvitationMembershipTopology,
  assertInitialInvitationMembershipTopology,
  changeTreeContainsMembershipChange,
  createInvitationMutationAdmission,
  InvitationMembershipQueue,
  prepareInitialInvitationMembership,
  type InitialInvitationMembershipState,
} from './invitation-membership.js';

function topology(
  overrides: Partial<InitialInvitationMembershipState> = {},
): InitialInvitationMembershipState {
  return {
    createdLocally: true,
    founder: 'founder',
    recipient: 'recipient',
    readers: [],
    writers: ['founder'],
    ...overrides,
  };
}

describe('invitation membership queue', () => {
  test('admits at the first mutation boundary and does not recheck mid-commit', () => {
    let available = false;
    const beginMutation = createInvitationMutationAdmission(() => {
      if (!available) throw new Error('invitation offer is unavailable');
    });

    expect(() => beginMutation()).toThrow(/offer is unavailable/);
    available = true;
    expect(() => beginMutation()).not.toThrow();
    available = false;
    expect(() => beginMutation()).not.toThrow();
  });

  test('serializes operations in FIFO order and survives a rejected operation', async () => {
    const queue = new InvitationMembershipQueue();
    const events: string[] = [];
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstStarted!: () => void;
    const firstStartedPromise = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });

    const first = queue.run(async () => {
      events.push('first:start');
      firstStarted();
      await firstGate;
      events.push('first:end');
    });
    const second = queue.run(async () => {
      events.push('second:start');
      events.push('second:end');
    });

    await firstStartedPromise;
    expect(events).toEqual(['first:start']);
    releaseFirst();
    await Promise.all([first, second]);
    expect(events).toEqual([
      'first:start',
      'first:end',
      'second:start',
      'second:end',
    ]);

    await expect(
      queue.run(async () => {
        throw new Error('expected failure');
      }),
    ).rejects.toThrow('expected failure');
    await expect(queue.run(async () => 'next')).resolves.toBe('next');
  });

  test('holds captured bootstrap state until the final bundle releases', async () => {
    const queue = new InvitationMembershipQueue();
    const events: string[] = [];
    let releaseBundle!: () => void;
    const bundleGate = new Promise<void>((resolve) => {
      releaseBundle = resolve;
    });
    let preflightFinished!: () => void;
    const preflightFinishedPromise = new Promise<void>((resolve) => {
      preflightFinished = resolve;
    });

    const bundle = queue.run(async () => {
      events.push('preflight');
      preflightFinished();
      await bundleGate;
      events.push('final-bundle');
    });
    const concurrentSync = queue.run(async () => {
      events.push('sync-state-write');
    });
    const concurrentKeyUpdate = queue.run(async () => {
      events.push('keychain-state-write');
    });
    const concurrentSnapshot = queue.run(async () => {
      events.push('snapshot-state-write');
    });

    await preflightFinishedPromise;
    await Promise.resolve();
    expect(events).toEqual(['preflight']);

    releaseBundle();
    await Promise.all([
      bundle,
      concurrentSync,
      concurrentKeyUpdate,
      concurrentSnapshot,
    ]);
    expect(events).toEqual([
      'preflight',
      'final-bundle',
      'sync-state-write',
      'keychain-state-write',
      'snapshot-state-write',
    ]);
  });

  test('allows a callback to enqueue work without awaiting its own slot', async () => {
    const queue = new InvitationMembershipQueue();
    const events: string[] = [];
    let callbackWork!: Promise<void>;

    await queue.run(async () => {
      events.push('owner');
      callbackWork = queue.run(async () => {
        events.push('callback-work');
      });
    });
    await callbackWork;

    expect(events).toEqual(['owner', 'callback-work']);
  });

  test('rechecks availability after waiting for an occupied mutation slot', async () => {
    const queue = new InvitationMembershipQueue();
    let releaseBlocker!: () => void;
    let blockerStarted!: () => void;
    const blocked = new Promise<void>((resolve) => {
      releaseBlocker = resolve;
    });
    const started = new Promise<void>((resolve) => {
      blockerStarted = resolve;
    });
    const first = queue.run(async () => {
      blockerStarted();
      await blocked;
    });
    await started;

    let available = true;
    let mutated = false;
    const invitation = queue.run(async () => {
      if (!available) throw new Error('invitation offer is unavailable');
      mutated = true;
    });
    available = false;
    releaseBlocker();

    await first;
    await expect(invitation).rejects.toThrow(/offer is unavailable/);
    expect(mutated).toBe(false);
  });
});

describe('initial invitation membership topology', () => {
  test.each([
    [
      'reader',
      { issuer: 'founder', recipient: 'recipient', readers: ['recipient'], writers: ['founder'] },
    ],
    [
      'editor',
      {
        issuer: 'founder',
        recipient: 'recipient',
        readers: ['recipient'],
        writers: ['founder', 'recipient'],
      },
    ],
  ] as const)('accepts the exact %s recipient topology', (role, state) => {
    expect(() =>
      assertAcceptedInvitationMembershipTopology(state, role),
    ).not.toThrow();
  });

  test.each([
    [
      'an unrelated reader',
      { issuer: 'founder', recipient: 'recipient', readers: ['recipient', 'stranger'], writers: ['founder'] },
      'reader',
    ],
    [
      'an unrelated writer',
      { issuer: 'founder', recipient: 'recipient', readers: ['recipient'], writers: ['founder', 'stranger'] },
      'editor',
    ],
    [
      'a duplicate reader',
      { issuer: 'founder', recipient: 'recipient', readers: ['recipient', 'recipient'], writers: ['founder'] },
      'reader',
    ],
    [
      'a missing issuer',
      { issuer: 'founder', recipient: 'recipient', readers: ['recipient'], writers: [] },
      'reader',
    ],
    [
      'editor access for a reader offer',
      { issuer: 'founder', recipient: 'recipient', readers: ['recipient'], writers: ['founder', 'recipient'] },
      'reader',
    ],
  ] as const)('rejects %s after bootstrap', (_name, state, role) => {
    expect(() =>
      assertAcceptedInvitationMembershipTopology(state, role),
    ).toThrow();
  });

  test.each([
    ['reader before mutation', 'reader', topology()],
    [
      'reader partial retry',
      'reader',
      topology({ readers: ['recipient'] }),
    ],
    [
      'editor reader-only partial retry',
      'editor',
      topology({ readers: ['recipient'] }),
    ],
    [
      'editor fully-mutated retry',
      'editor',
      topology({
        readers: ['recipient'],
        writers: ['founder', 'recipient'],
      }),
    ],
  ] as const)('allows %s', (_name, role, state) => {
    expect(() =>
      assertInitialInvitationMembershipTopology(state, role, 'preflight'),
    ).not.toThrow();
  });

  test.each([
    [
      'a non-founder process',
      topology({ createdLocally: false }),
      'editor',
      /founder process/,
    ],
    [
      'a removed founder',
      topology({ writers: [] }),
      'reader',
      /no longer an authorized writer/,
    ],
    [
      'an unrelated reader',
      topology({ readers: ['stranger'] }),
      'reader',
      /unrelated reader/,
    ],
    [
      'an unrelated writer',
      topology({ writers: ['founder', 'stranger'] }),
      'editor',
      /unrelated writer/,
    ],
    [
      'recipient writer access on a reader invitation',
      topology({ writers: ['founder', 'recipient'] }),
      'reader',
      /unrelated writer/,
    ],
  ] as const)('rejects %s', (_name, state, role, message) => {
    expect(() =>
      assertInitialInvitationMembershipTopology(state, role, 'preflight'),
    ).toThrow(message);
  });

  test('requires the exact completed role before attestation', () => {
    expect(() =>
      assertInitialInvitationMembershipTopology(
        topology({ readers: ['recipient'] }),
        'reader',
        'ready-to-attest',
      ),
    ).not.toThrow();
    expect(() =>
      assertInitialInvitationMembershipTopology(
        topology({ readers: ['recipient'] }),
        'editor',
        'ready-to-attest',
      ),
    ).toThrow(/requested role/);
  });
});

describe('invitation membership repair', () => {
  test('re-publishes both ACL snapshots after a partial failure and exact retry', async () => {
    const state = topology({
      readers: ['recipient'],
      writers: ['founder'],
    });
    let readerRepairs = 0;
    let writerRepairs = 0;
    let failWriterRepair = true;

    const prepare = () =>
      prepareInitialInvitationMembership({
        role: 'editor',
        getState: async () => state,
        addReader: async () => 'cached-welcome',
        addWriter: async () => {
          if (!state.writers.includes('recipient')) {
            (state.writers as string[]).push('recipient');
          }
        },
        repairReaders: async () => {
          readerRepairs++;
        },
        repairWriters: async () => {
          writerRepairs++;
          if (failWriterRepair) {
            failWriterRepair = false;
            throw new Error('publish failed');
          }
        },
      });

    await expect(prepare()).rejects.toThrow('publish failed');
    await expect(prepare()).resolves.toBe('cached-welcome');
    expect(readerRepairs).toBe(2);
    expect(writerRepairs).toBe(2);
    expect(state).toEqual(
      topology({
        readers: ['recipient'],
        writers: ['founder', 'recipient'],
      }),
    );
  });
});

describe('ACL-bearing sync detection', () => {
  test('finds nested inline and deferred membership nodes', () => {
    const nested: CRDTChangeNode<Uint8Array> = {
      kind: crdtDocumentChangeNode,
      change: new Uint8Array([1]),
      children: {
        parent: {
          kind: crdtReaderChangeNode,
          children: crdtChangeNodeDeferred,
        },
      },
    };
    expect(changeTreeContainsMembershipChange(nested)).toBe(true);
    expect(
      changeTreeContainsMembershipChange({
        kind: crdtWriterChangeNode,
        children: crdtChangeNodeDeferred,
      }),
    ).toBe(true);
    expect(
      changeTreeContainsMembershipChange({
        kind: crdtDocumentChangeNode,
        change: new Uint8Array([2]),
      }),
    ).toBe(false);
  });
});
