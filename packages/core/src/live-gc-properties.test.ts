import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { PeerborneDocument } from './peerborne-document.js';
import { InvitationMembershipQueue } from './invitation-membership.js';
import { crdtDocumentChangeNode } from './crdt-change-node.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock(
  'multiformats',
  () => ({
    CID: { parse: (value: string) => ({ toString: () => value }) },
  }),
  { virtual: true },
);
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({
    TopicValidatorResult: { Accept: 'accept', Reject: 'reject' },
  }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function fixture(protectedIds: Set<string>, retained: string[] = []) {
  const deleted: string[] = [],
    unpinned: string[] = [];
  const document = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/gc',
    _mutationQueue: new InvitationMembershipQueue(),
    _gcLifecycle: {},
    _gcClosed: false,
    _gcCandidates: new Set<string>(),
    _recentTips: [],
    _latestSnapshot: { lastChangeNodeCID: 'snapshot-boundary' },
    _lastSyncMessage: {
      changeId: 'root',
      changes: {
        kind: crdtDocumentChangeNode,
        children: Object.fromEntries(
          retained.map((id) => [id, { kind: crdtDocumentChangeNode }]),
        ),
      },
    },
    swarm: {
      unregisterDocument: jest.fn(),
      heliaNode: {
        blockstore: {
          delete: async (cid: { toString(): string }) => {
            deleted.push(cid.toString());
          },
        },
        pins: {
          isPinned: async (cid: { toString(): string }) =>
            protectedIds.has(cid.toString()),
          rm: async function* (cid: { toString(): string }) {
            unpinned.push(cid.toString());
          },
        },
      },
    },
  });
  return { document, deleted, unpinned };
}

test('garbage collection preserves existing pins without unpinning them', async () => {
  const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  try {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.boolean(), { minLength: 1, maxLength: 12 }),
        async (flags) => {
          const ids = flags.map((_, index) => `block-${index}`);
          const pins = new Set(ids.filter((_, index) => flags[index]));
          const { document, deleted, unpinned } = fixture(pins);
          await document._gcPrunedBlocks(new Set(ids));
          expect(unpinned).toEqual([]);
          expect(deleted).toEqual(ids.filter((id) => !pins.has(id)));
        },
      ),
      { seed: 2012201, numRuns: 30, examples: [[[true]]] },
    );
  } finally {
    log.mockRestore();
  }
});

test('overlapping GC requests coalesce without losing newly queued candidates', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.array(fc.integer({ min: 0, max: 24 }), { maxLength: 10 }), {
        minLength: 1,
        maxLength: 8,
      }),
      async (batches) => {
        const { document, deleted } = fixture(new Set());
        const entered = deferred(),
          release = deferred();
        document.swarm.heliaNode.pins.isPinned = async (cid: {
          toString(): string;
        }) => {
          if (cid.toString() === 'first') {
            entered.resolve();
            await release.promise;
          }
          return false;
        };
        const first = document._gcPrunedBlocks(new Set(['first']));
        await entered.promise;
        const others = batches.map((batch) =>
          document._gcPrunedBlocks(
            new Set(batch.map((value) => `block-${value}`)),
          ),
        );
        release.resolve();
        await Promise.all([first, ...others]);
        expect(new Set(deleted)).toEqual(
          new Set([
            'first',
            ...batches.flat().map((value) => `block-${value}`),
          ]),
        );
        expect(deleted.length).toBe(new Set(deleted).size);
        expect(document._gcCandidates.size).toBe(0);
        expect(document._gcInProgress).toBeUndefined();
      },
    ),
    { seed: 2012204, numRuns: 30 },
  );
});

test('deletion keeps its queue slot until I/O settles and reports provider failures without inspecting them', async () => {
  const diagnostic = jest
    .spyOn(console, 'error')
    .mockImplementation(() => undefined);
  try {
    await fc.assert(
      fc.asyncProperty(fc.boolean(), async (fail) => {
        diagnostic.mockClear();
        const { document, deleted } = fixture(new Set());
        const entered = deferred(),
          release = deferred();
        let inspected = 0,
          mutated = false;
        const failure = new Proxy(
          {},
          {
            get() {
              inspected++;
              throw new Error('foreign error inspected');
            },
          },
        );
        document.swarm.heliaNode.blockstore.delete = async (cid: {
          toString(): string;
        }) => {
          deleted.push(cid.toString());
          entered.resolve();
          await release.promise;
          if (fail) throw failure;
        };
        const collecting = document._gcPrunedBlocks(
          new Set(['first', 'retained']),
        );
        await entered.promise;
        const mutation = document._mutationQueue.run(async () => {
          mutated = true;
          document._lastSyncMessage = {
            changeId: 'new-root',
            changes: {
              kind: crdtDocumentChangeNode,
              children: { retained: { kind: crdtDocumentChangeNode } },
            },
          };
        });
        await Promise.resolve();
        expect(mutated).toBe(false);
        release.resolve();
        await Promise.all([collecting, mutation]);
        expect(mutated).toBe(true);
        expect(deleted).toEqual(['first']);
        expect(inspected).toBe(0);
        expect(diagnostic.mock.calls).toEqual(
          fail ? [['Document block garbage collection failed']] : [],
        );
      }),
      { seed: 2012205, numRuns: 16 },
    );
  } finally {
    diagnostic.mockRestore();
  }
});

test('close invalidates pending pin checks and waits for started deletions before unregistering', async () => {
  await fc.assert(
    fc.asyncProperty(fc.boolean(), async (deletionStarted) => {
      const { document, deleted } = fixture(new Set());
      const entered = deferred(),
        release = deferred();
      if (deletionStarted)
        document.swarm.heliaNode.blockstore.delete = async (cid: {
          toString(): string;
        }) => {
          deleted.push(cid.toString());
          entered.resolve();
          await release.promise;
        };
      else
        document.swarm.heliaNode.pins.isPinned = async () => {
          entered.resolve();
          await release.promise;
          return false;
        };
      const collecting = document._gcPrunedBlocks(new Set(['first', 'later']));
      await entered.promise;
      const closing = document.close();
      await Promise.resolve();
      expect(document.swarm.unregisterDocument).not.toHaveBeenCalled();
      release.resolve();
      await Promise.all([collecting, closing]);
      expect(deleted).toEqual(deletionStarted ? ['first'] : []);
      expect(document.swarm.unregisterDocument).toHaveBeenCalledTimes(1);
    }),
    { seed: 2012206, numRuns: 12 },
  );
});

test('closing permanently refuses new maintenance and queued GC admission', async () => {
  await fc.assert(
    fc.asyncProperty(fc.boolean(), async (duringClose) => {
      const { document, deleted } = fixture(new Set());
      document._compactionConfig = { gcAfterPrune: true };
      const entered = deferred(),
        release = deferred();
      let collecting: Promise<void> | undefined;
      if (duringClose) {
        document.swarm.heliaNode.pins.isPinned = async () => {
          entered.resolve();
          await release.promise;
          return false;
        };
        collecting = document._gcPrunedBlocks(new Set(['before-close']));
        await entered.promise;
      }
      const closing = document.close();
      if (!duringClose) await closing;
      const maintenance = expect(document.collectGarbage()).rejects.toThrow(
        /closed/,
      );
      const queued = document._gcPrunedBlocks(new Set(['after-close']));
      release.resolve();
      await Promise.all([closing, collecting, maintenance, queued]);
      await document._gcPrunedBlocks(new Set(['after-unregister']));
      expect(deleted).toEqual([]);
      expect(document._gcCandidates.has('after-close')).toBe(false);
      expect(document._gcCandidates.has('after-unregister')).toBe(false);
    }),
    { seed: 2012214, numRuns: 12, examples: [[true], [false]] },
  );
});

test('protected candidate hints survive until tree, boundary, tip or pin protection expires', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom('tree', 'boundary', 'tip', 'pin'),
      async (mode) => {
        const pins = new Set(mode === 'pin' ? ['candidate'] : []);
        const { document, deleted } = fixture(
          pins,
          mode === 'tree' ? ['candidate'] : [],
        );
        document._compactionConfig = { gcAfterPrune: true };
        if (mode === 'boundary')
          document._latestSnapshot.lastChangeNodeCID = 'candidate';
        if (mode === 'tip')
          document._recentTips = [
            { cid: 'candidate', kind: crdtDocumentChangeNode },
          ];
        await document._gcPrunedBlocks(new Set(['candidate']));
        expect(deleted).toEqual([]);
        expect(document._gcCandidates).toEqual(new Set(['candidate']));
        await document._mutationQueue.run(async () => {
          document._lastSyncMessage = {
            changeId: 'next-root',
            changes: { kind: crdtDocumentChangeNode },
          };
          document._latestSnapshot = { lastChangeNodeCID: 'next-boundary' };
          document._recentTips = [];
          pins.clear();
        });
        await expect(document.collectGarbage()).resolves.toEqual({
          pending: 0,
        });
        expect(deleted).toEqual(['candidate']);
      },
    ),
    {
      seed: 2012215,
      numRuns: 16,
      examples: [['tree'], ['boundary'], ['tip'], ['pin']],
    },
  );
});

test('candidate admission rejects excessive counts and lengths atomically', async () => {
  const full = new Set(
    Array.from({ length: 32768 }, (_, index) => `existing-${index}`),
  );
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 0, max: 3 }), async (kind) => {
      const { document, deleted } = fixture(new Set());
      const before = kind === 0 ? new Set(full) : new Set(['existing']);
      document._gcCandidates = before;
      const candidates =
        kind === 0
          ? ['existing-0', 'new']
          : kind === 1
            ? ['valid', '']
            : kind === 2
              ? ['valid', 'x'.repeat(513)]
              : ['valid', 5];
      await expect(
        document._gcPrunedBlocks(new Set(candidates)),
      ).rejects.toThrow(/candidate limit/);
      expect(document._gcCandidates).toBe(before);
      expect(document._gcCandidates).toEqual(
        kind === 0 ? full : new Set(['existing']),
      );
      expect(deleted).toEqual([]);
    }),
    { seed: 2012207, numRuns: 8, examples: [[0], [1], [2], [3]] },
  );
});

test('explicit maintenance requires opt-in and drains retained pending work', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.boolean(),
      fc.integer({ min: 0, max: 8 }),
      async (enabled, count) => {
        const { document, deleted } = fixture(new Set());
        document._compactionConfig = { gcAfterPrune: enabled };
        const pending = Array.from(
          { length: count },
          (_, index) => `pending-${index}`,
        );
        document._gcCandidates = new Set(pending);
        if (!enabled) {
          await expect(document.collectGarbage()).rejects.toThrow(
            /not enabled/,
          );
          expect(deleted).toEqual([]);
          expect(document._gcCandidates).toEqual(new Set(pending));
        } else {
          await expect(document.collectGarbage()).resolves.toEqual({
            pending: 0,
          });
          expect(deleted).toEqual(pending);
        }
      },
    ),
    { seed: 2012208, numRuns: 20 },
  );
});

test('checks the native offline Helia adapter with actual CIDs and pins', async () => {
  await promisify(execFile)(
    process.execPath,
    ['--import', 'tsx', '--test', `${__dirname}/live-gc-native.fixture.mjs`],
    { timeout: 60_000 },
  );
}, 70_000);

test('candidate admission histories own their inputs and match an independent union model', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(
        fc.array(
          fc.oneof(
            fc.integer({ min: 0, max: 60 }).map((value) => `block-${value}`),
            fc.constantFrom('', 'x'.repeat(513)),
          ),
          { maxLength: 12 },
        ),
        { maxLength: 50 },
      ),
      async (batches) => {
        const { document, deleted } = fixture(new Set());
        document._gcInProgress = Promise.resolve();
        let expected: string[] = [];
        for (const batch of batches) {
          const caller = new Set(batch),
            before = document._gcCandidates;
          const permitted = batch.every(
            (id) => id.length >= 1 && id.length <= 512,
          );
          const result = document._gcPrunedBlocks(caller);
          caller.clear();
          if (permitted) {
            await result;
            expected = [...new Set([...expected, ...batch])];
          } else {
            await expect(result).rejects.toThrow(/candidate limit/);
            expect(document._gcCandidates).toBe(before);
          }
          expect(document._gcCandidates).toEqual(new Set(expected));
          expect(document._gcCandidates.size).toBeLessThanOrEqual(32768);
        }
        expect(deleted).toEqual([]);
      },
    ),
    { seed: 2012210, numRuns: 100 },
  );
});

test('nonboolean pin results fail closed and leave candidates available for a later retry', async () => {
  const diagnostic = jest
    .spyOn(console, 'error')
    .mockImplementation(() => undefined);
  try {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(undefined, null, 0, 1, 'false', [], {}),
        async (value) => {
          const { document, deleted } = fixture(new Set());
          document.swarm.heliaNode.pins.isPinned = async () => value;
          await document._gcPrunedBlocks(new Set(['candidate']));
          expect(deleted).toEqual([]);
          expect(document._gcCandidates).toEqual(new Set(['candidate']));
          document.swarm.heliaNode.pins.isPinned = async () => false;
          await document._gcPrunedBlocks(new Set());
          expect(deleted).toEqual(['candidate']);
          expect(document._gcCandidates.size).toBe(0);
        },
      ),
      { seed: 2012211, numRuns: 14 },
    );
  } finally {
    diagnostic.mockRestore();
  }
});

test('pin-query reentrancy cannot use a lease after its native identity guards change', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom('snapshot', 'boundary', 'tips', 'health', 'lifecycle'),
      async (mode) => {
        const { document, deleted } = fixture(new Set());
        document.swarm.heliaNode.pins.isPinned = async () => {
          if (mode === 'snapshot')
            document._latestSnapshot = { lastChangeNodeCID: 'candidate' };
          if (mode === 'boundary')
            document._latestSnapshot.lastChangeNodeCID = 'candidate';
          if (mode === 'tips')
            document._recentTips.push({
              cid: 'candidate',
              kind: crdtDocumentChangeNode,
            });
          if (mode === 'health')
            document._bootstrapLoadApplicationState = 'pending';
          if (mode === 'lifecycle') document._gcLifecycle = {};
          return false;
        };
        await document._gcPrunedBlocks(new Set(['candidate']));
        expect(deleted).toEqual([]);
      },
    ),
    { seed: 2012212, numRuns: 25 },
  );
});

test('a drain defers work arriving in its second pass and explicit maintenance completes it', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 1, max: 8 }), async (count) => {
      const { document, deleted } = fixture(new Set());
      document._compactionConfig = { gcAfterPrune: true };
      const firstEntered = deferred(),
        firstRelease = deferred();
      const secondEntered = deferred(),
        secondRelease = deferred();
      document.swarm.heliaNode.pins.isPinned = async (cid: {
        toString(): string;
      }) => {
        if (cid.toString() === 'first') {
          firstEntered.resolve();
          await firstRelease.promise;
        }
        if (cid.toString() === 'second') {
          secondEntered.resolve();
          await secondRelease.promise;
        }
        return false;
      };
      const first = document._gcPrunedBlocks(new Set(['first']));
      await firstEntered.promise;
      const second = document._gcPrunedBlocks(new Set(['second']));
      firstRelease.resolve();
      await secondEntered.promise;
      const remaining = Array.from(
        { length: count },
        (_, index) => `deferred-${index}`,
      );
      const third = document._gcPrunedBlocks(new Set(remaining));
      secondRelease.resolve();
      await Promise.all([first, second, third]);
      expect(deleted).toEqual(['first', 'second']);
      expect(document._gcCandidates).toEqual(new Set(remaining));
      await expect(document.collectGarbage()).resolves.toEqual({ pending: 0 });
      expect(deleted).toEqual(['first', 'second', ...remaining]);
    }),
    { seed: 2012213, numRuns: 12 },
  );
});

test('garbage collection rechecks current tree and snapshot protection before deletion', async () => {
  const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  try {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 16 }), async (count) => {
        const ids = Array.from(
          { length: count },
          (_, index) => `block-${index}`,
        );
        const retained = ids.filter((_, index) => index % 2 === 0);
        const { document, deleted } = fixture(new Set(), retained);
        await document._gcPrunedBlocks(
          new Set([...ids, 'root', 'snapshot-boundary']),
        );
        expect(deleted).toEqual(ids.filter((id) => !retained.includes(id)));
      }),
      { seed: 2012202, numRuns: 20 },
    );
  } finally {
    log.mockRestore();
  }
});

test('a mutation between deletion slots invalidates the remaining stale plan', async () => {
  const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  try {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 8 }), async (count) => {
        const ids = Array.from(
          { length: count },
          (_, index) => `retained-${index}`,
        );
        const { document, deleted } = fixture(new Set());
        const entered = deferred(),
          release = deferred();
        const pause = async (cid: { toString(): string }) => {
          if (cid.toString() === 'first') {
            entered.resolve();
            await release.promise;
          }
        };
        document.swarm.heliaNode.pins.isPinned = async (cid: {
          toString(): string;
        }) => {
          await pause(cid);
          return false;
        };
        document.swarm.heliaNode.pins.rm = async function* (cid: {
          toString(): string;
        }) {
          await pause(cid);
        };
        const collecting = document._gcPrunedBlocks(new Set(['first', ...ids]));
        await entered.promise;
        const mutation = document._mutationQueue.run(async () => {
          document._lastSyncMessage = {
            changeId: 'new-root',
            changes: {
              kind: crdtDocumentChangeNode,
              children: Object.fromEntries(
                ids.map((id) => [id, { kind: crdtDocumentChangeNode }]),
              ),
            },
          };
        });
        await Promise.resolve();
        release.resolve();
        await Promise.all([collecting, mutation]);
        expect(deleted).toEqual(['first']);
      }),
      { seed: 2012203, numRuns: 20 },
    );
  } finally {
    log.mockRestore();
  }
});
