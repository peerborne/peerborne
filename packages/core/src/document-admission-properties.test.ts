import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  bootstrap,
  context,
  control,
  flushAndCollect,
  id,
  storeKey,
} from './__testutils__/group-security-coordinator.js';
import {
  GroupSecurityCoordinator,
  type GroupSecurityDocumentContext,
} from './group-security-coordinator.js';
import {
  GroupDocumentOperationBudget,
  GroupDocumentOperationGate,
  type PreparedGroupDocumentOperation,
} from './group-document-operation.js';

const prepared = (
  commit: () => void = () => {},
  isAuthorizationCurrent: () => boolean = () => true,
) => ({ commit, isAuthorizationCurrent });

function deferred<T = void>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

describe('anchored document admission boundaries', () => {
  test('preserves captured input and rejects cancellation or rekey while preparation is suspended', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ maxLength: 48 }),
        fc.constantFrom('unchanged', 'rekey', 'cancel', 'ack', 'authorization'),
        fc.boolean(),
        async (bytes, action, forgePreparationContext) => {
          const value = await context();
          const coordinator = await bootstrap(value);
          const expected = coordinator.documentContext;
          const originalHead = new Uint8Array(expected.controlHead);
          const originalBytes = new Uint8Array(bytes);
          const input = new Uint8Array(bytes);
          const entered = deferred();
          const release = deferred();
          const abort = new AbortController();
          let stagedContext!: GroupSecurityDocumentContext;
          let applied = 0;
          let authorized = true;
          const options = { signal: abort.signal };
          const pending = coordinator.runDocumentOperation(
            expected,
            input,
            async (captured, owned, signal) => {
              stagedContext = captured;
              expect(owned).toEqual(originalBytes);
              expect(captured.controlHead).toEqual(originalHead);
              expect(signal.aborted).toBe(false);
              entered.resolve();
              await release.promise;
              return prepared(
                () => {
                  applied += 1;
                },
                () => authorized,
              );
            },
            options,
          );
          const result = pending.then(
            () => 'committed',
            (error: { code: string }) => error.code,
          );
          input.fill(0xff);
          options.signal = new AbortController().signal;
          expected.controlHead.fill(0xee);
          expected.state.groupId.fill(0xdd);
          await Promise.race([
            entered.promise,
            result.then((code) => {
              throw new Error(`preparation did not start: ${code}`);
            }),
          ]);
          if (action === 'rekey') {
            await coordinator.createCommit(
              { changes: [] },
              control(2, 'update', value.identities.actorId),
            );
            expect(coordinator.publicState.epoch).toBe(1n);
          }
          if (action === 'ack') await flushAndCollect(coordinator);
          if (action === 'authorization') authorized = false;
          if (forgePreparationContext) {
            const current = coordinator.documentContext;
            Object.assign(stagedContext.state, current.state);
            stagedContext.controlHead.set(current.controlHead);
          }
          if (action === 'cancel') {
            abort.abort();
            expect(await result).toBe('aborted');
            expect(coordinator.pendingDocumentOperations).toEqual({
              operations: 1,
              bytes: bytes.length,
            });
          }
          release.resolve();
          const shouldCommit = action === 'unchanged' || action === 'ack';
          expect(await result).toBe(
            shouldCommit
              ? 'committed'
              : action === 'rekey'
                ? 'stale-context'
                : action === 'authorization'
                  ? 'authorization-changed'
                  : 'aborted',
          );
          await turn();
          expect(applied).toBe(shouldCommit ? 1 : 0);
          expect(coordinator.pendingDocumentOperations).toEqual({
            operations: 0,
            bytes: 0,
          });
        },
      ),
      { seed: 2011101, numRuns: 70 },
    );
  });

  test('binds every security-context component before invoking preparation', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(
          'protocol',
          'group',
          'epoch',
          'tree',
          'transcript',
          'head',
        ),
        async (field) => {
          const value = await context();
          const coordinator = await bootstrap(value);
          const captured = coordinator.documentContext;
          switch (field) {
            case 'protocol':
              Object.assign(captured.state.protocol, {
                id: 'different.protocol',
              });
              break;
            case 'group':
              captured.state.groupId[0] ^= 1;
              break;
            case 'epoch':
              Object.assign(captured.state, { epoch: 1n });
              break;
            case 'tree':
              captured.state.treeHash[0] ^= 1;
              break;
            case 'transcript':
              captured.state.confirmedTranscriptHash[0] ^= 1;
              break;
            case 'head':
              captured.controlHead[0] ^= 1;
              break;
          }
          const prepare = jest.fn(async () => prepared(() => {}));
          await expect(
            coordinator.runDocumentOperation(
              captured,
              new Uint8Array([1]),
              prepare,
            ),
          ).rejects.toMatchObject({ code: 'stale-context' });
          expect(prepare).not.toHaveBeenCalled();
          expect(coordinator.pendingDocumentOperations.operations).toBe(0);
        },
      ),
      {
        seed: 2011102,
        numRuns: 36,
        examples: [
          ['protocol'],
          ['group'],
          ['epoch'],
          ['tree'],
          ['transcript'],
          ['head'],
        ],
      },
    );
  });

  test('calibrates native reservation closures against an independent live-ticket ledger', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            reserve: fc.boolean(),
            bytes: fc.nat(20),
            index: fc.nat(100),
          }),
          { maxLength: 160 },
        ),
        (events) => {
          const budget = new GroupDocumentOperationBudget(3, 12);
          const tickets: Array<{
            bytes: number;
            released: boolean;
            release: () => void;
          }> = [];
          for (const event of events) {
            const live = tickets.filter((ticket) => !ticket.released);
            const used = live.reduce((sum, ticket) => sum + ticket.bytes, 0);
            if (event.reserve) {
              if (live.length < 3 && used + event.bytes <= 12) {
                tickets.push({
                  bytes: event.bytes,
                  released: false,
                  release: budget.reserve(event.bytes),
                });
              } else {
                expect(() => budget.reserve(event.bytes)).toThrow(
                  /capacity-exceeded/,
                );
              }
            } else if (tickets.length > 0) {
              const ticket = tickets[event.index % tickets.length];
              ticket.release();
              ticket.release();
              ticket.released = true;
            }
            const remaining = tickets.filter((ticket) => !ticket.released);
            expect(budget.usage).toEqual({
              operations: remaining.length,
              bytes: remaining.reduce((sum, ticket) => sum + ticket.bytes, 0),
            });
          }
          for (const ticket of tickets) ticket.release();
          expect(budget.usage).toEqual({ operations: 0, bytes: 0 });
        },
      ),
      { seed: 2011103, numRuns: 500 },
    );
  });

  test('owns native byte views and rejects shared or reflected impostors without invoking accessors', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ maxLength: 64 }),
        fc.constantFrom('offset', 'shadow', 'shared', 'wrong-kind', 'proxy'),
        async (bytes, kind) => {
          const value = await context();
          const coordinator = await bootstrap(value);
          let reads = 0;
          let input: unknown;
          if (kind === 'offset') {
            const storage = new Uint8Array(bytes.length + 4);
            storage.set(bytes, 2);
            input = new Uint8Array(storage.buffer, 2, bytes.length);
          } else if (kind === 'shadow') {
            input = new Uint8Array(bytes);
            for (const property of [
              'byteLength',
              'buffer',
              'subarray',
              Symbol.iterator,
            ])
              Object.defineProperty(input, property, {
                get() {
                  reads += 1;
                  throw new Error('synthetic accessor');
                },
              });
          } else if (kind === 'shared')
            input = new Uint8Array(new SharedArrayBuffer(bytes.length));
          else if (kind === 'wrong-kind') input = new Uint16Array(bytes.length);
          else
            input = new Proxy(new Uint8Array(bytes), {
              get() {
                reads += 1;
                throw new Error('synthetic proxy');
              },
            });
          const prepare = jest.fn(
            async (
              _captured: GroupSecurityDocumentContext,
              owned: Uint8Array,
            ) => {
              expect(owned).toEqual(bytes);
              return prepared(() => {});
            },
          );
          const pending = coordinator.runDocumentOperation(
            coordinator.documentContext,
            input as Uint8Array,
            prepare,
          );
          if (kind === 'offset' || kind === 'shadow') {
            await pending;
            expect(prepare).toHaveBeenCalledTimes(1);
          } else {
            await expect(pending).rejects.toMatchObject({
              code: 'invalid-input',
            });
            expect(prepare).not.toHaveBeenCalled();
          }
          expect(reads).toBe(0);
          expect(coordinator.pendingDocumentOperations.operations).toBe(0);
        },
      ),
      { seed: 2011106, numRuns: 50 },
    );
  });

  test('uses shared credits across gates and retains them after a timed-out verifier', async () => {
    jest.useFakeTimers();
    const shared = new GroupDocumentOperationBudget(1, 4);
    const first = new GroupDocumentOperationGate(1, 4, 10, shared);
    const second = new GroupDocumentOperationGate(1, 4, 10, shared);
    const entered = deferred();
    const release = deferred();
    let applied = 0;
    const hooks = {
      capture: async () => 0,
      prepare: async () => {
        entered.resolve();
        await release.promise;
        return prepared(() => {
          applied += 1;
        });
      },
      commit: async (_context: number, finish: (matches: boolean) => void) => {
        finish(true);
      },
      poison: () => {},
    };
    try {
      const pending = first.run(new Uint8Array(4), hooks);
      const outcome = pending.catch((error: { code: string }) => error.code);
      await entered.promise;
      await jest.advanceTimersByTimeAsync(10);
      expect(await outcome).toBe('timeout');
      expect(shared.usage).toEqual({ operations: 1, bytes: 4 });
      await expect(second.run(new Uint8Array(1), hooks)).rejects.toMatchObject({
        code: 'capacity-exceeded',
      });
      release.resolve();
      await jest.advanceTimersByTimeAsync(0);
      expect(shared.usage).toEqual({ operations: 0, bytes: 0 });
      expect(applied).toBe(0);
      await second.run(new Uint8Array(4), {
        ...hooks,
        prepare: async () =>
          prepared(() => {
            applied += 1;
          }),
      });
      expect(applied).toBe(1);
      expect(shared.usage.operations).toBe(0);
    } finally {
      release.resolve();
      jest.useRealTimers();
    }
  });

  test('rejects oversized, already-aborted and accessor-backed requests before preparing', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    const prepare = jest.fn(async () => prepared(() => {}));
    const captured = coordinator.documentContext;
    await expect(
      coordinator.runDocumentOperation(
        captured,
        new Uint8Array(1024 * 1024 + 1),
        prepare,
      ),
    ).rejects.toMatchObject({ code: 'invalid-input' });
    const controller = new AbortController();
    controller.abort();
    await expect(
      coordinator.runDocumentOperation(captured, new Uint8Array(1), prepare, {
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: 'aborted' });
    let reads = 0;
    const options = Object.defineProperty({}, 'signal', {
      enumerable: true,
      get() {
        reads += 1;
        throw new Error('synthetic signal accessor');
      },
    });
    await expect(
      coordinator.runDocumentOperation(
        captured,
        new Uint8Array(1),
        prepare,
        options,
      ),
    ).rejects.toMatchObject({ code: 'invalid-input' });
    expect(reads).toBe(0);
    expect(prepare).not.toHaveBeenCalled();
    expect(coordinator.pendingDocumentOperations).toEqual({
      operations: 0,
      bytes: 0,
    });
    await coordinator.runDocumentOperation(
      captured,
      new Uint8Array(1),
      prepare,
    );
    expect(prepare).toHaveBeenCalledTimes(1);
  });

  test('checks protected terminal markers immediately before finalization without loading document history', async () => {
    for (const terminal of ['fork', 'removal'] as const) {
      const value = await context();
      const coordinator = await bootstrap(value);
      const capture = coordinator.documentContext;
      const entered = deferred();
      const release = deferred();
      const load = jest.spyOn(value.store, 'load');
      let applied = false;
      const pending = coordinator.runDocumentOperation(
        capture,
        new Uint8Array([7]),
        async () => {
          entered.resolve();
          await release.promise;
          return prepared(() => {
            applied = true;
          });
        },
      );
      const outcome = pending.catch((error: { code: string }) => error.code);
      await entered.promise;
      const anchor = (await value.rollbackAnchor.load(storeKey))!;
      if (terminal === 'fork') {
        await value.rollbackAnchor.poison(storeKey, {
          epoch: 1n,
          parentRecordId: anchor.controlHead,
          firstRecordId: id(2),
          secondRecordId: id(3),
          evidenceHash: id(4),
        });
      } else {
        await value.rollbackAnchor.retire(storeKey, anchor, {
          epoch: 1n,
          parentRecordId: anchor.controlHead,
          recordId: id(2),
          memberId: value.identities.actorId,
        });
      }
      release.resolve();
      expect(await outcome).toBe(
        terminal === 'fork' ? 'fork-detected' : 'removed-from-group',
      );
      expect(applied).toBe(false);
      expect(load).not.toHaveBeenCalled();
      expect(coordinator.pendingDocumentOperations.operations).toBe(0);
    }
  });

  test('poisons on opaque finalizer failure and observes rejected native promises without then getters', async () => {
    for (const kind of ['throw', 'promise', 'then-getter'] as const) {
      const value = await context();
      const coordinator = await bootstrap(value);
      let getterReads = 0;
      const finalize = (() => {
        if (kind === 'throw') throw new Error('synthetic finalizer failure');
        if (kind === 'promise')
          return Promise.reject(new Error('synthetic asynchronous failure'));
        return Object.defineProperty({}, 'then', {
          get() {
            getterReads += 1;
            throw new Error('must not inspect');
          },
        });
      }) as () => void;
      await expect(
        coordinator.runDocumentOperation(
          coordinator.documentContext,
          new Uint8Array(0),
          async () => prepared(finalize),
        ),
      ).rejects.toBeDefined();
      await turn();
      expect(getterReads).toBe(0);
      expect(() => coordinator.documentContext).toThrow(/poisoned/);
      expect(coordinator.pendingDocumentOperations.operations).toBe(
        kind === 'then-getter' ? 1 : 0,
      );
    }
  });
  test('requires a current strict-boolean authorization guard without invoking prepared-record accessors', async () => {
    for (const kind of [
      'false',
      'throw',
      'number',
      'then-getter',
      'record-getter',
    ] as const) {
      const value = await context();
      const coordinator = await bootstrap(value);
      let applied = 0;
      let reads = 0;
      const stage: unknown =
        kind === 'record-getter'
          ? Object.defineProperty(
              {
                commit() {
                  applied += 1;
                },
              },
              'isAuthorizationCurrent',
              {
                enumerable: true,
                get() {
                  reads += 1;
                  return () => true;
                },
              },
            )
          : {
              commit() {
                applied += 1;
              },
              isAuthorizationCurrent() {
                if (kind === 'false') return false;
                if (kind === 'throw')
                  throw new Error('synthetic authorization failure');
                if (kind === 'number') return 1;
                return Object.defineProperty({}, 'then', {
                  get() {
                    reads += 1;
                    throw new Error('must not inspect');
                  },
                });
              },
            };
      await expect(
        coordinator.runDocumentOperation(
          coordinator.documentContext,
          new Uint8Array(1),
          async () => stage as PreparedGroupDocumentOperation,
        ),
      ).rejects.toMatchObject({
        code:
          kind === 'false' || kind === 'throw'
            ? 'authorization-changed'
            : 'invalid-preparation',
      });
      expect(applied).toBe(0);
      expect(reads).toBe(0);
      expect(coordinator.pendingDocumentOperations.operations).toBe(
        kind === 'then-getter' ? 1 : 0,
      );
      expect(coordinator.publicState.epoch).toBe(0n);
    }
  });

  test('retains credits for unexpected asynchronous guards and finalizers until their native work settles', async () => {
    for (const kind of ['guard', 'finalizer'] as const) {
      const value = await context();
      const coordinator = await bootstrap(value);
      const held = deferred<void>();
      const stage =
        kind === 'guard'
          ? { isAuthorizationCurrent: () => held.promise, commit: () => {} }
          : { isAuthorizationCurrent: () => true, commit: () => held.promise };
      const pending = coordinator.runDocumentOperation(
        coordinator.documentContext,
        new Uint8Array(1),
        async () => stage as unknown as PreparedGroupDocumentOperation,
      );
      try {
        await expect(pending).rejects.toMatchObject({
          code: 'invalid-preparation',
        });
        expect(coordinator.pendingDocumentOperations).toEqual({
          operations: 1,
          bytes: 1,
        });
        if (kind === 'finalizer')
          expect(() => coordinator.publicState).toThrow(/poisoned/);
      } finally {
        held.resolve();
        await turn();
      }
      expect(coordinator.pendingDocumentOperations).toEqual({
        operations: 0,
        bytes: 0,
      });
    }
  });

  test('captures both prepared functions before an authorization guard can replace the original record', async () => {
    const value = await context();
    const coordinator = await bootstrap(value);
    let original = 0;
    let replacement = 0;
    const stage = {
      commit: () => {
        original += 1;
      },
      isAuthorizationCurrent: () => {
        stage.commit = () => {
          replacement += 1;
        };
        return true;
      },
    };
    await coordinator.runDocumentOperation(
      coordinator.documentContext,
      new Uint8Array(1),
      async () => stage,
    );
    expect(original).toBe(1);
    expect(replacement).toBe(0);
  });

  test('quarantines unobservable decorated promise work without invoking constructor, species or then accessors', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(
          'constructor',
          'species',
          'species-proxy',
          'invalid-constructor',
          'then',
          'frozen',
        ),
        fc.boolean(),
        async (decoration, guard) => {
          const held = deferred<void>();
          let accessorReads = 0;
          const forbidden = () => {
            accessorReads += 1;
            throw new Error('must not inspect');
          };
          if (decoration === 'constructor')
            Object.defineProperty(held.promise, 'constructor', {
              get: forbidden,
            });
          if (decoration === 'species')
            Object.defineProperty(held.promise, 'constructor', {
              value: Object.defineProperty({}, Symbol.species, {
                get: forbidden,
              }),
            });
          if (decoration === 'species-proxy')
            Object.defineProperty(held.promise, 'constructor', {
              value: new Proxy(
                {},
                { get: forbidden, getOwnPropertyDescriptor: forbidden },
              ),
            });
          if (decoration === 'invalid-constructor')
            Object.defineProperty(held.promise, 'constructor', { value: 1 });
          if (decoration === 'then')
            Object.defineProperty(held.promise, 'then', { get: forbidden });
          if (decoration === 'frozen') Object.freeze(held.promise);
          const aggregate = new GroupDocumentOperationBudget(1, 16);
          const gate = new GroupDocumentOperationGate(1, 16, 1000, aggregate);
          const stage = {
            isAuthorizationCurrent: guard ? () => held.promise : () => true,
            commit: guard ? () => {} : () => held.promise,
          };
          await expect(
            gate.run(new Uint8Array(1), {
              capture: async () => 0,
              prepare: async () =>
                stage as unknown as PreparedGroupDocumentOperation,
              commit: async (_, finish) => finish(true),
              poison: () => {},
            }),
          ).rejects.toMatchObject({ code: 'invalid-preparation' });
          expect(gate.budget.usage).toEqual({ operations: 1, bytes: 1 });
          held.resolve();
          await turn();
          const observable = decoration === 'then' || decoration === 'frozen';
          const expected = observable
            ? { operations: 0, bytes: 0 }
            : { operations: 1, bytes: 1 };
          expect(gate.budget.usage).toEqual(expected);
          expect(aggregate.usage).toEqual(expected);
          expect(accessorReads).toBe(0);
        },
      ),
      { seed: 2011108, numRuns: 24 },
    );
  });
});
