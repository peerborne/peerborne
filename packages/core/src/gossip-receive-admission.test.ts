import { expect, test } from '@jest/globals';
import {
  GossipReceiveAdmission,
  MAX_KEPT_FRAME_SENDERS,
} from './gossip-receive-admission.js';
import { GroupDocumentOperationBudget } from './group-document-operation.js';

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

function blocking() {
  const started: number[] = [];
  const gates: PromiseWithResolvers<void>[] = [];
  const operation = async (frame: Uint8Array) => {
    started.push(frame[0]!);
    const gate = Promise.withResolvers<void>();
    gates.push(gate);
    await gate.promise;
  };
  const settleAll = async () => {
    for (let index = 0; index < gates.length; index++) {
      gates[index]!.resolve();
      await turn();
    }
  };
  return { started, gates, operation, settleAll };
}

test('the latest frame skipped for capacity runs once a credit frees', async () => {
  const local = new GroupDocumentOperationBudget(2, 1024);
  const aggregate = new GroupDocumentOperationBudget(8, 1024);
  const receive = new GossipReceiveAdmission(local, aggregate);
  const work = blocking();
  const retried: number[] = [];
  const retry = async (frame: Uint8Array) => {
    retried.push(frame[0]!);
  };

  const results = [1, 2, 3, 4, 5].map((value) =>
    receive.run(Uint8Array.of(value), work.operation, retry),
  );
  expect(work.started).toEqual([1, 2]);
  await expect(results[2]).resolves.toBeUndefined();
  expect(receive.keptBytes).toBe(1);
  expect(local.usage).toEqual({ operations: 2, bytes: 2 });

  work.gates[0]!.resolve();
  await turn();
  expect(retried).toEqual([5]);
  expect(receive.keptBytes).toBe(0);
  await work.settleAll();
  await Promise.all(results);
  expect(retried).toEqual([5]);
  expect(local.usage).toEqual({ operations: 0, bytes: 0 });
  expect(aggregate.usage).toEqual({ operations: 0, bytes: 0 });
});

test('a frame reaching a second stage keeps its arrival order', async () => {
  const receive = new GossipReceiveAdmission(
    new GroupDocumentOperationBudget(1, 1024),
    new GroupDocumentOperationBudget(8, 1024),
  );
  const work = blocking();
  const retried: number[] = [];
  const retry = async (frame: Uint8Array) => {
    retried.push(frame[0]!);
  };
  const early = Uint8Array.of(1);
  const first = receive.run(early, work.operation, retry);
  await receive.run(Uint8Array.of(2), work.operation, retry);
  // The earlier frame's second stage must not displace the newer skipped frame.
  await receive.run(early, work.operation, retry);
  work.gates[0]!.resolve();
  await first;
  await turn();
  expect(retried).toEqual([2]);
  await work.settleAll();
});

test('skipped frames are detached, invalid lengths are never retained, and close discards the retry', async () => {
  const receive = new GossipReceiveAdmission(
    new GroupDocumentOperationBudget(1, 4),
    new GroupDocumentOperationBudget(8, 1024),
  );
  const work = blocking();
  const retried: Uint8Array[] = [];
  const retry = async (frame: Uint8Array) => {
    retried.push(frame);
  };
  const first = receive.run(Uint8Array.of(1), work.operation, retry);
  const input = Uint8Array.of(9, 9);
  await receive.run(input, work.operation, retry);
  input.fill(0);
  await receive.run(new Uint8Array(0), work.operation, retry);
  await receive.run(new Uint8Array(5), work.operation, retry);
  expect(receive.keptBytes).toBe(2);
  work.gates[0]!.resolve();
  await first;
  await turn();
  expect(retried).toEqual([Uint8Array.of(9, 9)]);

  const second = receive.run(Uint8Array.of(1), work.operation, retry);
  await receive.run(Uint8Array.of(3), work.operation, retry);
  receive.close();
  expect(receive.keptBytes).toBe(0);
  await work.settleAll();
  await second;
  expect(retried).toHaveLength(1);
});

test('without a retry a skipped frame is dropped as before', async () => {
  const local = new GroupDocumentOperationBudget(1, 1024);
  const receive = new GossipReceiveAdmission(
    local,
    new GroupDocumentOperationBudget(8, 1024),
  );
  const work = blocking();
  const first = receive.run(Uint8Array.of(1), work.operation);
  await expect(
    receive.run(Uint8Array.of(2), work.operation),
  ).resolves.toBeUndefined();
  expect(receive.keptBytes).toBe(0);
  await work.settleAll();
  await first;
  expect(work.started).toEqual([1]);
  expect(local.usage).toEqual({ operations: 0, bytes: 0 });
});

test('a retained frame holds a shared credit, and one skipped for shared capacity is not retained', async () => {
  const aggregate = new GroupDocumentOperationBudget(3, 1024);
  const busy = new GossipReceiveAdmission(
    new GroupDocumentOperationBudget(1, 1024),
    aggregate,
  );
  const idle = new GossipReceiveAdmission(
    new GroupDocumentOperationBudget(4, 1024),
    aggregate,
  );
  const work = blocking();
  const retried: number[] = [];
  const retry = async (frame: Uint8Array) => {
    retried.push(frame[0]!);
  };
  const first = busy.run(Uint8Array.of(1), work.operation, retry);
  await busy.run(Uint8Array.of(2), work.operation, retry);
  await turn();
  expect(busy.keptBytes).toBe(1);
  expect(aggregate.usage).toEqual({ operations: 2, bytes: 2 });
  const second = idle.run(Uint8Array.of(5), work.operation, retry);
  // Shared credits are exhausted, so this skipped frame is dropped.
  await idle.run(Uint8Array.of(6), work.operation, retry);
  await idle.run(Uint8Array.of(7), work.operation, retry);
  await turn();
  expect(idle.keptBytes).toBe(0);
  await work.settleAll();
  await Promise.all([first, second]);
  for (let index = 0; index < 4; index++) await turn();
  await work.settleAll();
  expect(retried).toEqual([2]);
  expect(aggregate.usage).toEqual({ operations: 0, bytes: 0 });
});

test('each sender keeps its own frame waiting for the check', async () => {
  const local = new GroupDocumentOperationBudget(1, 1024);
  const checks: number[] = [];
  const pendingChecks: PromiseWithResolvers<'sync'>[] = [];
  const receive = new GossipReceiveAdmission(
    local,
    new GroupDocumentOperationBudget(16, 1024),
    async (frame) => {
      checks.push(frame[0]!);
      const check = Promise.withResolvers<'sync'>();
      pendingChecks.push(check);
      return check.promise;
    },
  );
  const work = blocking();
  const retried: number[] = [];
  const retry = async (frame: Uint8Array) => {
    retried.push(frame[0]!);
  };
  const busy = receive.run(Uint8Array.of(1), work.operation, retry, 'a');
  await receive.run(Uint8Array.of(2), work.operation, retry, 'a');
  // While a's first skipped frame is checked, a's last frame waits, and
  // frames from other senders do not replace it.
  await receive.run(Uint8Array.of(3), work.operation, retry, 'a');
  for (let index = 0; index < 5; index++)
    await receive.run(
      Uint8Array.of(20 + index),
      work.operation,
      retry,
      `b${index}`,
    );
  for (let index = 0; index < 7; index++) {
    pendingChecks.at(-1)!.resolve('sync');
    await turn();
  }
  expect(checks).toContain(3);
  await work.settleAll();
  await busy;
  for (let index = 0; index < 6; index++) await turn();
  expect(retried).toContain(3);
  expect(retried).not.toContain(2);
});

test('sync requests are evicted before ordinary frames', async () => {
  const local = new GroupDocumentOperationBudget(1, 1024);
  const receive = new GossipReceiveAdmission(
    local,
    new GroupDocumentOperationBudget(64, 1024),
    async (frame) => (frame[0]! >= 100 ? 'request' : 'sync'),
  );
  const work = blocking();
  const retried: number[] = [];
  const retry = async (frame: Uint8Array) => {
    retried.push(frame[0]!);
  };
  const busy = receive.run(Uint8Array.of(1), work.operation, retry, 'w');
  await receive.run(Uint8Array.of(2), work.operation, retry, 'writer');
  for (let index = 0; index < 4; index++) await turn();
  for (let index = 0; index < MAX_KEPT_FRAME_SENDERS + 2; index++) {
    await receive.run(
      Uint8Array.of(100 + index),
      work.operation,
      retry,
      `reader${index}`,
    );
    for (let turnIndex = 0; turnIndex < 3; turnIndex++) await turn();
  }
  await work.settleAll();
  await busy;
  for (let index = 0; index < 6; index++) await turn();
  expect(retried).toContain(2);
});

test('a frame from another sender does not displace a kept frame, and kept senders are bounded', async () => {
  const local = new GroupDocumentOperationBudget(1, 1024);
  const receive = new GossipReceiveAdmission(
    local,
    new GroupDocumentOperationBudget(16, 1024),
  );
  const work = blocking();
  const retried: number[] = [];
  const retry = async (frame: Uint8Array) => {
    retried.push(frame[0]!);
  };
  const first = receive.run(Uint8Array.of(1), work.operation, retry, 'writer');
  await receive.run(Uint8Array.of(2), work.operation, retry, 'writer');
  await receive.run(Uint8Array.of(99), work.operation, retry, 'junk');
  await receive.run(Uint8Array.of(98), work.operation, retry, 'junk');
  expect(receive.keptBytes).toBe(2);
  work.gates[0]!.resolve();
  await first;
  for (let index = 0; index < 4; index++) await turn();
  expect(retried.sort((a, b) => a - b)).toEqual([2, 98]);

  retried.length = 0;
  const busy = receive.run(Uint8Array.of(1), work.operation, retry, 'writer');
  for (let sender = 0; sender < MAX_KEPT_FRAME_SENDERS + 3; sender++)
    await receive.run(
      Uint8Array.of(10 + sender),
      work.operation,
      retry,
      `peer-${sender}`,
    );
  for (let index = 0; index < 4; index++) await turn();
  expect(receive.keptBytes).toBe(MAX_KEPT_FRAME_SENDERS);
  await work.settleAll();
  await busy;
  for (let index = 0; index < 4; index++) await turn();
  expect(retried.sort((a, b) => a - b)).toEqual(
    Array.from({ length: MAX_KEPT_FRAME_SENDERS }, (_, index) => 13 + index),
  );
  expect(local.usage).toEqual({ operations: 0, bytes: 0 });
});

test('a skipped frame that fails authentication never displaces a kept member frame', async () => {
  const local = new GroupDocumentOperationBudget(1, 1024);
  let checking = 0;
  let mostAtOnce = 0;
  const receive = new GossipReceiveAdmission(
    local,
    new GroupDocumentOperationBudget(8, 1024),
    async (frame) => {
      mostAtOnce = Math.max(mostAtOnce, ++checking);
      await turn();
      checking--;
      return frame[0]! < 100 ? 'sync' : undefined;
    },
  );
  const work = blocking();
  const retried: number[] = [];
  const retry = async (frame: Uint8Array) => {
    retried.push(frame[0]!);
  };
  const busy = receive.run(Uint8Array.of(1), work.operation, retry, 'member');
  await receive.run(Uint8Array.of(2), work.operation, retry, 'member');
  for (let index = 0; index < 4; index++) await turn();
  expect(receive.keptBytes).toBe(1);
  for (let index = 0; index < 20; index++)
    await receive.run(
      Uint8Array.of(200 + index),
      work.operation,
      retry,
      'member',
    );
  await receive.run(Uint8Array.of(150), work.operation, retry, 'stranger');
  for (let index = 0; index < 4; index++) await turn();
  expect(receive.keptBytes).toBe(1);
  expect(mostAtOnce).toBe(1);
  // A later member frame is kept again.
  await receive.run(Uint8Array.of(3), work.operation, retry, 'member');
  for (let index = 0; index < 4; index++) await turn();
  await work.settleAll();
  await busy;
  for (let index = 0; index < 4; index++) await turn();
  expect(retried).toEqual([3]);
  expect(local.usage).toEqual({ operations: 0, bytes: 0 });
});
