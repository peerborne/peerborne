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
  expect(receive.deferredBytes).toBe(1);
  expect(local.usage).toEqual({ operations: 2, bytes: 2 });

  work.gates[0]!.resolve();
  await turn();
  expect(retried).toEqual([5]);
  expect(receive.deferredBytes).toBe(0);
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
  expect(receive.deferredBytes).toBe(2);
  work.gates[0]!.resolve();
  await first;
  await turn();
  expect(retried).toEqual([Uint8Array.of(9, 9)]);

  const second = receive.run(Uint8Array.of(1), work.operation, retry);
  await receive.run(Uint8Array.of(3), work.operation, retry);
  receive.close();
  expect(receive.deferredBytes).toBe(0);
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
  expect(receive.deferredBytes).toBe(0);
  await work.settleAll();
  await first;
  expect(work.started).toEqual([1]);
  expect(local.usage).toEqual({ operations: 0, bytes: 0 });
});

test('a frame skipped for shared capacity runs when another subscription frees it', async () => {
  const aggregate = new GroupDocumentOperationBudget(2, 1024);
  const busy = new GossipReceiveAdmission(
    new GroupDocumentOperationBudget(4, 1024),
    aggregate,
  );
  const idle = new GossipReceiveAdmission(
    new GroupDocumentOperationBudget(4, 1024),
    aggregate,
  );
  const work = blocking();
  const retried: number[] = [];
  const pending = [
    busy.run(Uint8Array.of(1), work.operation),
    busy.run(Uint8Array.of(2), work.operation),
  ];
  await idle.run(Uint8Array.of(7), work.operation, async (frame) => {
    retried.push(frame[0]!);
  });
  expect(idle.deferredBytes).toBe(1);
  work.gates[1]!.resolve();
  await pending[1];
  await turn();
  expect(retried).toEqual([7]);
  await work.settleAll();
  await Promise.all(pending);
  expect(aggregate.usage).toEqual({ operations: 0, bytes: 0 });
});

test('a frame from another sender does not displace a kept frame, and kept senders are bounded', async () => {
  const local = new GroupDocumentOperationBudget(1, 1024);
  const receive = new GossipReceiveAdmission(
    local,
    new GroupDocumentOperationBudget(8, 1024),
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
  expect(receive.deferredBytes).toBe(2);
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
  expect(receive.deferredBytes).toBe(MAX_KEPT_FRAME_SENDERS);
  await work.settleAll();
  await busy;
  for (let index = 0; index < 4; index++) await turn();
  expect(retried.sort((a, b) => a - b)).toEqual(
    Array.from({ length: MAX_KEPT_FRAME_SENDERS }, (_, index) => 13 + index),
  );
  expect(local.usage).toEqual({ operations: 0, bytes: 0 });
});
