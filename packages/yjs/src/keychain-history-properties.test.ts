import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import * as yjs from 'yjs';
import { YjsKeychain } from './peerborne-yjs.js';

function entry(index: number): [string, string] {
  return [
    index.toString(16).padStart(64, '0'),
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  ];
}

function attach(doc: yjs.Doc) {
  const keychain = new YjsKeychain();
  Object.defineProperty(keychain, '_keychain', { value: doc, writable: true });
  return keychain;
}

function actorHistory(actors: readonly { client: number; width: number }[]) {
  const doc = new yjs.Doc({ gc: false });
  let count = 0;
  for (const actor of actors) {
    doc.clientID = actor.client;
    doc
      .getArray('keys')
      .push(Array.from({ length: actor.width }, () => entry(count++)));
  }
  return { doc, keychain: attach(doc), count };
}

function history(count: number, descending: boolean) {
  return actorHistory(
    Array.from({ length: count }, (_, index) => ({
      client: descending ? count - index : index + 1,
      width: 1,
    })),
  ).keychain;
}

const actors = fc.uniqueArray(
  fc.record({
    client: fc.integer({ min: 1, max: 10000 }),
    width: fc.integer({ min: 1, max: 8 }),
  }),
  { minLength: 1, maxLength: 25, selector: (actor) => actor.client },
);

test('valid append histories require only linear predecessor reads regardless of actor order', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 8, max: 80 }),
      fc.boolean(),
      (count, descending) => {
        const keychain = history(count, descending);
        const previous = Object.getOwnPropertyDescriptor(
          yjs.Item.prototype,
          'origin',
        );
        let reads = 0,
          instrumented = 0;
        Object.defineProperty(yjs.Item.prototype, 'origin', {
          configurable: true,
          set(this: yjs.Item, initial: yjs.ID | null) {
            instrumented++;
            let origin = initial;
            Object.defineProperty(this, 'origin', {
              configurable: true,
              get() {
                reads++;
                return origin;
              },
              set(value: yjs.ID | null) {
                origin = value;
              },
            });
          },
        });
        try {
          const update = keychain.history();
          expect(update.byteLength).toBeGreaterThan(0);
          expect(instrumented).toBeGreaterThanOrEqual(count);
          expect(reads).toBeLessThanOrEqual(8 * count);
        } finally {
          if (previous)
            Object.defineProperty(yjs.Item.prototype, 'origin', previous);
          else Reflect.deleteProperty(yjs.Item.prototype, 'origin');
        }
      },
    ),
    {
      seed: 2011901,
      numRuns: 32,
      examples: [
        [1000, true],
        [1000, false],
      ],
    },
  );
});

test('native batched and permuted actor histories retain identical state through merge and export', async () => {
  await fc.assert(
    fc.asyncProperty(actors, async (actors) => {
      const source = actorHistory(actors);
      const bytes = source.keychain.history();
      const before = new Uint8Array(bytes);
      const commitment = await source.keychain.stateCommitment();
      const receiver = new YjsKeychain();
      receiver.merge(bytes);
      expect(await receiver.stateCommitment()).toEqual(commitment);
      expect(source.keychain.history()).toEqual(before);
      const recovered = new yjs.Doc();
      yjs.applyUpdateV2(recovered, receiver.history());
      expect(recovered.getArray('keys').toArray()).toEqual(
        Array.from({ length: source.count }, (_, index) => entry(index)),
      );
      bytes.fill(0);
      expect(await receiver.stateCommitment()).toEqual(commitment);
    }),
    { seed: 2011905, numRuns: 80 },
  );
});

test('concurrent native append forks are rejected without changing the receiving keychain', async () => {
  await fc.assert(
    fc.asyncProperty(actors, async (actors) => {
      const source = actorHistory(actors);
      const base = source.keychain.history();
      const merged = new yjs.Doc({ gc: false });
      yjs.applyUpdateV2(merged, base);
      for (const client of [10001, 10002]) {
        const branch = new yjs.Doc({ gc: false });
        yjs.applyUpdateV2(branch, base);
        branch.clientID = client;
        branch.getArray('keys').push([entry(client)]);
        yjs.applyUpdateV2(merged, yjs.encodeStateAsUpdateV2(branch));
      }
      expect(() => attach(merged).history()).toThrow();
      const receiver = new YjsKeychain();
      receiver.merge(base);
      const before = receiver.history();
      const commitment = await receiver.stateCommitment();
      expect(() => receiver.merge(yjs.encodeStateAsUpdateV2(merged))).toThrow();
      expect(receiver.history()).toEqual(before);
      expect(await receiver.stateCommitment()).toEqual(commitment);
    }),
    { seed: 2011906, numRuns: 80 },
  );
});

test('a previously validated mutable Y.Doc cannot hide a later delete and reinsert', () => {
  fc.assert(
    fc.property(actors, fc.nat(), (actors, position) => {
      const source = actorHistory(actors);
      source.keychain.history();
      const keys = source.doc.getArray('keys');
      const before = keys.toArray();
      const index = position % source.count;
      const value = keys.get(index);
      keys.delete(index, 1);
      keys.insert(index, [value]);
      expect(keys.toArray()).toEqual(before);
      expect(() => source.keychain.history()).toThrow();
    }),
    { seed: 2011907, numRuns: 80 },
  );
});
