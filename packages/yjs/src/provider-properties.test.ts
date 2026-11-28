import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { mergeACLChanges } from '@peerborne/core';
import { applyUpdateV2, Doc } from 'yjs';
import {
  YjsACL,
  YjsJSONSerializer,
  YjsProvider,
  serializeKey,
} from './peerborne-yjs.js';

type GeneratedValue = number | string | { first: string; last: string };
const generatedValue = fc.oneof(
  fc.integer(),
  fc.string({ maxLength: 20 }),
  fc
    .record({
      first: fc.string({ maxLength: 20 }),
      last: fc.string({ maxLength: 20 }),
    })
    .map(({ first, last }) => ({ first, last })),
);

const edit = fc.record({
  key: fc.integer({ min: 0, max: 5 }).map((index) => `key${index}`),
  value: generatedValue,
  remove: fc.boolean(),
  priority: fc.integer(),
});
const program = fc.array(edit, { maxLength: 12 });

describe('Yjs provider generated delivery histories', () => {
  test('converges after concurrent edits, reordered duplicates, late ancestry and snapshot recovery', () => {
    const provider = new YjsProvider();
    const serializer = new YjsJSONSerializer();
    fc.assert(
      fc.property(program, program, (editsA, editsB) => {
        const docs: ReturnType<typeof provider.newDocument>[] = [];
        const create = (clientID: number) => {
          const doc = provider.newDocument();
          doc.clientID = clientID;
          docs.push(doc);
          return doc;
        };
        try {
          const packets: { changes: Uint8Array; priority: number }[] = [];
          const run = (
            clientID: number,
            edits: typeof editsA,
            witness: string,
          ) => {
            const doc = create(clientID);
            const [, first] = provider.localChange(doc, '', (draft) => {
              draft.getMap('witness').set(witness, 1);
            });
            packets.push({ changes: first, priority: 0 });
            const expected: Record<string, GeneratedValue> = {};
            for (const operation of edits) {
              const [, changes] = provider.localChange(doc, '', (draft) => {
                const values = draft.getMap<GeneratedValue>('values');
                if (operation.remove) values.delete(operation.key);
                else values.set(operation.key, operation.value);
              });
              if (operation.remove) delete expected[operation.key];
              else expected[operation.key] = operation.value;
              packets.push({ changes, priority: operation.priority });
            }
            expect(doc.getMap('values').toJSON()).toEqual(expected);
            return doc;
          };
          const a = run(1, editsA, 'a');
          const b = run(2, editsB, 'b');
          const late = create(3);
          const ordered = [...packets].sort(
            (left, right) => left.priority - right.priority,
          );
          const wire = (changes: Uint8Array) =>
            new Uint8Array(
              serializer.deserializeChanges(
                serializer.serializeChanges(changes),
              ),
            );
          for (const packet of ordered) {
            provider.remoteChange(a, wire(packet.changes));
            provider.remoteChange(a, wire(packet.changes));
          }
          for (const packet of [...ordered].reverse()) {
            provider.remoteChange(b, wire(packet.changes));
            provider.remoteChange(b, wire(packet.changes));
            provider.remoteChange(late, wire(packet.changes));
          }
          const state = (doc: typeof a) => ({
            values: doc.getMap('values').toJSON(),
            witness: doc.getMap('witness').toJSON(),
          });
          expect(state(a)).toEqual(state(b));
          expect(state(late)).toEqual(state(a));
          expect(a.getMap('witness').toJSON()).toEqual({ a: 1, b: 1 });
          const recovered = create(4);
          provider.remoteChange(recovered, wire(provider.getSnapshot(a)));
          expect(state(recovered)).toEqual(state(a));
          provider.remoteChange(recovered, wire(provider.getSnapshot(a)));
          expect(state(recovered)).toEqual(state(a));
          const fromHistory = create(5);
          provider.remoteChange(fromHistory, wire(provider.getHistory(a)));
          expect(state(fromHistory)).toEqual(state(a));
        } finally {
          docs.forEach((doc) => doc.destroy());
        }
      }),
      { seed: 9431, numRuns: 150, examples: [[[], []]] },
    );
  });

  test('recovers pruned history when the retained tail arrives before its snapshot', () => {
    const provider = new YjsProvider();
    const serializer = new YjsJSONSerializer();
    const wire = (changes: Uint8Array) =>
      new Uint8Array(
        serializer.deserializeChanges(serializer.serializeChanges(changes)),
      );
    fc.assert(
      fc.property(
        program,
        fc.nat(),
        fc.nat(),
        (edits, snapshotSeed, tailSeed) => {
          const source = provider.newDocument();
          source.clientID = 1;
          const recovered = provider.newDocument();
          recovered.clientID = 2;
          try {
            const packets: Uint8Array[] = [];
            const covered = snapshotSeed % (edits.length + 1);
            let snapshot =
              covered === 0 ? provider.getSnapshot(source) : undefined;
            for (const operation of edits) {
              const [, changes] = provider.localChange(source, '', (draft) => {
                const values = draft.getMap<GeneratedValue>('values');
                if (operation.remove) values.delete(operation.key);
                else values.set(operation.key, operation.value);
              });
              packets.push(changes);
              if (packets.length === covered)
                snapshot = provider.getSnapshot(source);
            }
            for (const changes of packets.slice(tailSeed % (covered + 1))) {
              provider.remoteChange(recovered, wire(changes));
            }
            provider.remoteChange(recovered, wire(snapshot!));
            expect(recovered.getMap('values').toJSON()).toEqual(
              source.getMap('values').toJSON(),
            );
          } finally {
            source.destroy();
            recovered.destroy();
          }
        },
      ),
      { seed: 9433, numRuns: 150, examples: [[[], 0, 0]] },
    );
  });
});

const aclProgram = fc.array(
  fc.record({
    key: fc.integer({ min: 0, max: 3 }),
    remove: fc.boolean(),
    priority: fc.integer(),
  }),
  { maxLength: 10 },
);

describe('Yjs ACL generated delivery orders', () => {
  test('changes delivered in any order with duplicates keep the live ACL complete and converge', async () => {
    const keys = await Promise.all(
      Array.from({ length: 4 }, async () =>
        (
          await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['sign', 'verify'],
          )
        ).publicKey,
      ),
    );
    const members = async (acl: YjsACL) =>
      (await Promise.all((await acl.users()).map(serializeKey))).sort();
    await fc.assert(
      fc.asyncProperty(aclProgram, async (operations) => {
        const sender = new YjsACL();
        const packets: { changes: Uint8Array; priority: number }[] = [];
        for (const { key, remove, priority } of operations) {
          const changes = remove
            ? await sender.remove(keys[key]!)
            : await sender.add(keys[key]!);
          packets.push({ changes, priority });
        }
        const ordered = packets
          .sort((left, right) => left.priority - right.priority)
          .map(({ changes }) => changes);
        const receiver = new YjsACL();
        let waiting: Uint8Array[] = [];
        for (const changes of [...ordered, ...ordered.reverse()]) {
          waiting = mergeACLChanges(receiver, [...waiting, changes]);
          expect(() => receiver.current()).not.toThrow();
          await receiver.users();
        }
        expect(waiting).toEqual([]);
        expect(await members(receiver)).toEqual(await members(sender));
      }),
      { seed: 9435, numRuns: 60, examples: [[[]]] },
    );
  }, 60_000);

  test('a concurrent revocation defeats a stale regrant through reconstruction and a fully informed grant restores membership', async () => {
    const [member, unaffected] = await Promise.all(
      Array.from({ length: 2 }, async () =>
        (
          await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['sign', 'verify'],
          )
        ).publicKey,
      ),
    );
    const founder = new YjsACL();
    founder.actorBinding.setLocalActor('1');
    await founder.add(member);
    await founder.add(unaffected);
    const serializedMember = await serializeKey(member);
    const base = founder.current();
    const replica = (actor: number) => {
      const acl = new YjsACL();
      acl.merge(base);
      acl.actorBinding.setLocalActor(String(actor));
      return acl;
    };

    await fc.assert(
      fc.asyncProperty(
        fc.tuple(fc.integer(), fc.integer(), fc.integer(), fc.integer()),
        fc.boolean(),
        async (priorities, staleGrantHasHigherActor) => {
          const left = replica(10);
          const right = replica(staleGrantHasHigherActor ? 40 : 20);
          const leftRevocation = await left.remove(member);
          const rightRevocation = await right.remove(member);
          const staleGrant = await right.add(member);
          expect(await right.check(member)).toBe(true);

          const deliver = (receiver: YjsACL, packets: Uint8Array[]) => {
            const ordered = packets
              .map((changes, index) => ({ changes, priority: priorities[index] }))
              .sort((a, b) => a.priority - b.priority);
            let held: Uint8Array[] = [];
            for (const packet of [...ordered, ...ordered.slice().reverse()]) {
              held = mergeACLChanges(receiver, [...held, packet.changes]);
              expect(() => receiver.current()).not.toThrow();
            }
            expect(held).toEqual([]);
          };

          const concurrent = [leftRevocation, rightRevocation, staleGrant];
          const joined = replica(50);
          deliver(joined, concurrent);
          expect(await joined.check(member)).toBe(false);
          expect(await joined.check(unaffected)).toBe(true);
          const reopened = new YjsACL();
          reopened.merge(joined.current());
          expect(await reopened.check(member)).toBe(false);

          const author = replica(30);
          author.merge(leftRevocation);
          author.merge(rightRevocation);
          const freshGrant = await author.add(member);
          for (const receiver of [reopened, replica(60)]) {
            deliver(receiver, [...concurrent, freshGrant]);
            expect(await receiver.check(member)).toBe(true);
            expect(await receiver.users()).toHaveLength(2);

            const native = new Doc({ gc: false });
            try {
              applyUpdateV2(native, receiver.current());
              expect(native.getMap('users').get(serializedMember)).toHaveLength(
                staleGrantHasHigherActor ? 1 : 2,
              );
            } finally {
              native.destroy();
            }
          }
        },
      ),
      { seed: 19026, numRuns: 60 },
    );
  }, 60_000);
});
