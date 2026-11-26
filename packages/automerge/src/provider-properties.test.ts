import {
  afterAll,
  beforeAll,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';
import fc from 'fast-check';
import { clone, from, init, type Change, type Doc } from '@automerge/automerge';
import { mergeACLChanges } from '@peerborne/core';
import {
  AutomergeACL,
  AutomergeJSONSerializer,
  AutomergeProvider,
  serializeKey,
} from './peerborne-automerge.js';

type PropertyDocument = {
  values: Record<string, GeneratedValue>;
  witnessA?: number;
  witnessB?: number;
};

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

describe('Automerge provider generated delivery histories', () => {
  beforeAll(() => {
    jest.spyOn(Date, 'now').mockReturnValue(0);
  });
  afterAll(() => {
    jest.restoreAllMocks();
  });

  test('converges after concurrent edits, reordered duplicates, late ancestry and snapshot recovery', () => {
    const provider = new AutomergeProvider<PropertyDocument>();
    const serializer = new AutomergeJSONSerializer();
    fc.assert(
      fc.property(program, program, (editsA, editsB) => {
        const genesis = from<PropertyDocument>({ values: {} }, { actor: '01' });
        const packets: { changes: Change[]; priority: number }[] = [];
        const run = (
          actor: string,
          edits: typeof editsA,
          witness: 'witnessA' | 'witnessB',
        ) => {
          let doc = clone(genesis, { actor });
          let changes: Change[];
          [doc, changes] = provider.localChange(doc, '', (draft) => {
            draft[witness] = 1;
          });
          packets.push({ changes, priority: 0 });
          const expected: Record<string, GeneratedValue> = {};
          for (const operation of edits) {
            [doc, changes] = provider.localChange(doc, '', (draft) => {
              if (operation.remove) delete draft.values[operation.key];
              else draft.values[operation.key] = operation.value;
            });
            if (operation.remove) delete expected[operation.key];
            else expected[operation.key] = operation.value;
            packets.push({ changes, priority: operation.priority });
          }
          expect(doc.values).toEqual(expected);
          return doc;
        };
        let a = run('02', editsA, 'witnessA');
        let b = run('03', editsB, 'witnessB');
        let late = init<PropertyDocument>({ actor: '04' });
        const ordered = [...packets].sort(
          (left, right) => left.priority - right.priority,
        );
        const wire = (changes: Change[]) =>
          serializer.deserializeChanges(serializer.serializeChanges(changes));
        for (const packet of ordered) {
          a = provider.remoteChange(a, wire(packet.changes));
          a = provider.remoteChange(a, wire(packet.changes));
          late = provider.remoteChange(late, wire(packet.changes));
        }
        for (const packet of [...ordered].reverse()) {
          b = provider.remoteChange(b, wire(packet.changes));
          b = provider.remoteChange(b, wire(packet.changes));
        }
        late = provider.remoteChange(late, wire(provider.getHistory(genesis)));
        expect(a).toEqual(b);
        expect(late).toEqual(a);
        expect(a.witnessA).toBe(1);
        expect(a.witnessB).toBe(1);
        const snapshot = provider.getSnapshot(a);
        let recovered = provider.applySnapshot(
          init<PropertyDocument>({ actor: '05' }),
          wire(snapshot),
        );
        expect(recovered).toEqual(a);
        recovered = provider.applySnapshot(recovered, wire(snapshot));
        expect(recovered).toEqual(a);
        const fromHistory: Doc<PropertyDocument> = provider.remoteChange(
          init<PropertyDocument>({ actor: '06' }),
          wire(provider.getHistory(a)),
        );
        expect(fromHistory).toEqual(a);
      }),
      { seed: 9430, numRuns: 150, examples: [[[], []]] },
    );
  });

  test('recovers pruned history when the retained tail arrives before its snapshot', () => {
    const provider = new AutomergeProvider<PropertyDocument>();
    const serializer = new AutomergeJSONSerializer();
    const wire = (changes: Change[]) =>
      serializer.deserializeChanges(serializer.serializeChanges(changes));
    fc.assert(
      fc.property(
        program,
        fc.nat(),
        fc.nat(),
        (edits, snapshotSeed, tailSeed) => {
          const genesis = from<PropertyDocument>(
            { values: {} },
            { actor: '01' },
          );
          let source = clone(genesis, { actor: '02' });
          const packets: Change[][] = [provider.getHistory(genesis)];
          const covered = 1 + (snapshotSeed % (edits.length + 1));
          let snapshot =
            covered === 1 ? provider.getSnapshot(source) : undefined;
          for (const operation of edits) {
            let changes: Change[];
            [source, changes] = provider.localChange(source, '', (draft) => {
              if (operation.remove) delete draft.values[operation.key];
              else draft.values[operation.key] = operation.value;
            });
            packets.push(changes);
            if (packets.length === covered)
              snapshot = provider.getSnapshot(source);
          }
          let recovered = init<PropertyDocument>({ actor: '03' });
          for (const changes of packets.slice(tailSeed % (covered + 1))) {
            recovered = provider.remoteChange(recovered, wire(changes));
          }
          recovered = provider.applySnapshot(recovered, wire(snapshot!));
          expect(recovered).toEqual(source);
        },
      ),
      { seed: 9432, numRuns: 150, examples: [[[], 0, 0]] },
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

describe('Automerge ACL generated delivery orders', () => {
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
    const members = async (acl: AutomergeACL) =>
      (await Promise.all((await acl.users()).map(serializeKey))).sort();
    await fc.assert(
      fc.asyncProperty(aclProgram, async (operations) => {
        const sender = new AutomergeACL();
        const packets: { changes: Change[]; priority: number }[] = [];
        for (const { key, remove, priority } of operations) {
          const changes = remove
            ? await sender.remove(keys[key]!)
            : await sender.add(keys[key]!);
          packets.push({ changes, priority });
        }
        const ordered = packets
          .sort((left, right) => left.priority - right.priority)
          .map(({ changes }) => changes);
        const receiver = new AutomergeACL();
        let waiting: Change[][] = [];
        for (const changes of [...ordered, ...ordered.reverse()]) {
          waiting = mergeACLChanges(receiver, [...waiting, changes]);
          expect(() => receiver.current()).not.toThrow();
          await receiver.users();
        }
        expect(waiting).toEqual([]);
        expect(await members(receiver)).toEqual(await members(sender));
      }),
      { seed: 9434, numRuns: 60, examples: [[[]]] },
    );
  }, 60_000);
});
