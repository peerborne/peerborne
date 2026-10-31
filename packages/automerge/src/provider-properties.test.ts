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
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
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
});
