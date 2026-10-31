import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { YjsJSONSerializer, YjsProvider } from './peerborne-yjs.js';

const edit = fc.record({
  key: fc.integer({ min: 0, max: 5 }).map((index) => `key${index}`),
  value: fc.integer(),
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
            const expected: Record<string, number> = {};
            for (const operation of edits) {
              const [, changes] = provider.localChange(doc, '', (draft) => {
                const values = draft.getMap<number>('values');
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
});
