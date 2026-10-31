import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  changeDocument,
  closeDocument,
  openDocument,
  peerConnect,
  peerDisconnect,
  syncDocument,
} from './actions.js';
import { peerborneReducer, type PeerborneState } from './reducers.js';

const operation = fc.record({
  kind: fc.constantFrom(
    'open',
    'close',
    'change',
    'sync',
    'connect',
    'disconnect',
  ),
  id: fc.constantFrom('a', 'b', 'c', '__proto__', 'constructor'),
  value: fc.integer(),
});
type State = PeerborneState<any, any, any, any, any, any>;

describe('generated Redux action histories', () => {
  test('matches a Map oracle without mutating previous states or interpreting inherited document names', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      fc.assert(
        fc.property(fc.array(operation, { maxLength: 100 }), (program) => {
          const reducer = peerborneReducer(
            {} as any,
            {} as any,
            {} as any,
            {} as any,
            {} as any,
            {} as any,
            {} as any,
            {} as any,
            {} as any,
          );
          let state: State = { node: {} as any, documents: {}, peers: [] };
          const docs = new Map<
            string,
            { ref: any; document: { version: number } }
          >();
          const peers: string[] = [];
          for (const step of program) {
            Object.values(state.documents).forEach(Object.freeze);
            Object.freeze(state.documents);
            Object.freeze(state.peers);
            Object.freeze(state);
            const previous = state;
            const document = { version: step.value };
            const known = docs.has(step.id);
            if (step.kind === 'open') {
              const ref = { document };
              state = reducer(state, openDocument(step.id, ref as any));
              docs.set(step.id, { ref, document });
            } else if (step.kind === 'close') {
              state = reducer(state, closeDocument(step.id));
              docs.delete(step.id);
              if (!known) expect(state).toBe(previous);
            } else if (step.kind === 'change' || step.kind === 'sync') {
              const action =
                step.kind === 'change'
                  ? changeDocument(step.id, document)
                  : syncDocument(step.id, document);
              state = reducer(state, action);
              if (known) docs.get(step.id)!.document = document;
              else expect(state).toBe(previous);
            } else if (step.kind === 'connect') {
              state = reducer(state, peerConnect(step.id));
              if (!peers.includes(step.id)) peers.push(step.id);
              else expect(state).toBe(previous);
            } else {
              state = reducer(state, peerDisconnect(step.id));
              const index = peers.indexOf(step.id);
              if (index === -1) expect(state).toBe(previous);
              else peers.splice(index, 1);
            }
            expect(state.node).toBe(previous.node);
            expect(state.peers).toEqual(peers);
            expect(Object.keys(state.documents).sort()).toEqual(
              [...docs.keys()].sort(),
            );
            for (const [id, value] of docs) {
              expect(Object.hasOwn(state.documents, id)).toBe(true);
              expect(state.documents[id].documentRef).toBe(value.ref);
              expect(state.documents[id].document).toBe(value.document);
            }
          }
        }),
        {
          seed: 9531,
          numRuns: 300,
          examples: [
            [[{ kind: 'open', id: '__proto__', value: 0 }]],
            [[{ kind: 'close', id: 'constructor', value: 0 }]],
          ],
        },
      );
    } finally {
      warn.mockRestore();
    }
  });
});
