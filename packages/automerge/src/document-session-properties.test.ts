import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { AutomergeProvider } from './peerborne-automerge.js';

describe('Automerge admitted document sessions', () => {
  test('keeps rejected and failed preparations invisible across generated local edits', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            value: fc.integer(),
            commit: fc.boolean(),
            fail: fc.boolean(),
          }),
          { maxLength: 30 },
        ),
        (operations) => {
          const provider = new AutomergeProvider<{ value: number }>();
          const session = provider.createDocumentSession(
            provider.newDocument(),
          );
          let expected: number | undefined;
          for (const operation of operations) {
            if (operation.fail) {
              expect(() =>
                session.prepareLocal('', (draft) => {
                  draft.value = operation.value;
                  throw new Error('synthetic');
                }),
              ).toThrow('synthetic');
            } else {
              const prepared = session.prepareLocal('', (draft) => {
                draft.value = operation.value;
              });
              expect(session.document.value).toBe(expected);
              expect(prepared.isCurrent()).toBe(true);
              if (operation.commit) {
                prepared.commit();
                prepared.commit();
                expected = operation.value;
              } else prepared.discard();
              expect(prepared.isCurrent()).toBe(false);
            }
            expect(session.document.value).toBe(expected);
          }
          session.close();
        },
      ),
      { seed: 2011121, numRuns: 80 },
    );
  });

  test('rejects orphaned native changes without advancing the live document', () => {
    const provider = new AutomergeProvider<{ value: number }>();
    const sender = provider.createDocumentSession(provider.newDocument());
    const receiver = provider.createDocumentSession(provider.newDocument());
    const first = sender.prepareLocal('', (draft) => {
      draft.value = 1;
    });
    first.commit();
    const second = sender.prepareLocal('', (draft) => {
      draft.value = 2;
    });
    second.commit();
    expect(() => receiver.prepareRemote(second.changes)).toThrow(
      'causal dependencies',
    );
    expect(receiver.document.value).toBeUndefined();
    receiver.prepareRemote(first.changes).commit();
    receiver.prepareRemote(second.changes).commit();
    expect(receiver.document.value).toBe(2);
    sender.close();
    receiver.close();
  });
});
