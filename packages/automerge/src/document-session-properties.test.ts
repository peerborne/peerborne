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

test('reserves callbacks and checkpoints atomically, merges concurrent state, and rejects malformed saves', () => {
  fc.assert(
    fc.property(fc.integer(), fc.integer(), (value, concurrent) => {
      const provider = new AutomergeProvider<{
        value?: number;
        concurrent?: number;
      }>();
      const source = provider.createDocumentSession(provider.newDocument());
      const target = provider.createDocumentSession(provider.newDocument());
      target
        .prepareLocal('', (draft) => {
          draft.concurrent = concurrent;
        })
        .commit();
      const pending = source.prepareLocal('', (draft) => {
        draft.value = value;
        expect(() =>
          source.prepareLocal('', (nested) => {
            nested.value = 99;
          }),
        ).toThrow('busy');
        expect(() =>
          source.prepareSnapshot!(provider.getSnapshot(provider.newDocument())),
        ).toThrow('busy');
      });
      const checkpoint = pending.snapshot!();
      expect(source.document.value).toBeUndefined();
      const discarded = target.prepareSnapshot!(checkpoint);
      expect(target.document.value).toBeUndefined();
      const merged = discarded.snapshot!();
      discarded.discard();
      expect(() => discarded.snapshot!()).toThrow('Stale');
      expect(target.document).toMatchObject({ concurrent });
      const accepted = target.prepareSnapshot!(merged);
      accepted.commit();
      expect(target.document).toMatchObject({ value, concurrent });
      expect(() => accepted.snapshot!()).toThrow('Stale');
      pending.commit();
      expect(() => pending.snapshot!()).toThrow('Stale');
      expect(() =>
        source.prepareLocal('', () => {
          throw new Error('callback failed');
        }),
      ).toThrow('callback failed');
      source
        .prepareLocal('', (draft) => {
          draft.value = 2;
        })
        .commit();
      expect(() =>
        target.prepareSnapshot!([new Uint8Array([1, 2, 3]) as any]),
      ).toThrow();
      expect(target.document).toMatchObject({ value, concurrent });
      source.close();
      target.close();
    }),
    { seed: 2011123, numRuns: 35 },
  );
});

test('burns discarded actor positions before a later plan can meet retained changes or checkpoints', () => {
  const provider = new AutomergeProvider<{
      discarded?: number;
      accepted?: number;
    }>(),
    source = provider.createDocumentSession(provider.newDocument()),
    target = provider.createDocumentSession(provider.newDocument());
  const discarded = source.prepareLocal('', (draft) => {
    draft.discarded = 1;
  });
  const checkpoint = discarded.snapshot!(),
    changes = discarded.changes;
  discarded.discard();
  const accepted = source.prepareLocal('', (draft) => {
    draft.accepted = 2;
  });
  accepted.commit();
  target.prepareSnapshot!(checkpoint).commit();
  expect(() => target.prepareRemote(accepted.changes).commit()).not.toThrow();
  expect(target.document).toMatchObject({ discarded: 1, accepted: 2 });
  const fromChanges = provider.createDocumentSession(provider.newDocument());
  fromChanges.prepareRemote(changes).commit();
  fromChanges.prepareRemote(accepted.changes).commit();
  expect(fromChanges.document).toMatchObject({ discarded: 1, accepted: 2 });
  source.close();
  target.close();
  fromChanges.close();
});
