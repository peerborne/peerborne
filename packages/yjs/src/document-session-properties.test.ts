import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { YjsProvider } from './peerborne-yjs.js';
import type { Doc } from 'yjs';

describe('Yjs admitted document sessions', () => {
  test('keeps preparation private and rejects escaped-stage mutations', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            value: fc.integer(),
            commit: fc.boolean(),
            escape: fc.boolean(),
          }),
          { maxLength: 35 },
        ),
        (operations) => {
          const provider = new YjsProvider();
          const initial = provider.newDocument();
          const session = provider.createDocumentSession(initial);
          let expected: number | undefined;
          for (const operation of operations) {
            let escaped!: Doc;
            const prepared = session.prepareLocal('', (draft) => {
              escaped = draft;
              draft.getMap('values').set('value', operation.value);
            });
            expect(initial.getMap('values').get('value')).toBe(expected);
            if (operation.escape) escaped.getMap('values').set('hidden', true);
            expect(prepared.isCurrent()).toBe(!operation.escape);
            if (operation.commit && !operation.escape) {
              prepared.commit();
              prepared.commit();
              expected = operation.value;
              escaped.getMap('values').set('hidden', true);
            } else prepared.discard();
            expect(session.document).toBe(initial);
            expect(initial.getMap('values').get('value')).toBe(expected);
            expect(initial.getMap('values').has('hidden')).toBe(false);
          }
          session.close();
          initial.destroy();
        },
      ),
      { seed: 2011122, numRuns: 80 },
    );
  });

  test('reuses its mirror for 1000 accepted edits and rejects missing native dependencies', () => {
    const provider = new YjsProvider();
    const snapshots = jest.spyOn(provider, 'getSnapshot');
    const initial = provider.newDocument();
    const session = provider.createDocumentSession(initial);
    for (let index = 0; index < 1000; index++)
      session
        .prepareLocal('', (draft) => {
          draft.getMap('values').set('value', index);
        })
        .commit();
    expect(session.document.getMap('values').get('value')).toBe(999);
    expect(initial.store.clients.size).toBe(1);
    expect(snapshots).toHaveBeenCalledTimes(1);
    const sender = provider.createDocumentSession(provider.newDocument());
    const receiver = provider.createDocumentSession(provider.newDocument());
    const first = sender.prepareLocal('', (draft) => {
      draft.getText('text').insert(0, 'first');
    });
    first.commit();
    const second = sender.prepareLocal('', (draft) => {
      draft.getText('text').insert(5, 'second');
    });
    second.commit();
    expect(() => receiver.prepareRemote(second.changes)).toThrow(
      'causal dependencies',
    );
    expect(receiver.document.getText('text').toString()).toBe('');
    receiver.prepareRemote(first.changes).commit();
    receiver.prepareRemote(second.changes).commit();
    expect(receiver.document.getText('text').toString()).toBe('firstsecond');
    session.close();
    sender.close();
    receiver.close();
    initial.destroy();
  });
});
