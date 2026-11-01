import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { YjsProvider } from './peerborne-yjs.js';
import { type Doc, Map as SharedMap, XmlElement } from 'yjs';

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

test('reserves callbacks and preserves native checkpoint isolation and concurrent state', () => {
  fc.assert(
    fc.property(fc.integer(), fc.integer(), (value, concurrent) => {
      const provider = new YjsProvider(),
        source = provider.createDocumentSession(provider.newDocument()),
        target = provider.createDocumentSession(provider.newDocument());
      target
        .prepareLocal('', (draft) => {
          draft.getMap('values').set('concurrent', concurrent);
        })
        .commit();
      let escaped!: Doc;
      const pending = source.prepareLocal('', (draft) => {
        escaped = draft;
        draft.getMap('values').set('value', value);
        expect(() =>
          source.prepareLocal('', (nested) => {
            nested.getMap('values').set('hidden', 99);
          }),
        ).toThrow('busy');
      });
      const checkpoint = pending.snapshot!();
      expect(source.document.getMap('values').size).toBe(0);
      const discarded = target.prepareSnapshot!(checkpoint);
      discarded.discard();
      expect(() => discarded.snapshot!()).toThrow('Stale');
      expect(target.document.getMap('values').toJSON()).toEqual({ concurrent });
      target.prepareSnapshot!(checkpoint).commit();
      expect(target.document.getMap('values').toJSON()).toEqual({
        value,
        concurrent,
      });
      escaped.getMap('values').set('hidden', 99);
      expect(() => pending.snapshot!()).toThrow('Stale');
      expect(() => pending.commit()).toThrow('stale');
      pending.discard();
      expect(source.document.getMap('values').size).toBe(0);
      expect(() =>
        target.prepareSnapshot!(new Uint8Array([1, 2, 3])),
      ).toThrow();
      expect(target.document.getMap('values').toJSON()).toEqual({
        value,
        concurrent,
      });
      const first = source.prepareLocal('', (draft) => {
        draft.getText('text').insert(0, 'hello');
      });
      first.commit();
      const second = source.prepareLocal('', (draft) => {
        draft.getText('text').insert(5, '!');
      });
      second.commit();
      const late = provider.createDocumentSession(provider.newDocument());
      expect(() => late.prepareSnapshot!(second.changes)).toThrow('causal');
      late.prepareSnapshot!(provider.getSnapshot(source.document)).commit();
      expect(late.document.getText('text').toString()).toBe('hello!');
      source.close();
      target.close();
      late.close();
    }),
    { seed: 2011124, numRuns: 35 },
  );
});

test('rejects retained mutable Any, binary, embed and formatting payloads before visible application', () => {
  const provider = new YjsProvider(),
    visible = provider.newDocument(),
    session = provider.createDocumentSession(visible);
  const object = { nested: { value: 1 } };
  for (const value of [object, [1, 2], new Uint8Array([1, 2])]) {
    expect(() =>
      session.prepareLocal('', (draft) => {
        draft.getMap('values').set('unsafe', value);
      }),
    ).toThrow('shared Yjs types');
    expect(visible.getMap('values').size).toBe(0);
  }
  object.nested.value = 99;
  session
    .prepareLocal('', (draft) => {
      draft.getMap('values').set('safe', 1);
    })
    .commit();
  const plain = provider.newDocument();
  const [, unsafe] = provider.localChange(plain, '', (draft) => {
    draft.getMap('values').set('unsafe', object);
  });
  expect(() => session.prepareRemote(unsafe)).toThrow('shared Yjs types');
  expect(() => provider.createDocumentSession(plain)).toThrow(
    'shared Yjs types',
  );
  expect(() =>
    session.prepareLocal('', (draft) => {
      draft.getText('text').insertEmbed(0, { unsafe: true });
    }),
  ).toThrow('shared Yjs types');
  session
    .prepareLocal('', (draft) => {
      draft.getText('text').insert(0, 'safe');
    })
    .commit();
  expect(() =>
    session.prepareLocal('', (draft) => {
      draft.getText('text').format(0, 1, { style: { unsafe: true } });
    }),
  ).toThrow('shared Yjs types');
  expect(visible.getMap('values').toJSON()).toEqual({ safe: 1 });
  expect(visible.getText('text').toString()).toBe('safe');
  session.close();
  visible.destroy();
  plain.destroy();
});

test('shared Map values retain update tracking while opaque XML metadata is rejected', () => {
  const provider = new YjsProvider(),
    document = provider.newDocument(),
    session = provider.createDocumentSession(document),
    nested = new SharedMap<number>();
  nested.set('value', 1);
  session
    .prepareLocal('', (draft) => {
      draft.getMap('values').set('nested', nested);
    })
    .commit();
  nested.set('value', 99);
  expect(
    (document.getMap('values').get('nested') as SharedMap<number>).get('value'),
  ).toBe(1);
  session
    .prepareLocal('', (draft) => {
      draft.getMap('values').set('safe', 2);
    })
    .commit();
  expect(
    (document.getMap('values').get('nested') as SharedMap<number>).get('value'),
  ).toBe(1);
  expect(() =>
    session.prepareLocal('', (draft) => {
      draft.getXmlFragment('xml').insert(0, [new XmlElement('unsafe')]);
    }),
  ).toThrow('Y.Map, Y.Array and Y.Text');
  expect(document.getXmlFragment('xml').length).toBe(0);
  session.close();
  document.destroy();
});
