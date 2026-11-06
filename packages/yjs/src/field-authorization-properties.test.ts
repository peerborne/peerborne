import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import * as Y from 'yjs';
import {
  assertDocumentOperationsAllowed,
  DocumentOperationTargets,
} from '@peerborne/core';
import { YjsProvider, YjsJSONSerializer } from './peerborne-yjs.js';
import { fieldDocumentFixture } from '../../core/src/__testutils__/field-authorization.js';
import { writeVarUint } from 'lib0/encoding';
import { recordYjsOperationTargets } from './operation-targets.js';

const initial = () => {
  const document = new Y.Doc();
  document.clientID = 10;
  const profile = new Y.Map<unknown>([
    ['name', 'seed'],
    ['permissions', 1],
  ]);
  const item = new Y.Map<unknown>([['value', 1]]);
  const items = new Y.Array<unknown>();
  items.push([item]);
  document.getMap('root').set('profile', profile);
  document.getMap('root').set('items', items);
  document.getMap('root').set('allowed', 0);
  return document;
};
const clone = (base: Y.Doc, client: number) => {
  const doc = new Y.Doc({ gc: base.gc });
  for (const [name, root] of base.share) {
    if (root instanceof Y.Map) doc.getMap(name);
    if (root instanceof Y.Array) doc.getArray(name);
    if (root instanceof Y.Text) doc.getText(name);
  }
  Y.applyUpdateV2(doc, Y.encodeStateAsUpdateV2(base));
  doc.clientID = client;
  return doc;
};
const pathsOf = (paths: readonly (readonly string[])[]) =>
  [...new Set(paths.map((path) => JSON.stringify(path)))].sort();

test('inspects native maps and deletes before GC, and refuses writes to ancestors or unrelated fields', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: 4 }),
      fc.integer({ min: 2, max: 1000 }),
      (kind, value) => {
        const document = initial(),
          session = new YjsProvider().createDocumentSession(document);
        const plan = session.prepareLocal(
          '',
          (draft) => {
            const root = draft.getMap('root'),
              profile = root.get('profile') as Y.Map<unknown>;
            if (kind === 0) profile.set('name', String(value));
            if (kind === 1) profile.set('permissions', value);
            if (kind === 2) root.delete('profile');
            if (kind === 3)
              root.set('profile', new Y.Map([['name', String(value)]]));
            if (kind === 4)
              (root.get('items') as Y.Array<Y.Map<unknown>>)
                .get(0)
                .set('value', value);
          },
          { inspectOperations: true },
        );
        const paths = pathsOf(plan.operationPaths!());
        expect(paths).toContain(
          JSON.stringify(
            kind === 0
              ? ['root', 'profile', 'name']
              : kind === 1
                ? ['root', 'profile', 'permissions']
                : kind === 4
                  ? ['root', 'items']
                  : ['root', 'profile'],
          ),
        );
        if (kind === 0)
          expect(() =>
            assertDocumentOperationsAllowed(plan, [
              ['root', 'profile', 'name'],
            ]),
          ).not.toThrow();
        else
          expect(() =>
            assertDocumentOperationsAllowed(plan, [
              ['root', 'profile', 'name'],
            ]),
          ).toThrow(/signed field grants/);
        expect(
          (document.getMap('root').get('profile') as Y.Map<unknown>).get(
            'permissions',
          ),
        ).toBe(1);
        plan.discard();
        session.close();
        document.destroy();
      },
    ),
    {
      seed: 2012321,
      numRuns: 45,
      examples: [
        [0, 2],
        [1, 2],
        [2, 2],
        [3, 2],
        [4, 2],
      ],
    },
  );
});

test('rejects a native concurrent losing map write even after the competing value wins', () => {
  fc.assert(
    fc.property(fc.integer({ min: 2, max: 1000 }), (value) => {
      const base = initial(),
        winning = clone(base, 100),
        losing = clone(base, 20);
      (winning.getMap('root').get('profile') as Y.Map<unknown>).set(
        'permissions',
        9999,
      );
      (losing.getMap('root').get('profile') as Y.Map<unknown>).set(
        'permissions',
        value,
      );
      const session = new YjsProvider().createDocumentSession(winning);
      const plan = session.prepareRemote(
        Y.encodeStateAsUpdateV2(losing, Y.encodeStateVector(base)),
        { inspectOperations: true },
      );
      expect(plan.operationPaths!()).toContainEqual([
        'root',
        'profile',
        'permissions',
      ]);
      expect(() =>
        assertDocumentOperationsAllowed(plan, [['root', 'allowed']]),
      ).toThrow(/signed field grants/);
      expect(
        (winning.getMap('root').get('profile') as Y.Map<unknown>).get(
          'permissions',
        ),
      ).toBe(9999);
      plan.discard();
      session.close();
      for (const doc of [base, winning, losing]) doc.destroy();
    }),
    { seed: 2012322, numRuns: 25 },
  );
});

test('sees insert-then-delete operations hidden by GC and requires grants for entire sequence containers', () => {
  fc.assert(
    fc.property(fc.integer({ min: 2, max: 1000 }), (value) => {
      const document = initial(),
        session = new YjsProvider().createDocumentSession(document);
      const hidden = session.prepareLocal(
        '',
        (draft) => {
          const root = draft.getMap('root');
          root.set('secret', new Y.Map([['value', value]]));
          root.delete('secret');
        },
        { inspectOperations: true },
      );
      expect(hidden.operationPaths!()).toContainEqual(['root', 'secret']);
      expect(() =>
        assertDocumentOperationsAllowed(hidden, [['root', 'allowed']]),
      ).toThrow();
      hidden.discard();
      const sequence = session.prepareLocal(
        '',
        (draft) => {
          (draft.getMap('root').get('items') as Y.Array<Y.Map<unknown>>)
            .get(0)
            .set('value', value);
        },
        { inspectOperations: true },
      );
      expect(sequence.operationPaths!()).toEqual([['root', 'items']]);
      expect(() =>
        assertDocumentOperationsAllowed(sequence, [['root', 'items', '0']]),
      ).toThrow();
      assertDocumentOperationsAllowed(sequence, [['root', 'items']]);
      sequence.commit();
      session.close();
      document.destroy();
    }),
    { seed: 2012323, numRuns: 20 },
  );
});

test('generated accepted/rejected histories preserve protected state and support replayed native deltas', () => {
  fc.assert(
    fc.property(
      fc.array(fc.boolean(), { minLength: 10, maxLength: 35 }),
      (accepted) => {
        const document = initial(),
          session = new YjsProvider().createDocumentSession(document);
        let expected = 0;
        for (let index = 0; index < accepted.length; index++) {
          const plan = session.prepareLocal(
            '',
            (draft) => {
              draft.getMap('root').set('allowed', index + 1);
            },
            { inspectOperations: true },
          );
          assertDocumentOperationsAllowed(plan, [['root', 'allowed']]);
          if (accepted[index]) {
            plan.commit();
            expected = index + 1;
          } else plan.discard();
          expect(document.getMap('root').get('allowed')).toBe(expected);
          const replay = session.prepareRemote(
            Y.encodeStateAsUpdateV2(document),
            { inspectOperations: true },
          );
          expect(replay.operationPaths!()).toEqual([]);
          assertDocumentOperationsAllowed(replay, []);
          replay.commit();
        }
        session.close();
        document.destroy();
      },
    ),
    { seed: 2012324, numRuns: 15 },
  );
});

test('the encrypted document boundary rejects signed out-of-scope Yjs changes before WAL admission', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 2, max: 1000 }), async (value) => {
      const f = await fieldDocumentFixture(
        new YjsProvider(),
        new YjsJSONSerializer(),
        [['root', 'allowed']],
      );
      const base = initial(),
        received = clone(base, 30),
        compromised = clone(base, 40),
        local = clone(base, 50);
      const receiver = f.create(received, false, true),
        attacker = f.create(compromised, true),
        honest = f.create(local);
      await receiver.activate();
      const stages = jest.spyOn(f.store, 'stage');
      const bad = await attacker.change((draft) => {
        (draft.getMap('root').get('profile') as Y.Map<unknown>).set(
          'permissions',
          value,
        );
      });
      await expect(receiver.receive(bad)).rejects.toThrow(
        /signed field grants/,
      );
      expect(stages).not.toHaveBeenCalled();
      expect(
        (received.getMap('root').get('profile') as Y.Map<unknown>).get(
          'permissions',
        ),
      ).toBe(1);
      expect((await f.store.load(f.storageKey)).entries).toHaveLength(0);
      await expect(
        honest.change((draft) => {
          (draft.getMap('root').get('profile') as Y.Map<unknown>).set(
            'permissions',
            value,
          );
        }),
      ).rejects.toThrow(/signed field grants/);
      const good = await honest.change((draft) => {
        draft.getMap('root').set('allowed', value);
      });
      expect(await receiver.receive(good)).toBe(true);
      expect(await receiver.receive(good)).toBe(false);
      expect(received.getMap('root').get('allowed')).toBe(value);
      expect(
        (received.getMap('root').get('profile') as Y.Map<unknown>).get(
          'permissions',
        ),
      ).toBe(1);
      expect(stages).toHaveBeenCalledTimes(1);
      for (const document of [receiver, attacker, honest])
        await document.close();
      stages.mockRestore();
      for (const doc of [base, received, compromised, local]) doc.destroy();
    }),
    { seed: 2012325, numRuns: 8 },
  );
});

function encodeItem(item: Y.Item, deleted?: Y.Item): Uint8Array {
  const encoder = new Y.UpdateEncoderV2();
  writeVarUint(encoder.restEncoder, 1);
  writeVarUint(encoder.restEncoder, 1);
  encoder.writeClient(item.id.client);
  writeVarUint(encoder.restEncoder, item.id.clock);
  item.write(encoder, 0);
  writeVarUint(encoder.restEncoder, deleted ? 1 : 0);
  if (deleted) {
    encoder.resetDsCurVal();
    writeVarUint(encoder.restEncoder, deleted.id.client);
    writeVarUint(encoder.restEncoder, 1);
    encoder.writeDsClock(deleted.id.clock);
    encoder.writeDsLen(deleted.length);
  }
  return encoder.toUint8Array();
}

test('forged routing labels cannot hide the actual native origin or right-origin parent', () => {
  fc.assert(
    fc.property(
      fc.boolean(),
      fc.integer({ min: 2, max: 1000 }),
      (right, value) => {
        const base = initial(),
          sender = clone(base, 20);
        const victim = (
          base.getMap('root').get('profile') as Y.Map<unknown>
        )._map.get('permissions')!;
        sender.getMap('root').set('allowed', value);
        const [struct] = Y.decodeUpdateV2(
          Y.encodeStateAsUpdateV2(sender, Y.encodeStateVector(base)),
        ).structs;
        expect(struct).toBeInstanceOf(Y.Item);
        const item = struct as Y.Item;
        item.origin = right ? null : victim.id;
        item.rightOrigin = right ? victim.id : null;
        item.parentSub = 'allowed';
        Object.assign(item, { parent: 'root' });
        const receiver = clone(base, 30),
          session = new YjsProvider().createDocumentSession(receiver);
        const plan = session.prepareRemote(encodeItem(item), {
          inspectOperations: true,
        });
        expect(plan.operationPaths!()).toContainEqual([
          'root',
          'profile',
          'permissions',
        ]);
        expect(() =>
          assertDocumentOperationsAllowed(plan, [['root', 'allowed']]),
        ).toThrow();
        plan.discard();
        session.close();
        for (const doc of [base, sender, receiver]) doc.destroy();
      },
    ),
    {
      seed: 2012326,
      numRuns: 24,
      examples: [
        [true, 2],
        [false, 2],
      ],
    },
  );
});

test('raw deletion sets cannot smuggle a protected deletion alongside an allowed insertion', () => {
  fc.assert(
    fc.property(fc.integer({ min: 2, max: 1000 }), (value) => {
      const base = initial(),
        sender = clone(base, 20);
      const victim = (
        base.getMap('root').get('profile') as Y.Map<unknown>
      )._map.get('permissions')!;
      sender.getMap('root').set('allowed', value);
      const [struct] = Y.decodeUpdateV2(
        Y.encodeStateAsUpdateV2(sender, Y.encodeStateVector(base)),
      ).structs;
      const receiver = clone(base, 30),
        session = new YjsProvider().createDocumentSession(receiver);
      const plan = session.prepareRemote(encodeItem(struct as Y.Item, victim), {
        inspectOperations: true,
      });
      expect(plan.operationPaths!()).toContainEqual(['root', 'allowed']);
      expect(plan.operationPaths!()).toContainEqual([
        'root',
        'profile',
        'permissions',
      ]);
      expect(() =>
        assertDocumentOperationsAllowed(plan, [['root', 'allowed']]),
      ).toThrow();
      plan.discard();
      session.close();
      expect(
        (receiver.getMap('root').get('profile') as Y.Map<unknown>).get(
          'permissions',
        ),
      ).toBe(1);
      for (const doc of [base, sender, receiver]) doc.destroy();
    }),
    { seed: 2012327, numRuns: 20 },
  );
});

test('native inspection scans root bindings once per transaction rather than once per operation', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 5, max: 25 }),
      fc.integer({ min: 30, max: 80 }),
      (roots, operations) => {
        const document = new Y.Doc();
        for (let index = 0; index < roots; index++)
          document.getMap(`root-${index}`);
        document.once('beforeObserverCalls', (transaction: Y.Transaction) => {
          const iterate = document.share[Symbol.iterator].bind(document.share);
          let visited = 0;
          Object.defineProperty(document.share, Symbol.iterator, {
            configurable: true,
            value: function* () {
              for (const entry of iterate()) {
                visited++;
                yield entry;
              }
            },
          });
          const targets = new DocumentOperationTargets();
          try {
            recordYjsOperationTargets(transaction, targets);
            expect(visited).toBe(roots);
            expect(targets.snapshot()).toHaveLength(operations);
          } finally {
            Reflect.deleteProperty(document.share, Symbol.iterator);
          }
        });
        document.transact(() => {
          for (let index = 0; index < operations; index++)
            document.getMap('root-0').set(`field-${index}`, index);
        });
        document.destroy();
      },
    ),
    { seed: 2012328, numRuns: 20 },
  );
});

test('text attributes require the container grant and unknown root schemas fail closed until declared', () => {
  fc.assert(
    fc.property(
      fc.boolean(),
      fc.integer({ min: 2, max: 1000 }),
      (unknown, value) => {
        const document = new Y.Doc();
        if (unknown) {
          const sender = new Y.Doc();
          sender.getMap('new-root').set('allowed', value);
          const changes = Y.encodeStateAsUpdateV2(sender);
          const session = new YjsProvider().createDocumentSession(document);
          expect(() =>
            session.prepareRemote(changes, { inspectOperations: true }),
          ).toThrow(/inspection failed/);
          expect(document.share.size).toBe(0);
          document.getMap('new-root');
          const plan = session.prepareRemote(changes, {
            inspectOperations: true,
          });
          assertDocumentOperationsAllowed(plan, [['new-root', 'allowed']]);
          plan.commit();
          expect(document.getMap('new-root').get('allowed')).toBe(value);
          session.close();
          sender.destroy();
        } else {
          document.getText('text').insert(0, 'seed');
          const session = new YjsProvider().createDocumentSession(document);
          const plan = session.prepareLocal(
            '',
            (draft) => {
              draft.getText('text').setAttribute('role', value);
            },
            { inspectOperations: true },
          );
          expect(plan.operationPaths!()).toEqual([['text']]);
          expect(() =>
            assertDocumentOperationsAllowed(plan, [['text', 'role']]),
          ).toThrow();
          assertDocumentOperationsAllowed(plan, [['text']]);
          plan.discard();
          session.close();
        }
        document.destroy();
      },
    ),
    {
      seed: 2012329,
      numRuns: 20,
      examples: [
        [false, 2],
        [true, 2],
      ],
    },
  );
});

test('authorized nested create/delete changes round-trip after GC and do not strand the next signed frame', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.boolean(),
      fc.boolean(),
      fc.integer({ min: 2, max: 1000 }),
      async (gc, together, value) => {
        const f = await fieldDocumentFixture(
          new YjsProvider(),
          new YjsJSONSerializer(),
          [['root', 'allowed']],
        );
        const base = initial();
        base.gc = gc;
        const local = clone(base, 20),
          remote = clone(base, 30);
        const sender = f.create(local),
          receiver = f.create(remote, false, true);
        let mirror!: Y.Doc;
        await receiver.activate();
        const first = await sender.change((draft) => {
          mirror = draft;
          const edit = () => {
            const root = draft.getMap('root');
            root.set('allowed', new Y.Map([['nested', value]]));
            root.delete('allowed');
          };
          if (together) draft.transact(edit);
          else edit();
        });
        expect(await receiver.receive(first)).toBe(true);
        expect(remote.getMap('root').has('allowed')).toBe(false);
        expect(mirror.gc).toBe(gc);
        expect(Y.encodeStateAsUpdateV2(mirror)).toEqual(
          Y.encodeStateAsUpdateV2(local),
        );
        const second = await sender.change((draft) => {
          draft.getMap('root').set('allowed', value);
        });
        expect(await receiver.receive(second)).toBe(true);
        expect(remote.getMap('root').get('allowed')).toBe(value);
        await sender.close();
        await receiver.close();
        for (const doc of [base, local, remote]) doc.destroy();
      },
    ),
    {
      seed: 2012330,
      numRuns: 12,
      examples: [
        [true, true, 2],
        [true, false, 2],
        [false, true, 2],
        [false, false, 2],
      ],
    },
  );
});

test('native GC callbacks cannot add unencoded state after operation inspection', () => {
  fc.assert(
    fc.property(fc.integer({ min: 2, max: 1000 }), (value) => {
      const document = initial(),
        session = new YjsProvider().createDocumentSession(document);
      let changed = false;
      expect(() =>
        session.prepareLocal(
          '',
          (draft) => {
            draft.gcFilter = () => {
              if (!changed) {
                changed = true;
                draft.getMap('root').set('protected', value);
              }
              return true;
            };
            draft.getMap('root').set('allowed', new Y.Map([['nested', value]]));
            draft.getMap('root').delete('allowed');
          },
          { inspectOperations: true },
        ),
      ).toThrow(/collecting staged garbage/);
      expect(changed).toBe(true);
      expect(document.getMap('root').has('protected')).toBe(false);
      const valid = session.prepareLocal(
        '',
        (draft) => {
          draft.getMap('root').set('allowed', value);
        },
        { inspectOperations: true },
      );
      assertDocumentOperationsAllowed(valid, [['root', 'allowed']]);
      valid.commit();
      expect(document.getMap('root').get('allowed')).toBe(value);
      session.close();
      document.destroy();
    }),
    { seed: 2012331, numRuns: 12 },
  );
});
