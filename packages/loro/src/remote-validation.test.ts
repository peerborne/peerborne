import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';
import { readFileSync } from 'node:fs';
import {
  LoroDoc,
  LoroList,
  LoroMap,
  LoroText,
  UndoManager,
  type JsonSchema,
} from 'loro-crdt';
import { LoroProvider } from './index.js';

// Each fixture is an update to `baseSnapshot()` from an authorized writer whose
// client altered bytes of an ordinary update and recomputed Loro's xxHash32
// header checksum. loro-crdt 1.19.1 imports every one of them.
function fixture(name: string): Uint8Array {
  return new Uint8Array(
    readFileSync(new URL(`./fixtures/${name}.bin`, import.meta.url)),
  );
}

function baseSnapshot(): Uint8Array {
  const doc = new LoroDoc();
  doc.setPeerId('1');
  doc.getText('t').insert(0, 'hello world');
  doc.getMap('m').set('k', 1);
  doc.getList('l').push('a');
  doc.getList('l').push('b');
  doc.getMap('m').setContainer('sub', new LoroMap()).set('x', 'y');
  doc.getMovableList('ml').push(1);
  doc.getMovableList('ml').push(2);
  const node = doc.getTree('tr').createNode();
  node.data.set('name', 'root');
  doc.getTree('tr').createNode(node.id);
  doc.getCounter('c').increment(3);
  doc.getText('rt').insert(0, 'rich text');
  doc.getText('rt').mark({ start: 0, end: 4 }, 'bold', true);
  doc.commit();
  return doc.export({ mode: 'snapshot' });
}

function replica(
  provider: LoroProvider,
  snapshot: Uint8Array,
  peer: `${number}` = '2',
): LoroDoc {
  const doc = provider.newDocument();
  doc.setPeerId(peer);
  return provider.applySnapshot(doc, snapshot);
}

function rawReplica(...blobs: Uint8Array[]): LoroDoc {
  const doc = new LoroDoc();
  for (const blob of blobs) doc.import(blob);
  return doc;
}

function restart(provider: LoroProvider, doc: LoroDoc): LoroDoc {
  return provider.remoteChange(
    provider.newDocument(),
    provider.getHistory(doc),
  );
}

function expectRejected(
  provider: LoroProvider,
  doc: LoroDoc,
  changes: Uint8Array,
  reason?: string,
): void {
  const before = provider.getSnapshot(doc);
  const json = doc.toJSON();
  expect(() => provider.remoteChange(doc, changes)).toThrow(reason);
  expect(provider.getSnapshot(doc)).toEqual(before);
  expect(doc.toJSON()).toEqual(json);
  expect(doc.exportPendingUpdates()).toBeUndefined();
}

function expectDurable(provider: LoroProvider, doc: LoroDoc): void {
  const restarted = restart(provider, doc);
  expect(restarted.oplogVersion().compare(doc.oplogVersion())).toBe(0);
  expect(restarted.toJSON()).toEqual(doc.toJSON());
  const reloaded = rawReplica(provider.getSnapshot(doc));
  expect(reloaded.toJSON()).toEqual(doc.toJSON());
}

describe('Loro remote payload validation', () => {
  // Loro reports the panics these payloads trigger on the console.
  beforeEach(() => {
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('raw Loro imports the crafted updates, then reloads different or unreadable state', () => {
    const base = baseSnapshot();
    const differs = rawReplica(base, fixture('unknown-tree-container'));
    const shown = differs.toJSON();
    const reloaded = rawReplica(differs.export({ mode: 'snapshot' }));
    expect(reloaded.oplogVersion().compare(differs.oplogVersion())).toBe(0);
    expect(reloaded.toJSON()).not.toEqual(shown);

    const panics = rawReplica(base, fixture('unknown-list-container'));
    expect(() => panics.toJSON()).not.toThrow();
    const unreadable = rawReplica(panics.export({ mode: 'snapshot' }));
    expect(() => unreadable.toJSON()).toThrow();
  });

  test('rejects an update that loads from history with different content', () => {
    const provider = new LoroProvider();
    const live = replica(provider, baseSnapshot());
    expectRejected(
      provider,
      live,
      fixture('unknown-tree-container'),
      'unsupported container',
    );
    expectDurable(provider, live);
  });

  test('rejects an update that leaves a history that cannot be read after restart', () => {
    const provider = new LoroProvider();
    const live = replica(provider, baseSnapshot());
    expectRejected(
      provider,
      live,
      fixture('unknown-list-container'),
      'unsupported container',
    );
    expectDurable(provider, live);
  });

  test('rejects operations that reach outside their container or causal past', () => {
    const provider = new LoroProvider();
    const live = replica(provider, baseSnapshot());
    expectRejected(
      provider,
      live,
      fixture('foreign-text-delete'),
      'deletes elements it cannot see',
    );
    expectRejected(
      provider,
      live,
      fixture('missing-tree-node'),
      'tree node that does not exist',
    );
    expectDurable(provider, live);
  });

  test('rejects a container value whose ID is not its own operation', () => {
    const provider = new LoroProvider();
    const live = replica(provider, baseSnapshot());
    expectRejected(
      provider,
      live,
      fixture('lossy-nested-container'),
      'container with a foreign ID',
    );
    expectDurable(provider, live);
  });

  test('keeps an update whose dependency never arrives out of the document', () => {
    const provider = new LoroProvider();
    const live = replica(provider, baseSnapshot());
    const before = provider.getSnapshot(live);
    const roots = live.getShallowValue();
    expect(provider.remoteChange(live, fixture('waiting-unknown-root'))).toBe(
      live,
    );
    expect(live.getShallowValue()).toEqual(roots);
    expect(provider.getSnapshot(live)).toEqual(before);
    expectDurable(provider, live);
  });

  test('discards a waiting update that fails with the change that releases it and keeps the rest', () => {
    const provider = new LoroProvider();
    const complete = rawReplica(baseSnapshot());
    const partial = complete.forkAt([{ peer: '1', counter: 31 }]);
    const missing = complete.export({
      mode: 'update',
      from: partial.oplogVersion(),
    });
    const author = rawReplica(baseSnapshot());
    author.setPeerId('7');
    const [, dependent] = provider.localChange(author, 'after', (doc) => {
      doc.getMap('m').set('after', true);
    });
    const live = provider.remoteChange(
      provider.newDocument(),
      partial.export({ mode: 'update' }),
    );
    const before = provider.getSnapshot(live);
    const crafted = fixture('unknown-tree-container');
    for (const update of [crafted, dependent]) {
      expect(provider.remoteChange(live, update)).toBe(live);
      expect(provider.hasIntegrated(live, update)).toBe(false);
      expect(provider.hasDiscarded(live, update)).toBe(false);
    }
    expect(provider.getSnapshot(live)).toEqual(before);
    provider.remoteChange(live, missing);
    expect(live.oplogVersion().compare(author.oplogVersion())).toBe(0);
    expect(live.toJSON()).toEqual(author.toJSON());
    expect(provider.hasIntegrated(live, missing)).toBe(true);
    expect(provider.hasIntegrated(live, dependent)).toBe(true);
    expect(provider.hasDiscarded(live, dependent)).toBe(false);
    expect(provider.hasIntegrated(live, crafted)).toBe(false);
    expect(provider.hasDiscarded(live, crafted)).toBe(true);
    expectRejected(provider, live, crafted, 'unsupported container');
    expectDurable(provider, live);
  });

  test('accepts only full snapshots and applies their history, not their encoded state', () => {
    const provider = new LoroProvider();
    const source = replica(provider, baseSnapshot(), '3');
    provider.localChange(source, 'edit', (doc) => {
      doc.getText('t').insert(0, '>> ');
    });
    const shallow = source.export({
      mode: 'shallow-snapshot',
      frontiers: source.oplogFrontiers(),
    });
    const fresh = provider.newDocument();
    expect(() => provider.applySnapshot(fresh, shallow)).toThrow(
      'Expected a Loro snapshot, received shallow-snapshot',
    );
    expect(fresh.isShallow()).toBe(false);
    expect(fresh.oplogVersion().length()).toBe(0);
    expect(() =>
      provider.remoteChange(fresh, provider.getSnapshot(source)),
    ).toThrow('Expected a Loro update, received snapshot');
    expect(() =>
      provider.applySnapshot(fresh, provider.getHistory(source)),
    ).toThrow('Expected a Loro snapshot, received update');

    const poisoned = rawReplica(
      baseSnapshot(),
      fixture('unknown-list-container'),
    );
    expect(() =>
      provider.applySnapshot(fresh, poisoned.export({ mode: 'snapshot' })),
    ).toThrow('unsupported container');
    expect(fresh.oplogVersion().length()).toBe(0);
    const live = replica(provider, baseSnapshot());
    expectRejected(
      provider,
      live,
      poisoned.export({ mode: 'update', from: live.oplogVersion() }),
    );

    const offline = replica(provider, baseSnapshot(), '4');
    provider.localChange(offline, 'offline', (doc) => {
      doc.getText('t').insert(0, 'offline ');
    });
    provider.applySnapshot(offline, provider.getSnapshot(source));
    provider.applySnapshot(fresh, provider.getSnapshot(offline));
    expect(fresh.toJSON()).toEqual(offline.toJSON());
    const [, edit] = provider.localChange(fresh, 'after', (doc) => {
      doc.getMap('m').set('after', true);
    });
    provider.remoteChange(source, edit);
    expect(source.getMap('m').get('after')).toBeUndefined();
    provider.applySnapshot(source, provider.getSnapshot(offline));
    expect(source.toJSON()).toEqual(fresh.toJSON());
  });

  test('a checkpoint restore validates the history it replays', () => {
    const provider = new LoroProvider();
    for (const [name, reason] of [
      ['unknown-list-container', 'unsupported container'],
      ['foreign-text-delete', 'deletes elements it cannot see'],
      ['missing-tree-node', 'tree node that does not exist'],
      ['lossy-nested-container', 'container with a foreign ID'],
    ] as const) {
      const history = rawReplica(baseSnapshot(), fixture(name)).export({
        mode: 'update',
      });
      const restored = provider.newDocument();
      expect(() => provider.remoteChange(restored, history)).toThrow(reason);
      expect(restored.oplogVersion().length()).toBe(0);
    }
    expectDurable(provider, replica(provider, baseSnapshot()));
  });

  test('accepts root containers that share a name in any delivery order', () => {
    const provider = new LoroProvider();
    const [alice, bob, carol] = (['1', '2', '3'] as const).map((peer) => {
      const doc = provider.newDocument();
      doc.setPeerId(peer);
      return doc;
    });
    const [, list] = provider.localChange(alice, 'list', (doc) => {
      doc.getList('x').push(1);
    });
    const [, map] = provider.localChange(bob, 'map', (doc) => {
      doc.getMap('x').set('k', 1);
    });
    provider.remoteChange(alice, map);
    provider.remoteChange(bob, list);
    provider.remoteChange(carol, map);
    provider.remoteChange(carol, list);
    for (const doc of [alice, bob, carol, restart(provider, bob)]) {
      expect(doc.oplogVersion().compare(alice.oplogVersion())).toBe(0);
      expect(doc.getList('x').toJSON()).toEqual([1]);
      expect(doc.getMap('x').toJSON()).toEqual({ k: 1 });
    }
  });

  test('a rejected payload leaves the document writable and in sync', () => {
    const provider = new LoroProvider();
    const base = baseSnapshot();
    const alice = replica(provider, base, '5');
    const bob = replica(provider, base, '6');
    for (const name of [
      'unknown-tree-container',
      'unknown-list-container',
      'lossy-nested-container',
      'foreign-text-delete',
      'missing-tree-node',
    ]) {
      expect(() => provider.remoteChange(bob, fixture(name))).toThrow();
    }
    const [, fromAlice] = provider.localChange(alice, 'alice', (doc) => {
      doc.getText('rt').insert(0, 'A ');
      doc.getTree('tr').createNode();
    });
    const [, fromBob] = provider.localChange(bob, 'bob', (doc) => {
      doc.getText('rt').insert(4, 'B ');
      doc.getList('l').delete(0, 1);
    });
    provider.remoteChange(alice, fromBob);
    provider.remoteChange(bob, fromAlice);
    expect(bob.toJSON()).toEqual(alice.toJSON());
    expectDurable(provider, bob);
  });

  test('honest replicas converge through shuffled delivery, snapshots and restarts', () => {
    const provider = new LoroProvider();
    let seed = 7;
    const random = () => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      return seed / 2 ** 32;
    };
    const pick = (n: number) => Math.floor(random() * n);
    const edit = (doc: LoroDoc, tag: string) => {
      const text = doc.getText('t');
      const list = doc.getList('l');
      const tree = doc.getTree('tr');
      switch (pick(8)) {
        case 0:
          for (const char of tag) text.insert(0, char);
          break;
        case 1:
          if (text.length > 4) text.delete(1, 3);
          else text.insert(0, tag);
          break;
        case 2:
          if (text.length > 2) text.mark({ start: 0, end: 2 }, 'bold', tag);
          break;
        case 3:
          list.insert(pick(list.length + 1), tag);
          if (list.length > 2) list.delete(pick(list.length - 1), 2);
          break;
        case 4: {
          const node = tree.createNode();
          node.data.set('tag', tag);
          const [first] = tree.roots();
          if (first !== undefined && first.id !== node.id) {
            tree.move(node.id, first.id);
          }
          break;
        }
        case 5: {
          const nested = doc
            .getMap('m')
            .setContainer(`n${pick(3)}`, new LoroMap())
            .setContainer('list', new LoroList());
          nested.insertContainer(0, new LoroText()).insert(0, tag);
          break;
        }
        case 6: {
          const moves = doc.getMovableList('ml');
          moves.push(tag);
          if (moves.length > 1) moves.move(0, moves.length - 1);
          break;
        }
        default:
          doc.getCounter('c').increment(1);
      }
    };
    const replicas = [0, 1, 2].map((index) => {
      const doc = provider.newDocument();
      doc.setPeerId(`${index + 10}` as `${number}`);
      return doc;
    });
    const published: Uint8Array[] = [];
    for (let round = 0; round < 12; round++) {
      const inbox: Uint8Array[][] = replicas.map(() => []);
      replicas.forEach((doc, index) => {
        const [, change] = provider.localChange(doc, 'edit', (d) =>
          edit(d, `${index}.${round}`),
        );
        published.push(change);
        replicas.forEach((_, other) => {
          if (other !== index && random() < 0.7) inbox[other]!.push(change);
        });
      });
      inbox.forEach((changes, index) => {
        for (const change of changes.sort(() => random() - 0.5)) {
          provider.remoteChange(replicas[index]!, change);
        }
      });
      if (round % 4 === 3) {
        const index = pick(replicas.length);
        const restarted = restart(provider, replicas[index]!);
        restarted.setPeerId(`${20 + round}` as `${number}`);
        replicas[index] = restarted;
        provider.applySnapshot(
          replicas[(index + 1) % replicas.length]!,
          provider.getSnapshot(restarted),
        );
      }
    }
    for (const doc of replicas) {
      for (const change of [...published].reverse()) {
        provider.remoteChange(doc, change);
      }
    }
    for (const doc of replicas) {
      expect(doc.toJSON()).toEqual(replicas[0]!.toJSON());
      expect(doc.exportPendingUpdates()).toBeUndefined();
      expectDurable(provider, doc);
    }
  });

  // Mallory's client rewrites an honest update in Loro's JSON form, then
  // re-encodes it with an unmodified Loro.
  function crafted(
    base: Uint8Array,
    peer: `${number}`,
    edit: (doc: LoroDoc) => void,
    rewrite: (json: JsonSchema) => void,
  ): Uint8Array {
    const author = rawReplica(base);
    const from = author.oplogVersion();
    author.setPeerId(peer);
    edit(author);
    author.commit();
    const json = author.exportJsonUpdates(from, author.oplogVersion(), false);
    rewrite(json);
    const encoder = rawReplica(base);
    encoder.importJsonUpdates(json);
    return encoder.export({ mode: 'update', from });
  }

  test('reaches the same verdict on a crafted container value in every delivery order', () => {
    const provider = new LoroProvider();
    const author = new LoroDoc();
    author.setPeerId('1');
    const node = author.getTree('tr').createNode();
    node.data.set('name', 'n');
    const other = author.getTree('tr').createNode();
    author.getText('t').insert(0, 'base');
    author.commit();
    const base = author.export({ mode: 'update' });
    const fork = (peer: `${number}`) => {
      const doc = rawReplica(base);
      doc.setPeerId(peer);
      return doc;
    };
    const [, deletion] = provider.localChange(fork('2'), 'c', (doc) => {
      doc.getTree('tr').delete(node.id);
    });
    const [, move] = provider.localChange(fork('4'), 'd', (doc) => {
      doc.getText('t').insert(0, 'dave ');
      doc.getTree('tr').move(node.id, other.id);
    });
    const poisoned = crafted(
      base,
      '8',
      (doc) => doc.getTree('tr').getNodeByID(node.id)!.data.set('x', 1),
      (json) => {
        const [op] = json.changes[0]!.ops;
        (op!.content as { value: unknown }).value =
          `🦜:cid:${op!.counter}@8:Unknown(21)`;
      },
    );
    const orders: Uint8Array[][] = [
      [deletion, poisoned, move],
      [deletion, move, poisoned],
      [poisoned, deletion, move],
    ];
    const replicas = orders.map((order) => {
      const doc = provider.remoteChange(provider.newDocument(), base);
      for (const update of order) {
        if (update === poisoned) {
          expect(() => provider.remoteChange(doc, update)).toThrow(
            'container with a foreign ID',
          );
        } else {
          provider.remoteChange(doc, update);
        }
      }
      return doc;
    });
    replicas[1]!.setPeerId('30');
    const [, later] = provider.localChange(replicas[1]!, 'y', (doc) => {
      doc.getText('t').insert(0, 'later ');
    });
    for (const doc of replicas) {
      provider.remoteChange(doc, later);
      expect(doc.toJSON()).toEqual(replicas[0]!.toJSON());
      expectDurable(provider, doc);
    }
  });

  test('rejects writes to containers that the change cannot have created', () => {
    const provider = new LoroProvider();
    const base = baseSnapshot();
    const live = replica(provider, base);
    const child = (doc: LoroDoc) =>
      doc.getMap('m').setContainer('c', new LoroMap()).set('k', 1);
    expectRejected(
      provider,
      live,
      crafted(base, '8', child, (json) => {
        json.changes[0]!.ops[1]!.container = 'cid:99@8:Map';
      }),
      'container it cannot see',
    );
    expectRejected(
      provider,
      live,
      crafted(base, '8', child, (json) => {
        json.changes[0]!.ops[1]!.container = 'cid:5@1:Map';
      }),
      'container it cannot see',
    );
    expectDurable(provider, live);
  });

  test('keeps an honest waiting update released together with a crafted one in either order', () => {
    const provider = new LoroProvider();
    const complete = rawReplica(baseSnapshot());
    const partial = complete.forkAt([{ peer: '1', counter: 31 }]);
    const missing = complete.export({
      mode: 'update',
      from: partial.oplogVersion(),
    });
    const carol = rawReplica(baseSnapshot());
    carol.setPeerId('3');
    const [, honest] = provider.localChange(carol, 'c', (doc) => {
      doc.getText('t').insert(0, 'carol ');
    });
    const poisoned = fixture('unknown-tree-container');
    for (const order of [
      [honest, poisoned, missing],
      [missing, honest, poisoned],
    ]) {
      const live = provider.remoteChange(
        provider.newDocument(),
        partial.export({ mode: 'update' }),
      );
      for (const update of order) {
        if (update === poisoned && order[0] === missing) {
          expect(() => provider.remoteChange(live, update)).toThrow();
        } else {
          provider.remoteChange(live, update);
        }
      }
      expect(provider.hasIntegrated(live, honest)).toBe(true);
      expect(provider.hasDiscarded(live, poisoned)).toBe(true);
      expect(live.getText('t').toString()).toBe('carol hello world');
    }
  });

  test('releases a chain of waiting updates delivered in order without rescanning', () => {
    const provider = new LoroProvider();
    const author = new LoroDoc();
    author.setPeerId('7');
    const updates = Array.from(
      { length: 4096 },
      () =>
        provider.localChange(author, 'e', (doc) => {
          doc.getCounter('c').increment(1);
        })[1],
    );
    const live = provider.newDocument();
    const started = performance.now();
    for (const update of updates.slice(1)) provider.remoteChange(live, update);
    expect(live.getCounter('c').value).toBe(0);
    provider.remoteChange(live, updates[0]!);
    expect(live.getCounter('c').value).toBe(4096);
    expect(performance.now() - started).toBeLessThan(20_000);
  }, 30_000);

  test('evicts the waiting updates of the peer holding the most first', () => {
    const provider = new LoroProvider();
    const complete = rawReplica(baseSnapshot());
    const partial = complete.forkAt([{ peer: '1', counter: 31 }]);
    const missing = complete.export({
      mode: 'update',
      from: partial.oplogVersion(),
    });
    const carol = rawReplica(baseSnapshot());
    carol.setPeerId('3');
    const [, honest] = provider.localChange(carol, 'c', (doc) => {
      doc.getText('t').insert(0, 'carol ');
    });
    const flooder = new LoroDoc();
    flooder.setPeerId('9');
    const flood = Array.from(
      { length: 4097 },
      () =>
        provider.localChange(flooder, 'f', (doc) => {
          doc.getCounter('f').increment(1);
        })[1],
    );
    const live = provider.remoteChange(
      provider.newDocument(),
      partial.export({ mode: 'update' }),
    );
    provider.remoteChange(live, honest);
    for (const update of flood.slice(1)) provider.remoteChange(live, update);
    expect(provider.hasDiscarded(live, honest)).toBe(false);
    expect(provider.hasDiscarded(live, flood[1]!)).toBe(true);
    provider.remoteChange(live, missing);
    expect(provider.hasIntegrated(live, honest)).toBe(true);
  }, 30_000);

  test('rejects an update that trapped Loro without validating it again', () => {
    const provider = new LoroProvider();
    const live = replica(provider, baseSnapshot());
    const source = replica(provider, baseSnapshot(), '3');
    const [, update] = provider.localChange(source, 'edit', (doc) => {
      doc.getMap('m').set('k', 2);
    });
    const importBatch = jest
      .spyOn(LoroDoc.prototype, 'importBatch')
      .mockImplementationOnce(() => {
        throw new WebAssembly.RuntimeError('unreachable');
      });
    expect(() => provider.remoteChange(live, update)).toThrow('unreachable');
    expect(() => provider.remoteChange(live, update)).toThrow('trapped Loro');
    expect(importBatch).toHaveBeenCalledTimes(1);
    expect(live.getMap('m').get('k')).toBe(1);
  });

  test('honest replicas converge with undo, rich text and nested containers in any delivery order', () => {
    for (const start of [1, 2, 3]) {
      const provider = new LoroProvider();
      let seed = start;
      const random = () => {
        seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
        return seed / 2 ** 32;
      };
      const pick = (n: number) => Math.floor(random() * n);
      const docs = [0, 1, 2, 3].map((index) => {
        const doc = provider.newDocument();
        doc.setPeerId(`${100 + index}` as `${number}`);
        return doc;
      });
      const undos = docs.map(
        (doc) => new UndoManager(doc, { mergeInterval: 0 }),
      );
      const inbox: Uint8Array[][] = docs.map(() => []);
      const edit = (doc: LoroDoc, tag: string) => {
        const text = doc.getText('t');
        const list = doc.getList('l');
        const moves = doc.getMovableList('ml');
        const tree = doc.getTree('tr');
        const map = doc.getMap('m');
        for (let count = 1 + pick(4); count > 0; count--) {
          switch (pick(12)) {
            case 0:
              text.insert(pick(text.length + 1), tag);
              break;
            case 1:
              if (text.length > 1) {
                const at = pick(text.length);
                text.delete(at, 1 + pick(text.length - at));
              }
              break;
            case 2:
              if (text.length > 2) {
                const at = pick(text.length - 1);
                text.mark(
                  { start: at, end: at + 1 + pick(text.length - at - 1) },
                  pick(2) ? 'bold' : 'link',
                  tag,
                );
              }
              break;
            case 3:
              text.update(
                text.toString().split('').reverse().join('').slice(0, 20) + tag,
              );
              break;
            case 4:
              list.insert(pick(list.length + 1), tag);
              if (list.length > 3) list.delete(pick(list.length - 2), 2);
              break;
            case 5:
              list
                .insertContainer(pick(list.length + 1), new LoroText())
                .insert(0, tag);
              break;
            case 6:
              moves.push(tag);
              if (moves.length > 1) {
                moves.move(pick(moves.length), pick(moves.length));
              }
              moves.set(pick(moves.length), `${tag}!`);
              if (moves.length > 3) moves.delete(pick(moves.length - 1), 1);
              break;
            case 7: {
              const nodes = tree.nodes().filter((n) => !n.isDeleted());
              if (nodes.length > 0 && pick(2)) {
                const target = nodes[pick(nodes.length)]!;
                if (pick(2)) {
                  tree.delete(target.id);
                } else {
                  const parent = nodes[pick(nodes.length)]!;
                  try {
                    tree.move(
                      target.id,
                      parent.id === target.id ? undefined : parent.id,
                    );
                  } catch {
                    // Moving a node under its own descendant is refused.
                  }
                }
              } else {
                const parent = nodes.length
                  ? nodes[pick(nodes.length)]!.id
                  : undefined;
                tree.createNode(parent).data.set('tag', tag);
              }
              break;
            }
            case 8: {
              const child = map.setContainer(`k${pick(3)}`, new LoroMap());
              child.set('v', tag);
              child.setContainer('list', new LoroList()).push(tag);
              break;
            }
            case 9:
              if (pick(2)) map.delete(`k${pick(3)}`);
              else map.set(`k${pick(3)}`, tag);
              break;
            case 10:
              moves.insertContainer(0, new LoroText()).insert(0, tag);
              break;
            default:
              doc.getCounter('c').increment(pick(2) ? 1 : -2);
          }
        }
      };
      for (let round = 0; round < 30; round++) {
        docs.forEach((doc, index) => {
          if (pick(3) === 0) return;
          let change: Uint8Array;
          if (pick(8) === 0 && undos[index]!.canUndo()) {
            const from = doc.oplogVersion();
            undos[index]!.undo();
            doc.commit();
            if (from.compare(doc.oplogVersion()) === 0) return;
            change = doc.export({ mode: 'update', from });
          } else {
            [, change] = provider.localChange(doc, 'e', (d) =>
              edit(d, `${index}.${round}`),
            );
          }
          inbox.forEach((box, other) => {
            if (other !== index) box.push(change);
          });
        });
        docs.forEach((doc, index) => {
          const box = inbox[index]!;
          const delivered =
            pick(3) === 0 ? box.splice(0) : box.splice(0, pick(box.length + 1));
          const order =
            pick(3) === 0
              ? delivered.reverse()
              : delivered.sort(() => random() - 0.5);
          for (const update of order) provider.remoteChange(doc, update);
        });
      }
      docs.forEach((doc, index) => {
        for (const update of inbox[index]!.splice(0).reverse()) {
          provider.remoteChange(doc, update);
        }
      });
      for (const doc of docs) {
        expect(doc.oplogVersion().compare(docs[0]!.oplogVersion())).toBe(0);
        expect(doc.toJSON()).toEqual(docs[0]!.toJSON());
      }
    }
  }, 60_000);
});
