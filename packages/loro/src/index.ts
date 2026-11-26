import {
  LoroDoc,
  LoroTree,
  decodeImportBlobMeta,
  type ContainerID,
  type OpId,
  type PeerID,
  type VersionVector,
} from 'loro-crdt';
import { PartialLocalChangeError, type CRDTProvider } from '@peerborne/core';

export type LoroChange = (document: LoroDoc) => void;

type Version = Map<PeerID, number>;

interface BlobRange {
  readonly mode: string;
  readonly start: ReadonlyArray<readonly [PeerID, number]>;
  readonly end: ReadonlyArray<readonly [PeerID, number]>;
  readonly dependencies: readonly OpId[];
}

const CONTAINER_TYPES = new Set([
  'Map',
  'List',
  'Text',
  'Tree',
  'MovableList',
  'Counter',
]);

/** The most updates a document holds while their dependencies are missing. */
const MAX_WAITING_UPDATES = 4096;

const ranges = new WeakMap<Uint8Array, BlobRange>();
const waitingUpdates = new WeakMap<LoroDoc, Uint8Array[]>();

function rangeOf(blob: Uint8Array): BlobRange {
  let range = ranges.get(blob);
  if (range === undefined) {
    const meta = decodeImportBlobMeta(blob, true);
    range = {
      mode: meta.mode,
      start: [...meta.partialStartVersionVector.toJSON()],
      end: [...meta.partialEndVersionVector.toJSON()],
      dependencies: meta.startFrontiers,
    };
    ranges.set(blob, range);
  }
  return range;
}

function expectMode(blob: Uint8Array, mode: 'update' | 'snapshot'): BlobRange {
  const range = rangeOf(blob);
  if (range.mode !== mode) {
    throw new Error(`Expected a Loro ${mode}, received ${range.mode}`);
  }
  return range;
}

function covers(version: Version, range: BlobRange): boolean {
  return range.end.every(([peer, end]) => (version.get(peer) ?? 0) >= end);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    left.every((byte, index) => byte === right[index])
  );
}

/**
 * Selects the queued updates that integrate on `document`, in an order where
 * each one's dependencies come first.
 */
function integrable(
  document: LoroDoc,
  queue: readonly Uint8Array[],
): Uint8Array[] {
  const version: Version = document.oplogVersion().toJSON();
  const selected: Uint8Array[] = [];
  for (let progressed = true; progressed;) {
    progressed = false;
    for (let index = queue.length - 1; index >= 0; index--) {
      const blob = queue[index]!;
      if (selected.includes(blob)) continue;
      const range = rangeOf(blob);
      if (
        range.dependencies.some(
          ({ peer, counter }) => (version.get(peer) ?? 0) <= counter,
        ) ||
        range.start.some(([peer, start]) => (version.get(peer) ?? 0) < start)
      ) {
        continue;
      }
      selected.push(blob);
      for (const [peer, end] of range.end) {
        version.set(peer, Math.max(version.get(peer) ?? 0, end));
      }
      progressed = true;
    }
  }
  return selected;
}

function containerType(id: string): string {
  return id.slice(id.lastIndexOf(':') + 1);
}

function opId(id: string): OpId {
  const at = id.indexOf('@');
  return { peer: id.slice(at + 1) as PeerID, counter: Number(id.slice(0, at)) };
}

function sameValue(left: unknown, right: unknown): boolean {
  const pending: Array<[unknown, unknown]> = [[left, right]];
  while (pending.length > 0) {
    const [a, b] = pending.pop()!;
    if (Object.is(a, b)) continue;
    if (
      typeof a !== 'object' ||
      typeof b !== 'object' ||
      a === null ||
      b === null ||
      Array.isArray(a) !== Array.isArray(b) ||
      a instanceof Uint8Array !== b instanceof Uint8Array
    ) {
      return false;
    }
    const keys = Object.keys(a);
    if (keys.length !== Object.keys(b).length) return false;
    for (const key of keys) {
      if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
      pending.push([
        (a as Record<string, unknown>)[key],
        (b as Record<string, unknown>)[key],
      ]);
    }
  }
  return true;
}

function release(document: LoroDoc): void {
  try {
    document.free();
  } catch {
    // A document that trapped while borrowed cannot be freed.
  }
}

/**
 * Loro decodes operations without checking that they make sense. Reject the
 * ones an unmodified client cannot produce: unknown container types, deletions
 * of elements outside the change's causal past or container, and tree nodes
 * that do not exist there. Each rule depends only on the change and its causal
 * past, so every replica reaches the same verdict in any delivery order.
 * Returns the root containers the operations write to.
 */
function assertOperations(
  document: LoroDoc,
  staged: LoroDoc,
  from: VersionVector,
  to: VersionVector,
): Set<ContainerID> {
  const { changes } = staged.exportJsonUpdates(from, to, false);
  const roots = new Set<ContainerID>();
  const created = new Set<string>();
  const written = new Map<PeerID, Array<readonly [number, ContainerID]>>();
  for (const change of changes) {
    const { peer } = opId(change.id);
    let ops = written.get(peer);
    if (ops === undefined) written.set(peer, (ops = []));
    for (const { container, content, counter } of change.ops) {
      if (
        !CONTAINER_TYPES.has(containerType(container)) ||
        content.type === 'unknown'
      ) {
        throw new Error('Loro update writes to an unsupported container');
      }
      ops.push([counter, container]);
      if (container.startsWith('cid:root-')) roots.add(container);
      if (containerType(container) === 'Tree' && content.type === 'create') {
        if (content.target !== `${counter}@${peer}`) {
          throw new Error('Loro update creates a tree node with a foreign ID');
        }
        created.add(`${container} ${content.target}`);
      }
    }
  }
  const imported: Version = from.toJSON();
  const ownersOf = (id: OpId, length: number): ContainerID[] => {
    const ops = written.get(id.peer);
    if (ops === undefined || id.counter < (imported.get(id.peer) ?? 0)) {
      return staged.getChangedContainersIn(id, length);
    }
    let low = 0;
    let high = ops.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if (ops[middle]![0] <= id.counter) low = middle + 1;
      else high = middle;
    }
    const owners = new Set<ContainerID>();
    for (
      let index = Math.max(low - 1, 0);
      index < ops.length && ops[index]![0] < id.counter + length;
      index++
    ) {
      owners.add(ops[index]![1]);
    }
    return [...owners];
  };
  for (const change of changes) {
    const { peer } = opId(change.id);
    const past: Version = staged.frontiersToVV(change.deps.map(opId)).toJSON();
    const precedes = (id: OpId, counter: number, length = 1): boolean =>
      id.counter + length <= (past.get(id.peer) ?? 0) ||
      (id.peer === peer && id.counter + length <= counter);
    for (const { container, content, counter } of change.ops) {
      if (content.type === 'delete' && 'start_id' in content) {
        const start = opId(content.start_id);
        const length = Math.abs(content.len);
        const owners = precedes(start, counter, length)
          ? ownersOf(start, length)
          : [];
        if (owners.length !== 1 || owners[0] !== container) {
          throw new Error('Loro update deletes elements it cannot see');
        }
      }
      if (containerType(container) === 'Tree' && 'target' in content) {
        const tree = document.getContainerById(container);
        const parent = 'parent' in content ? content.parent : undefined;
        for (const node of [content.target, parent]) {
          if (node == null) continue;
          if (
            !precedes(opId(node), counter + 1) ||
            (!created.has(`${container} ${node}`) &&
              !(tree instanceof LoroTree && tree.has(node)))
          ) {
            throw new Error(
              'Loro update moves a tree node that does not exist',
            );
          }
        }
      }
    }
  }
  return roots;
}

function assertKnownRoots(document: LoroDoc): ContainerID[] {
  const roots = Object.values(document.getShallowValue());
  if (roots.some((id) => !CONTAINER_TYPES.has(containerType(id)))) {
    throw new Error('Loro update registers an unsupported root container');
  }
  return roots;
}

/**
 * Imports `updates` into a fork of `document` and checks their operations,
 * then that every root container reads the same after a snapshot round trip
 * and the version vector is unchanged. Roots are compared by container ID
 * because Loro resolves a root name shared by two container types by
 * registration order, which differs between replicas and reloads.
 */
function validateImport(
  document: LoroDoc,
  updates: readonly Uint8Array[],
): void {
  const staged = document.fork();
  const reloaded = new LoroDoc();
  try {
    const from = staged.oplogVersion();
    staged.importBatch([...updates]);
    const to = staged.oplogVersion();
    const version: Version = to.toJSON();
    if (
      staged.exportPendingUpdates() !== undefined ||
      !updates.every((update) => covers(version, rangeOf(update)))
    ) {
      throw new Error('Loro update does not integrate with its dependencies');
    }
    const roots = assertOperations(document, staged, from, to);
    for (const id of assertKnownRoots(staged)) roots.add(id);
    reloaded.import(staged.export({ mode: 'snapshot' }));
    for (const id of assertKnownRoots(reloaded)) roots.add(id);
    if (reloaded.oplogVersion().compare(to) !== 0) {
      throw new Error('Loro update does not survive a snapshot round trip');
    }
    for (const id of roots) {
      if (
        !sameValue(
          reloaded.getContainerById(id)?.toJSON(),
          staged.getContainerById(id)?.toJSON(),
        )
      ) {
        throw new Error('Loro update does not survive a snapshot round trip');
      }
    }
  } finally {
    release(staged);
    release(reloaded);
  }
}

/**
 * Experimental document provider. Snapshots retain history so offline replicas
 * can merge without introducing a shallow-history compatibility boundary.
 * ACL, keychain and wire serializers are supplied independently by the caller.
 *
 * Remote updates and snapshots are untrusted even when authenticated, because
 * Loro's checksum is not a MAC. An update waits outside the document until its
 * dependencies arrive, and is then validated on a fork with the updates it
 * releases before any of them reach the document. Validation reads the whole
 * document, so it costs O(document) per integrated remote update.
 */
export class LoroProvider implements CRDTProvider<
  LoroDoc,
  Uint8Array,
  LoroChange
> {
  newDocument(): LoroDoc {
    return new LoroDoc();
  }

  localChange(
    document: LoroDoc,
    message: string,
    change: LoroChange,
  ): [LoroDoc, Uint8Array] {
    const from = document.oplogVersion();
    try {
      change(document);
    } catch (error) {
      document.commit({ message });
      if (from.compare(document.oplogVersion()) === 0) throw error;
      throw new PartialLocalChangeError(
        error,
        document,
        document.export({ mode: 'update', from }),
      );
    }
    document.commit({ message });
    return [document, document.export({ mode: 'update', from })];
  }

  /**
   * Rejects a blob that is not a valid update and leaves `document` unchanged.
   * An update whose dependencies are missing waits and is validated once they
   * arrive, together with the update that released it. When that batch fails
   * but the releasing update passes on its own, each waiting update is then
   * validated on its own, and the ones that fail are discarded.
   */
  remoteChange(document: LoroDoc, changes: Uint8Array): LoroDoc {
    const range = expectMode(changes, 'update');
    if (covers(document.oplogVersion().toJSON(), range)) return document;
    const held = waitingUpdates.get(document) ?? [];
    if (held.some((update) => sameBytes(update, changes))) return document;
    const queue = [...held, changes];
    const ready = integrable(document, queue);
    if (!ready.includes(changes)) {
      waitingUpdates.set(document, queue.slice(-MAX_WAITING_UPDATES));
      return document;
    }
    let valid = true;
    try {
      validateImport(document, ready);
    } catch (error) {
      if (ready.length === 1 || integrable(document, [changes]).length === 0) {
        throw error;
      }
      valid = false;
    }
    if (valid) {
      document.importBatch(ready);
    } else {
      validateImport(document, [changes]);
      document.importBatch([changes]);
      for (const update of ready) {
        if (update === changes || integrable(document, [update]).length === 0) {
          continue;
        }
        try {
          validateImport(document, [update]);
          document.importBatch([update]);
        } catch {
          // `hasDiscarded` reports the update from now on.
        }
      }
    }
    waitingUpdates.set(
      document,
      queue.filter((update) => !ready.includes(update)),
    );
    return document;
  }

  /**
   * An update is integrated once the oplog covers the end of every peer range
   * it carries. One still waiting for a dependency is not.
   */
  hasIntegrated(document: LoroDoc, changes: Uint8Array): boolean {
    return covers(document.oplogVersion().toJSON(), rangeOf(changes));
  }

  /**
   * An update is discarded once it is neither integrated nor waiting: it
   * failed validation with the update that released it, the waiting queue
   * evicted it, or `remoteChange` rejected it.
   */
  hasDiscarded(document: LoroDoc, changes: Uint8Array): boolean {
    if (this.hasIntegrated(document, changes)) return false;
    const held = waitingUpdates.get(document) ?? [];
    return (
      !held.includes(changes) &&
      !held.some((update) => sameBytes(update, changes))
    );
  }

  getHistory(document: LoroDoc): Uint8Array {
    return document.export({ mode: 'update' });
  }

  getSnapshot(document: LoroDoc): Uint8Array {
    return document.export({ mode: 'snapshot' });
  }

  /**
   * Applies only the operation history of a full snapshot, as a validated
   * update. The snapshot's encoded state is never loaded into `document`.
   */
  applySnapshot(document: LoroDoc, snapshot: Uint8Array): LoroDoc {
    expectMode(snapshot, 'snapshot');
    const source = new LoroDoc();
    try {
      source.import(snapshot);
      if (source.isShallow()) {
        throw new Error('Expected a Loro snapshot with its full history');
      }
      return this.remoteChange(
        document,
        source.export({ mode: 'update', from: document.oplogVersion() }),
      );
    } finally {
      release(source);
    }
  }
}
