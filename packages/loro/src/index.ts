import {
  LoroDoc,
  decodeImportBlobMeta,
  isValidContainerId,
  type ContainerID,
  type JsonOp,
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

/** How Loro's JSON form marks a value that is a container. */
const CONTAINER_VALUE = '🦜:';

/** The most updates a document holds while their dependencies are missing. */
const MAX_WAITING_UPDATES = 4096;

/**
 * The most updates that may trap Loro during validation of one document. Each
 * trap leaks the fork it happened in, so the document is retired after that.
 */
const MAX_TRAPPED_UPDATES = 16;

const ranges = new WeakMap<Uint8Array, BlobRange>();

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
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/**
 * Updates held for one document, found by their bytes. Past `capacity`, the
 * oldest update of the peer holding the most is evicted, so one writer cannot
 * push out everyone else's.
 */
class HeldUpdates {
  private readonly updates = new Set<Uint8Array>();
  private readonly buckets = new Map<string, Uint8Array[]>();

  constructor(private readonly capacity: number) {}

  private static key(blob: Uint8Array): string {
    // Bytes 16 to 19 hold the header checksum.
    return `${blob.byteLength}:${blob[16]},${blob[17]},${blob[18]},${blob[19]}`;
  }

  private static author(blob: Uint8Array): PeerID | undefined {
    return rangeOf(blob).end[0]?.[0];
  }

  get size(): number {
    return this.updates.size;
  }

  values(): IterableIterator<Uint8Array> {
    return this.updates.values();
  }

  find(blob: Uint8Array): Uint8Array | undefined {
    if (this.updates.has(blob)) return blob;
    return this.buckets
      .get(HeldUpdates.key(blob))
      ?.find((held) => sameBytes(held, blob));
  }

  add(blob: Uint8Array): void {
    if (this.find(blob) !== undefined) return;
    this.updates.add(blob);
    const key = HeldUpdates.key(blob);
    this.buckets.set(key, [...(this.buckets.get(key) ?? []), blob]);
    if (this.updates.size <= this.capacity) return;
    const counts = new Map<PeerID | undefined, number>();
    for (const update of this.updates) {
      const author = HeldUpdates.author(update);
      counts.set(author, (counts.get(author) ?? 0) + 1);
    }
    const heaviest = [...counts].reduce((a, b) => (b[1] > a[1] ? b : a))[0];
    for (const update of this.updates) {
      if (HeldUpdates.author(update) === heaviest) {
        this.delete(update);
        return;
      }
    }
  }

  delete(blob: Uint8Array): void {
    if (!this.updates.delete(blob)) return;
    const key = HeldUpdates.key(blob);
    const bucket = this.buckets.get(key)!.filter((held) => held !== blob);
    if (bucket.length > 0) this.buckets.set(key, bucket);
    else this.buckets.delete(key);
  }
}

const waitingUpdates = new WeakMap<LoroDoc, HeldUpdates>();
const trappedUpdates = new WeakMap<LoroDoc, HeldUpdates>();

function held(
  registry: WeakMap<LoroDoc, HeldUpdates>,
  document: LoroDoc,
  capacity: number,
): HeldUpdates {
  let updates = registry.get(document);
  if (updates === undefined) {
    registry.set(document, (updates = new HeldUpdates(capacity)));
  }
  return updates;
}

/**
 * Selects the `candidates` that integrate on `document`, each after the ones
 * it depends on. An update is examined again only when the peer it waits for
 * advances.
 */
function integrable(
  document: LoroDoc,
  candidates: Iterable<Uint8Array>,
): Uint8Array[] {
  const version: Version = document.oplogVersion().toJSON();
  const selected: Uint8Array[] = [];
  const blocked = new Map<PeerID, Uint8Array[]>();
  const pending = [...candidates].reverse();
  while (pending.length > 0) {
    const blob = pending.pop()!;
    const range = rangeOf(blob);
    const missing =
      range.dependencies.find(
        ({ peer, counter }) => (version.get(peer) ?? 0) <= counter,
      )?.peer ??
      range.start.find(
        ([peer, start]) => (version.get(peer) ?? 0) < start,
      )?.[0];
    if (missing !== undefined) {
      const waiting = blocked.get(missing);
      if (waiting === undefined) blocked.set(missing, [blob]);
      else waiting.push(blob);
      continue;
    }
    selected.push(blob);
    for (const [peer, end] of range.end) {
      if ((version.get(peer) ?? 0) >= end) continue;
      version.set(peer, end);
      const released = blocked.get(peer);
      if (released === undefined) continue;
      blocked.delete(peer);
      for (let index = released.length - 1; index >= 0; index--) {
        pending.push(released[index]!);
      }
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

function containerValue(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.startsWith(CONTAINER_VALUE)) {
    return undefined;
  }
  const id = value.slice(CONTAINER_VALUE.length);
  return isValidContainerId(id) ? id : undefined;
}

function holdsContainerValue(value: unknown): boolean {
  const pending = [value];
  while (pending.length > 0) {
    const next = pending.pop();
    if (containerValue(next) !== undefined) return true;
    if (typeof next === 'object' && next !== null) {
      pending.push(...Object.values(next));
    }
  }
  return false;
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
 * Checks the containers and tree nodes the operation at `counter` creates and
 * adds them to `created`: a container value must have a known type and the
 * operation's own ID, and a tree node the ID of the operation creating it.
 */
function collectCreations(
  peer: PeerID,
  { container, content, counter }: JsonOp,
  created: Set<string>,
): void {
  const values =
    content.type === 'insert' && 'value' in content
      ? 'key' in content || !Array.isArray(content.value)
        ? [content.value]
        : content.value
      : content.type === 'set'
        ? [content.value]
        : [];
  values.forEach((value, index) => {
    const id = containerValue(value);
    if (id === undefined) {
      if (holdsContainerValue(value)) {
        throw new Error('Loro update nests a container in a value');
      }
      return;
    }
    if (
      !CONTAINER_TYPES.has(containerType(id)) ||
      id !== `cid:${counter + index}@${peer}:${containerType(id)}`
    ) {
      throw new Error('Loro update creates a container with a foreign ID');
    }
    created.add(id);
  });
  if (content.type === 'mark' && holdsContainerValue(content.style_value)) {
    throw new Error('Loro update nests a container in a value');
  }
  if (containerType(container) === 'Tree' && content.type === 'create') {
    if (content.target !== `${counter}@${peer}`) {
      throw new Error('Loro update creates a tree node with a foreign ID');
    }
    created.add(`cid:${content.target}:Map`);
    created.add(`${container} ${content.target}`);
  }
}

/**
 * Loro decodes operations without checking that they make sense. Reject the
 * ones an unmodified client cannot produce:
 *
 * - an unknown container type, as a target or a value;
 * - a container value whose ID is not that of the operation creating it, or
 *   one nested in another value;
 * - a write to a container that is not created in the change's causal past;
 * - a deletion of elements outside the change's causal past or container;
 * - a tree node that is not created in the change's causal past.
 *
 * Each rule depends only on the change and its causal past, read from
 * `staged`, so every replica reaches the same verdict in any delivery order.
 * Returns the root containers the operations write to.
 */
function assertOperations(
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
    for (const op of change.ops) {
      const { container, content, counter } = op;
      if (
        !CONTAINER_TYPES.has(containerType(container)) ||
        content.type === 'unknown'
      ) {
        throw new Error('Loro update writes to an unsupported container');
      }
      ops.push([counter, container]);
      if (container.startsWith('cid:root-')) roots.add(container);
      collectCreations(peer, op, created);
    }
  }
  const earlier = new Map<string, Set<string>>();
  const createdBy = (id: OpId): Set<string> => {
    const key = `${id.counter}@${id.peer}`;
    let creations = earlier.get(key);
    if (creations === undefined) {
      creations = new Set();
      for (const change of staged.exportJsonInIdSpan({ ...id, length: 1 })) {
        for (const op of change.ops) {
          if (op.counter === id.counter) {
            collectCreations(id.peer, op, creations);
          }
        }
      }
      earlier.set(key, creations);
    }
    return creations;
  };
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
      if (!container.startsWith('cid:root-')) {
        const creator = opId(container.slice(4, container.lastIndexOf(':')));
        if (
          !precedes(creator, counter) ||
          (!created.has(container) && !createdBy(creator).has(container))
        ) {
          throw new Error('Loro update writes to a container it cannot see');
        }
      }
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
        const parent = 'parent' in content ? content.parent : undefined;
        for (const node of [content.target, parent]) {
          if (node == null) continue;
          const key = `${container} ${node}`;
          if (
            !precedes(opId(node), counter + 1) ||
            (!created.has(key) && !createdBy(opId(node)).has(key))
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
 * Imports `updates` into a fork of `document` and checks their operations.
 * Then, as a defence in depth, checks that every root container reads the
 * same after a snapshot round trip and the version vector is unchanged. The
 * round trip reads the visible state, which concurrent changes can alter, so
 * every malformation it has caught is also rejected by an operation rule.
 * Roots are compared by container ID because Loro resolves a root name shared
 * by two container types by registration order, which differs between
 * replicas and reloads.
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
    const roots = assertOperations(staged, from, to);
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
   * but the releasing update passes on its own, the waiting updates are
   * validated one at a time, each after its dependencies. The ones that fail,
   * and those that depend on them, are discarded.
   */
  remoteChange(document: LoroDoc, changes: Uint8Array): LoroDoc {
    const range = expectMode(changes, 'update');
    if (covers(document.oplogVersion().toJSON(), range)) return document;
    const trapped = held(trappedUpdates, document, MAX_TRAPPED_UPDATES);
    if (trapped.find(changes) !== undefined) {
      throw new Error('Loro update trapped Loro when it was validated before');
    }
    if (trapped.size >= MAX_TRAPPED_UPDATES) {
      throw new Error(
        'Loro document is retired after remote updates trapped Loro; reopen it',
      );
    }
    const waiting = held(waitingUpdates, document, MAX_WAITING_UPDATES);
    if (waiting.find(changes) !== undefined) return document;
    const ready = integrable(document, [...waiting.values(), changes]);
    if (!ready.includes(changes)) {
      waiting.add(changes);
      return document;
    }
    const validate = (updates: readonly Uint8Array[]): void => {
      try {
        validateImport(document, updates);
      } catch (error) {
        if (updates.length === 1 && error instanceof WebAssembly.RuntimeError) {
          trapped.add(updates[0]!);
        }
        throw error;
      }
    };
    let valid = true;
    try {
      validate(ready);
    } catch (error) {
      if (ready.length === 1 || integrable(document, [changes]).length === 0) {
        throw error;
      }
      valid = false;
    }
    if (valid) {
      document.importBatch(ready);
    } else {
      validate([changes]);
      document.importBatch([changes]);
      for (const update of ready) {
        if (update === changes || integrable(document, [update]).length === 0) {
          continue;
        }
        try {
          validate([update]);
          document.importBatch([update]);
        } catch {
          // `hasDiscarded` reports the update from now on.
        }
      }
    }
    for (const update of ready) waiting.delete(update);
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
   * failed validation after its dependencies arrived, depends on one that did,
   * the waiting queue evicted it, or `remoteChange` rejected it.
   */
  hasDiscarded(document: LoroDoc, changes: Uint8Array): boolean {
    return (
      !this.hasIntegrated(document, changes) &&
      waitingUpdates.get(document)?.find(changes) === undefined
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
