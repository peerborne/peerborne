import {
  decodeChange,
  getAllChanges,
  getBackend,
  type Doc,
  type Change,
} from '@automerge/automerge';
import {
  DocumentOperationTargets,
  type DocumentWritePaths,
} from '@peerborne/core';

type Node = { parent: string; key: string; kind: 'map' | 'sequence' };
const kinds = new Map<string, Node['kind']>([
  ['makeMap', 'map'],
  ['makeTable', 'map'],
  ['makeList', 'sequence'],
  ['makeText', 'sequence'],
]);
const actions = new Set([
  ...kinds.keys(),
  'set',
  'del',
  'inc',
  'markBegin',
  'markEnd',
]);
const MAX_OBJECTS = 262144;

/** Immutable object creation ancestry includes losing and deleted objects. */
export class AutomergeOperationIndex {
  private constructor(private readonly nodes: Map<string, Node>) {}

  static from(document: Doc<unknown>): AutomergeOperationIndex {
    const nodes = new Map<string, Node>();
    for (const bytes of getAllChanges(document))
      AutomergeOperationIndex.add(nodes, decodeChange(bytes));
    return new AutomergeOperationIndex(nodes);
  }

  private static add(
    nodes: Map<string, Node>,
    change: ReturnType<typeof decodeChange>,
  ): void {
    if (!/^(?:[0-9a-f]{2}){1,64}$/.test(change.actor))
      throw new RangeError('Automerge authorization actor exceeds bounds');
    for (let index = 0; index < change.ops.length; index++) {
      const op = change.ops[index],
        kind = kinds.get(op.action);
      if (!kind) continue;
      if (
        !Number.isSafeInteger(change.startOp + index) ||
        nodes.size >= MAX_OBJECTS
      )
        throw new RangeError('Automerge authorization ancestry exceeds bounds');
      const id = `${change.startOp + index}@${change.actor}`;
      const previous = nodes.get(id);
      if (
        previous &&
        (previous.parent !== op.obj ||
          previous.key !== op.key ||
          previous.kind !== kind)
      )
        throw new Error('Conflicting Automerge object ancestry');
      nodes.set(id, { parent: op.obj, key: op.key, kind });
    }
  }

  inspect(base: Doc<unknown>, changes: readonly Change[]) {
    return this.prepare(base, changes, true);
  }

  extend(base: Doc<unknown>, changes: readonly Change[]): { accept(): void } {
    return this.prepare(base, changes, false);
  }

  private prepare(
    base: Doc<unknown>,
    changes: readonly Change[],
    collect: boolean,
  ): {
    paths: DocumentWritePaths;
    accept(): void;
  } {
    const backend = getBackend(base);
    const fresh = changes
      .map((bytes) => decodeChange(bytes))
      .filter((change) => backend.getChangeByHash(change.hash) === null);
    const overlay = new Map<string, Node>();
    for (const change of fresh) AutomergeOperationIndex.add(overlay, change);
    if (this.nodes.size + overlay.size > MAX_OBJECTS)
      throw new RangeError('Automerge authorization ancestry exceeds bounds');
    const node = (id: string) => overlay.get(id) ?? this.nodes.get(id);
    const target = (object: string, key: string): readonly string[] => {
      const chain: Node[] = [],
        seen = new Set<string>();
      let id = object;
      while (id !== '_root') {
        const value = node(id);
        if (!value || seen.has(id) || chain.length >= 64)
          throw new Error('Unknown Automerge operation ancestry');
        seen.add(id);
        chain.push(value);
        id = value.parent;
      }
      const path: string[] = [];
      for (let index = chain.length - 1; index >= 0; index--) {
        path.push(chain[index].key);
        if (chain[index].kind === 'sequence') return path;
      }
      path.push(key);
      return path;
    };
    const paths = new DocumentOperationTargets();
    if (collect)
      for (const change of fresh)
        for (const op of change.ops) {
          if (!actions.has(op.action))
            throw new Error('Unsupported Automerge operation');
          paths.add(target(op.obj, op.key));
        }
    return {
      paths: paths.snapshot(),
      accept: () => {
        for (const [id, value] of overlay) this.nodes.set(id, value);
      },
    };
  }
}
