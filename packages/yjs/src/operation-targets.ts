import {
  AbstractType,
  GC,
  Item,
  Map as YMap,
  Array as YArray,
  Text as YText,
  findIndexSS,
  type Transaction,
} from 'yjs';
import { DocumentOperationTargets } from '@peerborne/core';

function target(
  item: Item,
  roots: ReadonlyMap<AbstractType<any>, string>,
): readonly string[] {
  const chain: Item[] = [];
  const seen = new Set<Item>();
  let current = item;
  let root: AbstractType<any>;
  while (true) {
    if (
      seen.has(current) ||
      chain.length >= 64 ||
      !(current.parent instanceof AbstractType)
    )
      throw new Error('Unknown Yjs operation ancestry');
    seen.add(current);
    chain.push(current);
    if (current.parent._item === null) {
      root = current.parent;
      break;
    }
    current = current.parent._item;
  }
  const name = roots.get(root);
  if (name === undefined) throw new Error('Unknown Yjs operation root');
  const path: string[] = [name];
  for (let index = chain.length - 1; index >= 0; index--) {
    const parent = chain[index].parent;
    if (parent instanceof YArray || parent instanceof YText) return path;
    if (!(parent instanceof YMap))
      throw new Error('Yjs operation root schema is unavailable');
    const key = chain[index].parentSub;
    if (key === null) throw new Error('Invalid Yjs map operation');
    path.push(key);
  }
  return path;
}

/**
 * Inspect integrated items before native GC, including losing writes and deletion ranges.
 * A GC struct has no parent or content: it was sent collected or lies under a deletion this
 * replica already accepted. It cannot become visible here, so it consumes work without a
 * target; a replica that integrates the same operation as an item still checks its path.
 */
export function recordYjsOperationTargets(
  transaction: Transaction,
  targets: DocumentOperationTargets,
): void {
  const roots = new Map<AbstractType<any>, string>();
  for (const [name, root] of transaction.doc.share) {
    if (roots.size >= 4096)
      throw new Error('Yjs operation roots exceed bounds');
    roots.set(root, name);
  }
  const visit = (client: number, start: number, end: number) => {
    if (start === end) return;
    const structs = transaction.doc.store.clients.get(client);
    if (
      !structs ||
      !Number.isSafeInteger(start) ||
      !Number.isSafeInteger(end) ||
      start < 0 ||
      end < start
    )
      throw new Error('Invalid Yjs operation range');
    for (
      let index = findIndexSS(structs, start);
      index < structs.length;
      index++
    ) {
      const item = structs[index];
      if (item.id.clock >= end) break;
      const work =
        Math.min(end, item.id.clock + item.length) -
        Math.max(start, item.id.clock);
      if (item instanceof GC) targets.addInert(work);
      else if (item instanceof Item) targets.add(target(item, roots), work);
      else throw new Error('Unknown Yjs operation struct');
    }
  };
  for (const [client, end] of transaction.afterState)
    visit(client, transaction.beforeState.get(client) ?? 0, end);
  for (const [client, ranges] of transaction.deleteSet.clients)
    for (const range of ranges)
      visit(client, range.clock, range.clock + range.len);
}
