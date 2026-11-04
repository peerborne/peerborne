export interface KeychainHistoryPlan {
  readonly valid: boolean;
  readonly order: readonly number[];
  readonly probes: number;
}

export function keychainHistoryTailClock(
  clock: number,
  length: number,
): number {
  //@ verify
  //@ requires 0 <= clock && clock <= 9007199254740991
  //@ requires 1 <= length && length <= 1000
  //@ ensures \result === -1 <==> length - 1 > 9007199254740991 - clock
  //@ ensures \result !== -1 ==> \result === clock + (length - 1) && clock <= \result && \result <= 9007199254740991
  const offset = length - 1;
  return offset > 9007199254740991 - clock ? -1 : clock + offset;
}

/** Index unique predecessor links, then consume the chain rooted at the empty sentinel. */
export function orderKeychainHistory(
  ids: readonly string[],
  parents: readonly string[],
): KeychainHistoryPlan {
  //@ verify
  //@ requires ids.length === parents.length && ids.length <= 1000
  //@ ensures 0 <= \result.order.length && \result.order.length <= ids.length
  //@ ensures 0 <= \result.probes && \result.probes <= ids.length + 1
  //@ ensures \result.probes === 0 || \result.probes === \result.order.length + 1
  //@ ensures \result.valid <==> \result.probes > 0 && \result.order.length === ids.length
  //@ ensures \result.probes > 0 <==> forall(i: int, 0 <= i && i < ids.length ==> ids[i] !== "") && forall(i: int, forall(j: int, 0 <= i && i < ids.length && 0 <= j && j < ids.length && ids[i] === ids[j] ==> i === j)) && forall(i: int, forall(j: int, 0 <= i && i < ids.length && 0 <= j && j < ids.length && parents[i] === parents[j] ==> i === j))
  //@ ensures forall(i: int, 0 <= i && i < \result.order.length ==> 0 <= \result.order[i] && \result.order[i] < ids.length)
  //@ ensures forall(i: int, forall(j: int, 0 <= i && i < \result.order.length && 0 <= j && j < \result.order.length && \result.order[i] === \result.order[j] ==> i === j))
  //@ ensures \result.order.length > 0 ==> parents[\result.order[0]] === ""
  //@ ensures forall(i: int, 1 <= i && i < \result.order.length ==> parents[\result.order[i]] === ids[\result.order[i - 1]])
  //@ ensures \result.probes > 0 ==> forall(i: int, 0 <= i && i < ids.length ==> parents[i] !== (\result.order.length === 0 ? "" : ids[\result.order[\result.order.length - 1]]))
  const byParent = new Map<string, number>();
  const seen = new Set<string>();
  for (let index = 0; index < ids.length; index++) {
    //@ invariant 0 <= index && index <= ids.length
    //@ invariant byParent.size === index && seen.size === index
    //@ invariant forall(key: string, seen.has(key) <==> exists(i: int, 0 <= i && i < index && ids[i] === key))
    //@ invariant forall(key: string, byParent.has(key) <==> exists(i: int, 0 <= i && i < index && parents[i] === key))
    //@ invariant forall(i: int, 0 <= i && i < index ==> byParent.has(parents[i]) && byParent.get(parents[i]) === i && ids[i] !== "")
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < index && 0 <= j && j < index && ids[i] === ids[j] ==> i === j))
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < index && 0 <= j && j < index && parents[i] === parents[j] ==> i === j))
    //@ decreases ids.length - index
    const id = ids[index];
    const parent = parents[index];
    if (id === '' || seen.has(id) || byParent.has(parent)) {
      return { valid: false, order: [], probes: 0 };
    }
    seen.add(id);
    byParent.set(parent, index);
  }
  const order: number[] = [];
  let cursor = '';
  let probes = 1;
  while (byParent.has(cursor)) {
    //@ invariant 0 <= order.length && order.length <= ids.length
    //@ invariant order.length + byParent.size === ids.length
    //@ invariant probes === order.length + 1
    //@ invariant forall(i: int, 0 <= i && i < order.length ==> 0 <= order[i] && order[i] < ids.length)
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < order.length && 0 <= j && j < order.length && order[i] === order[j] ==> i === j))
    //@ invariant forall(key: string, byParent.has(key) ==> exists(i: int, 0 <= i && i < ids.length && parents[i] === key))
    //@ invariant forall(i: int, 0 <= i && i < ids.length ==> (byParent.has(parents[i]) <==> !order.includes(i)))
    //@ invariant forall(i: int, 0 <= i && i < ids.length && byParent.has(parents[i]) ==> byParent.get(parents[i]) === i)
    //@ invariant order.length === 0 ? cursor === "" : cursor === ids[order[order.length - 1]]
    //@ invariant order.length > 0 ==> parents[order[0]] === ""
    //@ invariant forall(i: int, 1 <= i && i < order.length ==> parents[order[i]] === ids[order[i - 1]])
    //@ invariant forall(i: int, 0 <= i && i < order.length ==> parents[order[i]] !== cursor)
    //@ decreases byParent.size
    const next = byParent.get(cursor)!;
    //@ assert 0 <= next && next < ids.length
    //@ assert parents[next] === cursor && !order.includes(next)
    byParent.delete(cursor);
    order.push(next);
    cursor = ids[next];
    probes++;
  }
  return { valid: order.length === ids.length, order, probes };
}

export function sameKeychainEntry(
  left: readonly string[],
  right: readonly string[],
): boolean {
  //@ verify
  //@ requires left.length === 2 && right.length === 2
  //@ ensures \result <==> left[0] === right[0] && left[1] === right[1]
  return left[0] === right[0] && left[1] === right[1];
}

export function isKeychainPrefix(
  prefix: readonly (readonly string[])[],
  entries: readonly (readonly string[])[],
): boolean {
  //@ verify
  //@ requires prefix.length <= 4294967295 && entries.length <= 4294967295
  //@ requires forall(i: int, 0 <= i && i < prefix.length ==> prefix[i].length === 2)
  //@ requires forall(i: int, 0 <= i && i < entries.length ==> entries[i].length === 2)
  //@ ensures \result <==> prefix.length <= entries.length && forall(i: int, 0 <= i && i < prefix.length ==> prefix[i][0] === entries[i][0] && prefix[i][1] === entries[i][1])
  if (prefix.length > entries.length) return false;
  for (let index = 0; index < prefix.length; index++) {
    //@ invariant 0 <= index && index <= prefix.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> prefix[i][0] === entries[i][0] && prefix[i][1] === entries[i][1])
    //@ decreases prefix.length - index
    if (!sameKeychainEntry(prefix[index], entries[index])) return false;
  }
  return true;
}

/** Distinguish truncation from the first rewritten entry before committing. */
export function firstKeychainRewrite(
  before: readonly (readonly string[])[],
  after: readonly (readonly string[])[],
): number {
  //@ verify
  //@ requires before.length <= after.length && after.length <= 4294967295
  //@ requires forall(i: int, 0 <= i && i < before.length ==> before[i].length === 2)
  //@ requires forall(i: int, 0 <= i && i < after.length ==> after[i].length === 2)
  //@ ensures -1 <= \result && \result < before.length
  //@ ensures \result === -1 <==> forall(i: int, 0 <= i && i < before.length ==> before[i][0] === after[i][0] && before[i][1] === after[i][1])
  //@ ensures \result >= 0 ==> before[\result][0] !== after[\result][0] || before[\result][1] !== after[\result][1]
  for (let index = 0; index < before.length; index++) {
    //@ invariant 0 <= index && index <= before.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> before[i][0] === after[i][0] && before[i][1] === after[i][1])
    //@ decreases before.length - index
    if (!sameKeychainEntry(before[index], after[index])) return index;
  }
  return -1;
}
