/** Return the unique qualifying bucket, -1 for none, or -2 for a conflict. */
export function selectQuorumBucket(
  counts: readonly number[],
  threshold: number,
): number {
  //@ verify
  //@ requires 1 <= threshold && threshold <= 9007199254740991
  //@ requires counts.length <= 4294967295
  //@ requires forall(k: int, 0 <= k && k < counts.length ==> 0 <= counts[k] && counts[k] <= 9007199254740991)
  //@ ensures -2 <= \result && \result < counts.length
  //@ ensures \result >= 0 ==> counts[\result] >= threshold
  //@ ensures \result >= 0 ==> forall(k: int, 0 <= k && k < counts.length && k !== \result ==> counts[k] < threshold)
  //@ ensures \result === -1 <==> forall(k: int, 0 <= k && k < counts.length ==> counts[k] < threshold)
  //@ ensures \result === -2 <==> exists(a: int, exists(b: int, 0 <= a && a < b && b < counts.length && counts[a] >= threshold && counts[b] >= threshold))
  let winner = -1;
  for (let index = 0; index < counts.length; index++) {
    //@ invariant 0 <= index && index <= counts.length
    //@ invariant winner === -1 || (0 <= winner && winner < index && counts[winner] >= threshold)
    //@ invariant winner === -1 ==> forall(k: int, 0 <= k && k < index ==> counts[k] < threshold)
    //@ invariant winner >= 0 ==> forall(k: int, 0 <= k && k < index && k !== winner ==> counts[k] < threshold)
    //@ decreases counts.length - index
    if (counts[index] >= threshold) {
      if (winner !== -1) return -2;
      winner = index;
    }
  }
  return winner;
}

/** Strict-majority default for safe-integer peer counts; this is not consensus. */
export function defaultQuorumQ(k: number): number {
  //@ verify
  //@ requires -9007199254740991 <= k && k <= 9007199254740991
  //@ ensures k <= 0 ==> \result === 0
  //@ ensures k > 0 ==> 1 <= \result && \result <= k
  //@ ensures k > 0 ==> 2 * \result > k && 2 * (\result - 1) <= k
  if (k <= 0) return 0;
  return Math.floor(k / 2) + 1;
}

/** An explicit trust floor is independent of the currently reachable peers. */
export function requiredQuorumQ(k: number, configuredFloor: number): number {
  //@ verify
  //@ requires 0 <= k && k <= 9007199254740991
  //@ requires 0 <= configuredFloor && configuredFloor <= 9007199254740991
  //@ ensures 0 <= \result && \result <= 9007199254740991
  //@ ensures configuredFloor > 0 ==> \result === configuredFloor
  //@ ensures configuredFloor === 0 ==> \result === defaultQuorumQ(k)
  //@ ensures \result >= configuredFloor
  return configuredFloor > 0 ? configuredFloor : defaultQuorumQ(k);
}

/** Select the first eligible occurrence of each identity in input order. */
export function firstEligiblePeerIndices(
  peerIds: readonly string[],
  eligible: readonly boolean[],
): number[] {
  //@ verify
  //@ requires peerIds.length <= 4294967295 && eligible.length === peerIds.length
  //@ ensures \result.length <= peerIds.length
  //@ ensures forall(j: int, 0 <= j && j < \result.length ==> 0 <= \result[j] && \result[j] < peerIds.length)
  //@ ensures forall(a: int, forall(b: int, 0 <= a && a < b && b < \result.length ==> \result[a] < \result[b]))
  //@ ensures forall(a: int, forall(b: int, 0 <= a && a < b && b < \result.length ==> peerIds[\result[a]] !== peerIds[\result[b]]))
  //@ ensures forall(i: int, 0 <= i && i < peerIds.length ==> (\result.includes(i) <==> eligible[i] && forall(k: int, 0 <= k && k < i ==> !eligible[k] || peerIds[k] !== peerIds[i])))
  const seen = new Set<string>();
  const selected: number[] = [];
  for (let index = 0; index < peerIds.length; index++) {
    //@ invariant 0 <= index && index <= peerIds.length
    //@ invariant selected.length <= index
    //@ invariant forall(j: int, 0 <= j && j < selected.length ==> 0 <= selected[j] && selected[j] < index)
    //@ invariant forall(a: int, forall(b: int, 0 <= a && a < b && b < selected.length ==> selected[a] < selected[b]))
    //@ invariant forall(a: int, forall(b: int, 0 <= a && a < b && b < selected.length ==> peerIds[selected[a]] !== peerIds[selected[b]]))
    //@ invariant forall(key: string, seen.has(key) <==> exists(j: int, 0 <= j && j < index && eligible[j] && peerIds[j] === key))
    //@ invariant forall(i: int, 0 <= i && i < index ==> (selected.includes(i) <==> eligible[i] && forall(k: int, 0 <= k && k < i ==> !eligible[k] || peerIds[k] !== peerIds[i])))
    //@ decreases peerIds.length - index
    if (eligible[index] && !seen.has(peerIds[index])) {
      seen.add(peerIds[index]);
      selected.push(index);
    }
  }
  return selected;
}

/** Count captured digest strings; native byte validation precedes this step. */
export function countQuorumDigests(
  digests: readonly string[],
): Map<string, number> {
  //@ verify
  //@ requires digests.length <= 4294967295
  //@ ensures forall(key: string, \result.has(key) <==> digests.includes(key))
  //@ ensures forall(key: string, \result.has(key) ==> \result[key] >= 1 && \result[key] <= digests.length)
  const counts = new Map<string, number>();
  for (let index = 0; index < digests.length; index++) {
    //@ invariant 0 <= index && index <= digests.length
    //@ invariant forall(key: string, counts.has(key) <==> exists(j: int, 0 <= j && j < index && digests[j] === key))
    //@ invariant forall(key: string, counts.has(key) ==> counts[key] >= 1 && counts[key] <= index)
    //@ decreases digests.length - index
    const digest = digests[index];
    const previous = counts.get(digest);
    const count = previous === undefined ? 0 : previous;
    counts.set(digest, count + 1);
  }
  return counts;
}

/** Project a winning identity set back to its captured candidate positions. */
export function quorumCohortIndices(
  peerIds: readonly string[],
  agreeing: Set<string>,
): number[] {
  //@ verify
  //@ requires peerIds.length <= 4294967295
  //@ ensures \result.length <= peerIds.length
  //@ ensures forall(j: int, 0 <= j && j < \result.length ==> 0 <= \result[j] && \result[j] < peerIds.length)
  //@ ensures forall(a: int, forall(b: int, 0 <= a && a < b && b < \result.length ==> \result[a] < \result[b]))
  //@ ensures forall(i: int, 0 <= i && i < peerIds.length ==> (\result.includes(i) <==> agreeing.has(peerIds[i])))
  const selected: number[] = [];
  for (let index = 0; index < peerIds.length; index++) {
    //@ invariant 0 <= index && index <= peerIds.length
    //@ invariant selected.length <= index
    //@ invariant forall(j: int, 0 <= j && j < selected.length ==> 0 <= selected[j] && selected[j] < index)
    //@ invariant forall(a: int, forall(b: int, 0 <= a && a < b && b < selected.length ==> selected[a] < selected[b]))
    //@ invariant forall(i: int, 0 <= i && i < index ==> (selected.includes(i) <==> agreeing.has(peerIds[i])))
    //@ decreases peerIds.length - index
    if (agreeing.has(peerIds[index])) selected.push(index);
  }
  return selected;
}

export function quorumFailureReason(
  queried: number,
  responding: number,
  threshold: number,
  conflicting: boolean,
):
  | 'no-peers-queried'
  | 'conflicting-quorum'
  | 'insufficient-responses'
  | 'no-agreement' {
  //@ verify
  //@ requires 0 <= responding && responding <= queried && queried <= 4294967295
  //@ requires 1 <= threshold && threshold <= 9007199254740991
  //@ ensures \result === "no-peers-queried" <==> queried === 0
  //@ ensures \result === "conflicting-quorum" <==> queried > 0 && conflicting
  //@ ensures \result === "insufficient-responses" <==> queried > 0 && !conflicting && responding < threshold
  //@ ensures \result === "no-agreement" <==> queried > 0 && !conflicting && responding >= threshold
  if (queried === 0) return 'no-peers-queried';
  if (conflicting) return 'conflicting-quorum';
  return responding < threshold ? 'insufficient-responses' : 'no-agreement';
}
