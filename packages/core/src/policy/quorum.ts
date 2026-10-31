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
