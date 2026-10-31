export function replayWindowFloor(
  currentEpoch: bigint,
  window: bigint,
): bigint {
  //@ verify
  //@ requires 0n <= currentEpoch && currentEpoch <= 18446744073709551615n
  //@ requires 1n <= window && window <= 65535n
  //@ ensures 0n <= \result && \result <= currentEpoch
  //@ ensures \result === (currentEpoch + 1n > window ? currentEpoch - window + 1n : 0n)
  //@ ensures currentEpoch - \result < window
  return currentEpoch + 1n > window ? currentEpoch - window + 1n : 0n;
}

export function authorizationAnchorFloor(
  currentEpoch: bigint,
  window: bigint,
): bigint {
  //@ verify
  //@ requires 0n <= currentEpoch && currentEpoch <= 18446744073709551615n
  //@ requires 1n <= window && window <= 65535n
  //@ ensures 0n <= \result && \result <= replayWindowFloor(currentEpoch, window)
  //@ ensures replayWindowFloor(currentEpoch, window) > 0n ==> \result + 1n === replayWindowFloor(currentEpoch, window)
  //@ ensures replayWindowFloor(currentEpoch, window) === 0n ==> \result === 0n
  const floor = replayWindowFloor(currentEpoch, window);
  return floor === 0n ? 0n : floor - 1n;
}

export function firstMissingRetainedEpoch<Entry>(
  byEpoch: Map<bigint, Entry>,
  currentEpoch: bigint,
  window: bigint,
): bigint {
  //@ verify
  //@ type Entry (==)
  //@ requires 0n <= currentEpoch && currentEpoch <= 18446744073709551615n
  //@ requires 1n <= window && window <= 65535n
  //@ ensures \result === -1n <==> forall(epoch: int, authorizationAnchorFloor(currentEpoch, window) <= epoch && epoch <= currentEpoch ==> byEpoch.has(epoch))
  //@ ensures \result !== -1n ==> authorizationAnchorFloor(currentEpoch, window) <= \result && \result <= currentEpoch && !byEpoch.has(\result)
  //@ ensures \result !== -1n ==> forall(epoch: int, authorizationAnchorFloor(currentEpoch, window) <= epoch && epoch < \result ==> byEpoch.has(epoch))
  const floor = authorizationAnchorFloor(currentEpoch, window);
  for (let epoch = floor; epoch <= currentEpoch; epoch += 1n) {
    //@ invariant floor <= epoch && epoch <= currentEpoch + 1n
    //@ invariant forall(prior: int, floor <= prior && prior < epoch ==> byEpoch.has(prior))
    //@ decreases currentEpoch - epoch + 1n
    if (!byEpoch.has(epoch)) return epoch;
  }
  return -1n;
}

/** Retain the authorization anchor and every outstanding delivery's record. */
export function shouldPruneReplay(
  epoch: bigint,
  currentEpoch: bigint,
  window: bigint,
  pendingDelivery: boolean,
): boolean {
  //@ verify
  //@ requires 0n <= currentEpoch && currentEpoch <= 18446744073709551615n
  //@ requires 1n <= window && window <= 65535n
  //@ ensures \result <==> epoch < authorizationAnchorFloor(currentEpoch, window) && !pendingDelivery
  //@ ensures pendingDelivery ==> !\result
  //@ ensures epoch >= authorizationAnchorFloor(currentEpoch, window) ==> !\result
  return (
    epoch < authorizationAnchorFloor(currentEpoch, window) && !pendingDelivery
  );
}
