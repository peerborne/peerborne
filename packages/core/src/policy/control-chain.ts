export function isControlActionValid(
  hasPrevious: boolean,
  creating: boolean,
): boolean {
  //@ verify
  //@ ensures \result <==> (hasPrevious ? !creating : creating)
  return hasPrevious !== creating;
}

export function isSelfUpdateTransitionAllowed(
  updating: boolean,
  actorIsSubject: boolean,
  noWelcomes: boolean,
  priorEpoch: bigint,
  nextEpoch: bigint,
  treeChanged: boolean,
  transcriptChanged: boolean,
): boolean {
  //@ verify
  //@ requires 0n <= priorEpoch && priorEpoch <= 18446744073709551615n
  //@ requires 0n <= nextEpoch && nextEpoch <= 18446744073709551615n
  //@ ensures \result <==> updating && actorIsSubject && noWelcomes && priorEpoch < 18446744073709551615n && nextEpoch === priorEpoch + 1n && treeChanged && transcriptChanged
  return (
    updating &&
    actorIsSubject &&
    noWelcomes &&
    priorEpoch < 18446744073709551615n &&
    nextEpoch === priorEpoch + 1n &&
    treeChanged &&
    transcriptChanged
  );
}

export function controlEpochFollows(
  hasPrevious: boolean,
  previousEpoch: bigint,
  initialEpoch: bigint,
  incomingEpoch: bigint,
  creating: boolean,
): boolean {
  //@ verify
  //@ requires 0n <= previousEpoch && previousEpoch <= 18446744073709551615n
  //@ requires 0n <= initialEpoch && initialEpoch <= 18446744073709551615n
  //@ requires 0n <= incomingEpoch && incomingEpoch <= 18446744073709551615n
  //@ ensures \result <==> isControlActionValid(hasPrevious, creating) && (hasPrevious ? previousEpoch < 18446744073709551615n && incomingEpoch === previousEpoch + 1n : incomingEpoch === initialEpoch)
  //@ ensures \result && hasPrevious ==> previousEpoch < incomingEpoch
  //@ ensures hasPrevious && previousEpoch === 18446744073709551615n ==> !\result
  if (!isControlActionValid(hasPrevious, creating)) return false;
  return hasPrevious
    ? previousEpoch < 18446744073709551615n &&
        incomingEpoch === previousEpoch + 1n
    : incomingEpoch === initialEpoch;
}

/** Admission after signature, protocol/group and occupied-slot checks. */
export function classifyControlAppend(
  hasPrevious: boolean,
  previousEpoch: bigint,
  initialEpoch: bigint,
  incomingEpoch: bigint,
  creating: boolean,
  hasParent: boolean,
  parentMatches: boolean,
  operationKnown: boolean,
):
  | 'ready'
  | 'operation-id-conflict'
  | 'epoch-out-of-order'
  | 'parent-mismatch' {
  //@ verify
  //@ requires 0n <= previousEpoch && previousEpoch <= 18446744073709551615n
  //@ requires 0n <= initialEpoch && initialEpoch <= 18446744073709551615n
  //@ requires 0n <= incomingEpoch && incomingEpoch <= 18446744073709551615n
  //@ ensures \result === "operation-id-conflict" <==> operationKnown
  //@ ensures \result === "epoch-out-of-order" <==> !operationKnown && !controlEpochFollows(hasPrevious, previousEpoch, initialEpoch, incomingEpoch, creating)
  //@ ensures \result === "parent-mismatch" <==> !operationKnown && controlEpochFollows(hasPrevious, previousEpoch, initialEpoch, incomingEpoch, creating) && !(hasPrevious ? hasParent && parentMatches : !hasParent)
  //@ ensures \result === "ready" <==> !operationKnown && controlEpochFollows(hasPrevious, previousEpoch, initialEpoch, incomingEpoch, creating) && (hasPrevious ? hasParent && parentMatches : !hasParent)
  if (operationKnown) return 'operation-id-conflict';
  if (
    !controlEpochFollows(
      hasPrevious,
      previousEpoch,
      initialEpoch,
      incomingEpoch,
      creating,
    )
  ) {
    return 'epoch-out-of-order';
  }
  if (hasPrevious ? !hasParent || !parentMatches : hasParent) {
    return 'parent-mismatch';
  }
  return 'ready';
}
