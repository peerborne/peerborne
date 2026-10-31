export function shouldCompact(
  enabled: boolean,
  unsupported: boolean,
  inProgress: boolean,
  totalChanges: number,
  sinceSnapshot: number,
  minimumChanges: number,
  interval: number,
): boolean {
  //@ verify
  //@ requires 0 <= totalChanges && totalChanges <= 9007199254740991
  //@ requires 0 <= sinceSnapshot && sinceSnapshot <= 9007199254740991
  //@ requires 0 <= minimumChanges && minimumChanges <= 9007199254740991
  //@ requires 0 <= interval && interval <= 9007199254740991
  //@ ensures \result <==> enabled && !unsupported && !inProgress && totalChanges >= minimumChanges && sinceSnapshot >= interval
  return (
    enabled &&
    !unsupported &&
    !inProgress &&
    !(totalChanges < minimumChanges) &&
    !(sinceSnapshot < interval)
  );
}

export function canReplacePendingWelcome(
  existing: boolean,
  authenticated: boolean,
): boolean {
  //@ verify
  //@ ensures \result <==> !existing || authenticated
  return !existing || authenticated;
}

export function firstUnauthenticatedEntry(
  authenticated: readonly boolean[],
): number {
  //@ verify
  //@ requires authenticated.length <= 4294967295
  //@ ensures -1 <= \result && \result < authenticated.length
  //@ ensures \result === -1 <==> forall(j: int, 0 <= j && j < authenticated.length ==> authenticated[j])
  //@ ensures \result >= 0 ==> !authenticated[\result]
  //@ ensures forall(j: int, 0 <= j && j < \result ==> authenticated[j])
  for (let index = 0; index < authenticated.length; index++) {
    //@ invariant 0 <= index && index <= authenticated.length
    //@ invariant forall(j: int, 0 <= j && j < index ==> authenticated[j])
    //@ decreases authenticated.length - index
    if (!authenticated[index]) return index;
  }
  return -1;
}
