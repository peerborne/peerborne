export function syncRequestTimeAllowed(issuedAt: number, now: number): boolean {
  //@ verify
  //@ requires 0 <= issuedAt && issuedAt <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ ensures \result <==> now - issuedAt <= 60000 && issuedAt - now <= 30000
  return issuedAt - now >= -60000 && issuedAt - now <= 30000;
}

export function advanceSyncRequestClock(
  previous: number,
  observed: number,
): number {
  //@ verify
  //@ requires 0 <= previous && previous <= 9007199254740991
  //@ requires 0 <= observed && observed <= 9007199254740991
  //@ ensures \result === (previous > observed ? previous : observed)
  //@ ensures previous <= \result && observed <= \result && \result <= 9007199254740991
  return previous > observed ? previous : observed;
}

export function syncRequestReplayExpired(
  issuedAt: number,
  now: number,
): boolean {
  //@ verify
  //@ requires 0 <= issuedAt && issuedAt <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ ensures \result <==> now - issuedAt > 60000
  //@ ensures \result ==> !syncRequestTimeAllowed(issuedAt, now)
  return now - issuedAt > 60000;
}

export function pruneSyncRequestReplays(
  keys: readonly string[],
  ledger: Map<string, number>,
  now: number,
): Map<string, number> {
  //@ verify
  //@ requires 0 <= now && now <= 9007199254740991
  //@ requires keys.length === ledger.size && ledger.size <= 128
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < keys.length ==> keys[i] !== keys[j]))
  //@ requires forall(key: string, ledger.has(key) <==> keys.includes(key))
  //@ requires forall(key: string, ledger.has(key) ==> 0 <= ledger.get(key) && ledger.get(key) <= 9007199254740991)
  //@ ensures forall(key: string, \result.has(key) <==> ledger.has(key) && !syncRequestReplayExpired(ledger.get(key), now))
  //@ ensures forall(key: string, \result.has(key) ==> \result.get(key) === ledger.get(key))
  //@ ensures \result.size <= ledger.size
  const result = new Map<string, number>();
  for (let index = 0; index < keys.length; index++) {
    //@ invariant 0 <= index && index <= keys.length
    //@ invariant result.size <= index
    //@ invariant forall(key: string, result.has(key) <==> ledger.has(key) && !syncRequestReplayExpired(ledger.get(key), now) && exists(i: int, 0 <= i && i < index && keys[i] === key))
    //@ invariant forall(key: string, result.has(key) ==> result.get(key) === ledger.get(key))
    //@ decreases keys.length - index
    const key = keys[index];
    if (!syncRequestReplayExpired(ledger.get(key)!, now))
      result.set(key, ledger.get(key)!);
  }
  return result;
}

export function classifySyncRequestReplay(
  issuedAt: number,
  now: number,
  known: boolean,
  size: number,
  capacity: number,
): 'stale' | 'replay' | 'capacity' | 'fresh' {
  //@ verify
  //@ requires 0 <= issuedAt && issuedAt <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ requires 0 <= size && size <= capacity && capacity <= 9007199254740991
  //@ ensures \result === "stale" <==> !syncRequestTimeAllowed(issuedAt, now)
  //@ ensures \result === "replay" <==> syncRequestTimeAllowed(issuedAt, now) && known
  //@ ensures \result === "capacity" <==> syncRequestTimeAllowed(issuedAt, now) && !known && size === capacity
  //@ ensures \result === "fresh" <==> syncRequestTimeAllowed(issuedAt, now) && !known && size < capacity
  if (!syncRequestTimeAllowed(issuedAt, now)) return 'stale';
  if (known) return 'replay';
  return size < capacity ? 'fresh' : 'capacity';
}

export function rememberSyncRequest(
  ledger: Map<string, number>,
  key: string,
  issuedAt: number,
  capacity: number,
): Map<string, number> {
  //@ verify
  //@ requires 0 <= issuedAt && issuedAt <= 9007199254740991
  //@ requires 0 <= capacity && capacity <= 9007199254740991
  //@ requires ledger.size < capacity && !ledger.has(key)
  //@ ensures \result.size === ledger.size + 1 && \result.size <= capacity
  //@ ensures \result.has(key) && \result.get(key) === issuedAt
  //@ ensures forall(id: string, \result.has(id) <==> ledger.has(id) || id === key)
  //@ ensures forall(id: string, ledger.has(id) ==> \result.get(id) === ledger.get(id))
  const result = new Map(ledger);
  result.set(key, issuedAt);
  return result;
}

export function syncResponseAllowed(
  now: number,
  lastResponse: number,
  hasChange: boolean,
  changeKnown: boolean,
  hasSnapshot: boolean,
  snapshotKnown: boolean,
): boolean {
  //@ verify
  //@ requires 0 <= now && now <= 9007199254740991
  //@ requires 0 <= lastResponse && lastResponse <= 9007199254740991
  //@ ensures \result <==> now - lastResponse >= 2000 && hasChange && (!changeKnown || hasSnapshot && !snapshotKnown)
  return (
    now - lastResponse >= 2000 &&
    hasChange &&
    (!changeKnown || (hasSnapshot && !snapshotKnown))
  );
}
