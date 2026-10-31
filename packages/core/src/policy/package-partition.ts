/** Install a new package without resurrecting a consumed reference. */
export function insertPendingPackage<Pending, Marker>(
  pending: Map<string, Pending>,
  consumed: Map<string, Marker>,
  reference: string,
  value: Pending,
): Map<string, Pending> {
  //@ verify
  //@ type Pending (==)
  //@ type Marker (==)
  //@ requires !pending.has(reference) && !consumed.has(reference)
  //@ requires forall(key: string, pending.has(key) ==> !consumed.has(key))
  //@ ensures \result.has(reference) && \result.get(reference) === value
  //@ ensures forall(key: string, \result.has(key) <==> pending.has(key) || key === reference)
  //@ ensures forall(key: string, pending.has(key) ==> \result.get(key) === pending.get(key))
  //@ ensures forall(key: string, \result.has(key) ==> !consumed.has(key))
  //@ ensures \result.size === pending.size + 1
  const result = new Map(pending);
  result.set(reference, value);
  return result;
}

/** Remove exactly the pending ciphertext being consumed. */
export function removePendingPackage<Pending>(
  pending: Map<string, Pending>,
  reference: string,
): Map<string, Pending> {
  //@ verify
  //@ type Pending (==)
  //@ requires pending.has(reference)
  //@ ensures !\result.has(reference)
  //@ ensures forall(key: string, \result.has(key) <==> pending.has(key) && key !== reference)
  //@ ensures forall(key: string, \result.has(key) ==> \result.get(key) === pending.get(key))
  //@ ensures \result.size + 1 === pending.size
  const result = new Map(pending);
  result.delete(reference);
  return result;
}

/** Add an irreversible tombstone without modifying any existing marker. */
export function insertConsumptionMarker<Marker>(
  consumed: Map<string, Marker>,
  reference: string,
  marker: Marker,
): Map<string, Marker> {
  //@ verify
  //@ type Marker (==)
  //@ requires !consumed.has(reference)
  //@ ensures \result.has(reference) && \result.get(reference) === marker
  //@ ensures forall(key: string, \result.has(key) <==> consumed.has(key) || key === reference)
  //@ ensures forall(key: string, consumed.has(key) ==> \result.get(key) === consumed.get(key))
  //@ ensures \result.size === consumed.size + 1
  const result = new Map(consumed);
  result.set(reference, marker);
  return result;
}

/** Preserve the binding of every existing operation while adding a replay. */
export function bindOperationToRecord(
  bindings: Map<string, string>,
  operation: string,
  record: string,
): Map<string, string> {
  //@ verify
  //@ requires !bindings.has(operation) || bindings.get(operation) === record
  //@ ensures \result.has(operation) && \result.get(operation) === record
  //@ ensures forall(key: string, \result.has(key) <==> bindings.has(key) || key === operation)
  //@ ensures forall(key: string, bindings.has(key) ==> \result.get(key) === bindings.get(key))
  const result = new Map(bindings);
  result.set(operation, record);
  return result;
}
