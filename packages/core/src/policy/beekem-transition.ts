export type BeeKEMGenerationDisposition =
  | 'stale'
  | 'duplicate'
  | 'fork'
  | 'next'
  | 'gap';

/** Generation policy after the runtime adapter validates the uint32 header. */
export function classifyBeeKEMGeneration(
  current: number,
  incoming: number,
  sameUpdateDigest: boolean,
): BeeKEMGenerationDisposition {
  //@ verify
  //@ requires 0 <= current && current <= 4294967295
  //@ requires 1 <= incoming && incoming <= 4294967295
  //@ ensures \result === "stale" <==> incoming < current
  //@ ensures \result === "duplicate" <==> incoming === current && sameUpdateDigest
  //@ ensures \result === "fork" <==> incoming === current && !sameUpdateDigest
  //@ ensures \result === "next" <==> incoming === current + 1
  //@ ensures \result === "gap" <==> incoming > current + 1
  if (incoming < current) return 'stale';
  if (incoming === current) return sameUpdateDigest ? 'duplicate' : 'fork';
  if (incoming === current + 1) return 'next';
  return 'gap';
}

/** BeeKEM transitions preserve the lifetime leaf count or append one leaf. */
export function isAppendOnlyLeafCount(
  current: number,
  incoming: number,
  capacity: number,
): boolean {
  //@ verify
  //@ requires 1 <= current && current <= capacity && capacity < 9007199254740991
  //@ requires 1 <= incoming && incoming <= 9007199254740991
  //@ ensures \result <==> incoming <= capacity && (incoming === current || incoming === current + 1)
  //@ ensures \result ==> current <= incoming && incoming <= current + 1 && incoming <= capacity
  //@ ensures current === capacity && \result ==> incoming === current
  return (
    incoming <= capacity && (incoming === current || incoming === current + 1)
  );
}
