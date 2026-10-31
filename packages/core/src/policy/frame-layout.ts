/** Validate a field and reserve the mandatory bytes following it. */
export function boundedFieldEnd(
  total: number,
  offset: number,
  length: number,
  minimum: number,
  maximum: number,
  trailer: number,
): number {
  //@ verify
  //@ requires 0 <= total && total <= 4294967295
  //@ requires 0 <= offset && offset <= total
  //@ requires 0 <= length && length <= 4294967295
  //@ requires 0 <= minimum && minimum <= maximum && maximum <= 4294967295
  //@ requires 0 <= trailer && trailer <= 4294967295
  //@ ensures \result === -1 <==> length < minimum || length > maximum || trailer > total - offset || length > total - offset - trailer
  //@ ensures \result !== -1 ==> \result === offset + length && offset <= \result && \result <= total - trailer
  if (
    length < minimum ||
    length > maximum ||
    trailer > total - offset ||
    length > total - offset - trailer
  ) {
    return -1;
  }
  return offset + length;
}

/** Copy as much of one field as this chunk supplies, without over-reading. */
export function frameCopyLength(
  received: number,
  expected: number,
  available: number,
): number {
  //@ verify
  //@ requires 0 <= received && received <= expected && expected <= 4294967295
  //@ requires 0 <= available && available <= 9007199254740991
  //@ ensures 0 <= \result && \result <= available
  //@ ensures received + \result <= expected
  //@ ensures \result === (expected - received < available ? expected - received : available)
  //@ ensures received < expected && available > 0 ==> \result > 0
  //@ ensures received + \result === expected || \result === available
  const remaining = expected - received;
  return remaining < available ? remaining : available;
}
