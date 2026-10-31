/** Bound Cartesian expansion before allocating physical-index lookups. */
export function boundedCartesianSize(
  left: number,
  right: number,
  limit: number,
): number {
  //@ verify
  //@ requires 0 <= left && left <= 65536 && 0 <= right && right <= 65536
  //@ requires 0 <= limit && limit <= 9007199254740991
  //@ ensures \result === -1 <==> left * right > limit
  //@ ensures \result !== -1 ==> \result === left * right && 0 <= \result && \result <= limit
  //@ ensures left === 0 || right === 0 ==> \result === 0
  const count = left * right;
  return count > limit ? -1 : count;
}
