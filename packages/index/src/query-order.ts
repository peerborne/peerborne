export interface SortDirection {
  readonly direction: 'asc' | 'desc';
}

export function compareCodeUnits(left: string, right: string): number {
  //@ verify
  //@ ensures \result === 0 <==> left === right
  //@ ensures \result === -1 <==> left < right
  //@ ensures \result === 1 <==> left > right
  return left === right ? 0 : left < right ? -1 : 1;
}

export function compareFiniteNumbers(left: number, right: number): number {
  //@ verify
  //@ type left real
  //@ type right real
  //@ ensures \result === 0 <==> left === right
  //@ ensures \result === -1 <==> left < right
  //@ ensures \result === 1 <==> left > right
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

/** Compare owned normalized fields lazily, then the unique document path. */
export function compareQueryKeys(
  directions: readonly SortDirection[],
  comparisonAt: (index: number) => number,
  leftPath: string,
  rightPath: string,
): number {
  //@ verify
  //@ requires directions.length <= 8
  //@ requires forall(i: int, 0 <= i && i < directions.length ==> -1 <= comparisonAt(i) && comparisonAt(i) <= 1)
  //@ ensures -1 <= \result && \result <= 1
  //@ ensures forall(i: int, 0 <= i && i < directions.length ==> comparisonAt(i) === 0) ==> \result === compareCodeUnits(leftPath, rightPath)
  //@ ensures \result === 0 <==> leftPath === rightPath && forall(i: int, 0 <= i && i < directions.length ==> comparisonAt(i) === 0)
  //@ ensures exists(i: int, 0 <= i && i < directions.length && comparisonAt(i) !== 0) ==> exists(i: int, 0 <= i && i < directions.length && comparisonAt(i) !== 0 && forall(j: int, 0 <= j && j < i ==> comparisonAt(j) === 0) && \result === (directions[i].direction === "desc" ? -comparisonAt(i) : comparisonAt(i)))
  for (let index = 0; index < directions.length; index++) {
    //@ invariant 0 <= index && index <= directions.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> comparisonAt(i) === 0)
    //@ decreases directions.length - index
    const compared = comparisonAt(index);
    if (compared !== 0)
      return directions[index].direction === 'desc' ? -compared : compared;
  }
  return compareCodeUnits(leftPath, rightPath);
}

export function takeQueryPage<Entry>(
  entries: readonly Entry[],
  first: number,
): Entry[] {
  //@ verify
  //@ type Entry (==)
  //@ requires 0 <= first && first <= 9007199254740991
  //@ requires entries.length <= 4294967295
  //@ ensures \result.length === (first < entries.length ? first : entries.length)
  //@ ensures forall(i: int, 0 <= i && i < \result.length ==> \result[i] === entries[i])
  return entries.slice(0, first);
}
