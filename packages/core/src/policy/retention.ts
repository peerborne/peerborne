/** Never select a retained or protected CID, and select every safe candidate. */
export function selectDeletableCids(
  candidates: readonly string[],
  retained: Set<string>,
  protectedCids: Set<string>,
): Set<string> {
  //@ verify
  //@ requires candidates.length <= 4294967295
  //@ ensures forall(cid: string, \result.has(cid) <==> candidates.includes(cid) && !retained.has(cid) && !protectedCids.has(cid))
  const result = new Set<string>();
  for (let index = 0; index < candidates.length; index++) {
    //@ invariant 0 <= index && index <= candidates.length
    //@ invariant forall(cid: string, result.has(cid) ==> !retained.has(cid) && !protectedCids.has(cid) && exists(j: int, 0 <= j && j < index && candidates[j] === cid))
    //@ invariant forall(j: int, 0 <= j && j < index && !retained.has(candidates[j]) && !protectedCids.has(candidates[j]) ==> result.has(candidates[j]))
    //@ decreases candidates.length - index
    const cid = candidates[index];
    if (!retained.has(cid) && !protectedCids.has(cid)) result.add(cid);
  }
  return result;
}
