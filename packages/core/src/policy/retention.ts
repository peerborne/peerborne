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

export type BlockGcPhase =
  'ready' | 'checking' | 'deleting' | 'settled' | 'aborted';
export type BlockGcAction = 'check' | 'delete' | 'settle' | 'abort';

export function canRetainGcCandidate(
  known: boolean,
  count: number,
  length: number,
): boolean {
  //@ verify
  //@ requires 0 <= count && count <= 32768 && 0 <= length && length <= 9007199254740991
  //@ ensures \result <==> 1 <= length && length <= 512 && (known || count < 32768)
  //@ ensures \result && !known ==> count + 1 <= 32768
  return length >= 1 && length <= 512 && (known || count < 32768);
}

export function gcLeaseIsCurrent(
  sameTree: boolean,
  sameSnapshot: boolean,
  sameTips: boolean,
  active: boolean,
): boolean {
  //@ verify
  //@ ensures \result <==> sameTree && sameSnapshot && sameTips && active
  return sameTree && sameSnapshot && sameTips && active;
}

export function advanceBlockGc(
  phase: BlockGcPhase,
  action: BlockGcAction,
  leaseCurrent: boolean,
  unpinned: boolean,
): BlockGcPhase {
  //@ verify
  //@ ensures \result === "deleting" <==> phase === "checking" && action === "delete" && leaseCurrent && unpinned
  //@ ensures \result === "checking" <==> phase === "ready" && action === "check" && leaseCurrent
  //@ ensures \result === "settled" <==> phase === "deleting" && action === "settle"
  //@ ensures phase === "settled" || phase === "aborted" ==> \result === "aborted"
  if (phase === 'ready' && action === 'check' && leaseCurrent)
    return 'checking';
  if (phase === 'checking' && action === 'delete' && leaseCurrent && unpinned)
    return 'deleting';
  if (phase === 'deleting' && action === 'settle') return 'settled';
  return 'aborted';
}
