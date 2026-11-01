export type DocumentJournalRecovery = 'current' | 'finish-anchor' | 'reject';

export function classifyDocumentJournalRecovery(
  stored: number,
  anchored: number,
  commitmentMatches: boolean,
  parentMatches: boolean,
): DocumentJournalRecovery {
  //@ verify
  //@ requires 0 <= stored && stored <= 9007199254740991
  //@ requires 0 <= anchored && anchored <= 9007199254740991
  //@ ensures \result === "current" <==> stored === anchored && commitmentMatches
  //@ ensures \result === "finish-anchor" <==> stored > anchored && stored - anchored === 1 && parentMatches
  //@ ensures \result === "reject" <==> !(stored === anchored && commitmentMatches) && !(stored > anchored && stored - anchored === 1 && parentMatches)
  if (stored === anchored && commitmentMatches) return 'current';
  if (stored > anchored && stored - anchored === 1 && parentMatches)
    return 'finish-anchor';
  return 'reject';
}

export function canAdvanceDocumentAuthority(
  previous: bigint,
  next: bigint,
  sameGroup: boolean,
  headChanged: boolean,
): boolean {
  //@ verify
  //@ requires 0n <= previous && previous <= 18446744073709551615n
  //@ requires 0n <= next && next <= 18446744073709551615n
  //@ ensures \result <==> next > previous && sameGroup && headChanged
  return next > previous && sameGroup && headChanged;
}
