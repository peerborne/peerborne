export type DocumentJournalRecovery = 'current' | 'finish-anchor' | 'reject';

export interface DocumentJournalReadPlan {
  readonly entries: number;
  readonly publications: number;
  readonly pending: boolean;
  readonly pendingToken: boolean;
  readonly rowReads: number;
}

export function planDocumentJournalRead(
  entries: number,
  publications: number,
  hasPending: boolean,
  recovery: boolean,
): DocumentJournalReadPlan {
  //@ verify
  //@ requires 0 <= entries && entries <= 128
  //@ requires 0 <= publications && publications <= 16
  //@ ensures \result.entries === entries
  //@ ensures \result.publications === (recovery ? 0 : publications)
  //@ ensures \result.pending <==> hasPending && !recovery
  //@ ensures \result.pendingToken <==> hasPending && recovery
  //@ ensures !(\result.pending && \result.pendingToken)
  //@ ensures \result.rowReads === 1 + \result.entries + \result.publications + (\result.pending ? 1 : 0)
  //@ ensures 1 <= \result.rowReads && \result.rowReads <= 146
  //@ ensures recovery ==> \result.rowReads === 1 + entries && \result.rowReads <= 129 && \result.publications === 0 && !\result.pending
  const publicationReads = recovery ? 0 : publications;
  const pending = hasPending && !recovery;
  return {
    entries,
    publications: publicationReads,
    pending,
    pendingToken: hasPending && recovery,
    rowReads: 1 + entries + publicationReads + (pending ? 1 : 0),
  };
}

export function canRecordDocumentPublicationBinding(
  ledger: Map<string, number>,
  token: string,
  bindingRevision: number,
  entryRevision: number,
  checkpoint: boolean,
  limit: number,
): boolean {
  //@ verify
  //@ requires ledger.size <= 9007199254740991
  //@ requires 0 <= bindingRevision && bindingRevision <= 9007199254740991
  //@ requires 0 <= entryRevision && entryRevision <= 9007199254740991
  //@ requires 0 <= limit && limit <= 9007199254740991
  //@ ensures \result <==> !ledger.has(token) && ledger.size < limit && 1 <= bindingRevision && bindingRevision <= entryRevision && (checkpoint || bindingRevision === entryRevision)
  return (
    !ledger.has(token) &&
    ledger.size < limit &&
    1 <= bindingRevision &&
    bindingRevision <= entryRevision &&
    (checkpoint || bindingRevision === entryRevision)
  );
}

export function recordDocumentPublicationBinding(
  ledger: Map<string, number>,
  token: string,
  revision: number,
  limit: number,
): Map<string, number> {
  //@ verify
  //@ requires !ledger.has(token)
  //@ requires ledger.size < limit && limit <= 9007199254740991
  //@ requires 1 <= revision && revision <= 9007199254740991
  //@ requires forall(key: string, ledger.has(key) ==> 1 <= ledger.get(key) && ledger.get(key) <= 9007199254740991)
  //@ ensures \result.has(token) && \result.get(token) === revision
  //@ ensures forall(key: string, \result.has(key) <==> ledger.has(key) || key === token)
  //@ ensures forall(key: string, ledger.has(key) ==> \result.get(key) === ledger.get(key))
  //@ ensures forall(key: string, \result.has(key) ==> 1 <= \result.get(key) && \result.get(key) <= 9007199254740991)
  //@ ensures \result.size === ledger.size + 1 && \result.size <= limit
  const result = new Map(ledger);
  result.set(token, revision);
  return result;
}

export function canRetainDocumentPublicationBindings(
  ledger: Map<string, number>,
  pending: readonly string[],
  limit: number,
): boolean {
  //@ verify
  //@ requires pending.length <= 4294967295
  //@ requires 0 <= limit && limit <= 9007199254740991
  //@ ensures \result <==> pending.length <= limit && forall(i: int, 0 <= i && i < pending.length ==> ledger.has(pending[i])) && forall(i: int, forall(j: int, 0 <= i && i < j && j < pending.length ==> pending[i] !== pending[j]))
  if (pending.length > limit) return false;
  const seen = new Set<string>();
  for (let index = 0; index < pending.length; index++) {
    //@ invariant 0 <= index && index <= pending.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> ledger.has(pending[i]) && seen.has(pending[i]))
    //@ invariant forall(key: string, seen.has(key) ==> exists(i: int, 0 <= i && i < index && pending[i] === key))
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < j && j < index ==> pending[i] !== pending[j]))
    //@ decreases pending.length - index
    if (!ledger.has(pending[index]) || seen.has(pending[index])) return false;
    seen.add(pending[index]);
  }
  return true;
}

export function retainDocumentPublicationBindings(
  ledger: Map<string, number>,
  pending: readonly string[],
  limit: number,
): Map<string, number> {
  //@ verify
  //@ requires pending.length <= 4294967295 && pending.length <= limit && limit <= 9007199254740991
  //@ requires forall(i: int, 0 <= i && i < pending.length ==> ledger.has(pending[i]))
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < pending.length ==> pending[i] !== pending[j]))
  //@ requires forall(key: string, ledger.has(key) ==> 1 <= ledger.get(key) && ledger.get(key) <= 9007199254740991)
  //@ ensures forall(key: string, \result.has(key) <==> pending.includes(key))
  //@ ensures forall(key: string, \result.has(key) ==> ledger.has(key) && \result.get(key) === ledger.get(key))
  //@ ensures forall(key: string, \result.has(key) ==> 1 <= \result.get(key) && \result.get(key) <= 9007199254740991)
  //@ ensures \result.size === pending.length && \result.size <= limit
  const result = new Map<string, number>();
  for (let index = 0; index < pending.length; index++) {
    //@ invariant 0 <= index && index <= pending.length
    //@ invariant result.size === index
    //@ invariant forall(key: string, result.has(key) <==> exists(i: int, 0 <= i && i < index && pending[i] === key))
    //@ invariant forall(key: string, result.has(key) ==> ledger.has(key) && result.get(key) === ledger.get(key))
    //@ invariant forall(key: string, result.has(key) ==> 1 <= result.get(key) && result.get(key) <= 9007199254740991)
    //@ decreases pending.length - index
    result.set(pending[index], ledger.get(pending[index])!);
  }
  return result;
}

export function selectDocumentPublicationBindings(
  before: Map<string, number>,
  candidate: Map<string, number>,
  anchored: boolean,
): Map<string, number> {
  //@ verify
  //@ ensures anchored ==> \result === candidate
  //@ ensures !anchored ==> \result === before
  return anchored ? candidate : before;
}

export function isAcceptedDocumentPublicationToken(
  ledger: Map<string, number>,
  token: string,
  revision: number,
  currentRevision: number,
): boolean {
  //@ verify
  //@ requires 0 <= revision && revision <= 9007199254740991
  //@ requires 0 <= currentRevision && currentRevision <= 9007199254740991
  //@ requires forall(key: string, ledger.has(key) ==> 1 <= ledger.get(key) && ledger.get(key) <= 9007199254740991)
  //@ ensures \result <==> ledger.has(token) && 1 <= revision && revision <= currentRevision && ledger.get(token) === revision
  return (
    ledger.has(token) &&
    isAcceptedDocumentPublication(revision, currentRevision, ledger.get(token)!)
  );
}

export function isAcceptedDocumentPublication(
  revision: number,
  currentRevision: number,
  bindingRevision: number,
): boolean {
  //@ verify
  //@ requires 0 <= revision && revision <= 9007199254740991
  //@ requires 0 <= currentRevision && currentRevision <= 9007199254740991
  //@ requires 0 <= bindingRevision && bindingRevision <= 9007199254740991
  //@ ensures \result <==> 1 <= revision && revision <= currentRevision && bindingRevision === revision
  return (
    1 <= revision && revision <= currentRevision && bindingRevision === revision
  );
}

export function classifyDocumentJournalRecovery(
  stored: number,
  anchored: number,
  commitmentMatches: boolean,
  parentMatches: boolean,
  markerAuthenticated: boolean,
): DocumentJournalRecovery {
  //@ verify
  //@ requires 0 <= stored && stored <= 9007199254740991
  //@ requires 0 <= anchored && anchored <= 9007199254740991
  //@ ensures \result === "current" <==> markerAuthenticated && stored === anchored && commitmentMatches
  //@ ensures \result === "finish-anchor" <==> markerAuthenticated && stored > anchored && stored - anchored === 1 && parentMatches
  //@ ensures \result === "reject" <==> !markerAuthenticated || !(stored === anchored && commitmentMatches) && !(stored > anchored && stored - anchored === 1 && parentMatches)
  if (!markerAuthenticated) return 'reject';
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
