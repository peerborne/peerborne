export interface JournalPublicationIndex {
  readonly id: string;
  readonly bytes: number;
}

export interface JournalPublicationPlan {
  readonly decision: 'accept' | 'duplicate' | 'capacity';
  readonly publications: readonly JournalPublicationIndex[];
  readonly retained: readonly number[];
  readonly bytes: number;
}

export function planJournalPublication(
  publications: readonly JournalPublicationIndex[],
  id: string,
  bytes: number,
  append: boolean,
): JournalPublicationPlan {
  //@ verify
  //@ requires publications.length <= 16
  //@ requires forall(i: int, 0 <= i && i < publications.length ==> 1 <= publications[i].bytes && publications[i].bytes <= 1048648)
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < publications.length ==> publications[i].id !== publications[j].id))
  //@ requires append ? 1 <= bytes && bytes <= 1048648 : bytes === 0
  //@ ensures \result.decision === "accept" || \result.decision === "duplicate" || \result.decision === "capacity"
  //@ ensures 0 <= \result.bytes && \result.bytes <= 16777216 && \result.publications.length <= 16
  //@ ensures \result.decision !== "accept" ==> \result.publications.length === 0 && \result.retained.length === 0 && \result.bytes === 0
  //@ ensures \result.decision === "duplicate" <==> append && exists(i: int, 0 <= i && i < publications.length && publications[i].id === id)
  //@ ensures \result.decision === "accept" ==> \result.publications.length === \result.retained.length + (append ? 1 : 0)
  //@ ensures \result.decision === "accept" ==> forall(i: int, 0 <= i && i < \result.retained.length ==> 0 <= \result.retained[i] && \result.retained[i] < publications.length && \result.publications[i].id === publications[\result.retained[i]].id && \result.publications[i].bytes === publications[\result.retained[i]].bytes)
  //@ ensures forall(i: int, forall(j: int, 0 <= i && i < j && j < \result.retained.length ==> \result.retained[i] < \result.retained[j]))
  //@ ensures \result.decision === "accept" ==> forall(i: int, 0 <= i && i < publications.length ==> (\result.retained.includes(i) <==> append || publications[i].id !== id))
  //@ ensures \result.decision === "accept" && append ==> \result.publications[\result.publications.length - 1].id === id && \result.publications[\result.publications.length - 1].bytes === bytes
  //@ ensures \result.decision === "accept" ==> forall(i: int, forall(j: int, 0 <= i && i < j && j < \result.publications.length ==> \result.publications[i].id !== \result.publications[j].id))
  const next: JournalPublicationIndex[] = [];
  const retained: number[] = [];
  let total = 0;
  let removed = false;
  for (let index = 0; index < publications.length; index++) {
    //@ invariant 0 <= index && index <= publications.length
    //@ invariant next.length === retained.length && retained.length <= index
    //@ invariant 0 <= total && total <= next.length * 1048648
    //@ invariant retained.length + (removed ? 1 : 0) === index
    //@ invariant removed <==> !append && exists(i: int, 0 <= i && i < index && publications[i].id === id)
    //@ invariant append ==> forall(i: int, 0 <= i && i < index ==> publications[i].id !== id)
    //@ invariant forall(i: int, 0 <= i && i < retained.length ==> 0 <= retained[i] && retained[i] < index && next[i].id === publications[retained[i]].id && next[i].bytes === publications[retained[i]].bytes)
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < j && j < retained.length ==> retained[i] < retained[j]))
    //@ invariant forall(i: int, 0 <= i && i < index ==> (retained.includes(i) <==> append || publications[i].id !== id))
    //@ decreases publications.length - index
    const publication = publications[index];
    if (append && publication.id === id)
      return {
        decision: 'duplicate',
        publications: [],
        retained: [],
        bytes: 0,
      };
    if (append || publication.id !== id) {
      next.push({ id: publication.id, bytes: publication.bytes });
      retained.push(index);
      total += publication.bytes;
    } else {
      removed = true;
    }
  }
  if (
    total > 16777216 ||
    (append && (publications.length >= 16 || bytes > 16777216 - total))
  )
    return { decision: 'capacity', publications: [], retained: [], bytes: 0 };
  if (append) {
    next.push({ id, bytes });
    total += bytes;
  }
  return { decision: 'accept', publications: next, retained, bytes: total };
}

export function classifyJournalStage(
  revision: number,
  expected: number,
  hasPending: boolean,
  checkpoint: boolean,
  entries: number,
  retainedBytes: number,
  entryBytes: number,
): 'accept' | 'conflict' | 'capacity' {
  //@ verify
  //@ requires 0 <= revision && revision <= 9007199254740991 && 0 <= expected && expected <= 9007199254740991
  //@ requires 0 <= entries && entries <= 128 && 0 <= retainedBytes && retainedBytes <= 134217728
  //@ requires 1 <= entryBytes && entryBytes <= 134217728
  //@ ensures \result === "accept" || \result === "conflict" || \result === "capacity"
  //@ ensures \result === "conflict" <==> revision !== expected || revision === 9007199254740991 || hasPending
  //@ ensures \result === "accept" <==> revision === expected && revision < 9007199254740991 && !hasPending && entryBytes <= 134217728 - 32 && (checkpoint || entries < 128 && entryBytes + 32 <= 134217728 - retainedBytes)
  //@ ensures \result === "accept" ==> revision + 1 <= 9007199254740991 && entryBytes + 32 <= 134217728
  if (revision !== expected || revision === 9007199254740991 || hasPending)
    return 'conflict';
  if (
    entryBytes > 134217728 - 32 ||
    (!checkpoint &&
      (entries >= 128 || entryBytes + 32 > 134217728 - retainedBytes))
  )
    return 'capacity';
  return 'accept';
}

export function isJournalCommitCurrent(
  revision: number,
  expected: number,
  hasPending: boolean,
  sameToken: boolean,
  sameCheckpoint: boolean,
): boolean {
  //@ verify
  //@ requires 0 <= revision && revision <= 9007199254740991 && 0 <= expected && expected <= 9007199254740991
  //@ ensures \result <==> revision === expected && revision < 9007199254740991 && hasPending && sameToken && sameCheckpoint
  //@ ensures \result ==> revision + 1 <= 9007199254740991
  return (
    revision === expected &&
    revision < 9007199254740991 &&
    hasPending &&
    sameToken &&
    sameCheckpoint
  );
}
