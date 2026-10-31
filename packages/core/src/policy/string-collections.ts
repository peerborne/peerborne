/** First duplicate identity, or -1 when every identity is distinct. */
export function firstDuplicateString(values: readonly string[]): number {
  //@ verify
  //@ requires values.length <= 4294967295
  //@ ensures -1 <= \result && \result < values.length
  //@ ensures \result === -1 <==> forall(a: int, forall(b: int, 0 <= a && a < b && b < values.length ==> values[a] !== values[b]))
  //@ ensures \result >= 0 ==> exists(a: int, 0 <= a && a < \result && values[a] === values[\result])
  const seen = new Set<string>();
  for (let index = 0; index < values.length; index++) {
    //@ invariant 0 <= index && index <= values.length
    //@ invariant forall(j: int, 0 <= j && j < index ==> seen.has(values[j]))
    //@ invariant forall(key: string, seen.has(key) ==> exists(j: int, 0 <= j && j < index && values[j] === key))
    //@ invariant forall(a: int, forall(b: int, 0 <= a && a < b && b < index ==> values[a] !== values[b]))
    //@ decreases values.length - index
    if (seen.has(values[index])) return index;
    seen.add(values[index]);
  }
  return -1;
}

/** Count advertised identities absent from an already installed frontier. */
export function countMissingStrings(
  expected: readonly string[],
  installed: Set<string>,
): number {
  //@ verify
  //@ requires expected.length <= 4294967295
  //@ ensures 0 <= \result && \result <= expected.length
  //@ ensures \result === 0 <==> forall(j: int, 0 <= j && j < expected.length ==> installed.has(expected[j]))
  let missing = 0;
  for (let index = 0; index < expected.length; index++) {
    //@ invariant 0 <= index && index <= expected.length
    //@ invariant 0 <= missing && missing <= index
    //@ invariant missing === 0 <==> forall(j: int, 0 <= j && j < index ==> installed.has(expected[j]))
    //@ decreases expected.length - index
    if (!installed.has(expected[index])) missing++;
  }
  return missing;
}

/** Exact set equality also rejects duplicate canonical identities. */
export function sameDistinctStringMembers(
  actual: readonly string[],
  expected: readonly string[],
): boolean {
  //@ verify
  //@ requires actual.length <= 4294967295 && expected.length <= 4294967295
  //@ requires forall(a: int, forall(b: int, 0 <= a && a < b && b < expected.length ==> expected[a] !== expected[b]))
  //@ ensures \result <==> actual.length === expected.length && forall(a: int, forall(b: int, 0 <= a && a < b && b < actual.length ==> actual[a] !== actual[b])) && forall(j: int, 0 <= j && j < expected.length ==> actual.includes(expected[j]))
  if (actual.length !== expected.length) return false;
  if (firstDuplicateString(actual) !== -1) return false;
  for (let index = 0; index < expected.length; index++) {
    //@ invariant 0 <= index && index <= expected.length
    //@ invariant forall(j: int, 0 <= j && j < index ==> actual.includes(expected[j]))
    //@ decreases expected.length - index
    if (!actual.includes(expected[index])) return false;
  }
  return true;
}

export function classifyAcceptedMembership(
  issuer: string,
  recipient: string,
  readers: readonly string[],
  writers: readonly string[],
  editor: boolean,
): 'sameIdentity' | 'duplicates' | 'readers' | 'writers' | 'valid' {
  //@ verify
  //@ requires readers.length <= 4294967295 && writers.length <= 4294967295
  //@ ensures \result === "sameIdentity" <==> issuer === recipient
  //@ ensures \result === "valid" <==> issuer !== recipient && readers.length === 1 && readers[0] === recipient && writers.length === (editor ? 2 : 1) && forall(a: int, forall(b: int, 0 <= a && a < b && b < writers.length ==> writers[a] !== writers[b])) && writers.includes(issuer) && (!editor || writers.includes(recipient))
  if (issuer === recipient) return 'sameIdentity';
  if (
    firstDuplicateString(readers) !== -1 ||
    firstDuplicateString(writers) !== -1
  )
    return 'duplicates';
  if (readers.length !== 1 || readers[0] !== recipient) return 'readers';
  const expectedWriters = editor ? [issuer, recipient] : [issuer];
  if (!sameDistinctStringMembers(writers, expectedWriters)) return 'writers';
  return 'valid';
}

export function classifyInitialMembership(
  createdLocally: boolean,
  founder: string,
  recipient: string,
  readers: readonly string[],
  writers: readonly string[],
  editor: boolean,
  ready: boolean,
):
  | 'notFounder'
  | 'sameIdentity'
  | 'duplicates'
  | 'founderMissing'
  | 'unrelatedReader'
  | 'unrelatedWriter'
  | 'readerMissing'
  | 'roleMissing'
  | 'valid' {
  //@ verify
  //@ requires readers.length <= 4294967295 && writers.length <= 4294967295
  //@ ensures \result === "valid" <==> createdLocally && founder !== recipient && forall(a: int, forall(b: int, 0 <= a && a < b && b < readers.length ==> readers[a] !== readers[b])) && forall(a: int, forall(b: int, 0 <= a && a < b && b < writers.length ==> writers[a] !== writers[b])) && writers.includes(founder) && forall(identity: string, readers.includes(identity) ==> identity === recipient) && forall(identity: string, writers.includes(identity) ==> identity === founder || (editor && identity === recipient)) && (!ready || (readers.length === 1 && readers.includes(recipient) && writers.length === (editor ? 2 : 1) && (!editor || writers.includes(recipient))))
  if (!createdLocally) return 'notFounder';
  if (founder === recipient) return 'sameIdentity';
  if (
    firstDuplicateString(readers) !== -1 ||
    firstDuplicateString(writers) !== -1
  )
    return 'duplicates';
  if (!writers.includes(founder)) return 'founderMissing';
  if (readers.some((identity) => identity !== recipient))
    return 'unrelatedReader';
  if (
    writers.some(
      (identity) => identity !== founder && (!editor || identity !== recipient),
    )
  )
    return 'unrelatedWriter';
  if (ready) {
    if (readers.length !== 1 || !readers.includes(recipient))
      return 'readerMissing';
    if (
      writers.length !== (editor ? 2 : 1) ||
      (editor && !writers.includes(recipient))
    )
      return 'roleMissing';
  }
  return 'valid';
}
