/** Check ownership-sensitive names before building an index projection. */
export function isIndexFieldPathSegment(segment: string): boolean {
  //@ verify
  //@ ensures \result <==> segment !== "" && segment !== "__proto__" && segment !== "prototype" && segment !== "constructor"
  return segment !== '' &&
    segment !== '__proto__' &&
    segment !== 'prototype' &&
    segment !== 'constructor';
}

export function hasSafeIndexFieldPathSegments(segments: readonly string[]): boolean {
  //@ verify
  //@ requires segments.length <= 4294967295
  //@ ensures \result <==> segments.length > 0 && forall(i: int, 0 <= i && i < segments.length ==> isIndexFieldPathSegment(segments[i]))
  if (segments.length === 0) return false;
  for (let i = 0; i < segments.length; i++) {
    //@ invariant 0 <= i && i <= segments.length
    //@ invariant forall(j: int, 0 <= j && j < i ==> isIndexFieldPathSegment(segments[j]))
    //@ decreases segments.length - i
    if (!isIndexFieldPathSegment(segments[i])) return false;
  }
  return true;
}
