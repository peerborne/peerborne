/** Validate the bounded retained revision suffix before requesting journal rows. */
export function isDocumentJournalIndexValid(
  revision: number,
  revisions: readonly number[],
  bytes: number,
): boolean {
  //@ verify
  //@ requires 0 <= revision && revision <= 9007199254740991
  //@ requires revisions.length <= 4294967295
  //@ requires 0 <= bytes && bytes <= 134217728
  //@ requires forall(i: int, 0 <= i && i < revisions.length ==> -9007199254740991 <= revisions[i] && revisions[i] <= 9007199254740991)
  //@ ensures \result <==> revisions.length <= 128 && revisions.length <= bytes && (revisions.length === 0 ==> revision === 0 && bytes === 0) && (revisions.length > 0 ==> revisions[revisions.length - 1] === revision) && forall(i: int, 0 <= i && i < revisions.length ==> 1 <= revisions[i] && revisions[i] <= revision) && forall(i: int, 1 <= i && i < revisions.length ==> revisions[i] - revisions[i - 1] === 1)
  if (revisions.length > 128 || bytes < revisions.length) return false;
  if (revisions.length === 0) return revision === 0 && bytes === 0;
  let previous = 0;
  for (let index = 0; index < revisions.length; index++) {
    //@ invariant 0 <= index && index <= revisions.length
    //@ invariant 0 <= previous && previous <= revision
    //@ invariant index === 0 ==> previous === 0
    //@ invariant index > 0 ==> previous === revisions[index - 1]
    //@ invariant forall(i: int, 0 <= i && i < index ==> 1 <= revisions[i] && revisions[i] <= revision)
    //@ invariant forall(i: int, 1 <= i && i < index ==> revisions[i] - revisions[i - 1] === 1)
    //@ decreases revisions.length - index
    const current = revisions[index];
    if (
      current < 1 ||
      current > revision ||
      (index > 0 && current - previous !== 1)
    )
      return false;
    previous = current;
  }
  return previous === revision;
}
