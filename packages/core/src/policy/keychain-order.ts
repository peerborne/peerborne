export function sameKeychainEntry(
  left: readonly string[],
  right: readonly string[],
): boolean {
  //@ verify
  //@ requires left.length === 2 && right.length === 2
  //@ ensures \result <==> left[0] === right[0] && left[1] === right[1]
  return left[0] === right[0] && left[1] === right[1];
}

export function isKeychainPrefix(
  prefix: readonly (readonly string[])[],
  entries: readonly (readonly string[])[],
): boolean {
  //@ verify
  //@ requires prefix.length <= 4294967295 && entries.length <= 4294967295
  //@ requires forall(i: int, 0 <= i && i < prefix.length ==> prefix[i].length === 2)
  //@ requires forall(i: int, 0 <= i && i < entries.length ==> entries[i].length === 2)
  //@ ensures \result <==> prefix.length <= entries.length && forall(i: int, 0 <= i && i < prefix.length ==> prefix[i][0] === entries[i][0] && prefix[i][1] === entries[i][1])
  if (prefix.length > entries.length) return false;
  for (let index = 0; index < prefix.length; index++) {
    //@ invariant 0 <= index && index <= prefix.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> prefix[i][0] === entries[i][0] && prefix[i][1] === entries[i][1])
    //@ decreases prefix.length - index
    if (!sameKeychainEntry(prefix[index], entries[index])) return false;
  }
  return true;
}

/** Distinguish truncation from the first rewritten entry before committing. */
export function firstKeychainRewrite(
  before: readonly (readonly string[])[],
  after: readonly (readonly string[])[],
): number {
  //@ verify
  //@ requires before.length <= after.length && after.length <= 4294967295
  //@ requires forall(i: int, 0 <= i && i < before.length ==> before[i].length === 2)
  //@ requires forall(i: int, 0 <= i && i < after.length ==> after[i].length === 2)
  //@ ensures -1 <= \result && \result < before.length
  //@ ensures \result === -1 <==> forall(i: int, 0 <= i && i < before.length ==> before[i][0] === after[i][0] && before[i][1] === after[i][1])
  //@ ensures \result >= 0 ==> before[\result][0] !== after[\result][0] || before[\result][1] !== after[\result][1]
  for (let index = 0; index < before.length; index++) {
    //@ invariant 0 <= index && index <= before.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> before[i][0] === after[i][0] && before[i][1] === after[i][1])
    //@ decreases before.length - index
    if (!sameKeychainEntry(before[index], after[index])) return index;
  }
  return -1;
}
