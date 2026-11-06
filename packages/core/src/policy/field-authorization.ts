export function isFieldPathPrefix(
  grant: readonly string[],
  target: readonly string[],
): boolean {
  //@ verify
  //@ requires grant.length <= 4294967295 && target.length <= 4294967295
  //@ ensures \result <==> grant.length <= target.length && forall(i: int, 0 <= i && i < grant.length ==> grant[i] === target[i])
  if (grant.length > target.length) return false;
  for (let index = 0; index < grant.length; index++) {
    //@ invariant 0 <= index && index <= grant.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> grant[i] === target[i])
    //@ decreases grant.length - index
    if (grant[index] !== target[index]) return false;
  }
  return true;
}

export function grantsFieldPath(
  grants: readonly (readonly string[])[],
  target: readonly string[],
): boolean {
  //@ verify
  //@ requires grants.length <= 4294967295 && target.length <= 4294967295
  //@ requires forall(i: int, 0 <= i && i < grants.length ==> grants[i].length <= 4294967295)
  //@ ensures \result <==> exists(i: int, 0 <= i && i < grants.length && grants[i].length <= target.length && forall(j: int, 0 <= j && j < grants[i].length ==> grants[i][j] === target[j]))
  for (let index = 0; index < grants.length; index++) {
    //@ invariant 0 <= index && index <= grants.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> !(grants[i].length <= target.length && forall(j: int, 0 <= j && j < grants[i].length ==> grants[i][j] === target[j])))
    //@ decreases grants.length - index
    if (isFieldPathPrefix(grants[index], target)) return true;
  }
  return false;
}

export function firstUnauthorizedFieldPath(
  grants: readonly (readonly string[])[],
  targets: readonly (readonly string[])[],
): number {
  //@ verify
  //@ requires grants.length <= 4294967295 && targets.length <= 4294967295
  //@ requires forall(i: int, 0 <= i && i < grants.length ==> grants[i].length <= 4294967295)
  //@ requires forall(i: int, 0 <= i && i < targets.length ==> targets[i].length <= 4294967295)
  //@ ensures -1 <= \result && \result < targets.length
  //@ ensures \result === -1 <==> forall(i: int, 0 <= i && i < targets.length ==> exists(j: int, 0 <= j && j < grants.length && grants[j].length <= targets[i].length && forall(k: int, 0 <= k && k < grants[j].length ==> grants[j][k] === targets[i][k])))
  //@ ensures \result >= 0 ==> !exists(j: int, 0 <= j && j < grants.length && grants[j].length <= targets[\result].length && forall(k: int, 0 <= k && k < grants[j].length ==> grants[j][k] === targets[\result][k]))
  //@ ensures forall(i: int, 0 <= i && i < \result ==> exists(j: int, 0 <= j && j < grants.length && grants[j].length <= targets[i].length && forall(k: int, 0 <= k && k < grants[j].length ==> grants[j][k] === targets[i][k])))
  for (let index = 0; index < targets.length; index++) {
    //@ invariant 0 <= index && index <= targets.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> exists(j: int, 0 <= j && j < grants.length && grants[j].length <= targets[i].length && forall(k: int, 0 <= k && k < grants[j].length ==> grants[j][k] === targets[i][k])))
    //@ decreases targets.length - index
    if (!grantsFieldPath(grants, targets[index])) return index;
  }
  return -1;
}

export function canAdmitFieldInspection(
  scanned: number,
  additional: number,
  distinct: number,
  known: boolean,
  units: number,
  addedUnits: number,
): boolean {
  //@ verify
  //@ requires 0 <= scanned && scanned <= 131072 && 0 <= distinct && distinct <= 4096
  //@ requires 0 <= units && units <= 1048576
  //@ requires 0 <= additional && additional <= 9007199254740991 && 0 <= addedUnits && addedUnits <= 9007199254740991
  //@ ensures \result <==> 1 <= additional && additional <= 131072 - scanned && (known || distinct < 4096) && addedUnits <= 1048576 - units
  //@ ensures \result ==> scanned + additional <= 131072 && units + addedUnits <= 1048576
  return (
    additional >= 1 &&
    additional <= 131072 - scanned &&
    (known || distinct < 4096) &&
    addedUnits <= 1048576 - units
  );
}
