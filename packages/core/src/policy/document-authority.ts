export function documentAuthorityControllerIndex(
  roles: readonly number[],
): number {
  //@ verify
  //@ requires roles.length <= 4294967295
  //@ ensures -1 <= \result && \result < roles.length
  //@ ensures \result >= 0 <==> 1 <= roles.length && roles.length <= 256 && forall(i: int, 0 <= i && i < roles.length ==> roles[i] === 1 || roles[i] === 2 || roles[i] === 3) && exists(i: int, 0 <= i && i < roles.length && roles[i] === 3 && forall(j: int, 0 <= j && j < roles.length && roles[j] === 3 ==> j === i))
  //@ ensures \result >= 0 ==> roles[\result] === 3 && forall(i: int, 0 <= i && i < roles.length && roles[i] === 3 ==> i === \result)
  if (roles.length < 1 || roles.length > 256) return -1;
  let controller = -1;
  for (let index = 0; index < roles.length; index++) {
    //@ invariant 0 <= index && index <= roles.length
    //@ invariant -1 <= controller && controller < index
    //@ invariant forall(i: int, 0 <= i && i < index ==> roles[i] === 1 || roles[i] === 2 || roles[i] === 3)
    //@ invariant controller === -1 <==> forall(i: int, 0 <= i && i < index ==> roles[i] !== 3)
    //@ invariant controller >= 0 ==> roles[controller] === 3 && forall(i: int, 0 <= i && i < index && roles[i] === 3 ==> i === controller)
    //@ decreases roles.length - index
    const role = roles[index];
    if (role !== 1 && role !== 2 && role !== 3) return -1;
    if (role === 3) {
      if (controller !== -1) return -1;
      controller = index;
    }
  }
  return controller;
}

export function validDocumentAuthorityFields(
  values: readonly string[],
  minimum: number,
  maximum: number,
): boolean {
  //@ verify
  //@ requires values.length <= 4294967295
  //@ requires 0 <= minimum && minimum <= maximum && maximum <= 4294967295
  //@ ensures \result <==> forall(i: int, 0 <= i && i < values.length ==> minimum <= values[i].length && values[i].length <= maximum) && forall(i: int, forall(j: int, 0 <= i && i < j && j < values.length ==> values[i] !== values[j]))
  const seen = new Set<string>();
  for (let index = 0; index < values.length; index++) {
    //@ invariant 0 <= index && index <= values.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> minimum <= values[i].length && values[i].length <= maximum)
    //@ invariant forall(i: int, 0 <= i && i < index ==> seen.has(values[i]))
    //@ invariant forall(key: string, seen.has(key) ==> exists(i: int, 0 <= i && i < index && values[i] === key))
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < j && j < index ==> values[i] !== values[j]))
    //@ decreases values.length - index
    if (seen.has(values[index])) return false;
    if (values[index].length < minimum || values[index].length > maximum)
      return false;
    seen.add(values[index]);
  }
  return true;
}

export function isDocumentAuthorityRosterValid(
  memberIds: readonly string[],
  publicKeys: readonly string[],
  roles: readonly number[],
): boolean {
  //@ verify
  //@ requires memberIds.length <= 4294967295 && publicKeys.length <= 4294967295 && roles.length <= 4294967295
  //@ ensures \result <==> memberIds.length === roles.length && publicKeys.length === roles.length && 1 <= roles.length && roles.length <= 256 && forall(i: int, 0 <= i && i < roles.length ==> roles[i] === 1 || roles[i] === 2 || roles[i] === 3) && exists(i: int, 0 <= i && i < roles.length && roles[i] === 3 && forall(j: int, 0 <= j && j < roles.length && roles[j] === 3 ==> j === i)) && forall(i: int, 0 <= i && i < roles.length ==> memberIds[i].length === 64 && 1 <= publicKeys[i].length && publicKeys[i].length <= 4096) && forall(i: int, forall(j: int, 0 <= i && i < j && j < roles.length ==> memberIds[i] !== memberIds[j] && publicKeys[i] !== publicKeys[j]))
  if (memberIds.length !== roles.length || publicKeys.length !== roles.length)
    return false;
  if (documentAuthorityControllerIndex(roles) < 0) return false;
  if (!validDocumentAuthorityFields(memberIds, 64, 64)) return false;
  if (!validDocumentAuthorityFields(publicKeys, 1, 4096)) return false;
  return true;
}

export function canBindDocumentController<Controller>(
  controllers: Map<string, Controller>,
  head: string,
  limit: number,
): boolean {
  //@ verify
  //@ type Controller (==)
  //@ requires 0 <= limit && limit <= 9007199254740991
  //@ ensures \result <==> controllers.size < limit && !controllers.has(head)
  return controllers.size < limit && !controllers.has(head);
}

export function bindDocumentController<Controller>(
  controllers: Map<string, Controller>,
  head: string,
  controller: Controller,
  limit: number,
): Map<string, Controller> {
  //@ verify
  //@ type Controller (==)
  //@ requires 0 <= limit && limit <= 9007199254740991
  //@ requires controllers.size < limit && !controllers.has(head)
  //@ ensures \result.size === controllers.size + 1 && \result.size <= limit
  //@ ensures \result.has(head) && \result.get(head) === controller
  //@ ensures forall(key: string, \result.has(key) <==> controllers.has(key) || key === head)
  //@ ensures forall(key: string, controllers.has(key) ==> \result.get(key) === controllers.get(key))
  const result = new Map(controllers);
  result.set(head, controller);
  return result;
}
