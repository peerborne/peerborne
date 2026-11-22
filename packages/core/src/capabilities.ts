/**
 * Document-level capabilities for UCAN-based authorization.
 *
 * Capabilities are hierarchical - higher capabilities imply lower ones:
 * /doc/admin > /doc/write > /doc/read
 */

/** Full control: add/remove members, delete document, read, write */
export const CAP_DOC_ADMIN = '/doc/admin';

/** Modify document content + read */
export const CAP_DOC_WRITE = '/doc/write';

/** Decrypt and read document */
export const CAP_DOC_READ = '/doc/read';

/** Access historical epoch keys */
export const CAP_DOC_HISTORY = '/doc/history';

/**
 * All document capabilities in order of decreasing privilege.
 * Note: /doc/history is deliberately excluded because it is orthogonal to
 * the read/write/admin hierarchy. History access is independent -- a user
 * can have read+history or read without history.
 */
export const CAPABILITY_HIERARCHY = [
  CAP_DOC_ADMIN,
  CAP_DOC_WRITE,
  CAP_DOC_READ,
] as const;

/** Capabilities that are not part of the hierarchy and require exact match. */
export const NON_HIERARCHICAL_CAPABILITIES = [CAP_DOC_HISTORY] as const;

Object.freeze(CAPABILITY_HIERARCHY);
Object.freeze(NON_HIERARCHICAL_CAPABILITIES);

export type DocumentCapability =
  | (typeof CAPABILITY_HIERARCHY)[number]
  | (typeof NON_HIERARCHICAL_CAPABILITIES)[number];

/**
 * Check if a capability implies another capability.
 * Admin implies write, write implies read.
 */
export function capabilityImplies(held: string, required: string): boolean {
  //@ verify
  //@ ensures \result <==> held === required || (held === "/doc/admin" && (required === "/doc/write" || required === "/doc/read")) || (held === "/doc/write" && required === "/doc/read")
  const heldIndex = CAPABILITY_HIERARCHY.indexOf(held as any);
  const requiredIndex = CAPABILITY_HIERARCHY.indexOf(required as any);

  if (heldIndex === -1 || requiredIndex === -1) {
    // For non-hierarchical capabilities (like /doc/history), exact match required
    return held === required;
  }

  // Lower index = higher privilege
  return heldIndex <= requiredIndex;
}

/**
 * Future field-level capability pattern.
 * /doc/write/field/{fieldPath} -- Write to specific Yjs sub-document
 * /doc/read/field/{fieldPath} -- Read specific Yjs sub-document
 */
export function isFieldCapability(capability: string): boolean {
  //@ verify
  //@ ensures \result <==> capability.includes("/field/")
  return capability.includes('/field/');
}

export interface DelegatedCapability {
  readonly resource: string;
  readonly ability: string;
}

/** Exact resource binding precedes capability attenuation. */
export function parentGrantsCapability(
  parent: readonly DelegatedCapability[],
  resource: string,
  ability: string,
): boolean {
  //@ verify
  //@ ensures \result <==> exists(candidate: DelegatedCapability, parent.includes(candidate) && candidate.resource === resource && capabilityImplies(candidate.ability, ability))
  return parent.some(
    (candidate) =>
      candidate.resource === resource &&
      capabilityImplies(candidate.ability, ability),
  );
}

/** Return the first grant that would broaden its parent's authority. */
export function findUnauthorizedCapability(
  delegated: readonly DelegatedCapability[],
  parent: readonly DelegatedCapability[],
): number {
  //@ verify
  //@ requires delegated.length <= 4294967295 && parent.length <= 4294967295
  //@ ensures -1 <= \result && \result < delegated.length
  //@ ensures \result === -1 <==> forall(i: int, 0 <= i && i < delegated.length ==> parentGrantsCapability(parent, delegated[i].resource, delegated[i].ability))
  //@ ensures \result >= 0 ==> !parentGrantsCapability(parent, delegated[\result].resource, delegated[\result].ability)
  //@ ensures forall(i: int, 0 <= i && i < \result ==> parentGrantsCapability(parent, delegated[i].resource, delegated[i].ability))
  for (let index = 0; index < delegated.length; index++) {
    //@ invariant 0 <= index && index <= delegated.length
    //@ invariant forall(i: int, 0 <= i && i < index ==> parentGrantsCapability(parent, delegated[i].resource, delegated[i].ability))
    //@ decreases delegated.length - index
    const grant = delegated[index];
    if (!parentGrantsCapability(parent, grant.resource, grant.ability))
      return index;
  }
  return -1;
}

function isLineTerminator(code: number): boolean {
  //@ verify
  //@ ensures \result <==> code === 10 || code === 13 || code === 8232 || code === 8233
  return code === 10 || code === 13 || code === 0x2028 || code === 0x2029;
}

function isFieldMarkerAt(capability: string, index: number): boolean {
  //@ verify
  //@ requires 0 <= index && index + 7 <= capability.length && capability.length <= 4294967295
  //@ ensures \result <==> capability.slice(index, index + 7) === "/field/"
  return capability.slice(index, index + 7) === '/field/';
}

function fieldPathStart(capability: string): number {
  //@ verify
  //@ requires capability.length <= 4294967295
  //@ ensures \result === -1 || 7 <= \result && \result < capability.length
  //@ ensures \result >= 0 ==> isFieldMarkerAt(capability, \result - 7) && forall(j: int, \result - 7 <= j && j < capability.length ==> !isLineTerminator(capability.charCodeAt(j)))
  //@ ensures forall(i: int, 0 <= i && i + 7 < capability.length && (\result === -1 || i + 7 < \result) && isFieldMarkerAt(capability, i) ==> exists(j: int, i <= j && j < capability.length && isLineTerminator(capability.charCodeAt(j))))
  let boundary = capability.length;
  while (
    boundary > 0 &&
    !isLineTerminator(capability.charCodeAt(boundary - 1))
  ) {
    //@ invariant 0 <= boundary && boundary <= capability.length
    //@ invariant forall(j: int, boundary <= j && j < capability.length ==> !isLineTerminator(capability.charCodeAt(j)))
    //@ decreases boundary
    boundary--;
  }

  for (let index = boundary; index + 7 < capability.length; index++) {
    //@ invariant boundary <= index && index <= capability.length
    //@ invariant forall(i: int, boundary <= i && i < index && i + 7 < capability.length ==> !isFieldMarkerAt(capability, i))
    //@ decreases capability.length - index
    if (isFieldMarkerAt(capability, index)) return index + 7;
  }
  return -1;
}

export function getFieldPath(capability: string): string | undefined {
  const start = fieldPathStart(capability);
  return start < 0 ? undefined : capability.slice(start);
}
