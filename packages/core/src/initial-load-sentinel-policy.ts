export interface InitialLoadSentinelPolicy {
  securityAware: boolean;
  requireAuthenticatedInitialLoad: boolean;
}

export function allowsUnauthenticatedUnknownDocumentSentinel(
  policy: InitialLoadSentinelPolicy,
): boolean {
  return !policy.securityAware && !policy.requireAuthenticatedInitialLoad;
}

export function unknownDocumentAdvertisement(
  policy: InitialLoadSentinelPolicy,
): Uint8Array[] {
  return allowsUnauthenticatedUnknownDocumentSentinel(policy)
    ? [new Uint8Array([0xff])]
    : [];
}

export function isUnknownDocumentAdvertisement(
  response: Uint8Array,
  policy: InitialLoadSentinelPolicy,
): boolean {
  return (
    allowsUnauthenticatedUnknownDocumentSentinel(policy) &&
    response.length === 1 &&
    response[0] === 0xff
  );
}
