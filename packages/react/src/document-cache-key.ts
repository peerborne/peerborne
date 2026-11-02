interface DocumentCacheNamespace {
  readonly contextKeyPrefix: string;
}

export function getPeerborneDocumentCacheKey(
  caches: DocumentCacheNamespace,
  documentPath: string,
): string {
  //@ verify
  //@ ensures \result === caches.contextKeyPrefix + documentPath
  //@ ensures \result.length === caches.contextKeyPrefix.length + documentPath.length
  //@ ensures \result.slice(caches.contextKeyPrefix.length) === documentPath
  return `${caches.contextKeyPrefix}${documentPath}`;
}
