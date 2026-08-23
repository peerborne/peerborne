/**
 * Per-Peerborne caches shared by usePeerborneDocumentState hook instances.
 *
 * Extracted into a separate internal module so that test files can reset
 * caches between tests without adding test-only exports to the public
 * hooks API surface. This module is NOT re-exported from the package
 * index.
 */

import type { PeerborneDocument } from '@peerborne/core';

/* eslint-disable @typescript-eslint/no-explicit-any */
export type PeerborneContextOpenResultAny = {
  docRef?: PeerborneDocument<any, any, any, any, any, any>;
  document?: any;
  readers?: any[];
  writers?: any[];
};

export type PeerborneHookCaches = {
  contextKeyPrefix: string;
  openTasks: Map<string, Promise<PeerborneContextOpenResultAny>>;
  openTaskResults: Map<string, PeerborneContextOpenResultAny>;
  subscriberCounts: Map<string, number>;
};

let cachesByPeerborne = new WeakMap<object, PeerborneHookCaches>();
let nextContextKeyPrefix = 0;

export function getPeerborneHookCaches(peerborne: object): PeerborneHookCaches {
  let caches = cachesByPeerborne.get(peerborne);
  if (!caches) {
    caches = {
      contextKeyPrefix: `peerborne-${nextContextKeyPrefix++}:`,
      openTasks: new Map(),
      openTaskResults: new Map(),
      subscriberCounts: new Map(),
    };
    cachesByPeerborne.set(peerborne, caches);
  }
  return caches;
}

export function getPeerborneDocumentCacheKey(
  caches: PeerborneHookCaches,
  documentPath: string,
): string {
  return `${caches.contextKeyPrefix}${documentPath}`;
}

export function resetPeerborneHookCaches(): void {
  cachesByPeerborne = new WeakMap();
  nextContextKeyPrefix = 0;
}
/* eslint-enable @typescript-eslint/no-explicit-any */
