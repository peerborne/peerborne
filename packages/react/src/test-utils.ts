import { jest } from '@jest/globals';
import React, { useState } from 'react';
import { PeerborneContext, usePeerborneDocumentState } from './hooks.js';
import {
  getPeerborneHookCaches,
  resetPeerborneHookCaches,
} from './hooks-cache.js';

/** Reset all module-level caches. Test-only helper. */
export function resetCaches() {
  resetPeerborneHookCaches();
}

/** Read-only access to module-level cache sizes. Test-only helper. */
export function getCacheSizes(peerborne: object) {
  const { openTasks, openTaskResults, subscriberCounts } =
    getPeerborneHookCaches(peerborne);
  return {
    openTasks: openTasks.size,
    openTaskResults: openTaskResults.size,
    subscriberCounts: subscriberCounts.size,
  };
}

export function createMockDocument(data: any = { test: 'data' }): any {
  const subscriptions = new Map<string, { handler: Function; filter: string }>();
  return {
    open: jest.fn(() => Promise.resolve()),
    close: jest.fn(() => Promise.resolve()),
    getReaders: jest.fn(() => Promise.resolve(['reader1'])),
    getWriters: jest.fn(() => Promise.resolve(['writer1'])),
    document: data,
    change: jest.fn(),
    addReader: jest.fn(() => Promise.resolve()),
    removeReader: jest.fn(() => Promise.resolve()),
    addWriter: jest.fn(() => Promise.resolve()),
    removeWriter: jest.fn(() => Promise.resolve()),
    subscribe: jest.fn((id: string, handler: Function, filter: string) => {
      subscriptions.set(id, { handler, filter });
    }),
    unsubscribe: jest.fn((id: string) => {
      subscriptions.delete(id);
    }),
    _subscriptions: subscriptions,
  };
}

export function createMockPeerborne(mockDoc: any) {
  return { doc: jest.fn(() => mockDoc) } as any;
}

export function createMockPeerborneMultiDoc(docMap: Record<string, any>) {
  return {
    doc: jest.fn((path: string) => docMap[path] || null),
  } as any;
}

// Wrapper providing PeerborneContext with real React state.
export function TestProvider(props: { children: React.ReactNode }) {
  const [docCache, setDocCache] = useState<Record<string, any>>({});
  const [docDataCache, setDocDataCache] = useState<Record<string, any>>({});
  const [docReadersCache, setDocReadersCache] = useState<Record<string, any[]>>({});
  const [docWritersCache, setDocWritersCache] = useState<Record<string, any[]>>({});
  return React.createElement(
    PeerborneContext.Provider,
    {
      value: {
        docCache, docDataCache, docReadersCache, docWritersCache,
        setDocCache, setDocDataCache, setDocReadersCache, setDocWritersCache,
      },
    },
    props.children,
  );
}

// Test component that uses the hook and exposes the returned tuple.
export function TestConsumer(props: {
  peerborne: any;
  documentPath: string;
  originFilter?: 'all' | 'remote' | 'local';
  captureRef?: { current: any };
}) {
  const [docData, changeFn, acl] = usePeerborneDocumentState(
    props.peerborne,
    props.documentPath,
    props.originFilter,
  );
  if (props.captureRef) {
    props.captureRef.current = { docData, changeFn, acl };
  }
  return React.createElement('div', { 'data-testid': 'doc-data' }, JSON.stringify(docData));
}
