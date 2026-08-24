import {
  ACLProvider,
  AuthProvider,
  ChangesSerializer,
  Peerborne,
  CRDTProvider,
  SyncMessageSerializer,
  KeychainProvider,
  LoadMessageSerializer,
  PeerborneDocument,
  PeerborneConfig,
} from '@peerborne/core';
import {
  useEffect,
  useState,
  useContext,
  useRef,
  createContext,
  type Dispatch,
  type SetStateAction,
} from 'react';
import {
  getPeerborneDocumentCacheKey,
  getPeerborneHookCaches,
} from './hooks-cache.js';

export type PeerborneContextOpenResult<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
> = {
  docRef?: PeerborneDocument<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >;
  readers?: PublicKey[];
  writers?: PublicKey[];
};

export const PeerborneContext = createContext<{
  // Cache keys are scoped by Peerborne instance and document path.
  docCache: Record<string, PeerborneDocument<any, any, any, any, any, any>>;
  docDataCache: Record<string, any>;
  docReadersCache: Record<string, any[]>;
  docWritersCache: Record<string, any[]>;
  setDocCache: Dispatch<
    SetStateAction<Record<string, PeerborneDocument<any, any, any, any, any, any>>>
  >;
  setDocDataCache: Dispatch<SetStateAction<Record<string, any>>>;
  setDocReadersCache: Dispatch<SetStateAction<Record<string, any[]>>>;
  setDocWritersCache: Dispatch<SetStateAction<Record<string, any[]>>>;
}>({
  // Default no-op setters; real implementations are provided by the context provider component.
  docCache: {},
  docDataCache: {},
  docReadersCache: {},
  docWritersCache: {},
  setDocCache: () => {},
  setDocDataCache: () => {},
  setDocReadersCache: () => {},
  setDocWritersCache: () => {},
});

function setCacheEntry<Cache extends Record<string, Value>, Value>(
  setter: Dispatch<SetStateAction<Cache>>,
  key: string,
  value: Value,
): void {
  setter((cache) => {
    return { ...cache, [key]: value };
  });
}

function deleteCacheEntry<Cache extends Record<string, unknown>>(
  setter: Dispatch<SetStateAction<Cache>>,
  key: string,
): void {
  setter((cache) => {
    if (!(key in cache)) return cache;
    const next = { ...cache };
    delete next[key];
    return next;
  });
}

export function usePeerborne<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
>(
  privateKey: PrivateKey | undefined,
  publicKey: PublicKey | undefined,
  provider: CRDTProvider<DocType, ChangesType, ChangeFnType>,
  changesSerializer: ChangesSerializer<ChangesType>,
  syncMessageSerializer: SyncMessageSerializer<ChangesType, PublicKey>,
  loadMessageSerializer: LoadMessageSerializer,
  authProvider: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  aclProvider: ACLProvider<ChangesType, PublicKey>,
  keychainProvider: KeychainProvider<ChangesType, DocumentKey>,
  config?: PeerborneConfig,
) {
  const [peerborne, setPeerborne] = useState<
    | Peerborne<
        DocType,
        ChangesType,
        ChangeFnType,
        PrivateKey,
        PublicKey,
        DocumentKey
      >
    | undefined
  >();

  useEffect(() => {
    (async () => {
      if (privateKey && publicKey) {
        const peerborne = new Peerborne(
          privateKey,
          publicKey,
          provider,
          changesSerializer,
          syncMessageSerializer,
          loadMessageSerializer,
          authProvider,
          aclProvider,
          keychainProvider,
        );
        await peerborne.initialize(config);
        setPeerborne(peerborne);
      }
    })();
  }, [privateKey, publicKey]);

  return peerborne;
}

export function usePeerborneDocumentState<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
>(
  peerborne: Peerborne<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >,
  documentPath: string,
  originFilter: 'all' | 'remote' | 'local' = 'all',
): [
  DocType | undefined,
  (fn: ChangeFnType, message?: string) => void,
  {
    readers: PublicKey[];
    addReader: (user: PublicKey) => Promise<void>;
    removeReader: (user: PublicKey) => Promise<void>;
    writers: PublicKey[];
    addWriter: (user: PublicKey) => Promise<void>;
    removeWriter: (user: PublicKey) => Promise<void>;
  },
] {
  const {
    docCache,
    docDataCache,
    docReadersCache,
    docWritersCache,
    setDocCache,
    setDocDataCache,
    setDocReadersCache,
    setDocWritersCache,
  } = useContext(PeerborneContext);
  const hookCaches = getPeerborneHookCaches(peerborne);
  const documentCacheKey = getPeerborneDocumentCacheKey(hookCaches, documentPath);
  const subscriptionIdRef = useRef(`usePeerborneDocumentState-${Math.random().toString(36).slice(2)}`);

  useEffect(() => {
    const { openTasks, openTaskResults, subscriberCounts } = hookCaches;
    let active = true;
    let subscribedDocRef: PeerborneDocument<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    > | null = null;

    subscriberCounts.set(documentPath, (subscriberCounts.get(documentPath) || 0) + 1);

    const updateContext = (
      docRef: PeerborneDocument<
        DocType,
        ChangesType,
        ChangeFnType,
        PrivateKey,
        PublicKey,
        DocumentKey
      >,
      current: DocType,
      readers: PublicKey[],
      writers: PublicKey[],
    ) => {
      setCacheEntry(setDocCache, documentCacheKey, docRef);
      setCacheEntry(setDocDataCache, documentCacheKey, current);
      setCacheEntry(setDocReadersCache, documentCacheKey, readers);
      setCacheEntry(setDocWritersCache, documentCacheKey, writers);
    };

    (async () => {
      let openTask = openTasks.get(documentPath) as
        | Promise<
            PeerborneContextOpenResult<
              DocType,
              ChangesType,
              ChangeFnType,
              PrivateKey,
              PublicKey,
              DocumentKey
            >
          >
        | undefined;

      try {
        if (!openTask) {
          const docRef = peerborne.doc(documentPath);
          if (!docRef) {
            console.warn(`Failed to open/find document: ${documentPath}`);
            return;
          }
          openTask = (async () => {
            await docRef.open();
            const readers = await docRef.getReaders();
            const writers = await docRef.getWriters();
            return { docRef, readers, writers };
          })();
          openTasks.set(documentPath, openTask);
        }

        const result = await openTask;
        if (!active || !result.docRef) return;

        const cachedResult = openTaskResults.get(documentPath);
        const docRef = (cachedResult?.docRef || result.docRef) as PeerborneDocument<
          DocType,
          ChangesType,
          ChangeFnType,
          PrivateKey,
          PublicKey,
          DocumentKey
        >;
        const current = (cachedResult?.document ?? docRef.document) as DocType;
        const readers = (cachedResult?.readers ?? result.readers ?? []) as PublicKey[];
        const writers = (cachedResult?.writers ?? result.writers ?? []) as PublicKey[];
        openTaskResults.set(documentPath, { docRef, document: current, readers, writers });
        updateContext(docRef, current, readers, writers);

        docRef.subscribe(
          subscriptionIdRef.current,
          (current, nextReaders, nextWriters) => {
            if (!active) return;
            openTaskResults.set(documentPath, {
              docRef,
              document: current,
              readers: nextReaders,
              writers: nextWriters,
            });
            updateContext(docRef, current, nextReaders, nextWriters);
          },
          originFilter,
        );
        subscribedDocRef = docRef;
      } catch {
        if (active) {
          console.warn(`Failed to open/find document: ${documentPath}`);
        }
      }
    })();

    return () => {
      active = false;
      subscribedDocRef?.unsubscribe(subscriptionIdRef.current);

      const count = (subscriberCounts.get(documentPath) || 1) - 1;
      if (count > 0) {
        subscriberCounts.set(documentPath, count);
        return;
      }

      subscriberCounts.delete(documentPath);
      openTaskResults.delete(documentPath);
      deleteCacheEntry(setDocCache, documentCacheKey);
      deleteCacheEntry(setDocDataCache, documentCacheKey);
      deleteCacheEntry(setDocReadersCache, documentCacheKey);
      deleteCacheEntry(setDocWritersCache, documentCacheKey);

      const pendingTask = openTasks.get(documentPath);
      if (!pendingTask) {
        return;
      }

      pendingTask
        .then((result) => {
          if (
            (subscriberCounts.get(documentPath) || 0) === 0 &&
            openTasks.get(documentPath) === pendingTask
          ) {
            openTasks.delete(documentPath);
            if (result.docRef && typeof result.docRef.close === 'function') {
              result.docRef.close().catch(() => {});
            }
          }
        })
        .catch(() => {
          if (openTasks.get(documentPath) === pendingTask) {
            openTasks.delete(documentPath);
          }
        });
    };
  }, [documentCacheKey, documentPath, hookCaches, originFilter, peerborne]);

  return [
    docDataCache[documentCacheKey],
    (fn: ChangeFnType, message?: string) => {
      const docRef = docCache[documentCacheKey];
      docRef && docRef.change(fn, message);
    },
    {
      readers: docReadersCache[documentCacheKey],
      addReader: async (user: PublicKey) => {
        const docRef = docCache[documentCacheKey];
        await docRef.addReader(user);
      },
      removeReader: async (user: PublicKey) => {
        const docRef = docCache[documentCacheKey];
        await docRef.removeReader(user);
      },
      writers: docWritersCache[documentCacheKey],
      addWriter: async (user: PublicKey) => {
        const docRef = docCache[documentCacheKey];
        await docRef.addWriter(user);
      },
      removeWriter: async (user: PublicKey) => {
        const docRef = docCache[documentCacheKey];
        await docRef.removeWriter(user);
      },
    },
  ];
}
