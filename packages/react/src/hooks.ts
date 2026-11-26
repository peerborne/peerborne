import {
  ACLProvider,
  AuthProvider,
  ChangeDeliveryFailure,
  ChangesSerializer,
  Peerborne,
  CRDTProvider,
  SyncMessageSerializer,
  KeychainProvider,
  LoadMessageSerializer,
  PeerborneDocument,
  PeerborneConfig,
  RemoveWriterOptions,
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
  type PeerborneDocumentInitialization,
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
  syncMessageSerializer: SyncMessageSerializer<ChangesType>,
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
  initialization: PeerborneDocumentInitialization = 'open',
): [
  DocType | undefined,
  (fn: ChangeFnType, message?: string) => void,
  {
    readers: PublicKey[];
    /** Resend the Welcome to an existing reader; it cannot add a new identity. */
    resendReaderWelcome: (
      user: PublicKey,
      readerKemPublicKey: Uint8Array,
    ) => Promise<void>;
    removeReader: (user: PublicKey) => Promise<void>;
    writers: PublicKey[];
    addWriter: (user: PublicKey) => Promise<void>;
    removeWriter: (
      user: PublicKey,
      options?: RemoveWriterOptions,
    ) => Promise<void>;
    setKemKeyPair: (keyPair: CryptoKeyPair | undefined) => Promise<void>;
  },
  Error | undefined,
  ChangeDeliveryFailure | undefined,
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
  const activationKey = `${documentCacheKey}\0${initialization}\0${originFilter}`;
  const [activationFailure, setActivationFailure] = useState<{
    key: string;
    error: Error;
  }>();
  const [delivery, setDelivery] = useState<{
    key: string;
    failure: ChangeDeliveryFailure | undefined;
  }>();

  useEffect(() => {
    const {
      openTasks,
      openTaskModes,
      openTaskResults,
      subscriberCounts,
      activationRetries,
      createdPaths,
      retainedDocuments,
    } = hookCaches;
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

    type OpenTask = Promise<
      PeerborneContextOpenResult<
        DocType,
        ChangesType,
        ChangeFnType,
        PrivateKey,
        PublicKey,
        DocumentKey
      >
    >;

    // A path this node created opens instead: creating it again would found
    // a different document.
    const activate = async (mode: PeerborneDocumentInitialization): OpenTask => {
      const docRef = peerborne.doc(documentPath);
      if (!docRef) {
        throw new Error(`Failed to open/find document: ${documentPath}`);
      }
      const creating = mode === 'create' && !createdPaths.has(documentPath);
      await (creating ? docRef.create() : docRef.open());
      if (creating) createdPaths.add(documentPath);
      try {
        const readers = await docRef.getReaders();
        const writers = await docRef.getWriters();
        return { docRef, readers, writers };
      } catch (error) {
        await docRef.close().catch(() => {});
        throw error;
      }
    };

    const shareTask = (task: OpenTask, mode: PeerborneDocumentInitialization) => {
      openTasks.set(documentPath, task);
      openTaskModes.set(task, mode);
      return task;
    };

    // A caller adopts a shared activation of the other initialization mode
    // only if it activates the document, and otherwise runs its own.
    const joinActivation = (): OpenTask => {
      const existing = openTasks.get(documentPath) as OpenTask | undefined;
      if (!existing) {
        return shareTask(activate(initialization), initialization);
      }
      if (openTaskModes.get(existing) !== initialization) {
        return shareTask(
          existing.catch(() => activate(initialization)),
          initialization,
        );
      }
      return existing;
    };

    // A failed activation is evicted so later mounts start a new one, and a
    // waiter follows a replacement that superseded the task it joined.
    const awaitActivation = async (
      task: OpenTask,
    ): Promise<Awaited<OpenTask>> => {
      try {
        return await task;
      } catch (error) {
        const latest = openTasks.get(documentPath) as OpenTask | undefined;
        if (latest === task) {
          openTasks.delete(documentPath);
        }
        if (!active || !latest || latest === task) {
          throw error;
        }
        return awaitActivation(latest);
      }
    };

    // A consumer whose activation failed stays counted, so it retries once
    // another consumer activates the path and holds its own subscription.
    const run = async () => {
      try {
        const result = await awaitActivation(joinActivation());
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
        let { readers: activatedReaders, writers: activatedWriters } = result;
        if (!cachedResult && retainedDocuments.has(docRef)) {
          [activatedReaders, activatedWriters] = await Promise.all([
            docRef.getReaders(),
            docRef.getWriters(),
          ]);
          if (!active) return;
        }
        const settled = openTaskResults.get(documentPath);
        const current = (settled?.document ?? docRef.document) as DocType;
        const readers = (settled?.readers ?? activatedReaders ?? []) as PublicKey[];
        const writers = (settled?.writers ?? activatedWriters ?? []) as PublicKey[];
        openTaskResults.set(documentPath, { docRef, document: current, readers, writers });
        updateContext(docRef, current, readers, writers);

        const syncDelivery = () => {
          if (!active) return;
          const failure = docRef.deliveryFailure;
          setDelivery((previous) =>
            previous?.key === activationKey && previous.failure === failure
              ? previous
              : { key: activationKey, failure },
          );
        };
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
            syncDelivery();
          },
          originFilter,
        );
        docRef.subscribeDeliveryFailures(subscriptionIdRef.current, syncDelivery);
        subscribedDocRef = docRef;
        syncDelivery();
        setActivationFailure(undefined);
      } catch (error) {
        if (active) {
          console.warn(`Failed to open/find document: ${documentPath}`);
          setActivationFailure({
            key: activationKey,
            error: error instanceof Error ? error : new Error(String(error)),
          });
          const retries = activationRetries.get(documentPath) ?? new Set();
          retries.add(run);
          activationRetries.set(documentPath, retries);
        }
        return;
      }

      const retries = activationRetries.get(documentPath);
      activationRetries.delete(documentPath);
      retries?.forEach((retry) => {
        if (retry !== run) retry();
      });
    };

    run();

    return () => {
      active = false;
      setActivationFailure(undefined);
      subscribedDocRef?.unsubscribe(subscriptionIdRef.current);
      subscribedDocRef?.unsubscribeDeliveryFailures(subscriptionIdRef.current);

      const retries = activationRetries.get(documentPath);
      retries?.delete(run);
      if (retries?.size === 0) {
        activationRetries.delete(documentPath);
      }

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

      // A document this node created stays open, since closing it could
      // discard the only copy; a retired one is replaced by an open.
      pendingTask
        .then((result) => {
          if (
            (subscriberCounts.get(documentPath) || 0) === 0 &&
            openTasks.get(documentPath) === pendingTask
          ) {
            if (
              result.docRef &&
              createdPaths.has(documentPath) &&
              !result.docRef.retired
            ) {
              retainedDocuments.add(result.docRef);
              return;
            }
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
  }, [activationKey, documentCacheKey, documentPath, hookCaches, initialization, originFilter, peerborne]);

  return [
    docDataCache[documentCacheKey],
    (fn: ChangeFnType, message?: string) => {
      const docRef = docCache[documentCacheKey];
      docRef && docRef.change(fn, message);
    },
    {
      readers: docReadersCache[documentCacheKey],
      resendReaderWelcome: async (
        user: PublicKey,
        readerKemPublicKey: Uint8Array,
      ) => {
        const docRef = docCache[documentCacheKey];
        await docRef.addReader(user, readerKemPublicKey);
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
      removeWriter: async (user: PublicKey, options?: RemoveWriterOptions) => {
        const docRef = docCache[documentCacheKey];
        await docRef.removeWriter(user, options);
      },
      setKemKeyPair: async (keyPair: CryptoKeyPair | undefined) => {
        const docRef = docCache[documentCacheKey];
        await docRef.setKemKeyPair(keyPair);
      },
    },
    activationFailure?.key === activationKey ? activationFailure.error : undefined,
    delivery?.key === activationKey ? delivery.failure : undefined,
  ];
}
