import { useEffect, useId, useState } from 'react';
import type * as Y from 'yjs';
import type { RemoveWriterOptions } from '@peerborne/core';
import { VaultStore, type BrowserIdentity } from './vault-store';
import type { YjsPeerborne, YjsPeerborneDocument } from './utils';

interface OpenDocument {
  doc: YjsPeerborneDocument;
  revision: number;
  isVault: boolean;
  writes: Promise<void>;
}

const sessions = new WeakMap<YjsPeerborne, VaultSession>();
const emptyKeys: readonly CryptoKey[] = Object.freeze([]);

export class VaultSession {
  private readonly tasks = new Map<string, Promise<OpenDocument>>();
  private readonly documents = new Map<string, OpenDocument>();
  private readonly listeners = new Set<() => void>();
  private pendingWrites = 0;
  private readonly failedWrites = new Set<OpenDocument>();
  error: Error | undefined;
  vaults: string[] = [];

  constructor(
    readonly peerborne: YjsPeerborne,
    readonly identity: BrowserIdentity,
    private readonly store: VaultStore,
  ) {
    sessions.set(peerborne, this);
  }

  get storeOwner(): string {
    return this.store.owner;
  }
  get saving(): boolean {
    return this.pendingWrites > 0;
  }
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  private notify(): void {
    for (const listener of this.listeners) listener();
  }
  report(error: unknown): void {
    this.error =
      this.failedWrites.size > 0
        ? new Error(
            'Could not save the vault in this browser. Keep this tab open and retry.',
          )
        : error instanceof Error
          ? error
          : new Error('The vault operation failed');
    this.notify();
  }
  async initialize(): Promise<void> {
    this.vaults = await this.store.listVaults();
    this.notify();
  }

  open(path: string, mode: 'open' | 'create'): Promise<OpenDocument> {
    const existing = this.tasks.get(path);
    if (existing) return existing;
    const task = this.activate(path, mode);
    this.tasks.set(path, task);
    void task.catch(() => {
      if (this.tasks.get(path) === task) this.tasks.delete(path);
    });
    return task;
  }

  private async activate(
    path: string,
    mode: 'open' | 'create',
  ): Promise<OpenDocument> {
    const doc = this.peerborne.doc(path);
    try {
      await doc.setKemKeyPair(this.identity.kem);
      const saved = await this.store.load(path);
      if (saved) {
        if (mode === 'create') throw new Error('This vault already exists');
        try {
          await doc.restoreCheckpoint(saved.checkpoint);
        } finally {
          saved.checkpoint.payload.fill(0);
          saved.checkpoint.signature.fill(0);
        }
        await doc.open();
      } else {
        if (mode !== 'create')
          throw new Error('No saved document is available in this browser');
        await doc.create();
      }
      const entry: OpenDocument = {
        doc,
        revision: saved?.revision ?? 0,
        isVault: saved?.isVault ?? path.includes('/vaults/'),
        writes: Promise.resolve(),
      };
      this.documents.set(path, entry);
      doc.subscribe('browser-vault-persistence', () => {
        void this.save(entry).catch(() => undefined);
      });
      if (!saved) await this.save(entry);
      this.vaults = await this.store.listVaults();
      this.notify();
      return entry;
    } catch (error) {
      const entry = this.documents.get(path);
      if (entry) this.failedWrites.delete(entry);
      if (this.failedWrites.size === 0) this.error = undefined;
      this.documents.delete(path);
      this.notify();
      await doc.close().catch(() => undefined);
      throw error;
    }
  }

  private save(entry: OpenDocument): Promise<void> {
    this.pendingWrites++;
    this.notify();
    const operation = entry.writes
      .catch(() => undefined)
      .then(async () => {
        const checkpoint = await entry.doc.exportCheckpoint();
        try {
          entry.revision = await this.store.save(
            entry.doc.documentPath,
            entry.isVault,
            checkpoint,
            entry.revision,
          );
        } finally {
          checkpoint.payload.fill(0);
          checkpoint.signature.fill(0);
        }
      });
    entry.writes = operation;
    return operation
      .then(
        () => {
          this.failedWrites.delete(entry);
          if (this.failedWrites.size === 0) this.error = undefined;
        },
        (error) => {
          this.failedWrites.add(entry);
          this.report(error);
          throw error;
        },
      )
      .finally(() => {
        this.pendingWrites--;
        this.notify();
      });
  }

  async retry(): Promise<void> {
    await Promise.all(
      [...this.documents.values()].map((entry) => this.save(entry)),
    );
  }
  async mutate(
    entry: OpenDocument,
    operation: () => Promise<unknown>,
  ): Promise<void> {
    this.pendingWrites++;
    this.notify();
    try {
      await operation();
      await this.save(entry);
    } finally {
      this.pendingWrites--;
      this.notify();
    }
  }
}

export function useVaultSession(session: VaultSession): void {
  const [, update] = useState(0);
  useEffect(
    () => session.subscribe(() => update((value) => value + 1)),
    [session],
  );
}

export function useVaultDocumentState(
  peerborne: YjsPeerborne,
  path: string,
  _filter: 'all' = 'all',
  mode: 'open' | 'create' = 'open',
) {
  const session = sessions.get(peerborne);
  if (!session) throw new Error('The browser vault session is unavailable');
  const id = useId();
  const [state, setState] = useState<{
    path: string;
    entry: OpenDocument;
    document: Y.Doc;
    readers: CryptoKey[];
    writers: CryptoKey[];
  }>();
  const [failure, setFailure] = useState<Error>();
  useEffect(() => {
    let active = true;
    let subscribed: YjsPeerborneDocument | undefined;
    setFailure(undefined);
    void session
      .open(path, mode)
      .then(async (entry) => {
        const readers = await entry.doc.getReaders();
        const writers = await entry.doc.getWriters();
        if (!active) return;
        setState({
          path,
          entry,
          document: entry.doc.document,
          readers,
          writers,
        });
        entry.doc.subscribe(id, (document, nextReaders, nextWriters) => {
          if (active)
            setState({
              path,
              entry,
              document,
              readers: nextReaders,
              writers: nextWriters,
            });
        });
        subscribed = entry.doc;
      })
      .catch((error) => {
        if (active)
          setFailure(
            error instanceof Error
              ? error
              : new Error('Could not open the saved vault'),
          );
      });
    return () => {
      active = false;
      subscribed?.unsubscribe(id);
    };
  }, [session, path, mode, id]);
  const current = state?.path === path ? state : undefined;
  const mutate = async (
    operation: (doc: YjsPeerborneDocument) => Promise<unknown>,
  ) => {
    if (!current) throw new Error('The vault document is not ready');
    return session.mutate(current.entry, () => operation(current.entry.doc));
  };
  return [
    current?.document,
    (change: (doc: Y.Doc) => void) => {
      void mutate((doc) => doc.change(change)).catch((error) =>
        session.report(error),
      );
    },
    {
      docRef: current?.entry.doc,
      readers: current?.readers ?? emptyKeys,
      writers: current?.writers ?? emptyKeys,
      addReader: (key: CryptoKey, kem: Uint8Array) =>
        mutate((doc) => doc.addReader(key, kem)),
      removeReader: (key: CryptoKey) => mutate((doc) => doc.removeReader(key)),
      addWriter: (key: CryptoKey) => mutate((doc) => doc.addWriter(key)),
      removeWriter: (key: CryptoKey, options?: RemoveWriterOptions) =>
        mutate((doc) => doc.removeWriter(key, options)),
      setKemKeyPair: (pair: CryptoKeyPair | undefined) =>
        mutate((doc) => doc.setKemKeyPair(pair)),
    },
    failure,
  ] as const;
}
