import { useEffect, useId, useState, useSyncExternalStore } from 'react';
import type * as Y from 'yjs';
import {
  GossipFrameLimitError,
  type RemoveWriterOptions,
} from '@peerborne/core';
import { VaultStore, type BrowserIdentity } from './vault-store';
import type { YjsPeerborne, YjsPeerborneDocument } from './utils';

interface OpenDocument {
  doc: YjsPeerborneDocument;
  revision: number;
  isVault: boolean;
  writes: Promise<void>;
  reopening?: Promise<void>;
}

type SavedDocument = NonNullable<Awaited<ReturnType<VaultStore['load']>>>;

const sessions = new WeakMap<YjsPeerborne, VaultSession>();
const emptyKeys: readonly CryptoKey[] = Object.freeze([]);

/** A failed Yjs change stays in the in-place document, so core retires it. */
function retiredBy(error: unknown): boolean {
  return (
    (error instanceof GossipFrameLimitError && error.retired) ||
    (error instanceof Error && /\bwas retired\b/u.test(error.message))
  );
}

async function restore(
  doc: YjsPeerborneDocument,
  saved: SavedDocument,
): Promise<void> {
  try {
    await doc.restorePlaintextCheckpoint(saved.checkpoint);
  } finally {
    saved.checkpoint.payload.fill(0);
    saved.checkpoint.signature.fill(0);
  }
  await doc.open();
}

export class VaultSession {
  private readonly tasks = new Map<string, Promise<OpenDocument>>();
  private readonly documents = new Map<string, OpenDocument>();
  private readonly generations = new Map<string, number>();
  private readonly listeners = new Set<() => void>();
  private pendingWrites = 0;
  private readonly failedWrites = new Set<OpenDocument>();
  private readonly retired = new Set<OpenDocument>();
  private discardedEdit = false;
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
  /** Whether an edit is unsaved or was discarded since the user last dismissed it. */
  get unsaved(): boolean {
    return (
      this.retired.size > 0 || this.failedWrites.size > 0 || this.discardedEdit
    );
  }
  private get reopenFailed(): boolean {
    return [...this.retired].some((entry) => !entry.reopening);
  }
  get canRetry(): boolean {
    return this.reopenFailed || this.failedWrites.size > 0;
  }
  get error(): string | undefined {
    if (this.reopenFailed)
      return 'An edit could not be saved, and this tab could not reopen the vault from its last saved state. Retry, or reload the page.';
    if (this.failedWrites.size > 0)
      return 'Could not save the vault in this browser. Keep this tab open and retry.';
    if (this.discardedEdit)
      return 'An edit could not be saved and was discarded. The vault shows its last saved state.';
    return undefined;
  }
  generation(path: string): number {
    return this.generations.get(path) ?? 0;
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
  dismiss(): void {
    this.discardedEdit = false;
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

  private install(entry: OpenDocument): void {
    this.documents.set(entry.doc.documentPath, entry);
    entry.doc.subscribe('browser-vault-persistence', () => {
      void this.save(entry).catch(() => undefined);
    });
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
        await restore(doc, saved);
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
      this.install(entry);
      if (!saved) await this.save(entry);
      this.vaults = await this.store.listVaults();
      this.notify();
      return entry;
    } catch (error) {
      const entry = this.documents.get(path);
      if (entry?.doc === doc) {
        this.failedWrites.delete(entry);
        this.documents.delete(path);
      }
      this.notify();
      await doc.close().catch(() => undefined);
      throw error;
    }
  }

  private reopen(entry: OpenDocument): Promise<void> {
    entry.reopening ??= Promise.resolve().then(() => this.replace(entry));
    return entry.reopening;
  }

  /** Discard a retired instance's unsaved edit by reopening its last checkpoint. */
  private async replace(entry: OpenDocument): Promise<void> {
    const path = entry.doc.documentPath;
    this.retired.add(entry);
    this.failedWrites.delete(entry);
    this.notify();
    await entry.writes.catch(() => undefined);
    entry.doc.unsubscribe('browser-vault-persistence');
    await entry.doc.close().catch(() => undefined);
    const doc = this.peerborne.doc(path);
    try {
      await doc.setKemKeyPair(this.identity.kem);
      const saved = await this.store.load(path);
      if (!saved) throw new Error('No saved document is available');
      await restore(doc, saved);
      const next: OpenDocument = {
        doc,
        revision: saved.revision,
        isVault: entry.isVault,
        writes: Promise.resolve(),
      };
      this.install(next);
      this.tasks.set(path, Promise.resolve(next));
      this.generations.set(path, this.generation(path) + 1);
      this.retired.delete(entry);
      this.discardedEdit = true;
    } catch {
      await doc.close().catch(() => undefined);
      entry.reopening = undefined;
    } finally {
      this.notify();
    }
  }

  private save(entry: OpenDocument): Promise<void> {
    this.pendingWrites++;
    this.notify();
    const operation = entry.writes
      .catch(() => undefined)
      .then(async () => {
        const checkpoint = await entry.doc.exportPlaintextCheckpoint();
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
        },
        (error) => {
          if (retiredBy(error)) void this.reopen(entry);
          else if (
            !this.retired.has(entry) &&
            this.documents.get(entry.doc.documentPath) === entry
          )
            this.failedWrites.add(entry);
          throw error;
        },
      )
      .finally(() => {
        this.pendingWrites--;
        this.notify();
      });
  }

  async retry(): Promise<void> {
    await Promise.all([
      ...[...this.retired].map((entry) => this.reopen(entry)),
      ...[...this.documents.values()]
        .filter((entry) => !this.retired.has(entry))
        .map((entry) => this.save(entry)),
    ]);
  }

  /**
   * Apply `operation` to the current instance of `path` and save it. An
   * operation that retires the instance discards its edit by reopening the
   * last checkpoint; a failed edit stays reported until dismissed.
   */
  async mutate(
    path: string,
    operation: (doc: YjsPeerborneDocument) => Promise<unknown>,
    edit = false,
  ): Promise<void> {
    await this.documents.get(path)?.reopening;
    const entry = this.documents.get(path);
    if (!entry) throw new Error('The vault document is not ready');
    this.pendingWrites++;
    this.notify();
    try {
      try {
        await operation(entry.doc);
      } catch (error) {
        if (retiredBy(error)) await this.reopen(entry);
        else {
          if (edit) this.discardedEdit = true;
          await this.save(entry).catch(() => undefined);
        }
        throw error;
      }
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
  const generation = useSyncExternalStore(session.subscribe, () =>
    session.generation(path),
  );
  const [state, setState] = useState<{
    path: string;
    doc: YjsPeerborneDocument;
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
      .then(async ({ doc }) => {
        const readers = await doc.getReaders();
        const writers = await doc.getWriters();
        if (!active) return;
        setState({
          path,
          doc,
          document: doc.document,
          readers,
          writers,
        });
        doc.subscribe(id, (document, nextReaders, nextWriters) => {
          if (active)
            setState({
              path,
              doc,
              document,
              readers: nextReaders,
              writers: nextWriters,
            });
        });
        subscribed = doc;
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
  }, [session, path, mode, id, generation]);
  const current = state?.path === path ? state : undefined;
  const mutate = async (
    operation: (doc: YjsPeerborneDocument) => Promise<unknown>,
  ) => {
    if (!current) throw new Error('The vault document is not ready');
    return session.mutate(path, operation);
  };
  return [
    current?.document,
    (change: (doc: Y.Doc) => void) => {
      if (!current) return;
      void session
        .mutate(path, (doc) => doc.change(change), true)
        .catch(() => undefined);
    },
    {
      docRef: current?.doc,
      readers: current?.readers ?? emptyKeys,
      writers: current?.writers ?? emptyKeys,
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
