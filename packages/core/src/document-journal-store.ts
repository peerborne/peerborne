import type {
  DocumentJournalSnapshot,
  DocumentJournalStore,
  DocumentJournalPublication,
  DocumentJournalStagedPublication,
} from './document-replay-journal.js';
import {
  MAX_DOCUMENT_JOURNAL_BYTES,
  MAX_DOCUMENT_JOURNAL_ENTRIES,
  DocumentJournalCapacityError,
  DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD,
  MAX_DOCUMENT_STORED_PUBLICATION_BYTES,
} from './document-replay-journal.js';
import { documentBytesEqual } from './internal/document-binary.js';
import { copyUnsharedUint8Array } from './utils.js';

function clone(
  value: DocumentJournalSnapshot | undefined,
): DocumentJournalSnapshot {
  if (!value) return { revision: 0, entries: [] };
  if (
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0 ||
    !Array.isArray(value.entries) ||
    value.entries.length > MAX_DOCUMENT_JOURNAL_ENTRIES
  )
    throw new Error('Invalid journal store record');
  let bytes = 0;
  const entries = value.entries.map((entry) => {
    const owned = copyUnsharedUint8Array(
      entry,
      1,
      MAX_DOCUMENT_JOURNAL_BYTES - bytes,
      'stored journal entry',
    );
    bytes += owned.length;
    return owned;
  });
  if (
    value.publications !== undefined &&
    (!Array.isArray(value.publications) || value.publications.length > 16)
  )
    throw new Error('Invalid document publication queue');
  const publications = (value.publications ?? []).map((publication) =>
    ownPublication(publication),
  );
  if (
    publications.length > 16 ||
    publications.reduce(
      (sum, publication) => sum + publication.frame.length,
      0,
    ) >
      16 * 1024 * 1024
  )
    throw new Error('Document publication bound exceeded');
  const pending = value.pending && {
    token: copyUnsharedUint8Array(value.pending.token, 32, 32, 'journal token'),
    entry: copyUnsharedUint8Array(
      value.pending.entry,
      1,
      MAX_DOCUMENT_JOURNAL_BYTES,
      'pending journal entry',
    ),
    ...(value.pending.publication
      ? { publication: ownStagedPublication(value.pending.publication) }
      : {}),
  };
  return {
    revision: value.revision,
    entries,
    publications,
    ...(pending ? { pending } : {}),
  };
}

function ownPublication(
  value: DocumentJournalPublication,
): DocumentJournalPublication {
  return {
    id: copyUnsharedUint8Array(value.id, 32, 32, 'publication id'),
    frame: copyUnsharedUint8Array(
      value.frame,
      1,
      MAX_DOCUMENT_STORED_PUBLICATION_BYTES,
      'publication frame',
    ),
  };
}

function ownStagedPublication(
  value: DocumentJournalStagedPublication,
): DocumentJournalStagedPublication {
  if (
    !Number.isSafeInteger(value.bytes) ||
    value.bytes < 1 ||
    value.bytes > MAX_DOCUMENT_STORED_PUBLICATION_BYTES
  )
    throw new Error('Invalid publication reservation');
  return {
    id: copyUnsharedUint8Array(value.id, 32, 32, 'publication id'),
    bytes: value.bytes,
  };
}

function staged(
  current: DocumentJournalSnapshot,
  revision: number,
  token: Uint8Array,
  entry: Uint8Array,
  publication?: DocumentJournalStagedPublication,
  checkpoint = false,
): DocumentJournalSnapshot {
  if (current.revision !== revision || current.pending)
    throw new Error('Journal stage conflict');
  if (
    publication &&
    ((current.publications?.length ?? 0) >= 16 ||
      (current.publications ?? []).reduce(
        (sum, value) => sum + value.frame.length,
        publication.bytes,
      ) >
        16 * 1024 * 1024)
  )
    throw new DocumentJournalCapacityError();
  if (
    entry.length + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD >
    MAX_DOCUMENT_JOURNAL_BYTES
  )
    throw new DocumentJournalCapacityError();
  if (
    !checkpoint &&
    (current.entries.length >= MAX_DOCUMENT_JOURNAL_ENTRIES ||
      current.entries.reduce(
        (sum, value) => sum + value.length,
        entry.length + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD,
      ) > MAX_DOCUMENT_JOURNAL_BYTES)
  )
    throw new DocumentJournalCapacityError();
  return {
    ...current,
    pending: { token, entry, ...(publication ? { publication } : {}) },
  };
}
function committed(
  current: DocumentJournalSnapshot,
  revision: number,
  token: Uint8Array,
  checkpoint: boolean,
  acceptedEntry: Uint8Array,
  acceptedPublication?: DocumentJournalPublication,
): DocumentJournalSnapshot {
  if (
    current.revision !== revision ||
    revision === Number.MAX_SAFE_INTEGER ||
    !current.pending ||
    !documentBytesEqual(current.pending.token, token)
  )
    throw new Error('Journal commit conflict');
  if (
    acceptedEntry.length !==
    current.pending.entry.length + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD
  )
    throw new Error('Invalid accepted journal framing');
  if (
    !!current.pending.publication !== !!acceptedPublication ||
    (acceptedPublication &&
      (!documentBytesEqual(
        acceptedPublication.id,
        current.pending.publication!.id,
      ) ||
        acceptedPublication.frame.length !==
          current.pending.publication!.bytes))
  )
    throw new Error('Accepted publication does not match reservation');
  const entries = checkpoint
    ? [acceptedEntry]
    : [...current.entries, acceptedEntry];
  if (
    entries.length > MAX_DOCUMENT_JOURNAL_ENTRIES ||
    entries.reduce((sum, entry) => sum + entry.length, 0) >
      MAX_DOCUMENT_JOURNAL_BYTES
  )
    throw new Error('Journal storage bound exceeded');
  return {
    revision: revision + 1,
    entries,
    publications: [
      ...(current.publications ?? []),
      ...(acceptedPublication ? [acceptedPublication] : []),
    ],
  };
}
function discarded(
  current: DocumentJournalSnapshot,
  token: Uint8Array,
): DocumentJournalSnapshot {
  if (!current.pending || !documentBytesEqual(current.pending.token, token))
    return current;
  return {
    revision: current.revision,
    entries: current.entries,
    publications: current.publications,
  };
}

/** Reference store for deterministic simulations; it does not survive process exit. */
export class InMemoryDocumentJournalStore implements DocumentJournalStore {
  private readonly documents = new Map<string, DocumentJournalSnapshot>();
  async load(key: string): Promise<DocumentJournalSnapshot> {
    return clone(this.documents.get(key));
  }
  async loadAcceptedHead(
    key: string,
  ): Promise<{ revision: number; entry?: Uint8Array }> {
    const value = this.documents.get(key),
      entry = value?.entries.at(-1);
    return {
      revision: value?.revision ?? 0,
      ...(entry ? { entry: entry.slice() } : {}),
    };
  }
  async loadPublications(
    key: string,
  ): Promise<ReadonlyArray<DocumentJournalPublication>> {
    return (this.documents.get(key)?.publications ?? []).map(ownPublication);
  }
  async stage(
    key: string,
    revision: number,
    token: Uint8Array,
    entry: Uint8Array,
    publication?: DocumentJournalStagedPublication,
    checkpoint = false,
  ): Promise<void> {
    const ownToken = copyUnsharedUint8Array(token, 32, 32, 'journal token'),
      ownEntry = copyUnsharedUint8Array(
        entry,
        1,
        MAX_DOCUMENT_JOURNAL_BYTES,
        'journal entry',
      );
    this.documents.set(
      key,
      staged(
        clone(this.documents.get(key)),
        revision,
        ownToken,
        ownEntry,
        publication && ownStagedPublication(publication),
        checkpoint,
      ),
    );
  }
  async commit(
    key: string,
    revision: number,
    token: Uint8Array,
    checkpoint: boolean,
    acceptedEntry: Uint8Array,
    acceptedPublication?: DocumentJournalPublication,
  ): Promise<void> {
    const owned = copyUnsharedUint8Array(token, 32, 32, 'journal token');
    const accepted = copyUnsharedUint8Array(
      acceptedEntry,
      1,
      MAX_DOCUMENT_JOURNAL_BYTES,
      'accepted journal entry',
    );
    const publication =
      acceptedPublication && ownPublication(acceptedPublication);
    this.documents.set(
      key,
      committed(
        clone(this.documents.get(key)),
        revision,
        owned,
        checkpoint,
        accepted,
        publication,
      ),
    );
  }
  async publicationSent(key: string, id: Uint8Array): Promise<void> {
    const ownId = copyUnsharedUint8Array(id, 32, 32, 'publication id'),
      current = clone(this.documents.get(key));
    this.documents.set(key, {
      ...current,
      publications: current.publications?.filter(
        (value) => !documentBytesEqual(value.id, ownId),
      ),
    });
  }
  async discard(key: string, token: Uint8Array): Promise<void> {
    const owned = copyUnsharedUint8Array(token, 32, 32, 'journal token');
    this.documents.set(key, discarded(clone(this.documents.get(key)), owned));
  }
}

interface JournalHead {
  revision: number;
  revisions: number[];
  bytes: number;
  publications: { id: string; bytes: number }[];
  pending?: {
    token: Uint8Array;
    bytes: number;
    checkpoint: boolean;
    publicationBytes: number;
  };
}
function readHead(value: JournalHead | undefined): JournalHead {
  if (!value) return { revision: 0, revisions: [], bytes: 0, publications: [] };
  if (
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0 ||
    !Number.isSafeInteger(value.bytes) ||
    value.bytes < 0 ||
    value.bytes > MAX_DOCUMENT_JOURNAL_BYTES ||
    !Array.isArray(value.revisions) ||
    value.revisions.length > MAX_DOCUMENT_JOURNAL_ENTRIES ||
    !Array.isArray(value.publications) ||
    value.publications.length > 16
  )
    throw new Error('Invalid journal head');
  let previous = 0,
    publicationBytes = 0;
  for (const revision of value.revisions) {
    if (
      !Number.isSafeInteger(revision) ||
      revision <= previous ||
      revision > value.revision
    )
      throw new Error('Invalid journal revision index');
    previous = revision;
  }
  if (previous !== value.revision)
    throw new Error('Journal head has missing entries');
  const seen = new Set<string>();
  for (const publication of value.publications) {
    if (
      !/^[0-9a-f]{64}$/.test(publication.id) ||
      seen.has(publication.id) ||
      !Number.isSafeInteger(publication.bytes) ||
      publication.bytes < 1 ||
      publication.bytes > MAX_DOCUMENT_STORED_PUBLICATION_BYTES
    )
      throw new Error('Invalid publication index');
    seen.add(publication.id);
    publicationBytes += publication.bytes;
  }
  if (publicationBytes > 16 * 1024 * 1024)
    throw new Error('Publication byte bound exceeded');
  if (value.pending) {
    copyUnsharedUint8Array(
      value.pending.token,
      32,
      32,
      'pending journal token',
    );
    if (
      !Number.isSafeInteger(value.pending.bytes) ||
      value.pending.bytes < 1 ||
      value.pending.bytes > MAX_DOCUMENT_JOURNAL_BYTES ||
      typeof value.pending.checkpoint !== 'boolean' ||
      !Number.isSafeInteger(value.pending.publicationBytes) ||
      value.pending.publicationBytes < 0 ||
      value.pending.publicationBytes > MAX_DOCUMENT_STORED_PUBLICATION_BYTES
    )
      throw new Error('Invalid pending journal index');
  }
  return value;
}
const publicationId = (id: Uint8Array) =>
  Array.from(id, (byte) => byte.toString(16).padStart(2, '0')).join('');

/** Ciphertext-only WAL. Routine writes never read or rewrite the checkpoint. */
export class IndexedDBDocumentJournalStore implements DocumentJournalStore {
  private readonly database: Promise<IDBDatabase>;
  constructor(name: string, factory: IDBFactory = indexedDB) {
    if (!name || name.length > 256)
      throw new TypeError('Invalid journal database name');
    this.database = new Promise((resolve, reject) => {
      let failed = false;
      const request = factory.open(name, 1);
      request.onupgradeneeded = () => {
        for (const store of ['heads', 'entries', 'pending', 'publications'])
          request.result.createObjectStore(store);
      };
      request.onsuccess = () => {
        if (failed) {
          request.result.close();
          return;
        }
        request.result.onversionchange = () => request.result.close();
        resolve(request.result);
      };
      request.onerror = () => {
        failed = true;
        reject(new Error('Journal database could not be opened'));
      };
      request.onblocked = () => {
        failed = true;
        reject(new Error('Journal database upgrade is blocked'));
      };
    });
  }

  async load(key: string): Promise<DocumentJournalSnapshot> {
    const database = await this.database;
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(
        ['heads', 'entries', 'pending', 'publications'],
        'readonly',
      );
      const request = transaction.objectStore('heads').get(key);
      let head: JournalHead,
        entries: Uint8Array[] = [],
        publications: DocumentJournalPublication[] = [],
        pending: DocumentJournalSnapshot['pending'];
      let failure: unknown;
      const guard = (action: () => void) => {
        try {
          action();
        } catch (error) {
          failure = error;
          transaction.abort();
        }
      };
      request.onsuccess = () =>
        guard(() => {
          head = readHead(request.result);
          head.revisions.forEach((revision, index) => {
            const item = transaction
              .objectStore('entries')
              .get([key, revision]);
            item.onsuccess = () =>
              guard(() => {
                entries[index] = copyUnsharedUint8Array(
                  item.result,
                  1,
                  MAX_DOCUMENT_JOURNAL_BYTES,
                  'stored journal entry',
                );
              });
          });
          head.publications.forEach((publication, index) => {
            const item = transaction
              .objectStore('publications')
              .get([key, publication.id]);
            item.onsuccess = () =>
              guard(() => {
                publications[index] = ownPublication(item.result);
                if (
                  publications[index].frame.length !== publication.bytes ||
                  publicationId(publications[index].id) !== publication.id
                )
                  throw new Error('Publication index mismatch');
              });
          });
          if (head.pending) {
            const item = transaction.objectStore('pending').get(key);
            item.onsuccess = () =>
              guard(() => {
                if (
                  !item.result ||
                  !documentBytesEqual(item.result.token, head.pending!.token)
                )
                  throw new Error('Pending journal index mismatch');
                pending = {
                  token: copyUnsharedUint8Array(
                    item.result.token,
                    32,
                    32,
                    'journal token',
                  ),
                  entry: copyUnsharedUint8Array(
                    item.result.entry,
                    1,
                    MAX_DOCUMENT_JOURNAL_BYTES,
                    'pending entry',
                  ),
                  ...(item.result.publication
                    ? {
                        publication: ownStagedPublication(
                          item.result.publication,
                        ),
                      }
                    : {}),
                };
              });
          }
        });
      transaction.oncomplete = () => {
        if (
          entries.reduce((sum, value) => sum + value.length, 0) !== head.bytes
        ) {
          reject(new Error('Journal byte index mismatch'));
          return;
        }
        resolve({
          revision: head.revision,
          entries,
          publications,
          ...(pending ? { pending } : {}),
        });
      };
      transaction.onabort = transaction.onerror = () =>
        reject(failure ?? new Error('Journal read failed'));
    });
  }

  async loadAcceptedHead(
    key: string,
  ): Promise<{ revision: number; entry?: Uint8Array }> {
    const database = await this.database;
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(
          ['heads', 'entries'],
          'readonly',
        ),
        request = transaction.objectStore('heads').get(key);
      let revision = 0,
        entry: Uint8Array | undefined,
        failure: unknown;
      request.onsuccess = () => {
        try {
          const head = readHead(request.result);
          revision = head.revision;
          if (revision) {
            const item = transaction
              .objectStore('entries')
              .get([key, revision]);
            item.onsuccess = () => {
              try {
                entry = copyUnsharedUint8Array(
                  item.result,
                  1,
                  MAX_DOCUMENT_JOURNAL_BYTES,
                  'accepted journal entry',
                );
              } catch (error) {
                failure = error;
                transaction.abort();
              }
            };
          }
        } catch (error) {
          failure = error;
          transaction.abort();
        }
      };
      transaction.oncomplete = () =>
        resolve({ revision, ...(entry ? { entry } : {}) });
      transaction.onabort = transaction.onerror = () =>
        reject(failure ?? new Error('Journal head read failed'));
    });
  }

  async loadPublications(
    key: string,
  ): Promise<ReadonlyArray<DocumentJournalPublication>> {
    const database = await this.database;
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(
          ['heads', 'publications'],
          'readonly',
        ),
        request = transaction.objectStore('heads').get(key);
      const publications: DocumentJournalPublication[] = [];
      let failure: unknown;
      request.onsuccess = () => {
        try {
          const head = readHead(request.result);
          head.publications.forEach((publication, index) => {
            const item = transaction
              .objectStore('publications')
              .get([key, publication.id]);
            item.onsuccess = () => {
              try {
                const value = ownPublication(item.result);
                if (
                  publicationId(value.id) !== publication.id ||
                  value.frame.length !== publication.bytes
                )
                  throw new Error('Publication index mismatch');
                publications[index] = value;
              } catch (error) {
                failure = error;
                transaction.abort();
              }
            };
          });
        } catch (error) {
          failure = error;
          transaction.abort();
        }
      };
      transaction.oncomplete = () => resolve(publications);
      transaction.onabort = transaction.onerror = () =>
        reject(failure ?? new Error('Publication read failed'));
    });
  }

  stage(
    key: string,
    revision: number,
    token: Uint8Array,
    entry: Uint8Array,
    publication?: DocumentJournalStagedPublication,
    checkpoint = false,
  ): Promise<void> {
    const ownedToken = copyUnsharedUint8Array(token, 32, 32, 'journal token'),
      ownedEntry = copyUnsharedUint8Array(
        entry,
        1,
        MAX_DOCUMENT_JOURNAL_BYTES,
        'journal entry',
      ),
      ownedPublication = publication && ownStagedPublication(publication);
    return this.update(key, ['pending'], (head, transaction) => {
      if (head.revision !== revision || head.pending)
        throw new Error('Journal stage conflict');
      if (
        ownedEntry.length + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD >
        MAX_DOCUMENT_JOURNAL_BYTES
      )
        throw new DocumentJournalCapacityError();
      if (
        (!checkpoint &&
          (head.revisions.length >= MAX_DOCUMENT_JOURNAL_ENTRIES ||
            head.bytes +
              ownedEntry.length +
              DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD >
              MAX_DOCUMENT_JOURNAL_BYTES)) ||
        (ownedPublication &&
          (head.publications.length >= 16 ||
            head.publications.reduce(
              (sum, value) => sum + value.bytes,
              ownedPublication.bytes,
            ) >
              16 * 1024 * 1024))
      )
        throw new DocumentJournalCapacityError();
      transaction.objectStore('pending').put(
        {
          token: ownedToken,
          entry: ownedEntry,
          ...(ownedPublication ? { publication: ownedPublication } : {}),
        },
        key,
      );
      transaction.objectStore('heads').put(
        {
          ...head,
          pending: {
            token: ownedToken,
            bytes: ownedEntry.length,
            checkpoint,
            publicationBytes: ownedPublication?.bytes ?? 0,
          },
        },
        key,
      );
    });
  }

  commit(
    key: string,
    revision: number,
    token: Uint8Array,
    checkpoint: boolean,
    acceptedEntry: Uint8Array,
    acceptedPublication?: DocumentJournalPublication,
  ): Promise<void> {
    const owned = copyUnsharedUint8Array(token, 32, 32, 'journal token');
    const accepted = copyUnsharedUint8Array(
      acceptedEntry,
      1,
      MAX_DOCUMENT_JOURNAL_BYTES,
      'accepted journal entry',
    );
    const publication =
      acceptedPublication && ownPublication(acceptedPublication);
    return this.update(
      key,
      ['pending', 'entries', 'publications'],
      (head, transaction) => {
        if (
          head.revision !== revision ||
          revision === Number.MAX_SAFE_INTEGER ||
          !head.pending ||
          accepted.length !==
            head.pending.bytes + DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD ||
          head.pending.checkpoint !== checkpoint ||
          !documentBytesEqual(head.pending.token, owned)
        )
          throw new Error('Journal commit conflict');
        const request = transaction.objectStore('pending').get(key);
        request.onsuccess = () => {
          try {
            const pending = request.result;
            if (
              !pending ||
              !documentBytesEqual(pending.token, owned) ||
              pending.entry.length !== head.pending!.bytes
            )
              throw new Error('Pending journal changed');
            const reservation =
              pending.publication && ownStagedPublication(pending.publication);
            if (
              !!reservation !== !!publication ||
              (publication?.frame.length ?? 0) !==
                head.pending!.publicationBytes ||
              (reservation &&
                (!publication ||
                  reservation.bytes !== publication.frame.length ||
                  !documentBytesEqual(reservation.id, publication.id)))
            )
              throw new Error('Pending publication changed');
            const next = revision + 1;
            transaction.objectStore('entries').put(accepted, [key, next]);
            if (checkpoint)
              for (const old of head.revisions)
                transaction.objectStore('entries').delete([key, old]);
            if (publication)
              transaction
                .objectStore('publications')
                .put(publication, [key, publicationId(publication.id)]);
            transaction.objectStore('pending').delete(key);
            transaction.objectStore('heads').put(
              {
                revision: next,
                revisions: checkpoint ? [next] : [...head.revisions, next],
                bytes: checkpoint
                  ? accepted.length
                  : head.bytes + accepted.length,
                publications: [
                  ...head.publications,
                  ...(publication
                    ? [
                        {
                          id: publicationId(publication.id),
                          bytes: publication.frame.length,
                        },
                      ]
                    : []),
                ],
              },
              key,
            );
          } catch {
            transaction.abort();
          }
        };
      },
    );
  }

  discard(key: string, token: Uint8Array): Promise<void> {
    const owned = copyUnsharedUint8Array(token, 32, 32, 'journal token');
    return this.update(key, ['pending'], (head, transaction) => {
      if (!head.pending || !documentBytesEqual(head.pending.token, owned))
        return;
      transaction.objectStore('pending').delete(key);
      const { pending: _pending, ...remaining } = head;
      transaction.objectStore('heads').put(remaining, key);
    });
  }

  publicationSent(key: string, id: Uint8Array): Promise<void> {
    const owned = publicationId(
      copyUnsharedUint8Array(id, 32, 32, 'publication id'),
    );
    return this.update(key, ['publications'], (head, transaction) => {
      transaction.objectStore('publications').delete([key, owned]);
      transaction.objectStore('heads').put(
        {
          ...head,
          publications: head.publications.filter((value) => value.id !== owned),
        },
        key,
      );
    });
  }

  async close(): Promise<void> {
    (await this.database).close();
  }

  private async update(
    key: string,
    stores: string[],
    mutate: (head: JournalHead, transaction: IDBTransaction) => void,
  ): Promise<void> {
    const database = await this.database;
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(
          ['heads', ...stores],
          'readwrite',
          { durability: 'strict' },
        ),
        request = transaction.objectStore('heads').get(key);
      let failure: unknown;
      request.onsuccess = () => {
        try {
          mutate(readHead(request.result), transaction);
        } catch (error) {
          failure = error;
          transaction.abort();
        }
      };
      transaction.oncomplete = () => resolve();
      transaction.onabort = transaction.onerror = () =>
        reject(failure ?? new Error('Journal transaction failed'));
    });
  }
}
