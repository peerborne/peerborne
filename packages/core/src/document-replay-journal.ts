import { classifyDocumentJournalRecovery } from './policy/document-journal.js';
import {
  DocumentBinaryReader,
  DocumentBinaryWriter,
  documentBytesEqual,
  documentBytesId,
} from './internal/document-binary.js';
import {
  readDocumentContext,
  writeDocumentContext,
} from './document-security-wire.js';
import type { GroupSecurityDocumentContext } from './group-security-coordinator.js';
import { copyUnsharedUint8Array } from './utils.js';

export class DocumentJournalCapacityError extends Error {
  constructor() {
    super('Document journal capacity exceeded');
    this.name = 'DocumentJournalCapacityError';
  }
}
export interface DocumentJournalAnchor {
  readonly revision: number;
  readonly commitment: Uint8Array;
}
/** Must be stored independently of the journal; losing both defeats rollback detection. */
export interface DocumentJournalRollbackAnchor {
  load(key: string): Promise<DocumentJournalAnchor | undefined>;
  compareAndSwap(
    key: string,
    expected: DocumentJournalAnchor | undefined,
    next: DocumentJournalAnchor,
  ): Promise<boolean>;
}
export interface DocumentJournalPublication {
  readonly id: Uint8Array;
  readonly frame: Uint8Array;
}
export interface DocumentJournalSnapshot {
  readonly revision: number;
  readonly entries: ReadonlyArray<Uint8Array>;
  readonly publications?: ReadonlyArray<DocumentJournalPublication>;
  readonly pending?: {
    readonly token: Uint8Array;
    readonly entry: Uint8Array;
    readonly publication?: DocumentJournalPublication;
  };
}
/** Each mutation is one atomic transaction. A pending entry is never restored as accepted. */
export interface DocumentJournalStore {
  load(key: string): Promise<DocumentJournalSnapshot>;
  loadAcceptedHead?(
    key: string,
  ): Promise<{ readonly revision: number; readonly entry?: Uint8Array }>;
  loadPublications?(
    key: string,
  ): Promise<ReadonlyArray<DocumentJournalPublication>>;
  stage(
    key: string,
    expectedRevision: number,
    token: Uint8Array,
    entry: Uint8Array,
    publication?: DocumentJournalPublication,
    checkpoint?: boolean,
  ): Promise<void>;
  commit(
    key: string,
    expectedRevision: number,
    token: Uint8Array,
    checkpoint: boolean,
  ): Promise<void>;
  discard(key: string, token: Uint8Array): Promise<void>;
  publicationSent?(key: string, id: Uint8Array): Promise<void>;
}
export interface DocumentReplayReceipt {
  readonly memberId: Uint8Array;
  readonly sequence: number;
  readonly hash: Uint8Array;
}
export interface DocumentJournalItem {
  readonly outboundFrame?: Uint8Array;
  readonly checkpoint: boolean;
  readonly context: GroupSecurityDocumentContext;
  readonly changes: Uint8Array;
  readonly receipts: ReadonlyArray<DocumentReplayReceipt>;
  readonly authorityRecords: ReadonlyArray<Uint8Array>;
}
export interface PreparedDocumentJournal {
  commit(): Promise<void>;
  discard(): Promise<void>;
}

const DOMAIN = Uint8Array.from(
  'peerborne/document-replay-journal/v1\0',
  (value) => value.charCodeAt(0),
);
const MAX_SNAPSHOT = 64 * 1024 * 1024,
  MAX_ENTRY = MAX_SNAPSHOT + 17 * 1024 * 1024;
export const MAX_DOCUMENT_JOURNAL_ENTRIES = 128;
export const MAX_DOCUMENT_JOURNAL_BYTES = 128 * 1024 * 1024;
const ZERO = new Uint8Array(32);

function encodeItem(item: DocumentJournalItem): Uint8Array {
  const writer = new DocumentBinaryWriter(MAX_ENTRY);
  writeDocumentContext(writer, item.context);
  writer
    .bytes(item.changes, item.checkpoint ? MAX_SNAPSHOT : 512 * 1024)
    .integer(item.receipts.length, 2);
  if (
    item.receipts.length > 256 ||
    (!item.checkpoint && item.receipts.length !== 1)
  )
    throw new Error('Invalid journal receipts');
  const seen = new Set<string>();
  for (const receipt of item.receipts) {
    const member = copyUnsharedUint8Array(
        receipt.memberId,
        32,
        32,
        'journal member',
      ),
      id = documentBytesId(member);
    if (
      seen.has(id) ||
      !Number.isSafeInteger(receipt.sequence) ||
      receipt.sequence < 1
    )
      throw new Error('Invalid journal sequence');
    seen.add(id);
    writer
      .fixed(member)
      .integer(receipt.sequence, 8)
      .fixed(
        copyUnsharedUint8Array(receipt.hash, 32, 32, 'journal content hash'),
      );
  }
  if (
    !Array.isArray(item.authorityRecords) ||
    item.authorityRecords.length > 1024
  )
    throw new Error('Invalid journal authority history');
  writer.integer(item.authorityRecords.length, 2);
  let bytes = 0;
  for (const record of item.authorityRecords) {
    bytes += record.length;
    if (bytes > 16 * 1024 * 1024)
      throw new Error('Journal authority history exceeds bounds');
    writer.bytes(record, 1024 * 1024);
  }
  return writer.finish();
}

function decodeItem(
  bytes: Uint8Array,
  checkpoint: boolean,
): DocumentJournalItem {
  const reader = new DocumentBinaryReader(bytes, MAX_ENTRY),
    context = readDocumentContext(reader),
    changes = reader.bytes(checkpoint ? MAX_SNAPSHOT : 512 * 1024),
    count = reader.number(2);
  if (count > 256 || (!checkpoint && count !== 1))
    throw new Error('Invalid journal receipts');
  const receipts: DocumentReplayReceipt[] = [],
    seen = new Set<string>();
  for (let index = 0; index < count; index++) {
    const memberId = reader.fixed(32),
      sequence = reader.number(8),
      hash = reader.fixed(32),
      id = documentBytesId(memberId);
    if (!sequence || seen.has(id)) throw new Error('Invalid journal receipt');
    seen.add(id);
    receipts.push({ memberId, sequence, hash });
  }
  const authorityCount = reader.number(2),
    authorityRecords: Uint8Array[] = [];
  if (authorityCount > 1024)
    throw new Error('Invalid journal authority history');
  let total = 0;
  for (let index = 0; index < authorityCount; index++) {
    const record = reader.bytes(1024 * 1024);
    total += record.length;
    if (total > 16 * 1024 * 1024)
      throw new Error('Journal authority history exceeds bounds');
    authorityRecords.push(record);
  }
  reader.end();
  return { checkpoint, context, changes, receipts, authorityRecords };
}

function captureJournalSnapshot(
  value: DocumentJournalSnapshot,
): DocumentJournalSnapshot {
  const revision = value.revision,
    source = value.entries;
  const count = Array.isArray(source)
    ? Object.getOwnPropertyDescriptor(source, 'length')?.value
    : undefined;
  if (
    !Number.isSafeInteger(revision) ||
    revision < 0 ||
    !Array.isArray(source) ||
    !Number.isSafeInteger(count) ||
    count < 0 ||
    count > MAX_DOCUMENT_JOURNAL_ENTRIES
  )
    throw new Error('Invalid journal snapshot');
  let bytes = 0;
  const entries: Uint8Array[] = [];
  for (let index = 0; index < count; index++) {
    const field = Object.getOwnPropertyDescriptor(source, index);
    if (!field || !('value' in field))
      throw new Error('Invalid journal entry ownership');
    const entry = copyUnsharedUint8Array(
      field.value,
      1,
      Math.min(MAX_ENTRY + 128, MAX_DOCUMENT_JOURNAL_BYTES - bytes),
      'journal entry',
    );
    bytes += entry.length;
    entries.push(entry);
  }
  const token = value.pending?.token;
  return {
    revision,
    entries,
    ...(token
      ? {
          pending: {
            token: copyUnsharedUint8Array(
              token,
              32,
              32,
              'pending journal token',
            ),
            entry: new Uint8Array(),
          },
        }
      : {}),
  };
}

function copyAnchor(
  value: DocumentJournalAnchor | undefined,
): DocumentJournalAnchor | undefined {
  if (!value) return undefined;
  if (!Number.isSafeInteger(value.revision) || value.revision < 1)
    throw new Error('Invalid document journal anchor');
  return {
    revision: value.revision,
    commitment: copyUnsharedUint8Array(
      value.commitment,
      32,
      32,
      'journal anchor',
    ),
  };
}
export function documentJournalAnchorsEqual(
  a: DocumentJournalAnchor | undefined,
  b: DocumentJournalAnchor | undefined,
): boolean {
  return a === undefined
    ? b === undefined
    : b !== undefined &&
        a.revision === b.revision &&
        documentBytesEqual(a.commitment, b.commitment);
}
const digest = async (value: Uint8Array) =>
  new Uint8Array(
    await crypto.subtle.digest('SHA-256', value as Uint8Array<ArrayBuffer>),
  );

/** Device-key encrypted WAL with accepted markers, periodic checkpoints and an independent rollback anchor. */
export class DocumentReplayJournal {
  private readonly storageKey: string;
  private readonly genesis: Uint8Array;
  private head?: DocumentJournalAnchor;
  private entryCount = 0;
  private retainedBytes = 0;
  private opened = false;
  private active = false;
  private failed = false;

  constructor(
    private readonly documentId: string,
    genesis: Uint8Array,
    private readonly key: CryptoKey,
    private readonly store: DocumentJournalStore,
    private readonly anchor: DocumentJournalRollbackAnchor,
  ) {
    this.genesis = copyUnsharedUint8Array(genesis, 32, 32, 'journal genesis');
    this.storageKey = documentBytesId(this.genesis);
    if (
      key.type !== 'secret' ||
      key.algorithm.name !== 'AES-GCM' ||
      key.extractable ||
      !key.usages.includes('encrypt') ||
      !key.usages.includes('decrypt')
    )
      throw new Error('Journal requires a nonextractable AES-GCM device key');
  }

  assertBinding(documentId: string, genesis: Uint8Array): void {
    if (
      this.documentId !== documentId ||
      !documentBytesEqual(genesis, this.genesis)
    )
      throw new Error('Document journal binding mismatch');
  }

  get needsCheckpoint(): boolean {
    return (
      this.entryCount >= MAX_DOCUMENT_JOURNAL_ENTRIES - 1 ||
      this.retainedBytes > MAX_DOCUMENT_JOURNAL_BYTES - 18 * 1024 * 1024
    );
  }
  get revision(): number {
    return this.head?.revision ?? 0;
  }

  async restore(): Promise<ReadonlyArray<DocumentJournalItem>> {
    if (this.failed || this.active)
      throw new Error('Document journal is unavailable');
    this.active = true;
    try {
      const snapshot = captureJournalSnapshot(
        await this.store.load(this.storageKey),
      );
      const anchored = copyAnchor(await this.anchor.load(this.storageKey));
      let bytes = 0,
        previous: Uint8Array | undefined,
        previousRevision = 0;
      const items: DocumentJournalItem[] = [];
      let last:
        | { revision: number; commitment: Uint8Array; parent: Uint8Array }
        | undefined;
      for (const raw of snapshot.entries) {
        const owned = copyUnsharedUint8Array(
          raw,
          1,
          Math.min(MAX_ENTRY + 128, MAX_DOCUMENT_JOURNAL_BYTES - bytes),
          'journal entry',
        );
        bytes += owned.length;
        const reader = new DocumentBinaryReader(owned, MAX_ENTRY + 128),
          revision = reader.number(8),
          marker = reader.number(1),
          parent = reader.fixed(32),
          nonce = reader.fixed(12),
          ciphertext = reader.bytes(MAX_ENTRY + 16);
        reader.end();
        if (
          !revision ||
          marker > 1 ||
          (previous &&
            (!documentBytesEqual(previous, parent) ||
              revision !== previousRevision + 1)) ||
          (!previous &&
            marker === 0 &&
            (revision !== 1 || !documentBytesEqual(parent, ZERO)))
        )
          throw new Error('Journal causal chain is invalid');
        const aad = this.aad(revision, marker === 1, parent);
        const plaintext = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: nonce as Uint8Array<ArrayBuffer>,
            additionalData: aad as Uint8Array<ArrayBuffer>,
          },
          this.key,
          ciphertext as Uint8Array<ArrayBuffer>,
        );
        const item = decodeItem(new Uint8Array(plaintext), marker === 1);
        if (previous && item.checkpoint)
          throw new Error('Noninitial journal checkpoint');
        items.push(item);
        previous = await digest(owned);
        previousRevision = revision;
        last = { revision, commitment: previous, parent };
      }
      if ((last?.revision ?? 0) !== snapshot.revision || (!last && anchored))
        throw new Error('Journal rollback or eviction detected');
      const stored = last && {
        revision: last.revision,
        commitment: last.commitment,
      };
      const recovery = classifyDocumentJournalRecovery(
        snapshot.revision,
        anchored?.revision ?? 0,
        documentJournalAnchorsEqual(anchored, stored),
        !!last && documentBytesEqual(last.parent, anchored?.commitment ?? ZERO),
      );
      if (recovery === 'reject')
        throw new Error('Journal rollback or substitution detected');
      if (recovery === 'finish-anchor') {
        if (
          !(await this.anchor.compareAndSwap(
            this.storageKey,
            copyAnchor(anchored),
            copyAnchor(stored)!,
          )) ||
          !documentJournalAnchorsEqual(
            stored,
            copyAnchor(await this.anchor.load(this.storageKey)),
          )
        )
          throw new Error('Journal anchor conflict');
      }
      if (snapshot.pending)
        await this.store.discard(
          this.storageKey,
          copyUnsharedUint8Array(
            snapshot.pending.token,
            32,
            32,
            'journal pending token',
          ),
        );
      this.head = stored;
      this.entryCount = items.length;
      this.retainedBytes = bytes;
      this.opened = true;
      return items;
    } catch (error) {
      this.failed = true;
      throw error;
    } finally {
      this.active = false;
    }
  }

  async prepare(item: DocumentJournalItem): Promise<PreparedDocumentJournal> {
    const checkpoint = item.checkpoint;
    const outboundFrame =
      item.outboundFrame === undefined
        ? undefined
        : copyUnsharedUint8Array(
            item.outboundFrame,
            1,
            1024 * 1024,
            'outbound document frame',
          );
    if (
      !this.opened ||
      this.failed ||
      this.active ||
      this.revision === Number.MAX_SAFE_INTEGER ||
      (this.needsCheckpoint && !checkpoint)
    )
      throw new Error('Document journal is unavailable or needs compaction');
    if (typeof checkpoint !== 'boolean')
      throw new Error('Invalid journal checkpoint flag');
    this.active = true;
    const expected = copyAnchor(this.head),
      revision = this.revision + 1,
      token = crypto.getRandomValues(new Uint8Array(32));
    let done = false;
    try {
      const plaintext = encodeItem(item);
      if (
        !documentJournalAnchorsEqual(
          expected,
          copyAnchor(await this.anchor.load(this.storageKey)),
        )
      )
        throw new Error('Document journal anchor changed');
      const parent = expected?.commitment ?? ZERO,
        nonce = crypto.getRandomValues(new Uint8Array(12)),
        aad = this.aad(revision, checkpoint, parent);
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: aad as Uint8Array<ArrayBuffer>,
          },
          this.key,
          plaintext as Uint8Array<ArrayBuffer>,
        ),
      );
      const entry = new DocumentBinaryWriter(MAX_ENTRY + 128)
        .integer(revision, 8)
        .integer(checkpoint ? 1 : 0, 1)
        .fixed(parent)
        .fixed(nonce)
        .bytes(ciphertext, MAX_ENTRY + 16)
        .finish();
      const commitment = await digest(entry);
      const publication =
        outboundFrame === undefined
          ? undefined
          : { frame: outboundFrame, id: new Uint8Array() as Uint8Array };
      if (publication) {
        if (typeof this.store.publicationSent !== 'function')
          throw new Error('Journal store lacks publication support');
        publication.id = await digest(publication.frame);
      }
      await this.store.stage(
        this.storageKey,
        expected?.revision ?? 0,
        token.slice(),
        entry.slice(),
        publication && {
          id: publication.id.slice(),
          frame: publication.frame.slice(),
        },
        checkpoint,
      );
      return {
        commit: async () => {
          if (done)
            throw new Error('Journal preparation has already completed');
          done = true;
          try {
            await this.store.commit(
              this.storageKey,
              expected?.revision ?? 0,
              token.slice(),
              checkpoint,
            );
            const actual = this.store.loadAcceptedHead
              ? await this.store.loadAcceptedHead(this.storageKey)
              : await this.store.load(this.storageKey).then((value) => ({
                  revision: value.revision,
                  entry: value.entries.at(-1),
                }));
            if (
              actual.revision !== revision ||
              !actual.entry ||
              !documentBytesEqual(
                await digest(
                  copyUnsharedUint8Array(
                    actual.entry,
                    1,
                    MAX_ENTRY + 128,
                    'accepted journal entry',
                  ),
                ),
                commitment,
              )
            )
              throw new Error('Journal accepted marker was not persisted');
            const next = { revision, commitment };
            if (
              !(await this.anchor.compareAndSwap(
                this.storageKey,
                copyAnchor(expected),
                copyAnchor(next)!,
              ))
            )
              throw new Error('Document journal anchor conflict');
            if (
              !documentJournalAnchorsEqual(
                next,
                copyAnchor(await this.anchor.load(this.storageKey)),
              )
            )
              throw new Error('Document journal anchor was not persisted');
            this.head = next;
            this.entryCount = checkpoint ? 1 : this.entryCount + 1;
            this.retainedBytes = checkpoint
              ? entry.length
              : this.retainedBytes + entry.length;
          } catch (error) {
            this.failed = true;
            throw error;
          } finally {
            this.active = false;
          }
        },
        discard: async () => {
          if (done) return;
          done = true;
          try {
            await this.store.discard(this.storageKey, token.slice());
          } catch (error) {
            this.failed = true;
            throw error;
          } finally {
            this.active = false;
          }
        },
      };
    } catch (error) {
      if (!(error instanceof DocumentJournalCapacityError)) this.failed = true;
      this.active = false;
      throw error;
    }
  }

  async pendingPublications(): Promise<ReadonlyArray<Uint8Array>> {
    const publications = this.store.loadPublications
      ? await this.store.loadPublications(this.storageKey)
      : (await this.store.load(this.storageKey)).publications;
    if (!Array.isArray(publications) || publications.length > 16) {
      if (publications === undefined) return [];
      throw new Error('Invalid document publication queue');
    }
    let bytes = 0;
    return publications.map((value) => {
      const frame = copyUnsharedUint8Array(
        value.frame,
        1,
        Math.min(1024 * 1024, 16 * 1024 * 1024 - bytes),
        'outbound document frame',
      );
      bytes += frame.length;
      return frame;
    });
  }

  async publicationSent(frame: Uint8Array): Promise<void> {
    if (!this.store.publicationSent)
      throw new Error('Journal store lacks publication support');
    await this.store.publicationSent(this.storageKey, await digest(frame));
  }

  private aad(
    revision: number,
    checkpoint: boolean,
    parent: Uint8Array,
  ): Uint8Array {
    return new DocumentBinaryWriter()
      .fixed(DOMAIN)
      .text(this.documentId)
      .fixed(this.genesis)
      .integer(revision, 8)
      .integer(checkpoint ? 1 : 0, 1)
      .fixed(parent)
      .finish();
  }
}

/** Test/reference anchor. Persistence and independent storage are application responsibilities. */
export class InMemoryDocumentJournalRollbackAnchor
  implements DocumentJournalRollbackAnchor
{
  private readonly values = new Map<string, DocumentJournalAnchor>();
  async load(key: string): Promise<DocumentJournalAnchor | undefined> {
    return copyAnchor(this.values.get(key));
  }
  async compareAndSwap(
    key: string,
    expected: DocumentJournalAnchor | undefined,
    next: DocumentJournalAnchor,
  ): Promise<boolean> {
    if (!documentJournalAnchorsEqual(this.values.get(key), expected))
      return false;
    this.values.set(key, copyAnchor(next)!);
    return true;
  }
}
