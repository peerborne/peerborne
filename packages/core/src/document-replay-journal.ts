import {
  classifyDocumentJournalRecovery,
  canExposeDocumentJournalRecovery,
  canRecordDocumentPublicationBinding,
  recordDocumentPublicationBinding,
  canRetainDocumentPublicationBindings,
  retainDocumentPublicationBindings,
  selectDocumentPublicationBindings,
  isAcceptedDocumentPublicationToken,
} from './policy/document-journal.js';
import {
  DocumentBinaryReader,
  DocumentBinaryWriter,
  documentBytesEqual,
  documentBytesId,
} from './internal/document-binary.js';
import {
  documentContextsMatch,
  readDocumentContext,
  writeDocumentContext,
} from './document-security-wire.js';
import type { GroupSecurityDocumentContext } from './group-security-coordinator.js';
import {
  copyRecordedOperationPaths,
  MAX_RECORDED_OPERATION_PATHS,
  type DocumentWritePaths,
} from './document-field-authorization.js';
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
export interface DocumentJournalStagedPublication {
  readonly id: Uint8Array;
  readonly bytes: number;
  /** A queued publication the accepted one replaces in the same commit. */
  readonly replaces?: Uint8Array;
}
export interface DocumentJournalRecoverySnapshot {
  readonly revision: number;
  readonly entries: ReadonlyArray<Uint8Array>;
  readonly pending?: { readonly token: Uint8Array };
}
export interface DocumentJournalSnapshot extends DocumentJournalRecoverySnapshot {
  readonly publications?: ReadonlyArray<DocumentJournalPublication>;
  readonly pending?: {
    readonly token: Uint8Array;
    readonly entry: Uint8Array;
    readonly publication?: DocumentJournalStagedPublication;
  };
}
/** Each mutation is one atomic transaction. A pending entry is never restored as accepted. */
export interface DocumentJournalStore {
  load(key: string): Promise<DocumentJournalSnapshot>;
  /** Accepted entries and a discardable pending token; pending/outbox bodies are not read. */
  loadRecoverySnapshot?(key: string): Promise<DocumentJournalRecoverySnapshot>;
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
    publication?: DocumentJournalStagedPublication,
    checkpoint?: boolean,
  ): Promise<void>;
  commit(
    key: string,
    expectedRevision: number,
    token: Uint8Array,
    checkpoint: boolean,
    acceptedEntry: Uint8Array,
    acceptedPublication?: DocumentJournalPublication,
  ): Promise<void>;
  discard(key: string, token: Uint8Array): Promise<void>;
  publicationSent?(key: string, id: Uint8Array): Promise<void>;
  /** Remove every record stored under `key`. */
  delete?(key: string): Promise<void>;
  /** Replace the unsent publication `id` in its queue position. */
  replacePublication?(
    key: string,
    id: Uint8Array,
    publication: DocumentJournalPublication,
  ): Promise<void>;
}
export interface DocumentReplayReceipt {
  readonly memberId: Uint8Array;
  readonly sequence: number;
  readonly hash: Uint8Array;
}
export interface DocumentJournalItem {
  /** Published frame of a local entry; on restore, present while it is still unsent. */
  readonly outboundFrame?: Uint8Array;
  readonly checkpoint: boolean;
  readonly context: GroupSecurityDocumentContext;
  readonly changes: Uint8Array;
  readonly receipts: ReadonlyArray<DocumentReplayReceipt>;
  readonly authorityHead: Uint8Array;
  readonly authorityRecords: ReadonlyArray<Uint8Array>;
  /**
   * Required on every non-checkpoint entry and absent on checkpoints: the
   * bounded operation paths of a local entry's changes, `[]` for a peer's.
   */
  readonly operationPaths?: DocumentWritePaths;
  /**
   * The nonce of a local entry's encrypted frame, which identifies the frame
   * inside a coalesced publication. Absent on checkpoints and peers' entries.
   */
  readonly frameNonce?: Uint8Array;
  /** Only on checkpoints: the unsent local frames whose entries they fold. */
  readonly carriedFrames?: ReadonlyArray<DocumentJournalCarriedFrame>;
  /**
   * A queued publication that `outboundFrame` replaces when the entry is
   * accepted. It is not stored with the entry.
   */
  readonly replacesPublication?: Uint8Array;
}
/** An unsent local frame a checkpoint keeps re-signable after folding its entry. */
export interface DocumentJournalCarriedFrame {
  readonly context: GroupSecurityDocumentContext;
  readonly sequence: number;
  readonly nonce: Uint8Array;
  readonly changes: Uint8Array;
  readonly operationPaths: DocumentWritePaths;
}
export interface PreparedDocumentJournal {
  commit(): Promise<void>;
  discard(): Promise<void>;
}

const DOMAIN = Uint8Array.from(
  'peerborne/document-replay-journal/v1\0',
  (value) => value.charCodeAt(0),
);
/** Frames a checkpoint carries: a full outbox of 16 publications of 1,024 frames, and its own. */
export const MAX_DOCUMENT_JOURNAL_CARRIED_FRAMES = 16 * 1024 + 1;
/**
 * Encoded bound of carried frames: an outbox of changes and the frame being
 * written, twice the 4 MiB of unsent paths for a re-sign in progress, and
 * framing.
 */
const MAX_CARRIED_BYTES = 26 * 1024 * 1024;
const MAX_SNAPSHOT = 64 * 1024 * 1024,
  MAX_ENTRY = MAX_SNAPSHOT + 17 * 1024 * 1024 + MAX_CARRIED_BYTES;
export const DOCUMENT_JOURNAL_ACCEPTED_OVERHEAD = 32;
export const DOCUMENT_PUBLICATION_OVERHEAD = 72;
export const MAX_DOCUMENT_STORED_PUBLICATION_BYTES =
  1024 * 1024 + DOCUMENT_PUBLICATION_OVERHEAD;
const PUBLICATION_DOMAIN = Uint8Array.from(
  'peerborne/document-journal-publication/v1\0',
  (value) => value.charCodeAt(0),
);
const ACCEPTED_DOMAIN = Uint8Array.from(
  'peerborne/document-journal-accepted/v1\0',
  (value) => value.charCodeAt(0),
);
export const MAX_DOCUMENT_JOURNAL_ENTRIES = 128;
export const MAX_DOCUMENT_JOURNAL_BYTES = 128 * 1024 * 1024;
const ZERO = new Uint8Array(32);
const ENTRY = 0,
  CHECKPOINT = 1,
  DIVERGED = 2;
/** Encoded bound of a full recorded path list: 4,096 paths of 32 segments and 1 Mi units. */
const MAX_OPERATION_PATH_BYTES = 4 * 1024 * 1024;

interface PublicationBinding {
  readonly token: Uint8Array;
  readonly revision: number;
}
interface StoredDocumentJournalItem extends DocumentJournalItem {
  readonly publicationBindings: ReadonlyArray<PublicationBinding>;
}

function encodeItem(
  item: DocumentJournalItem,
  bindings: ReadonlyArray<PublicationBinding> = [],
): Uint8Array {
  const writer = new DocumentBinaryWriter(MAX_ENTRY);
  writeDocumentContext(writer, item.context);
  writer.fixed(
    copyUnsharedUint8Array(
      item.authorityHead,
      32,
      32,
      'journal authority head',
    ),
  );
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
  if (bindings.length > 16) throw new DocumentJournalCapacityError();
  writer.integer(bindings.length, 1);
  for (const binding of bindings) {
    if (!Number.isSafeInteger(binding.revision) || binding.revision < 1)
      throw new Error('Invalid publication binding');
    writer
      .fixed(
        copyUnsharedUint8Array(binding.token, 32, 32, 'publication binding'),
      )
      .integer(binding.revision, 8);
  }
  if (item.checkpoint) {
    if (item.operationPaths !== undefined || item.frameNonce !== undefined)
      throw new Error('Journal checkpoints carry no operation paths');
    const carried = item.carriedFrames ?? [];
    if (
      !Array.isArray(carried) ||
      carried.length > MAX_DOCUMENT_JOURNAL_CARRIED_FRAMES
    )
      throw new Error('Invalid journal carried frames');
    writer.integer(carried.length, 2);
    let previous: GroupSecurityDocumentContext | undefined,
      total = 0;
    for (const frame of carried) {
      if (!Number.isSafeInteger(frame.sequence) || frame.sequence < 1)
        throw new Error('Invalid journal carried frames');
      const same =
        previous !== undefined &&
        documentContextsMatch(previous, frame.context);
      const part = new DocumentBinaryWriter(MAX_CARRIED_BYTES).integer(
        same ? 1 : 0,
        1,
      );
      if (!same) writeDocumentContext(part, frame.context);
      previous = frame.context;
      part
        .integer(frame.sequence, 8)
        .fixed(copyUnsharedUint8Array(frame.nonce, 12, 12, 'frame nonce'))
        .bytes(frame.changes, 512 * 1024);
      writePaths(part, frame.operationPaths);
      const bytes = part.finish();
      total += bytes.length;
      if (total > MAX_CARRIED_BYTES) throw new DocumentJournalCapacityError();
      writer.fixed(bytes);
    }
  } else {
    if (item.carriedFrames !== undefined)
      throw new Error('Only journal checkpoints carry frames');
    writePaths(writer, item.operationPaths);
    writer.integer(item.frameNonce === undefined ? 0 : 1, 1);
    if (item.frameNonce !== undefined)
      writer.fixed(
        copyUnsharedUint8Array(item.frameNonce, 12, 12, 'frame nonce'),
      );
  }
  return writer.finish();
}

function writePaths(writer: DocumentBinaryWriter, value: unknown): void {
  const paths = copyRecordedOperationPaths(value);
  writer.integer(paths.length, 2);
  for (const path of paths) {
    writer.integer(path.length, 1);
    for (const segment of path) writer.text(segment, 4096);
  }
}

function readPaths(reader: DocumentBinaryReader): DocumentWritePaths {
  const pathCount = reader.number(2);
  if (pathCount > MAX_RECORDED_OPERATION_PATHS)
    throw new Error('Invalid journal operation paths');
  const paths: string[][] = [];
  for (let index = 0; index < pathCount; index++) {
    const depth = reader.number(1);
    if (depth > 32) throw new Error('Invalid journal operation paths');
    const path: string[] = [];
    for (let segment = 0; segment < depth; segment++)
      path.push(reader.text(4096));
    paths.push(path);
  }
  return copyRecordedOperationPaths(paths);
}

function decodeItem(
  bytes: Uint8Array,
  checkpoint: boolean,
): StoredDocumentJournalItem {
  const reader = new DocumentBinaryReader(bytes, MAX_ENTRY),
    context = readDocumentContext(reader),
    authorityHead = reader.fixed(32),
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
  const bindingCount = reader.number(1),
    publicationBindings: PublicationBinding[] = [];
  if (bindingCount > 16 || (!checkpoint && bindingCount > 1))
    throw new Error('Invalid publication bindings');
  for (let index = 0; index < bindingCount; index++)
    publicationBindings.push({
      token: reader.fixed(32),
      revision: reader.number(8),
    });
  let operationPaths: DocumentWritePaths | undefined,
    frameNonce: Uint8Array | undefined,
    carriedFrames: DocumentJournalCarriedFrame[] | undefined;
  if (!checkpoint) {
    operationPaths = readPaths(reader);
    const flag = reader.number(1);
    if (flag > 1) throw new Error('Invalid journal frame nonce');
    if (flag === 1) frameNonce = reader.fixed(12);
  } else {
    const carried = reader.number(2);
    if (carried > MAX_DOCUMENT_JOURNAL_CARRIED_FRAMES)
      throw new Error('Invalid journal carried frames');
    carriedFrames = [];
    let previous: GroupSecurityDocumentContext | undefined;
    for (let index = 0; index < carried; index++) {
      const same = reader.number(1);
      if (same > 1 || (same === 1 && previous === undefined))
        throw new Error('Invalid journal carried frames');
      const frameContext: GroupSecurityDocumentContext =
        same === 1 ? previous! : readDocumentContext(reader);
      if (
        same === 0 &&
        previous !== undefined &&
        documentContextsMatch(previous, frameContext)
      )
        throw new Error('Invalid journal carried frames');
      previous = frameContext;
      const sequence = reader.number(8);
      if (!sequence) throw new Error('Invalid journal carried frames');
      carriedFrames.push({
        context: frameContext,
        sequence,
        nonce: reader.fixed(12),
        changes: reader.bytes(512 * 1024),
        operationPaths: readPaths(reader),
      });
    }
  }
  reader.end();
  return {
    publicationBindings,
    checkpoint,
    context,
    changes,
    receipts,
    authorityHead,
    authorityRecords,
    ...(operationPaths ? { operationPaths } : {}),
    ...(frameNonce ? { frameNonce } : {}),
    ...(carriedFrames?.length ? { carriedFrames } : {}),
  };
}

function captureJournalSnapshot(
  value: DocumentJournalRecoverySnapshot,
): DocumentJournalRecoverySnapshot {
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
  private divergedMarker = false;
  private acceptedPublicationBindings = new Map<string, number>();
  private pendingPublicationBindings = new Map<string, PublicationBinding>();

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
      this.retainedBytes >
        MAX_DOCUMENT_JOURNAL_BYTES - 18 * 1024 * 1024 - MAX_OPERATION_PATH_BYTES
    );
  }
  get revision(): number {
    return this.head?.revision ?? 0;
  }
  /** The accepted branch ends in an authenticated divergence marker; it takes no more entries. */
  get diverged(): boolean {
    return this.divergedMarker;
  }

  async restore(): Promise<ReadonlyArray<DocumentJournalItem>> {
    if (this.failed || this.active)
      throw new Error('Document journal is unavailable');
    this.active = true;
    try {
      const loadRecovery = this.store.loadRecoverySnapshot;
      const snapshot = captureJournalSnapshot(
        loadRecovery === undefined
          ? await this.store.load(this.storageKey)
          : await Reflect.apply(loadRecovery, this.store, [this.storageKey]),
      );
      const anchored = copyAnchor(await this.anchor.load(this.storageKey));
      let bytes = 0,
        previous: Uint8Array | undefined,
        previousRevision = 0,
        authenticated = true;
      const items: StoredDocumentJournalItem[] = [],
        itemRevisions: number[] = [];
      let acceptedBindings = new Map<string, number>();
      let last:
        | { revision: number; commitment: Uint8Array; parent: Uint8Array }
        | undefined;
      let diverged = false;
      for (const owned of snapshot.entries) {
        if (diverged)
          throw new Error('Journal entry follows a divergence marker');
        bytes += owned.length;
        const accepted = new DocumentBinaryReader(owned, MAX_ENTRY + 128);
        const payload = accepted.bytes(MAX_ENTRY + 96),
          acceptance = accepted.fixed(28);
        accepted.end();
        const reader = new DocumentBinaryReader(payload, MAX_ENTRY + 128),
          revision = reader.number(8),
          marker = reader.number(1),
          parent = reader.fixed(32),
          nonce = reader.fixed(12),
          ciphertext = reader.bytes(MAX_ENTRY + 16);
        reader.end();
        if (
          !revision ||
          marker > DIVERGED ||
          (previous &&
            (!documentBytesEqual(previous, parent) ||
              revision !== previousRevision + 1)) ||
          (!previous &&
            marker !== CHECKPOINT &&
            (revision !== 1 || !documentBytesEqual(parent, ZERO)))
        )
          throw new Error('Journal causal chain is invalid');
        const acceptedMarker = await this.verifyAcceptedMarker(
          revision,
          payload,
          acceptance,
        );
        authenticated = authenticated && acceptedMarker;
        if (!acceptedMarker)
          throw new Error(
            'Journal entry has no authenticated acceptance marker',
          );
        const aad = this.aad(revision, marker, parent);
        const plaintext = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: nonce as Uint8Array<ArrayBuffer>,
            additionalData: aad as Uint8Array<ArrayBuffer>,
          },
          this.key,
          ciphertext as Uint8Array<ArrayBuffer>,
        );
        if (marker === DIVERGED) {
          if (plaintext.byteLength !== 0)
            throw new Error('Invalid journal divergence marker');
          diverged = true;
          previous = await digest(owned);
          previousRevision = revision;
          last = { revision, commitment: previous, parent };
          continue;
        }
        const item = decodeItem(
          new Uint8Array(plaintext),
          marker === CHECKPOINT,
        );
        if (previous && item.checkpoint)
          throw new Error('Noninitial journal checkpoint');
        for (const binding of item.publicationBindings) {
          const token = documentBytesId(binding.token);
          if (
            !canRecordDocumentPublicationBinding(
              acceptedBindings,
              token,
              binding.revision,
              revision,
              item.checkpoint,
              MAX_DOCUMENT_JOURNAL_ENTRIES + 16,
            )
          )
            throw new Error('Invalid accepted publication binding');
          acceptedBindings = recordDocumentPublicationBinding(
            acceptedBindings,
            token,
            binding.revision,
            MAX_DOCUMENT_JOURNAL_ENTRIES + 16,
          );
        }
        items.push(item);
        itemRevisions.push(revision);
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
        authenticated,
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
      const publications = await this.readPublications(
        acceptedBindings,
        stored?.revision ?? 0,
      );
      const finalAnchor = copyAnchor(await this.anchor.load(this.storageKey));
      if (
        !canExposeDocumentJournalRecovery(
          recovery,
          documentJournalAnchorsEqual(stored, finalAnchor),
        )
      )
        throw new Error('Journal anchor changed during recovery');
      for (const [index, frame] of publications.frames.entries()) {
        const entry = itemRevisions.indexOf(publications.revisions[index]);
        if (entry !== -1 && !items[entry].checkpoint)
          items[entry] = { ...items[entry], outboundFrame: frame };
      }
      this.acceptedPublicationBindings = acceptedBindings;
      this.pendingPublicationBindings = publications.bindings;
      this.head = stored;
      this.entryCount = snapshot.entries.length;
      this.retainedBytes = bytes;
      this.divergedMarker = diverged;
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
    const replaced =
      item.replacesPublication === undefined
        ? undefined
        : await digest(
            copyUnsharedUint8Array(
              item.replacesPublication,
              1,
              1024 * 1024,
              'replaced document frame',
            ),
          );
    const replacedBinding =
      replaced && this.pendingPublicationBindings.get(documentBytesId(replaced));
    if (replaced && (!outboundFrame || !replacedBinding))
      throw new Error('Replaced document publication is not queued');
    if (
      !this.opened ||
      this.failed ||
      this.active ||
      this.divergedMarker ||
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
    const beforeBindings = this.acceptedPublicationBindings;
    let candidateBindings = beforeBindings;
    let done = false;
    try {
      const binding: PublicationBinding | undefined =
        outboundFrame === undefined
          ? undefined
          : { token: crypto.getRandomValues(new Uint8Array(32)), revision };
      const kept = [...this.pendingPublicationBindings.values()].filter(
        (value) => value !== replacedBinding,
      );
      const bindings = checkpoint
        ? [...kept, ...(binding ? [binding] : [])]
        : binding
          ? [binding]
          : [];
      if (checkpoint) {
        const pending = kept.map((value) => documentBytesId(value.token));
        if (!canRetainDocumentPublicationBindings(beforeBindings, pending, 16))
          throw new Error('Invalid pending publication bindings');
        candidateBindings = retainDocumentPublicationBindings(
          beforeBindings,
          pending,
          16,
        );
      }
      if (binding) {
        const bindingId = documentBytesId(binding.token);
        if (
          beforeBindings.has(bindingId) ||
          !canRecordDocumentPublicationBinding(
            candidateBindings,
            bindingId,
            revision,
            revision,
            false,
            MAX_DOCUMENT_JOURNAL_ENTRIES + 16,
          )
        )
          throw new Error('Invalid new publication binding');
        candidateBindings = recordDocumentPublicationBinding(
          candidateBindings,
          bindingId,
          revision,
          MAX_DOCUMENT_JOURNAL_ENTRIES + 16,
        );
      }
      const plaintext = encodeItem(item, bindings);
      const entry = await this.sealEntry(
        expected,
        revision,
        checkpoint ? CHECKPOINT : ENTRY,
        plaintext,
      );
      const publication =
        outboundFrame === undefined
          ? undefined
          : {
              bytes: outboundFrame.length + DOCUMENT_PUBLICATION_OVERHEAD,
              id: new Uint8Array() as Uint8Array,
            };
      if (publication) {
        if (typeof this.store.publicationSent !== 'function')
          throw new Error('Journal store lacks publication support');
        publication.id = await digest(outboundFrame!);
      }
      await this.store.stage(
        this.storageKey,
        expected?.revision ?? 0,
        token.slice(),
        entry.slice(),
        publication && {
          id: publication.id.slice(),
          bytes: publication.bytes,
          ...(replaced ? { replaces: replaced.slice() } : {}),
        },
        checkpoint,
      );
      return {
        commit: async () => {
          if (done)
            throw new Error('Journal preparation has already completed');
          done = true;
          try {
            const { next, bytes } = await this.acceptStaged(
              expected,
              revision,
              token,
              checkpoint,
              entry,
              publication &&
                (async () => ({
                  id: publication.id.slice(),
                  frame: await this.sealPublication(
                    revision,
                    publication.id,
                    binding!.token,
                    outboundFrame!,
                  ),
                })),
            );
            this.acceptedPublicationBindings =
              selectDocumentPublicationBindings(
                beforeBindings,
                candidateBindings,
                true,
              );
            if (replaced)
              this.pendingPublicationBindings.delete(documentBytesId(replaced));
            if (publication && binding)
              this.pendingPublicationBindings.set(
                documentBytesId(publication.id),
                binding,
              );
            this.head = next;
            this.entryCount = checkpoint ? 1 : this.entryCount + 1;
            this.retainedBytes = checkpoint
              ? bytes
              : this.retainedBytes + bytes;
          } catch (error) {
            this.acceptedPublicationBindings =
              selectDocumentPublicationBindings(
                beforeBindings,
                candidateBindings,
                false,
              );
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
            this.acceptedPublicationBindings =
              selectDocumentPublicationBindings(
                beforeBindings,
                candidateBindings,
                false,
              );
          } catch (error) {
            this.failed = true;
            throw error;
          } finally {
            this.active = false;
          }
        },
      };
    } catch (error) {
      this.acceptedPublicationBindings = selectDocumentPublicationBindings(
        beforeBindings,
        candidateBindings,
        false,
      );
      if (!(error instanceof DocumentJournalCapacityError)) this.failed = true;
      this.active = false;
      throw error;
    }
  }

  /**
   * Durably end the accepted branch with an authenticated divergence marker.
   * It advances the rollback anchor, so dropping it reads as a rollback, and
   * the journal takes no further entries. Only a new journal starts clear.
   */
  async markDiverged(): Promise<void> {
    if (this.divergedMarker) return;
    if (
      !this.opened ||
      this.failed ||
      this.active ||
      this.revision === Number.MAX_SAFE_INTEGER
    )
      throw new Error('Document journal is unavailable');
    this.active = true;
    try {
      const expected = copyAnchor(this.head),
        revision = this.revision + 1,
        token = crypto.getRandomValues(new Uint8Array(32));
      const entry = await this.sealEntry(
        expected,
        revision,
        DIVERGED,
        new Uint8Array(),
      );
      await this.store.stage(
        this.storageKey,
        expected?.revision ?? 0,
        token.slice(),
        entry.slice(),
        undefined,
        false,
      );
      const { next, bytes } = await this.acceptStaged(
        expected,
        revision,
        token,
        false,
        entry,
      );
      this.head = next;
      this.entryCount++;
      this.retainedBytes += bytes;
      this.divergedMarker = true;
    } catch (error) {
      this.failed = true;
      throw error;
    } finally {
      this.active = false;
    }
  }

  private async sealEntry(
    expected: DocumentJournalAnchor | undefined,
    revision: number,
    marker: number,
    plaintext: Uint8Array,
  ): Promise<Uint8Array> {
    if (
      !documentJournalAnchorsEqual(
        expected,
        copyAnchor(await this.anchor.load(this.storageKey)),
      )
    )
      throw new Error('Document journal anchor changed');
    const parent = expected?.commitment ?? ZERO,
      nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          additionalData: this.aad(
            revision,
            marker,
            parent,
          ) as Uint8Array<ArrayBuffer>,
        },
        this.key,
        plaintext as Uint8Array<ArrayBuffer>,
      ),
    );
    return new DocumentBinaryWriter(MAX_ENTRY + 128)
      .integer(revision, 8)
      .integer(marker, 1)
      .fixed(parent)
      .fixed(nonce)
      .bytes(ciphertext, MAX_ENTRY + 16)
      .finish();
  }

  /** Accept a staged entry, confirm the stored head, then advance the independent anchor. */
  private async acceptStaged(
    expected: DocumentJournalAnchor | undefined,
    revision: number,
    token: Uint8Array,
    checkpoint: boolean,
    entry: Uint8Array,
    publication?: () => Promise<DocumentJournalPublication>,
  ): Promise<{ next: DocumentJournalAnchor; bytes: number }> {
    const accepted = await this.createAcceptedEntry(revision, entry);
    const commitment = await digest(accepted);
    await this.store.commit(
      this.storageKey,
      expected?.revision ?? 0,
      token.slice(),
      checkpoint,
      accepted.slice(),
      publication && (await publication()),
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
    return { next, bytes: accepted.length };
  }

  async pendingPublications(): Promise<ReadonlyArray<Uint8Array>> {
    if (!this.opened || this.failed || this.active)
      throw new Error('Document journal is unavailable');
    try {
      const result = await this.readPublications(
        this.acceptedPublicationBindings,
        this.revision,
      );
      if (
        this.failed ||
        this.active ||
        !documentJournalAnchorsEqual(
          this.head,
          copyAnchor(await this.anchor.load(this.storageKey)),
        )
      )
        throw new Error('Publication anchor is not current');
      this.pendingPublicationBindings = result.bindings;
      return result.frames;
    } catch (error) {
      this.failed = true;
      throw error;
    }
  }

  private async readPublications(
    accepted: Map<string, number>,
    maximumRevision: number,
  ): Promise<{
    frames: Uint8Array[];
    revisions: number[];
    bindings: Map<string, PublicationBinding>;
  }> {
    const publications = this.store.loadPublications
      ? await this.store.loadPublications(this.storageKey)
      : (await this.store.load(this.storageKey)).publications;
    if (publications === undefined)
      return {
        frames: [],
        revisions: [],
        bindings: new Map<string, PublicationBinding>(),
      };
    if (!Array.isArray(publications) || publications.length > 16)
      throw new Error('Invalid document publication queue');
    let bytes = 0;
    const owned = publications.map((value) => {
      const frame = copyUnsharedUint8Array(
        value.frame,
        1,
        Math.min(
          MAX_DOCUMENT_STORED_PUBLICATION_BYTES,
          16 * 1024 * 1024 - bytes,
        ),
        'stored document publication',
      );
      bytes += frame.length;
      return {
        id: copyUnsharedUint8Array(value.id, 32, 32, 'publication id'),
        frame,
      };
    });
    const result: Uint8Array[] = [],
      revisions: number[] = [],
      bindings = new Map<string, PublicationBinding>();
    const seenTokens = new Set<string>();
    for (const publication of owned) {
      const reader = new DocumentBinaryReader(
        publication.frame,
        MAX_DOCUMENT_STORED_PUBLICATION_BYTES,
      );
      const revision = reader.number(8),
        token = reader.fixed(32),
        nonce = reader.fixed(12),
        ciphertext = reader.bytes(1024 * 1024 + 16);
      reader.end();
      const id = documentBytesId(publication.id),
        tokenId = documentBytesId(token);
      if (
        !isAcceptedDocumentPublicationToken(
          accepted,
          tokenId,
          revision,
          maximumRevision,
        ) ||
        bindings.has(id) ||
        seenTokens.has(tokenId)
      )
        throw new Error(
          'Publication is not bound to the accepted journal branch',
        );
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: nonce as Uint8Array<ArrayBuffer>,
          additionalData: this.publicationAAD(
            revision,
            publication.id,
            token,
          ) as Uint8Array<ArrayBuffer>,
        },
        this.key,
        ciphertext as Uint8Array<ArrayBuffer>,
      );
      const frame = copyUnsharedUint8Array(
        new Uint8Array(plaintext),
        1,
        1024 * 1024,
        'accepted publication',
      );
      if (!documentBytesEqual(await digest(frame), publication.id))
        throw new Error('Publication commitment mismatch');
      result.push(frame);
      revisions.push(revision);
      bindings.set(id, { token, revision });
      seenTokens.add(tokenId);
    }
    return { frames: result, revisions, bindings };
  }

  private publicationAAD(
    revision: number,
    id: Uint8Array,
    token: Uint8Array,
  ): Uint8Array {
    return new DocumentBinaryWriter()
      .fixed(PUBLICATION_DOMAIN)
      .text(this.documentId)
      .fixed(this.genesis)
      .integer(revision, 8)
      .fixed(id)
      .fixed(token)
      .finish();
  }

  private async sealPublication(
    revision: number,
    id: Uint8Array,
    token: Uint8Array,
    frame: Uint8Array,
  ): Promise<Uint8Array> {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          additionalData: this.publicationAAD(
            revision,
            id,
            token,
          ) as Uint8Array<ArrayBuffer>,
        },
        this.key,
        frame as Uint8Array<ArrayBuffer>,
      ),
    );
    return new DocumentBinaryWriter(MAX_DOCUMENT_STORED_PUBLICATION_BYTES)
      .integer(revision, 8)
      .fixed(token)
      .fixed(nonce)
      .bytes(ciphertext, 1024 * 1024 + 16)
      .finish();
  }

  /**
   * Delete a restored diverged journal from its store, so a rebuild can reuse
   * the store. The rollback anchor still holds the diverged head, so the
   * rebuilt journal needs a new anchor namespace. Frames re-signed before the
   * divergence drain only while the diverged document stays open; deletion is
   * refused while any publication is unsent unless `discardUnsent` is set.
   */
  async deleteDiverged({ discardUnsent = false } = {}): Promise<void> {
    if (!this.opened || this.failed || this.active || !this.divergedMarker)
      throw new Error('Only a restored diverged journal can be deleted');
    if (typeof this.store.delete !== 'function')
      throw new Error('Journal store cannot delete a journal');
    this.active = true;
    try {
      const unsent = this.store.loadPublications
        ? await this.store.loadPublications(this.storageKey)
        : ((await this.store.load(this.storageKey)).publications ?? []);
      if (unsent.length > 0 && discardUnsent !== true)
        throw new Error('Diverged journal still holds unsent publications');
      this.failed = true;
      await this.store.delete(this.storageKey);
    } finally {
      this.active = false;
    }
  }

  async publicationSent(frame: Uint8Array): Promise<void> {
    if (!this.store.publicationSent)
      throw new Error('Journal store lacks publication support');
    const id = await digest(frame);
    await this.store.publicationSent(this.storageKey, id);
    this.pendingPublicationBindings.delete(documentBytesId(id));
  }

  /**
   * Replace an unsent publication with `next`, which keeps its binding to the
   * accepted entry and its place in the queue.
   */
  async replacePublication(frame: Uint8Array, next: Uint8Array): Promise<void> {
    if (!this.opened || this.failed || this.active)
      throw new Error('Document journal is unavailable');
    if (!this.store.replacePublication)
      throw new Error('Journal store cannot replace a publication');
    const owned = copyUnsharedUint8Array(
      next,
      1,
      1024 * 1024,
      'outbound document frame',
    );
    const id = await digest(frame),
      binding = this.pendingPublicationBindings.get(documentBytesId(id));
    if (!binding) throw new Error('Publication is not queued');
    const nextId = await digest(owned);
    const sealed = await this.sealPublication(
      binding.revision,
      nextId,
      binding.token,
      owned,
    );
    await this.store.replacePublication(this.storageKey, id, {
      id: nextId,
      frame: sealed,
    });
    this.pendingPublicationBindings.delete(documentBytesId(id));
    this.pendingPublicationBindings.set(documentBytesId(nextId), binding);
  }

  private acceptanceAAD(revision: number, commitment: Uint8Array): Uint8Array {
    return new DocumentBinaryWriter()
      .fixed(ACCEPTED_DOMAIN)
      .text(this.documentId)
      .fixed(this.genesis)
      .integer(revision, 8)
      .fixed(commitment)
      .finish();
  }

  private async createAcceptedEntry(
    revision: number,
    entry: Uint8Array,
  ): Promise<Uint8Array> {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aad = this.acceptanceAAD(revision, await digest(entry));
    const tag = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          additionalData: aad as Uint8Array<ArrayBuffer>,
        },
        this.key,
        new Uint8Array(),
      ),
    );
    if (tag.length !== 16) throw new Error('Invalid journal acceptance tag');
    return new DocumentBinaryWriter(MAX_ENTRY + 128)
      .bytes(entry, MAX_ENTRY + 96)
      .fixed(nonce)
      .fixed(tag)
      .finish();
  }

  private async verifyAcceptedMarker(
    revision: number,
    entry: Uint8Array,
    marker: Uint8Array,
  ): Promise<boolean> {
    const aad = this.acceptanceAAD(revision, await digest(entry));
    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: marker.slice(0, 12) as Uint8Array<ArrayBuffer>,
          additionalData: aad as Uint8Array<ArrayBuffer>,
        },
        this.key,
        marker.slice(12) as Uint8Array<ArrayBuffer>,
      );
      return plaintext.byteLength === 0;
    } catch {
      return false;
    }
  }

  private aad(
    revision: number,
    marker: number,
    parent: Uint8Array,
  ): Uint8Array {
    return new DocumentBinaryWriter()
      .fixed(DOMAIN)
      .text(this.documentId)
      .fixed(this.genesis)
      .integer(revision, 8)
      .integer(marker, 1)
      .fixed(parent)
      .finish();
  }
}

/** Test/reference anchor. Persistence and independent storage are application responsibilities. */
export class InMemoryDocumentJournalRollbackAnchor implements DocumentJournalRollbackAnchor {
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
