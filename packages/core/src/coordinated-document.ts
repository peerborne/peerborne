import {
  DocumentJournalCapacityError,
  type DocumentJournalCarriedFrame,
  type DocumentReplayJournal,
  type DocumentReplayReceipt,
  type PreparedDocumentJournal,
} from './document-replay-journal.js';
import type { AuthProvider } from './auth-provider.js';
import type { ChangesSerializer } from './changes-serializer.js';
import type { CRDTProvider } from './crdt-provider.js';
import {
  DocumentCausalDependencyError,
  type CRDTDocumentSession,
  type PreparedDocumentChange,
} from './document-crdt-session.js';
import type {
  GroupDocumentEncryptionMaterial,
  GroupSecurityCoordinator,
  GroupSecurityDocumentContext,
  GroupSecurityDocumentPreparation,
} from './group-security-coordinator.js';
import {
  GroupDocumentOperationBudget,
  GroupDocumentOperationError,
  type PreparedGroupDocumentOperation,
} from './group-document-operation.js';
import {
  documentBytesEqual,
  documentBytesId,
} from './internal/document-binary.js';
import { isWellFormedUtf16 } from './internal/canonical-encoding.js';
import { captureDocumentAuthorityLease } from './captured-document-authority.js';
import {
  assertDocumentGroupRoster,
  DocumentAuthorityLog,
  type PreparedDocumentRosterUpdate,
} from './document-authority-log.js';
import {
  assertDocumentOperationsAllowed,
  recordDocumentOperationPaths,
  type DocumentWritePaths,
} from './document-field-authorization.js';
import type { CapturedDocumentMember } from './policy/authority-capture.js';
import {
  copyUnsharedUint8Array,
  unsharedUint8ArrayByteLength,
} from './utils.js';
import {
  admitContentSequence,
  contentRolePermits,
  nextContentSequence,
} from './policy/document-content.js';
import { admitDocumentCatchUpReceipt } from './policy/document-catch-up.js';
import {
  advanceDocumentCheckpoint,
  canActivateRecoveredDocument,
  type DocumentCheckpointPhase,
} from './policy/document-journal.js';
import {
  decodeDocumentCatchUpCheckpoint,
  decodeDocumentCatchUpRefusal,
  decodeDocumentCatchUpRequest,
  decodeDocumentTopicCatchUpRequest,
  decodeEncryptedDocumentCatchUp,
  documentCatchUpAAD,
  encodeDocumentCatchUpCheckpoint,
  encodeDocumentCatchUpRefusal,
  encodeDocumentCatchUpRequest,
  encodeDocumentTopicCatchUpRequest,
  encodeEncryptedDocumentCatchUp,
  MAX_DOCUMENT_CATCH_UP_REQUEST_BYTES,
  MAX_DOCUMENT_CATCH_UP_SUFFIX_BYTES,
  MAX_DOCUMENT_CATCH_UP_SUFFIX_FRAMES,
  MAX_DOCUMENT_CATCH_UP_TOPIC_REQUEST_BYTES,
  type DocumentCatchUpBinding,
  type DocumentCatchUpCheckpoint,
  type DocumentCatchUpKind,
  type DocumentCatchUpRequest,
  type DocumentTopicCatchUpRequest,
} from './document-catch-up-wire.js';
import {
  decodeDocumentRedeliveryRequest,
  decodeEncryptedDocumentRedelivery,
  documentRedeliveryAAD,
  MAX_DOCUMENT_REDELIVERY_HELD,
  type DocumentRedeliveryRequest,
  encodeDocumentRedeliveryRequest,
  encodeEncryptedDocumentRedelivery,
  MAX_DOCUMENT_REDELIVERY_REQUEST_BYTES,
} from './document-redelivery-wire.js';
import {
  decodeDocumentContent,
  decodeEncryptedDocumentContent,
  decodeSignedDocumentContent,
  documentContentAAD,
  documentContextsMatch,
  documentFrameEpochTag,
  documentFrameNonce,
  encodeDocumentContent,
  encodeEncryptedDocumentContent,
  encodeSignedDocumentContent,
  MAX_DOCUMENT_CONTENT_BYTES,
  MAX_DOCUMENT_PUBLICATION_FRAMES,
  MAX_DOCUMENT_SECURITY_FRAME_BYTES,
  splitDocumentPublication,
} from './document-security-wire.js';

export interface DocumentMemberAuthority {
  readonly memberId: Uint8Array;
  readonly publicKey: string;
  readonly role: 1 | 2 | 3;
  /** Omit for whole-document writes; [] denies every operation. Map-key segments, not JSON pointer strings. */
  readonly writePaths?: DocumentWritePaths;
}

/** An application-pinned authority. A network-supplied roster is never a trust root. */
export interface DocumentAuthority {
  readonly documentId: string;
  readonly genesisId: Uint8Array;
  readonly headId: Uint8Array;
  /** True only when this authenticated history contains the accepted head as a prefix. */
  extendsHead(head: Uint8Array): boolean;
  assertCoordinator?(coordinator: GroupSecurityCoordinator): void;
  exportRecords?(): ReadonlyArray<Uint8Array>;
  applyUpdate?(
    coordinator: GroupSecurityCoordinator,
    encoded: Uint8Array,
  ): Promise<void>;
  /** Own data fields and a synchronous guard that invalidates when this captured authority changes. */
  capture(context: GroupSecurityDocumentContext): {
    readonly members: ReadonlyArray<DocumentMemberAuthority>;
    readonly headId: Uint8Array;
    isCurrent(): boolean;
  };
}

/** Outcome for this author's frames from the group context an update retired. */
export interface CoordinatedAuthorityUpdateResult {
  /** Frames re-signed as new frames in the current context. */
  readonly resent: number;
  /** Frames waiting for outbox space; they are re-signed as publications drain. */
  readonly waiting: number;
  /** Earlier frames of the retired context that are no longer retained. */
  readonly skipped: number;
  /** Frames the current roles or grants deny, with every later frame that depends on them. */
  readonly dropped: number;
  /**
   * The author can still write, but its replica holds edits its current grants
   * deny. The document is closed to further use; rebuild it from a checkpoint.
   */
  readonly diverged: boolean;
}

/** One of this author's frames, kept so a retired context's edits can be re-signed. */
interface OwnFrame {
  readonly context: GroupSecurityDocumentContext;
  /** Local write order, kept by re-signed copies so native dependencies stay ordered. */
  readonly order: number;
  readonly sequence: number;
  readonly changes: Uint8Array;
  /** Bounded covering operation paths recorded when it was written. */
  readonly paths: DocumentWritePaths;
  /** Its encryption nonce, which finds it inside a coalesced publication. */
  readonly nonce?: Uint8Array;
  /** Still in the outbox when queued: no peer can have received it. */
  readonly unsent?: boolean;
}

/**
 * The author's replica holds edits its current grants deny. Rebuild it from a
 * controller checkpoint into a journal with a new store, or the old one removed
 * with `deleteDiverged()`, and a new rollback anchor namespace.
 */
export class DocumentDivergedError extends Error {
  constructor() {
    super(
      'Coordinated document diverged from its current grants; rebuild it from a checkpoint',
    );
    this.name = 'DocumentDivergedError';
  }
}

// Unsent frames are never evicted; these bound the sent ones kept beside them.
const MAX_OWN_FRAMES = 16 * MAX_DOCUMENT_PUBLICATION_FRAMES + 64;
const MAX_OWN_BYTES = 32 * 1024 * 1024;
/** Encoded recorded paths of unsent frames; past it a local edit fails as a backlog. */
const MAX_CARRIED_PATH_BYTES = 4 * 1024 * 1024;
const WHOLE_DOCUMENT: DocumentWritePaths = Object.freeze([Object.freeze([])]);
/**
 * A whole-document record comes from an inspection that could not finish.
 * Receivers of a restricted author inspect within the same bounds, so they
 * cannot accept it under any grants.
 */
const uninspected = (paths: DocumentWritePaths) =>
  paths.some((path) => path.length === 0);

function utf8Bytes(text: string): number {
  let bytes = 0;
  for (let index = 0; index < text.length; index++) {
    const unit = text.charCodeAt(index);
    bytes += unit < 0x80 ? 1 : unit < 0x800 ? 2 : unit >= 0xd800 && unit < 0xe000 ? 2 : 3;
  }
  return bytes;
}

/** Size of a recorded path list as the journal encodes it. */
const encodedPathBytes = (paths: DocumentWritePaths) =>
  paths.reduce(
    (sum, path) =>
      sum + 1 + path.reduce((bytes, segment) => bytes + 4 + utf8Bytes(segment), 0),
    2,
  );

const pathBytes = (paths: DocumentWritePaths) =>
  paths.reduce(
    (sum, path) =>
      sum +
      64 +
      path.reduce((bytes, segment) => bytes + 32 + 2 * segment.length, 0),
    0,
  );

/** Charged in-memory size, with fixed overhead for each path array and segment string. */
const ownFrameBytes = (frame: OwnFrame) =>
  frame.changes.length + 64 + pathBytes(frame.paths);

/** The publications of an outbox and, by nonce, the publication holding each frame. */
interface QueuedFrames {
  readonly rows: Uint8Array[];
  readonly parts: Uint8Array[][];
  readonly rowOf: Map<string, number>;
}

function queueOf(rows: readonly Uint8Array[]): QueuedFrames {
  const parts = rows.map((row) => splitDocumentPublication(row));
  const rowOf = new Map<string, number>();
  parts.forEach((frames, row) => {
    for (const frame of frames)
      rowOf.set(documentBytesId(documentFrameNonce(frame)), row);
  });
  return { rows: [...rows], parts, rowOf };
}

/** Whether an outbox still holds the frame sealed with `nonce`, so no peer can have received it. */
function outboxHolds(
  queued: QueuedFrames,
  nonce: Uint8Array | undefined,
): boolean {
  return nonce !== undefined && queued.rowOf.has(documentBytesId(nonce));
}

function joinFrames(frames: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    frames.reduce((sum, frame) => sum + frame.length, 0),
  );
  let offset = 0;
  for (const frame of frames) {
    result.set(frame, offset);
    offset += frame.length;
  }
  return result;
}

/** The current roles or grants definitely deny a re-signed frame. */
class ResendDeniedError extends Error {}

export interface CoordinatedDocumentOptions {
  readonly coordinator: GroupSecurityCoordinator;
  readonly authority: DocumentAuthority;
  readonly journal?: DocumentReplayJournal;
  readonly persistPublications?: boolean;
  /** Append each local frame to the queued tail publication while it fits. */
  readonly joinPublications?: boolean;
  /**
   * Require the signed roles to enumerate the provider's exact decrypting
   * roster. Defaults to true when `authority` is a `DocumentAuthorityLog` and
   * the coordinator's provider implements `getAuthenticatedMemberIds`, the
   * configuration strict matching needs, and to false otherwise. Pass false
   * to opt out. With true, another authority throws here and a provider that
   * cannot report its members fails activation.
   */
  readonly requireGroupRosterMatch?: boolean;
  /**
   * Allow catch-up from the current unrestricted controller: requested on the
   * document topic, or relayed by the application.
   */
  readonly enableAuthenticatedCatchUp?: boolean;
  /**
   * On the controller, decide whether an authenticated member's topic request
   * gets a checkpoint, which holds the whole document state and its history.
   * Any answer but `true` refuses it. Without it, every current member does.
   */
  readonly authorizeCatchUp?: (memberId: Uint8Array) => boolean | Promise<boolean>;
  /**
   * Called when the controller refuses this replica's topic request; it then
   * stops requesting until `requestSecurityCatchUp()` is called. Without it,
   * a warning is logged.
   */
  readonly onCatchUpRefused?: (refusal: CoordinatedCatchUpRefusal) => void;
  /**
   * Called with the number of unsent frames dropped because they were sealed
   * for an earlier group context or authority head and their author cannot
   * re-sign them, or its current roles deny the re-signed frames. Without it,
   * a warning is logged.
   */
  readonly onPublicationsDropped?: (frames: number) => void;
}

/** Why the controller answered this replica's topic request without a checkpoint. */
export type CoordinatedCatchUpRefusal =
  | {
      /** The encoded snapshot exceeds the 512 KiB a checkpoint carries. */
      readonly reason: 'snapshot-too-large';
      readonly snapshotBytes: number;
    }
  | { readonly reason: 'denied' };

interface DocumentGroupRosterBinding {
  readonly context: GroupSecurityDocumentContext;
  readonly authorityHead: Uint8Array;
  readonly isCurrent: () => boolean;
}

interface Receipt {
  sequence: number;
  hash: Uint8Array;
}

type AuthorityLease = ReturnType<typeof captureDocumentAuthorityLease>;

interface CatchUpWork {
  readonly binding: DocumentCatchUpBinding;
  readonly roster: DocumentGroupRosterBinding;
  readonly lease: AuthorityLease;
  readonly material: GroupDocumentEncryptionMaterial;
  readonly work: GroupSecurityDocumentPreparation;
  assertCurrent(): void;
}

interface CatchUpPreparation<Value> {
  readonly value: Value;
  isCurrent?(): boolean;
  commit?(): void;
}

interface PendingCatchUp {
  readonly roster: DocumentGroupRosterBinding;
  readonly challenge: Uint8Array;
}

interface TopicCatchUp extends PendingCatchUp {
  readonly issuedAt: number;
}

function receiptEntries(
  receipts: ReadonlyMap<string, Receipt>,
): DocumentReplayReceipt[] {
  return [...receipts].map(([id, receipt]) => ({
    memberId: Uint8Array.from(id.match(/../g)!, (byte) => parseInt(byte, 16)),
    ...receipt,
  }));
}

const aggregate = new GroupDocumentOperationBudget(64, 64 * 1024 * 1024);
/** Received frames and ciphertext bytes waiting for their turn; each frame is charged. */
class ReceivedFrameBudget {
  private frames = 0;
  private bytes = 0;

  constructor(
    readonly maxFrames: number,
    readonly maxBytes: number,
  ) {}

  get usage(): Readonly<{ frames: number; bytes: number }> {
    return { frames: this.frames, bytes: this.bytes };
  }

  reserve(bytes: number): () => void {
    if (this.frames >= this.maxFrames || bytes > this.maxBytes - this.bytes)
      throw new GroupDocumentOperationError('capacity-exceeded');
    this.frames++;
    this.bytes += bytes;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.frames--;
      this.bytes -= bytes;
    };
  }
}

// Each received frame is charged twice its ciphertext: once for the frame
// and once for the plaintext pre-authentication keeps for its turn.
// One full outbox is 16 publications of up to 1,024 frames and 16 MiB. A
// sender's share in one document holds that backlog plus live edits sent
// while it drains, and two senders' shares leave room for every other one.
const SENDER_FRAMES = 16 * 1024 + 4096,
  SENDER_BYTES = 40 * 1024 * 1024;
const DOCUMENT_FRAMES = 48 * 1024,
  DOCUMENT_BYTES = 96 * 1024 * 1024;
const aggregateInbound = new ReceivedFrameBudget(128 * 1024, 192 * 1024 * 1024);
const ZERO_HASH = new Uint8Array(32);
const MAX_PUBLICATIONS = 16,
  MAX_PUBLICATION_BYTES = 16 * 1024 * 1024,
  STORED_PUBLICATION_OVERHEAD = 72;

/** Unsent changes fill the publication outbox; nothing was committed. */
export class DocumentPublicationBacklogError extends DocumentJournalCapacityError {
  constructor() {
    super();
    this.name = 'DocumentPublicationBacklogError';
    this.message =
      'Document outbox capacity is full of unsent encrypted changes (16 publications, 16 MiB); deliver them to a document peer before changing the document again';
  }
}

interface OutboxTail {
  readonly bytes: Uint8Array;
  readonly frames: number;
  // Every frame of one publication is sealed under this content binding.
  readonly aad: Uint8Array;
  // Queued publications, this one included.
  readonly rows: number;
}

/** A frame that decrypted under the current epoch during pre-authentication. */
interface AdmittedFrame {
  readonly frame: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly context: GroupSecurityDocumentContext;
  readonly aad: Uint8Array;
  readonly author: string;
  readonly sequence: number;
  readonly hash: Uint8Array;
  /**
   * Release the frame's charge. A frame that was not applied or held, whose
   * copies admission dropped while it waited, is returned for another turn.
   */
  release(processed: boolean): boolean;
}

interface WaitingFrame {
  // A copy was dropped because this frame was already waiting.
  copied: boolean;
}

// Sixteen full publications, counting each row's storage overhead, fit the
// journal's 16 MiB.
const MAX_JOINED_PUBLICATION_BYTES = MAX_DOCUMENT_SECURITY_FRAME_BYTES - 2048;

function reserveSender(
  senders: Map<string, ReceivedFrameBudget>,
  sender: string,
  bytes: number,
  frames: number,
  maxBytes: number,
): () => void {
  const budget =
    senders.get(sender) ?? new ReceivedFrameBudget(frames, maxBytes);
  senders.set(sender, budget);
  const forget = () => {
    if (budget.usage.frames === 0 && senders.get(sender) === budget)
      senders.delete(sender);
  };
  let release: () => void;
  try {
    release = budget.reserve(bytes);
  } catch (error) {
    forget();
    throw error;
  }
  return () => {
    release();
    forget();
  };
}

function concatFrames(head: Uint8Array, frame: Uint8Array): Uint8Array {
  const result = new Uint8Array(head.length + frame.length);
  result.set(head);
  result.set(frame, head.length);
  return result;
}

const MAX_HELD_FRAMES = 64;
const MAX_HELD_FRAMES_PER_AUTHOR = 32;
const MAX_HELD_BYTES = 8 * 1024 * 1024;
// An author's share of held frames matches its share of the frame count.
const MAX_HELD_BYTES_PER_AUTHOR =
  (MAX_HELD_BYTES * MAX_HELD_FRAMES_PER_AUTHOR) / MAX_HELD_FRAMES;
const HELD_FRAME_TTL_MS = 120_000;
const aggregateHeld = new GroupDocumentOperationBudget(
  1024,
  64 * 1024 * 1024,
);
// One author may hold a quarter of the process-wide held frames.
const aggregateHeldAuthors = new Map<string, GroupDocumentOperationBudget>();

type HeldReason = 'gap' | 'dependency';

/** An authenticated frame whose author prefix or native dependencies are missing. */
class HeldDocumentFrame extends Error {
  constructor(
    readonly reason: HeldReason,
    readonly context: GroupSecurityDocumentContext,
    readonly author: string,
    readonly sequence: number,
    readonly hash: Uint8Array,
    readonly ready?: () => boolean,
  ) {
    super('Document frame waits for its causal predecessors');
  }
}

/** An accepted frame kept for catch-up proofs and redelivery. */
interface RetainedFrame {
  readonly sequence: number;
  readonly hash: Uint8Array;
  /** Exact signed content: the unsigned frame and its author's signature. */
  readonly signed: Uint8Array;
  /** Exact encrypted wire frame. */
  readonly frame: Uint8Array;
  readonly order: number;
  /** When this replica last accepted or saw a duplicate of the frame. */
  observedAt: number;
}

const REDELIVERY_RESPONSE_FRAMES = 64;
const REDELIVERY_RESPONSE_BYTES = 4 * 1024 * 1024;
const REDELIVERY_REQUESTER_INTERVAL_MS = 2_000;
/** A request older than this, or not newer than its member's last, is not answered. */
const REDELIVERY_FRESHNESS_MS = 60_000;
/** Frames one replica resends per second across all requesters, with a burst of 64. */
const REDELIVERY_FRAMES_PER_SECOND = 32;

/** A member gets at most one topic checkpoint from this controller in this interval. */
const CATCH_UP_MEMBER_INTERVAL_MS = 10_000;
/**
 * Topic checkpoints that all coordinated documents in this module instance
 * answer together: a burst of four, refilled at one every 2 s. Each document
 * may take a burst of two, refilled at one every 4 s, so one document's
 * members cannot use the whole budget.
 */
const CATCH_UP_PROCESS = { burst: 4, refillMs: 2_000 };
const CATCH_UP_DOCUMENT = { burst: 2, refillMs: 4_000 };
const catchUpAnswers = { tokens: CATCH_UP_PROCESS.burst, refilledAt: 0 };
/** Topic requests a replica keeps outstanding; a newer one displaces the oldest. */
const MAX_TOPIC_CATCH_UPS = 4;

interface Bucket {
  tokens: number;
  refilledAt: number;
}

function refill(
  bucket: Bucket,
  limit: { burst: number; refillMs: number },
  now: number,
): void {
  bucket.tokens = Math.min(
    limit.burst,
    bucket.tokens + Math.max(0, now - bucket.refilledAt) / limit.refillMs,
  );
  bucket.refilledAt = now;
}

/** Take a checkpoint from the document's share and the process budget, or neither. */
function takeCatchUpAnswer(share: Bucket, now: number): boolean {
  refill(share, CATCH_UP_DOCUMENT, now);
  refill(catchUpAnswers, CATCH_UP_PROCESS, now);
  if (share.tokens < 1 || catchUpAnswers.tokens < 1) return false;
  share.tokens--;
  catchUpAnswers.tokens--;
  return true;
}

function boundRecent(map: Map<string, number>): void {
  if (map.size > 256) map.delete(map.keys().next().value!);
}

/** Frames a responder resends: its own at once, others' after suppression. */
export interface CoordinatedRedeliveryAnswer {
  readonly own: readonly Uint8Array[];
  readonly others: readonly { readonly author: string; readonly sequence: number }[];
  readonly since: number;
  /** This replica's position among the other current members, for staggering answers. */
  readonly rank: number;
}

interface SealedStage {
  readonly binding: DocumentCatchUpBinding;
  readonly lease: AuthorityLease;
  readonly material: GroupDocumentEncryptionMaterial;
  readonly work: GroupSecurityDocumentPreparation;
}

const MAX_RETAINED_FRAMES_PER_AUTHOR = 64;
const MAX_RETAINED_BYTES = 16 * 1024 * 1024;
const MAX_RETAINED_PROCESS_BYTES = 64 * 1024 * 1024;
/** Retained bytes across every coordinated document in this module instance. */
let retainedProcessBytes = 0;
/** Room kept for the signature, AEAD tag and outer framing of a checkpoint. */
const CHECKPOINT_SEAL_BYTES = 4096;

/** True when a verified suffix may replace a conflicting receipt, beside the proved policy. */
function catchUpReceiptExtends(
  current: number,
  offered: number,
  suffixVerified: boolean,
): boolean {
  return current > 0 && offered > current && suffixVerified;
}

interface HeldFrame {
  readonly frame: Uint8Array;
  readonly author: string;
  readonly sequence: number;
  readonly hash: Uint8Array;
  readonly heldAt: number;
  readonly holder: HeldFrames;
  readonly release: () => void;
  reason: HeldReason;
  attemptedAt: number;
  ready?: () => boolean;
}

interface HeldFrames {
  readonly context: GroupSecurityDocumentContext;
  readonly frames: HeldFrame[];
  bytes: number;
  remove(entry: HeldFrame): void;
}

// Every document's held frames, so the process-wide bound can evict anywhere.
const heldDocuments = new Set<HeldFrames>();

/**
 * Whether `usage` occupies a larger fraction of an author's frame or byte
 * share than `than`; equal shares are ranked by bytes.
 */
function heavier(
  usage: { frames: number; bytes: number },
  than: { frames: number; bytes: number },
  frames: number,
  bytes: number,
): boolean {
  const share = Math.max(usage.frames / frames, usage.bytes / bytes),
    other = Math.max(than.frames / frames, than.bytes / bytes);
  return share > other || (share === other && usage.bytes > than.bytes);
}

function farthestHeld(
  frames: readonly HeldFrame[],
  author: string,
  skip: ReadonlySet<HeldFrame>,
): HeldFrame | undefined {
  let farthest: HeldFrame | undefined;
  for (const entry of frames)
    if (
      entry.author === author &&
      !skip.has(entry) &&
      (!farthest || entry.sequence > farthest.sequence)
    )
      farthest = entry;
  return farthest;
}

/** Reserve process-wide credit, or name the exhausted bound. */
function reserveHeld(
  author: string,
  bytes: number,
): (() => void) | 'author' | 'shared' {
  const budget =
    aggregateHeldAuthors.get(author) ??
    new GroupDocumentOperationBudget(
      aggregateHeld.maxOperations / 4,
      aggregateHeld.maxBytes / 4,
    );
  aggregateHeldAuthors.set(author, budget);
  const forget = () => {
    if (
      budget.usage.operations === 0 &&
      aggregateHeldAuthors.get(author) === budget
    )
      aggregateHeldAuthors.delete(author);
  };
  let releaseAuthor: () => void;
  try {
    releaseAuthor = budget.reserve(bytes);
  } catch {
    forget();
    return 'author';
  }
  let releaseShared: () => void;
  try {
    releaseShared = aggregateHeld.reserve(bytes);
  } catch {
    releaseAuthor();
    forget();
    return 'shared';
  }
  return () => {
    releaseShared();
    releaseAuthor();
    forget();
  };
}

/** Whether a held frame's named dependencies may have arrived; a failing guard means not yet. */
function dependencyReady(ready: () => boolean): boolean {
  try {
    return ready() === true;
  } catch {
    return false;
  }
}

/** Coordinator-backed mutation path, deliberately separate from the BeeKEM wire protocol. */
export class CoordinatedDocument<
  Document,
  Changes,
  Change,
  PrivateKey,
  PublicKey,
  DocumentKey,
> {
  private readonly session: CRDTDocumentSession<Document, Changes, Change>;
  private readonly budget = new GroupDocumentOperationBudget(
    16,
    16 * 1024 * 1024,
  );
  private readonly inbound = new ReceivedFrameBudget(
    DOCUMENT_FRAMES,
    DOCUMENT_BYTES,
  );
  private readonly senders = new Map<string, ReceivedFrameBudget>();
  // Admitted frames waiting for their turn, by author, sequence and hash.
  private readonly admittedFrames = new Map<string, WaitingFrame>();
  // Changes whenever held frames are added, removed or replaced.
  private heldVersion = 0;
  // The last queued publication; null when the outbox is known to be empty.
  private outboxTail: OutboxTail | null | undefined;
  private deriving?: {
    readonly context: GroupSecurityDocumentContext;
    readonly value: Promise<GroupDocumentEncryptionMaterial>;
  };
  private tail: Promise<void> = Promise.resolve();
  private readonly localLane: Array<() => Promise<unknown>> = [];
  // Received publications whose author is not decoded yet, and frames of the
  // replica's own author that are waiting or queued for another turn.
  private undecidedPublications = 0;
  private ownFramesPending = 0;
  private receipts = new Map<string, Receipt>();
  private receiptsContext?: GroupSecurityDocumentContext;
  private recovered = false;
  private activated = false;
  private rosterBinding?: DocumentGroupRosterBinding;
  private pendingCatchUp?: PendingCatchUp;
  private persistedAuthorityLease?: () => boolean;
  private publications: Uint8Array[] = [];
  private held?: HeldFrames;
  private heldTimer?: ReturnType<typeof setTimeout>;
  private appliedFrames = 0;
  private own?: {
    readonly context: GroupSecurityDocumentContext;
    readonly frames: OwnFrame[];
    bytes: number;
    /** Write order at the last frame accepted from a peer in this context. */
    remoteMark: number;
  };
  private diverged = false;
  private resendQueue: OwnFrame[] = [];
  // Encoded paths of own frames still in the outbox, by frame nonce.
  private readonly unsent = new Map<string, number>();
  private unsentPathBytes = 0;
  private ownOrder = 0;
  private retained?: {
    readonly context: GroupSecurityDocumentContext;
    readonly authors: Map<string, RetainedFrame[]>;
    bytes: number;
    order: number;
  };
  private readonly redelivery = {
    answered: new Map<string, number>(),
    issued: new Map<string, number>(),
    tokens: REDELIVERY_RESPONSE_FRAMES,
    refilledAt: 0,
  };
  private heldAdded = 0;
  private heldApplied = 0;
  private staleRedeliveries = 0;
  private topicCatchUps: TopicCatchUp[] = [];
  private readonly catchUpAnswer = {
    answered: new Map<string, number>(),
    issued: new Map<string, number>(),
  };
  private staleCatchUps = 0;
  private readonly catchUpShare: Bucket = {
    tokens: CATCH_UP_DOCUMENT.burst,
    refilledAt: 0,
  };
  // Changes whenever accepted content changes, so a refused snapshot is not rebuilt.
  private contentVersion = 0;
  private oversized?: { readonly version: number; readonly bytes: number };
  private catchUpRefusal?: CoordinatedCatchUpRefusal;
  // Whether this replica accepted a frame or checkpoint, now or before a restart.
  private holdsContent = false;
  // Opened or added without content, and no checkpoint merged since.
  private joining = false;
  private material?: {
    context: GroupSecurityDocumentContext;
    value: GroupDocumentEncryptionMaterial;
  };
  private closed = false;
  private failed = false;
  private readonly genesisId: Uint8Array;

  constructor(
    readonly documentId: string,
    initial: Document,
    private readonly crdt: CRDTProvider<Document, Changes, Change>,
    private readonly serializer: ChangesSerializer<Changes>,
    private readonly auth: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
    private readonly privateKey: PrivateKey,
    private readonly publicKey: PublicKey,
    private readonly options: CoordinatedDocumentOptions,
  ) {
    const {
      authority,
      coordinator,
      journal,
      persistPublications,
      joinPublications,
      requireGroupRosterMatch,
      enableAuthenticatedCatchUp,
      authorizeCatchUp,
      onCatchUpRefused,
      onPublicationsDropped,
    } = options;
    if (
      !documentId ||
      documentId.length > 4096 ||
      !isWellFormedUtf16(documentId) ||
      authority.documentId !== documentId
    )
      throw new TypeError('Invalid coordinated document identity');
    if (typeof crdt.createDocumentSession !== 'function')
      throw new TypeError(
        'Coordinated documents require detached CRDT preparation',
      );
    if (
      requireGroupRosterMatch !== undefined &&
      typeof requireGroupRosterMatch !== 'boolean'
    )
      throw new TypeError('Group roster matching flag must be boolean');
    const strictGroupRoster =
      requireGroupRosterMatch ??
      (authority instanceof DocumentAuthorityLog &&
        coordinator.reportsAuthenticatedMembers === true);
    if (strictGroupRoster && !(authority instanceof DocumentAuthorityLog))
      throw new Error(
        'Strict group roster matching requires a signed document authority log',
      );
    if (
      enableAuthenticatedCatchUp !== undefined &&
      typeof enableAuthenticatedCatchUp !== 'boolean'
    )
      throw new TypeError('Document catch-up flag must be boolean');
    if (
      onPublicationsDropped !== undefined &&
      typeof onPublicationsDropped !== 'function'
    )
      throw new TypeError('Dropped publication handler must be a function');
    if (authorizeCatchUp !== undefined && typeof authorizeCatchUp !== 'function')
      throw new TypeError('Catch-up authorization must be a function');
    if (onCatchUpRefused !== undefined && typeof onCatchUpRefused !== 'function')
      throw new TypeError('Catch-up refusal handler must be a function');
    if (
      enableAuthenticatedCatchUp &&
      (!strictGroupRoster ||
        !journal ||
        typeof crdt.getSnapshot !== 'function')
    )
      throw new TypeError(
        'Document catch-up requires strict roster matching, a journal, and native snapshots',
      );

    this.options = {
      coordinator,
      authority,
      journal,
      persistPublications,
      joinPublications:
        persistPublications === true && joinPublications === true,
      requireGroupRosterMatch: strictGroupRoster,
      enableAuthenticatedCatchUp,
      authorizeCatchUp,
      onCatchUpRefused,
      onPublicationsDropped,
    };
    this.genesisId = copyUnsharedUint8Array(
      authority.genesisId,
      32,
      32,
      'document authority root',
    );
    authority.assertCoordinator?.(coordinator);
    journal?.assertBinding(documentId, this.genesisId);
    this.session = crdt.createDocumentSession(initial);
    if (
      enableAuthenticatedCatchUp &&
      typeof this.session.prepareMergeSnapshot !== 'function'
    ) {
      this.session.close();
      throw new TypeError(
        'Document catch-up requires detached native snapshot preparation',
      );
    }
  }

  get document(): Document {
    this.assertUsable();
    this.assertActivated();
    this.assertCurrentGroupRoster();
    return this.session.document;
  }

  get routingId(): string {
    return documentBytesId(this.genesisId);
  }

  async publicKeys(writersOnly: boolean): Promise<PublicKey[]> {
    this.assertUsable();
    const binding = this.rosterBinding;
    if (this.options.requireGroupRosterMatch) this.assertActivated();
    this.assertCurrentGroupRoster(binding);
    const lease = this.authority(this.options.coordinator.documentContext);
    const result: PublicKey[] = [];
    for (const member of lease.members.values()) {
      if (!writersOnly || contentRolePermits(member.role, false)) {
        result.push(await this.auth.deserializePublicKey(member.publicKey));
        this.assertCurrentGroupRoster(binding);
      }
    }
    if (!lease.isCurrent()) throw new Error('Document authority changed');
    if (this.options.requireGroupRosterMatch) {
      this.assertUsable();
      this.assertActivated();
      this.assertCurrentGroupRoster(binding);
    }
    return result;
  }

  /** A diverged document still drains the frames it committed before diverging. */
  private assertUsable(draining = false): void {
    if (this.diverged && !draining) throw new DocumentDivergedError();
    if (this.closed || this.failed)
      throw new Error('Coordinated document must be reopened');
  }

  private assertActivated(): void {
    if (
      (this.options.journal || this.options.requireGroupRosterMatch) &&
      !this.activated
    )
      throw new Error('Document activation is not complete');
  }

  private assertCurrentGroupRoster(binding = this.rosterBinding): void {
    if (
      this.options.requireGroupRosterMatch &&
      (!binding ||
        !binding.isCurrent() ||
        !documentContextsMatch(
          binding.context,
          this.options.coordinator.documentContext,
        ))
    ) {
      throw new Error('Authenticated group roster is not current');
    }
  }

  private async prepareGroupRoster(
    context: GroupSecurityDocumentContext,
    lease: ReturnType<typeof captureDocumentAuthorityLease>,
    work: GroupSecurityDocumentPreparation,
  ): Promise<DocumentGroupRosterBinding> {
    const current = this.rosterBinding;
    if (
      current?.isCurrent() &&
      documentContextsMatch(current.context, context) &&
      documentBytesEqual(current.authorityHead, lease.headId)
    ) {
      return current;
    }
    assertDocumentGroupRoster(
      lease.members.keys(),
      await work.readAuthenticatedMemberIds(),
    );
    return { context, authorityHead: lease.headId, isCurrent: lease.isCurrent };
  }

  /**
   * Queue document work. A `local` edit also joins the local lane: received
   * work holding the queue runs it at each turn and frame boundary, so a
   * received backlog never delays the replica's own edits.
   */
  private enqueue<T>(
    bytes: number,
    capture: () => () => Promise<T>,
    draining = false,
    local = false,
  ): Promise<T> {
    let owned: (() => void) | undefined, shared: (() => void) | undefined;
    try {
      this.assertUsable(draining);
      shared = aggregate.reserve(bytes);
      owned = this.budget.reserve(bytes);
      const work = capture();
      let started: Promise<T> | undefined,
        start!: (value: Promise<T>) => void;
      // Settles with the work, whether received work or the queue ran it.
      const finished = new Promise<T>((resolve) => {
        start = resolve;
      });
      const run = (): Promise<T> => {
        if (!started) {
          const index = this.localLane.indexOf(run);
          if (index !== -1) this.localLane.splice(index, 1);
          started = (async () => {
            this.assertUsable(draining);
            return work();
          })();
          start(started);
        }
        return started;
      };
      if (local) this.localLane.push(run);
      const turn = this.tail.then(run);
      const settled = finished.finally(() => {
        owned!();
        shared!();
      });
      this.tail = turn.then(
        () => {},
        () => {},
      );
      return settled;
    } catch (error) {
      owned?.();
      shared?.();
      return Promise.reject(error);
    }
  }

  /**
   * Run the local edits waiting while received work holds the queue, unless
   * a frame of the replica's own author, from another device, is waiting,
   * queued for another turn or held: an edit run first would sign the same
   * sequence.
   */
  private async serveLocal(): Promise<void> {
    while (this.localLane.length !== 0 && !this.ownFramesWaiting())
      await this.localLane[0]().then(
        () => {},
        () => {},
      );
  }

  private ownFramesWaiting(): boolean {
    if (this.undecidedPublications > 0 || this.ownFramesPending > 0)
      return true;
    const local = documentBytesId(this.options.coordinator.localMemberId);
    return this.held?.frames.some((entry) => entry.author === local) ?? false;
  }

  async activate(): Promise<void> {
    await this.enqueue(0, () => async () => {
      this.activated = false;
      await this.recover();
      const context = this.options.coordinator.documentContext;
      await this.options.coordinator.runDocumentOperation(
        context,
        new Uint8Array(),
        async (captured, _input, _signal, work) => {
          const lease = this.authority(captured);
          const own = lease.members.get(
            documentBytesId(this.options.coordinator.localMemberId),
          );
          if (!own) throw new Error('Local member has no document authority');
          const { value } = await work.observe<string>(
            this.auth.serializePublicKey(this.publicKey),
          );
          if (typeof value !== 'string' || value !== own.publicKey)
            throw new Error('Document signing identity mismatch');
          const roster = this.options.requireGroupRosterMatch
            ? await this.prepareGroupRoster(captured, lease, work)
            : undefined;
          return {
            isAuthorizationCurrent: () =>
              canActivateRecoveredDocument(
                this.recovered,
                !this.closed && !this.failed,
                lease.isCurrent(),
              ),
            commit: () => {
              this.rosterBinding = roster;
              this.activated = true;
              this.joining = !this.holdsContent && !this.controlsCatchUp(lease);
            },
          };
        },
      );
      await this.drainResend().catch(() => {});
    });
  }

  change(change: Change, message = ''): Promise<Uint8Array> {
    if (typeof message !== 'string' || message.length > 4096)
      return Promise.reject(new TypeError('Invalid change message'));
    return this.enqueue(
      MAX_DOCUMENT_CONTENT_BYTES,
      () => async () => {
        this.assertActivated();
        // A new edit depends natively on every waiting re-sign, so those go first.
        if (this.resendQueue.length > 0) {
          await this.drainResend();
          if (this.resendQueue.length > 0)
            throw new DocumentPublicationBacklogError();
        }
        return this.apply(undefined, change, message);
      },
      false,
      true,
    );
  }

  /**
   * Apply a publication of consecutive frames from one author. Every frame is
   * charged against the received bounds; a `sender` names the network peer,
   * whose share holds one full outbox backlog plus live edits. Each frame
   * must decrypt under the current epoch before the publication waits for its
   * turn. Frames the author already delivered, and copies of frames already
   * waiting or held, are dropped then, so unauthenticated input and replays
   * cost no signature check.
   */
  receive(frame: Uint8Array, sender?: string): Promise<boolean> {
    const reserved: Array<Array<() => void>> = [];
    const release = (index?: number) => {
      for (const releases of index === undefined
        ? reserved
        : [reserved[index] ?? []])
        for (const value of releases.splice(0).reverse()) value();
    };
    try {
      const length = unsharedUint8ArrayByteLength(
        frame,
        1,
        MAX_DOCUMENT_SECURITY_FRAME_BYTES,
        'document frame',
      );
      if (
        sender !== undefined &&
        (typeof sender !== 'string' || sender.length > 1024)
      )
        throw new TypeError('Invalid document frame sender');
      this.assertUsable();
      const frames = splitDocumentPublication(frame);
      const charge = (index: number) => {
        const releases = (reserved[index] ??= []);
        const bytes = 2 * frames[index].length;
        try {
          releases.push(aggregateInbound.reserve(bytes));
          releases.push(this.inbound.reserve(bytes));
          if (sender !== undefined)
            releases.push(
              reserveSender(
                this.senders,
                sender,
                bytes,
                SENDER_FRAMES,
                SENDER_BYTES,
              ),
            );
        } catch (error) {
          release(index);
          throw error;
        }
      };
      for (let index = 0; index < frames.length; index++) charge(index);
      const admitted = this.admitFrames(
        frames,
        (index) => () => release(index),
        (index) => {
          try {
            charge(index);
            return true;
          } catch {
            return false;
          }
        },
      );
      admitted.then(undefined, () => release());
      const result = this.tail.then(async () => {
        // A turn that admits no frames, such as a copy's, still serves them.
        await this.serveLocal();
        const accepted = await admitted;
        await this.serveLocal();
        this.assertUsable();
        this.assertActivated();
        let applied = false,
          failed = false,
          failure: unknown,
          stopped = accepted.length;
        const retry: AdmittedFrame[] = [];
        const delivered =
          accepted.length === 0
            ? undefined
            : this.deliveryCheck(accepted[0].context);
        const observe =
          accepted.length === 0
            ? undefined
            : this.copyObserver(accepted[0].context);
        for (const [index, value] of accepted.entries()) {
          await this.serveLocal();
          let processed = false;
          try {
            if (delivered!(value))
              observe!(value.author, value.sequence, value.frame);
            else if (await this.receiveOwned(value.frame, value)) applied = true;
            processed = true;
          } catch (error) {
            failed = true;
            failure = error;
            stopped = index + 1;
          } finally {
            if (value.release(processed)) retry.push(value);
          }
          if (failed) break;
        }
        for (const value of accepted.slice(stopped))
          if (value.release(false)) retry.push(value);
        // A copy that admission dropped behind one of these frames gets the
        // turn this one lost, after the publications that carried it.
        if (retry.length !== 0) this.retryFrames(retry);
        if (failed && !applied) throw failure;
        return applied;
      });
      const settled = result.finally(() => {
        release();
        void admitted.then(
          (values) => {
            for (const value of values) value.release(false);
          },
          () => {},
        );
      });
      this.tail = settled.then(
        () => {},
        () => {},
      );
      return settled;
    } catch (error) {
      release();
      return Promise.reject(error);
    }
  }

  /** Derive this document's key for `context` once, outside the document queue. */
  private materialFor(
    context: GroupSecurityDocumentContext,
  ): Promise<GroupDocumentEncryptionMaterial> {
    if (this.material && documentContextsMatch(this.material.context, context))
      return Promise.resolve(this.material.value);
    const pending = this.deriving;
    if (pending && documentContextsMatch(pending.context, context))
      return pending.value;
    let material: GroupDocumentEncryptionMaterial | undefined;
    const value = this.options.coordinator
      .runDocumentOperation(
        context,
        new Uint8Array(),
        async (captured, _input, _signal, work) => {
          material = await this.key(captured, work);
          return {
            isAuthorizationCurrent: () => !this.closed && !this.failed,
            commit: () => {},
          };
        },
      )
      .then(() => material!);
    const forget = () => {
      if (this.deriving?.value === value) this.deriving = undefined;
    };
    this.deriving = { context, value };
    value.then(forget, forget);
    return value;
  }

  /** Current epoch key and content binding that every accepted frame decrypts under. */
  private async frameKey(): Promise<{
    material: GroupDocumentEncryptionMaterial;
    aad: Uint8Array;
  }> {
    const context = this.options.coordinator.documentContext;
    const { headId } = this.authority(context);
    const material = await this.materialFor(context);
    return {
      material,
      aad: documentContentAAD(this.documentId, context, headId),
    };
  }

  private async decryptsUnder(
    frame: Uint8Array,
    { material, aad }: Awaited<ReturnType<typeof this.frameKey>>,
  ): Promise<boolean> {
    const envelope = decodeEncryptedDocumentContent(frame);
    if (!documentBytesEqual(envelope.epochTag, material.epochTag)) return false;
    try {
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: envelope.nonce as Uint8Array<ArrayBuffer>,
          additionalData: aad as Uint8Array<ArrayBuffer>,
        },
        material.key,
        envelope.ciphertext as Uint8Array<ArrayBuffer>,
      );
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Pre-authenticate a publication before it waits for its turn: every frame
   * must decrypt under the current epoch and binding, and all of them must
   * come from one author with consecutive sequences. A frame the author
   * already delivered, a held frame, or a copy of a frame already waiting is
   * released as soon as it is identified and dropped without a signature
   * check. Copies are matched by author, sequence and content hash, so a
   * forged frame cannot shadow the genuine one, and a different frame at the
   * accepted sequence still goes on to be reported as equivocation. A dropped
   * copy of a waiting frame is not lost: if that frame is then neither
   * applied nor held, it takes another turn.
   */
  private async admitFrames(
    frames: readonly Uint8Array[],
    releaser: (index: number) => () => void,
    recharge: (index: number) => boolean,
  ): Promise<AdmittedFrame[]> {
    // Until its author is known, a publication may hold the replica's own frames.
    let undecided = true;
    this.undecidedPublications++;
    const own = new Set<number>();
    const decide = (local: boolean) => {
      if (!undecided) return;
      undecided = false;
      this.undecidedPublications--;
      if (!local) return;
      for (let index = 0; index < frames.length; index++) own.add(index);
      this.ownFramesPending += frames.length;
    };
    const settle = (index: number) => {
      if (own.delete(index)) this.ownFramesPending--;
    };
    try {
      return await this.admitPublication(frames, releaser, recharge, decide, settle);
    } catch (error) {
      decide(false);
      for (const index of [...own]) settle(index);
      throw error;
    }
  }

  private async admitPublication(
    frames: readonly Uint8Array[],
    releaser: (index: number) => () => void,
    recharge: (index: number) => boolean,
    decide: (local: boolean) => void,
    settle: (index: number) => void,
  ): Promise<AdmittedFrame[]> {
    const context = this.options.coordinator.documentContext;
    const delivered = this.deliveryCheck(context);
    const key = await this.frameKey();
    const decoded: Array<{
      plaintext: Uint8Array;
      author: string;
      sequence: number;
      hash: Uint8Array;
      id: string;
      released: boolean;
    }> = [];
    const covered = (value: (typeof decoded)[number]) =>
      delivered(value) || this.admittedFrames.has(value.id);
    for (const [index, frame] of frames.entries()) {
      const envelope = decodeEncryptedDocumentContent(frame);
      if (!documentBytesEqual(envelope.epochTag, key.material.epochTag))
        throw new Error('Document epoch is unavailable');
      let plaintext: Uint8Array;
      try {
        plaintext = new Uint8Array(
          await crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: envelope.nonce as Uint8Array<ArrayBuffer>,
              additionalData: key.aad as Uint8Array<ArrayBuffer>,
            },
            key.material.key,
            envelope.ciphertext as Uint8Array<ArrayBuffer>,
          ),
        );
      } catch {
        throw new Error(
          'Document frame does not decrypt under the current epoch',
        );
      }
      const { unsigned } = decodeSignedDocumentContent(plaintext);
      const content = decodeDocumentContent(unsigned);
      const author = documentBytesId(content.memberId);
      if (index === 0)
        decide(
          author === documentBytesId(this.options.coordinator.localMemberId),
        );
      if (
        index !== 0 &&
        (author !== decoded[0].author ||
          content.sequence !== decoded[0].sequence + index)
      )
        throw new Error(
          'Document publication frames must be one author’s consecutive sequences',
        );
      const hash = new Uint8Array(
        await crypto.subtle.digest(
          'SHA-256',
          unsigned as Uint8Array<ArrayBuffer>,
        ),
      );
      const value = {
        plaintext,
        author,
        sequence: content.sequence,
        hash,
        id: `${author}:${content.sequence}:${documentBytesId(hash)}`,
        released: false,
      };
      // A copy stops holding queue capacity as soon as it is recognized.
      if (covered(value)) {
        releaser(index)();
        value.released = true;
      }
      decoded.push(value);
    }
    // Decide and register synchronously, so concurrent copies of one
    // publication keep exactly one whole instance.
    const admitted: AdmittedFrame[] = [];
    const observe = this.copyObserver(context);
    for (const [index, value] of decoded.entries()) {
      const release = releaser(index);
      const waiting = this.admittedFrames.get(value.id);
      if (waiting || delivered(value)) {
        if (waiting) waiting.copied = true;
        else observe(value.author, value.sequence, frames[index]);
        release();
        settle(index);
        continue;
      }
      // Its original was released unapplied while this frame decoded.
      if (value.released && !recharge(index)) {
        settle(index);
        continue;
      }
      const entry: WaitingFrame = { copied: false };
      this.admittedFrames.set(value.id, entry);
      let done = false;
      admitted.push({
        frame: frames[index],
        plaintext: value.plaintext,
        context,
        aad: key.aad,
        author: value.author,
        sequence: value.sequence,
        hash: value.hash,
        release: (processed) => {
          if (done) return false;
          done = true;
          release();
          settle(index);
          if (this.admittedFrames.get(value.id) === entry)
            this.admittedFrames.delete(value.id);
          return !processed && entry.copied;
        },
      });
    }
    return admitted;
  }

  /**
   * A check of whether a frame at `context` was already accepted or is held.
   * Contexts are compared only when the receipts or held frames are replaced,
   * so checking each frame of a publication stays cheap.
   */
  private deliveryCheck(
    context: GroupSecurityDocumentContext,
  ): (value: {
    author: string;
    sequence: number;
    hash: Uint8Array;
  }) => boolean {
    let receiptsSource: Map<string, Receipt> | undefined,
      receipts: ReadonlyMap<string, Receipt> = new Map(),
      heldVersion = -1,
      held = new Set<string>();
    return ({ author, sequence, hash }) => {
      if (receiptsSource !== this.receipts) {
        receiptsSource = this.receipts;
        receipts = this.receiptsAt(context);
      }
      if (heldVersion !== this.heldVersion) {
        heldVersion = this.heldVersion;
        held = new Set();
        if (this.held && documentContextsMatch(this.held.context, context))
          for (const entry of this.held.frames)
            held.add(
              `${entry.author}:${entry.sequence}:${documentBytesId(entry.hash)}`,
            );
      }
      const accepted = receipts.get(author);
      const last = accepted?.sequence ?? 0;
      return (
        sequence < last ||
        (sequence === last && documentBytesEqual(hash, accepted!.hash)) ||
        held.has(`${author}:${sequence}:${documentBytesId(hash)}`)
      );
    };
  }

  /**
   * Give frames another turn at the end of the queue. They are charged again;
   * the frames after the first that finds no capacity are dropped.
   */
  private retryFrames(frames: readonly AdmittedFrame[]): void {
    const releases: Array<() => void> = [];
    const release = () => {
      for (const value of releases.splice(0).reverse()) value();
    };
    // Frames that find capacity keep their turn in sequence order.
    let fitting = 0;
    for (const value of frames) {
      let shared: (() => void) | undefined;
      try {
        shared = aggregateInbound.reserve(2 * value.frame.length);
        releases.push(this.inbound.reserve(2 * value.frame.length), shared);
      } catch {
        shared?.();
        break;
      }
      fitting++;
    }
    if (fitting === 0) return;
    const turns = frames.slice(0, fitting);
    const local = documentBytesId(this.options.coordinator.localMemberId);
    let own = turns.filter((value) => value.author === local).length;
    this.ownFramesPending += own;
    const result = this.tail
      .then(async () => {
        const delivered = this.deliveryCheck(turns[0].context);
        for (const value of turns) {
          await this.serveLocal();
          this.assertUsable();
          try {
            if (!delivered(value)) await this.receiveOwned(value.frame, value);
          } catch {
            // Its later frames are still tried and may be held as gaps.
          } finally {
            if (value.author === local) {
              own--;
              this.ownFramesPending--;
            }
          }
        }
      })
      .finally(() => {
        this.ownFramesPending -= own;
        release();
      });
    this.tail = result.then(
      () => {},
      () => {},
    );
  }

  private async receiveOwned(
    frame: Uint8Array,
    decrypted?: AdmittedFrame,
  ): Promise<boolean> {
    try {
      if ((await this.apply(frame, undefined, '', decrypted)).length === 0)
        return false;
    } catch (error) {
      if (!(error instanceof HeldDocumentFrame)) throw error;
      this.hold(frame, error);
      return false;
    }
    this.appliedFrames++;
    await this.releaseHeld();
    return true;
  }

  /**
   * Keep a bounded set of authenticated frames until their predecessors
   * apply. Each author may hold half of a document's held frames and bytes
   * and a quarter of the process-wide bound. A frame expires two minutes after
   * it was held. When a bound is reached, the author occupying the largest
   * share of it gives up its farthest-ahead frame, in any document for the
   * process-wide bound, so no author can starve the others. Evictions are
   * planned first and applied only if the frame is then admitted; a frame
   * farther ahead than everything its author holds is refused instead.
   */
  private hold(frame: Uint8Array, pending: HeldDocumentFrame): void {
    this.assertUsable();
    if (
      !this.held ||
      !documentContextsMatch(this.held.context, pending.context)
    ) {
      this.clearHeld();
      const held: HeldFrames = {
        context: pending.context,
        frames: [],
        bytes: 0,
        remove: (entry) => this.removeHeld(held, entry),
      };
      this.held = held;
      this.heldVersion++;
    }
    const held = this.held;
    this.expireHeld(held);
    const same = held.frames.find(
      (entry) =>
        entry.author === pending.author && entry.sequence === pending.sequence,
    );
    if (same) {
      if (!documentBytesEqual(same.hash, pending.hash))
        throw new Error('Document author equivocated');
      same.reason = pending.reason;
      same.ready = pending.ready;
      same.attemptedAt = this.appliedFrames;
      return;
    }
    const length = frame.length;
    const victims = new Set<HeldFrame>();
    const refuse = () =>
      new Error('Document frames waiting for predecessors exceed their bound');
    const local = (author: string) => {
      let frames = author === pending.author ? 1 : 0,
        bytes = author === pending.author ? length : 0;
      for (const entry of held.frames)
        if (entry.author === author && !victims.has(entry)) {
          frames++;
          bytes += entry.frame.length;
        }
      return { frames, bytes };
    };
    const ownFarther = () => {
      const farthest = farthestHeld(held.frames, pending.author, victims);
      return farthest && farthest.sequence > pending.sequence
        ? farthest
        : undefined;
    };
    const take = (entry: HeldFrame | undefined) => {
      if (!entry) throw refuse();
      victims.add(entry);
    };
    const freed = (author?: string) => {
      let frames = 0,
        bytes = 0;
      for (const entry of victims)
        if (author === undefined || entry.author === author) {
          frames++;
          bytes += entry.frame.length;
        }
      return { frames, bytes };
    };
    // The author's own share of this document: only its farther frames go.
    for (
      let own = local(pending.author);
      own.frames > MAX_HELD_FRAMES_PER_AUTHOR ||
      own.bytes > MAX_HELD_BYTES_PER_AUTHOR;
      own = local(pending.author)
    )
      take(ownFarther());
    // The document bound: the author with the largest share gives way.
    for (;;) {
      const removed = freed();
      if (
        held.frames.length - removed.frames < MAX_HELD_FRAMES &&
        held.bytes - removed.bytes + length <= MAX_HELD_BYTES
      )
        break;
      let author = pending.author,
        most = local(pending.author);
      for (const entry of held.frames) {
        if (victims.has(entry)) continue;
        const usage = local(entry.author);
        if (
          heavier(
            usage,
            most,
            MAX_HELD_FRAMES_PER_AUTHOR,
            MAX_HELD_BYTES_PER_AUTHOR,
          )
        ) {
          most = usage;
          author = entry.author;
        }
      }
      take(
        author === pending.author
          ? ownFarther()
          : farthestHeld(held.frames, author, victims),
      );
    }
    // The author's process-wide share: only its farther frames here go.
    const authorFrames = aggregateHeld.maxOperations / 4,
      authorBytes = aggregateHeld.maxBytes / 4;
    const processUsage = (author: string) => {
      const usage = aggregateHeldAuthors.get(author)?.usage;
      const removed = freed(author);
      return {
        frames:
          (usage?.operations ?? 0) -
          removed.frames +
          (author === pending.author ? 1 : 0),
        bytes:
          (usage?.bytes ?? 0) -
          removed.bytes +
          (author === pending.author ? length : 0),
      };
    };
    for (
      let own = processUsage(pending.author);
      own.frames > authorFrames || own.bytes > authorBytes;
      own = processUsage(pending.author)
    )
      take(ownFarther());
    // The shared bound: the author with the largest process-wide share gives
    // up its farthest frame in the document where it holds the most.
    for (;;) {
      const usage = aggregateHeld.usage,
        removed = freed();
      if (
        usage.operations - removed.frames < aggregateHeld.maxOperations &&
        usage.bytes - removed.bytes + length <= aggregateHeld.maxBytes
      )
        break;
      let author = pending.author,
        most = processUsage(pending.author);
      for (const candidate of aggregateHeldAuthors.keys()) {
        const usage = processUsage(candidate);
        if (heavier(usage, most, authorFrames, authorBytes)) {
          most = usage;
          author = candidate;
        }
      }
      if (author === pending.author) {
        take(ownFarther());
        continue;
      }
      let victim: HeldFrame | undefined,
        heaviest = 0;
      for (const document of heldDocuments) {
        let bytes = 0;
        for (const entry of document.frames)
          if (entry.author === author && !victims.has(entry))
            bytes += entry.frame.length;
        if (bytes > heaviest) {
          heaviest = bytes;
          victim = farthestHeld(document.frames, author, victims);
        }
      }
      take(victim);
    }
    for (const entry of victims) entry.holder.remove(entry);
    const release = reserveHeld(pending.author, length);
    if (typeof release !== 'function') throw refuse();
    this.heldVersion++;
    held.frames.push({
      frame,
      author: pending.author,
      sequence: pending.sequence,
      hash: pending.hash,
      heldAt: performance.now(),
      holder: held,
      release,
      reason: pending.reason,
      attemptedAt: this.appliedFrames,
      ready: pending.ready,
    });
    held.bytes += length;
    heldDocuments.add(held);
    this.heldAdded++;
    this.scheduleExpiry();
  }

  /** Increases each time a frame starts waiting for its predecessors. */
  get heldGeneration(): number {
    return this.heldAdded;
  }

  private removeHeld(held: HeldFrames, entry: HeldFrame): void {
    const index = held.frames.indexOf(entry);
    if (index === -1) return;
    held.frames.splice(index, 1);
    this.heldVersion++;
    held.bytes -= entry.frame.length;
    entry.release();
    if (held.frames.length === 0) heldDocuments.delete(held);
    if (this.held === held) this.scheduleExpiry();
  }

  private expireHeld(held: HeldFrames): void {
    const now = performance.now();
    for (const entry of [...held.frames])
      if (!(now - entry.heldAt < HELD_FRAME_TTL_MS))
        this.removeHeld(held, entry);
  }

  /** Expire held frames on time even in a document that receives nothing. */
  private scheduleExpiry(): void {
    if (this.heldTimer !== undefined) clearTimeout(this.heldTimer);
    this.heldTimer = undefined;
    const held = this.held;
    if (!held || held.frames.length === 0) return;
    let earliest = Infinity;
    for (const entry of held.frames)
      earliest = Math.min(earliest, entry.heldAt);
    const timer = setTimeout(
      () => {
        if (this.heldTimer !== timer) return;
        this.heldTimer = undefined;
        if (this.held === held) this.expireHeld(held);
        this.scheduleExpiry();
      },
      Math.max(0, earliest + HELD_FRAME_TTL_MS - performance.now()),
    );
    this.heldTimer = timer;
    (timer as { unref?: () => void }).unref?.();
  }

  private clearHeld(): void {
    const held = this.held;
    this.held = undefined;
    this.heldVersion++;
    if (held) {
      heldDocuments.delete(held);
      for (const entry of held.frames.splice(0)) entry.release();
      held.bytes = 0;
    }
    if (this.heldTimer !== undefined) clearTimeout(this.heldTimer);
    this.heldTimer = undefined;
  }

  /** Apply held frames that an accepted frame or checkpoint made admissible. */
  private async releaseHeld(): Promise<void> {
    for (let progressed = true; progressed; ) {
      progressed = false;
      const held = this.held;
      if (!held || held.frames.length === 0) return;
      if (
        !documentContextsMatch(
          held.context,
          this.options.coordinator.documentContext,
        )
      ) {
        this.clearHeld();
        return;
      }
      const candidates = [...held.frames].sort(
        (a, b) => a.sequence - b.sequence,
      );
      for (const entry of candidates) {
        if (!held.frames.includes(entry)) continue;
        const accepted =
          this.receiptsAt(held.context).get(entry.author)?.sequence ?? 0;
        // Retry only when the author's prefix or a named dependency arrived.
        if (
          entry.sequence > accepted &&
          (entry.reason === 'gap'
            ? entry.sequence !== accepted + 1
            : entry.ready
              ? !dependencyReady(entry.ready)
              : entry.attemptedAt === this.appliedFrames)
        )
          continue;
        let applied = false,
          keep = false;
        try {
          applied = (await this.apply(entry.frame)).length !== 0;
        } catch (error) {
          if (error instanceof HeldDocumentFrame) {
            entry.reason = error.reason;
            entry.ready = error.ready;
            entry.attemptedAt = this.appliedFrames;
            keep = true;
          }
        }
        if (this.held !== held) return;
        if (keep) continue;
        this.removeHeld(held, entry);
        if (applied) {
          this.appliedFrames++;
          this.heldApplied++;
          progressed = true;
        }
      }
    }
    // Expire only what the retries above left held.
    if (this.held) this.expireHeld(this.held);
  }

  /** Keep each author's latest accepted frames in the current context, bounded. */
  private retain(
    context: GroupSecurityDocumentContext,
    author: string,
    value: Omit<RetainedFrame, 'order' | 'observedAt'>,
  ): void {
    if (
      !this.retained ||
      !documentContextsMatch(this.retained.context, context)
    ) {
      this.dropRetained();
      this.retained = { context, authors: new Map(), bytes: 0, order: 0 };
    }
    const retained = this.retained;
    const size = (frame: Pick<RetainedFrame, 'signed' | 'frame'>) =>
      frame.signed.length + frame.frame.length;
    const frames = retained.authors.get(author) ?? [];
    frames.push({ ...value, order: retained.order++, observedAt: Date.now() });
    retained.authors.set(author, frames);
    retained.bytes += size(value);
    retainedProcessBytes += size(value);
    const evict = (owner: string) => {
      const list = retained.authors.get(owner)!;
      const [oldest] = list.splice(0, 1);
      retained.bytes -= size(oldest);
      retainedProcessBytes -= size(oldest);
      if (list.length === 0) retained.authors.delete(owner);
    };
    if (frames.length > MAX_RETAINED_FRAMES_PER_AUTHOR) evict(author);
    // Over budget, the author holding the most bytes gives up its oldest frame.
    while (
      retained.bytes > 0 &&
      (retained.bytes > MAX_RETAINED_BYTES ||
        retainedProcessBytes > MAX_RETAINED_PROCESS_BYTES)
    ) {
      let owner: string | undefined,
        most = -1;
      for (const [id, list] of retained.authors) {
        const bytes = list.reduce((total, frame) => total + size(frame), 0);
        if (bytes > most) [owner, most] = [id, bytes];
      }
      evict(owner!);
    }
  }

  private dropRetained(): void {
    retainedProcessBytes -= this.retained?.bytes ?? 0;
    this.retained = undefined;
  }

  /** Retained frames of `author` after `sequence`, if they form its complete suffix. */
  private retainedSuffix(
    context: GroupSecurityDocumentContext,
    author: string,
    sequence: number,
    hash: Uint8Array,
    head: number,
  ): RetainedFrame[] | undefined {
    const retained = this.retained;
    if (!retained) return undefined;
    if (!documentContextsMatch(retained.context, context)) {
      if (!documentContextsMatch(context, this.options.coordinator.documentContext))
        return undefined;
      this.dropRetained();
      return undefined;
    }
    const frames = retained.authors.get(author) ?? [];
    const base = frames.find((frame) => frame.sequence === sequence);
    if (base && !documentBytesEqual(base.hash, hash)) return undefined;
    const suffix = frames.filter((frame) => frame.sequence > sequence);
    if (
      suffix.length !== head - sequence ||
      suffix.some((frame, index) => frame.sequence !== sequence + index + 1)
    )
      return undefined;
    return suffix;
  }

  private observeRetained(
    context: GroupSecurityDocumentContext,
    author: string,
    sequence: number,
  ): void {
    if (!this.retained || !documentContextsMatch(this.retained.context, context))
      return;
    const entry = this.retained.authors
      .get(author)
      ?.find((frame) => frame.sequence === sequence);
    if (entry) entry.observedAt = Date.now();
  }

  /**
   * Note copies of accepted frames at `context` that admission dropped before
   * verification; only the exact retained frame counts. The context is
   * matched once, and an author's retained frames are consecutive, so each
   * copy is found by its sequence.
   */
  private copyObserver(
    context: GroupSecurityDocumentContext,
  ): (author: string, sequence: number, copy: Uint8Array) => void {
    const retained =
      this.retained && documentContextsMatch(this.retained.context, context)
        ? this.retained
        : undefined;
    if (!retained) return () => {};
    const now = Date.now();
    return (author, sequence, copy) => {
      const frames = retained.authors.get(author);
      const entry = frames?.[sequence - frames[0].sequence];
      if (entry?.sequence === sequence && documentBytesEqual(entry.frame, copy))
        entry.observedAt = now;
    };
  }

  hasHeldFrames(): boolean {
    return (this.held?.frames.length ?? 0) > 0;
  }

  /** Run a signed exchange against the current authority outside the content path. */
  private async runSealed<Value>(
    input: Uint8Array,
    prepare: (stage: SealedStage, input: Uint8Array) => Promise<Value>,
  ): Promise<Value> {
    let value!: Value;
    let preparation: Promise<PreparedGroupDocumentOperation> | undefined;
    try {
      await this.options.coordinator.runDocumentOperation(
        this.options.coordinator.documentContext,
        input,
        (captured, owned, signal, work) => {
          preparation = (async () => {
            const lease = this.authority(captured);
            const roster = this.options.requireGroupRosterMatch
              ? await this.prepareGroupRoster(captured, lease, work)
              : undefined;
            this.assertCurrentGroupRoster(roster);
            const staged = await prepare(
              {
                binding: {
                  documentId: this.documentId,
                  genesisId: this.genesisId,
                  authorityHead: lease.headId,
                  context: captured,
                },
                lease,
                material: await this.key(captured, work),
                work,
              },
              owned,
            );
            return {
              isAuthorizationCurrent: () =>
                !signal.aborted &&
                !this.closed &&
                !this.failed &&
                lease.isCurrent(),
              commit: () => {
                value = staged;
              },
            };
          })();
          return preparation;
        },
      );
      return value;
    } finally {
      await preparation?.then(
        () => {},
        () => {},
      );
    }
  }

  /** Seal this member's accepted heads for peers to resend what it lacks. */
  createRedeliveryRequest(requesterPeer: string): Promise<Uint8Array> {
    return this.enqueue(0, () => async () => {
      this.assertActivated();
      return this.runSealed(new Uint8Array(), async (stage) => {
        const requesterId = this.options.coordinator.localMemberId;
        const member = stage.lease.members.get(documentBytesId(requesterId));
        if (!member) throw new Error('Local member has no document authority');
        return this.sealSigned(
          stage,
          documentRedeliveryAAD(stage.binding),
          encodeDocumentRedeliveryRequest({
            ...stage.binding,
            requesterId,
            requesterPeer,
            nonce: crypto.getRandomValues(new Uint8Array(16)),
            issuedAt: Date.now(),
            receipts: receiptEntries(this.sortedReceipts(stage.binding.context)),
            held: (this.held &&
            documentContextsMatch(this.held.context, stage.binding.context)
              ? [...this.held.frames]
              : []
            )
              .sort((a, b) =>
                a.author < b.author ? -1 : a.author > b.author ? 1 : a.sequence - b.sequence,
              )
              .slice(0, MAX_DOCUMENT_REDELIVERY_HELD)
              .map(({ author, sequence }) => ({
                memberId: Uint8Array.from(author.match(/../g)!, (byte) =>
                  parseInt(byte, 16),
                ),
                sequence,
              })),
          }),
          member,
          encodeEncryptedDocumentRedelivery,
        );
      });
    }, false, true);
  }

  /**
   * Authenticate a current member's request that GossipSub delivered from
   * `from`, and choose the retained frames past its heads to resend. The
   * request is authenticated outside the document queue and charged against
   * the received bounds and the sender's share, never the local edit budget.
   * Requests are answered once, at most every 2 s per member, and within a
   * shared per-replica frame budget.
   */
  async answerRedelivery(
    frame: Uint8Array,
    from: string | undefined,
  ): Promise<CoordinatedRedeliveryAnswer> {
    const length = unsharedUint8ArrayByteLength(
      frame,
      1,
      MAX_DOCUMENT_REDELIVERY_REQUEST_BYTES + 64,
      'document redelivery request',
    );
    if (from !== undefined && (typeof from !== 'string' || from.length > 1024))
      throw new TypeError('Invalid document frame sender');
    this.assertUsable();
    this.assertActivated();
    this.assertPublicationDispatchAllowed(this.rosterBinding, false);
    const releases: Array<() => void> = [];
    try {
      releases.push(aggregateInbound.reserve(length));
      releases.push(this.inbound.reserve(length));
      releases.push(
        reserveSender(
          this.senders,
          from ?? '',
          length,
          SENDER_FRAMES,
          SENDER_BYTES,
        ),
      );
      const envelope = decodeEncryptedDocumentRedelivery(
        copyUnsharedUint8Array(
          frame,
          length,
          length,
          'document redelivery request',
        ),
      );
      const context = this.options.coordinator.documentContext;
      const lease = this.authority(context);
      const binding: DocumentCatchUpBinding = {
        documentId: this.documentId,
        genesisId: this.genesisId,
        authorityHead: lease.headId,
        context,
      };
      const material = await this.materialFor(context);
      if (!documentBytesEqual(envelope.epochTag, material.epochTag))
        throw new Error('Document redelivery epoch is unavailable');
      let plaintext: Uint8Array;
      try {
        plaintext = new Uint8Array(
          await crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: envelope.nonce as Uint8Array<ArrayBuffer>,
              additionalData: documentRedeliveryAAD(
                binding,
              ) as Uint8Array<ArrayBuffer>,
            },
            material.key,
            envelope.ciphertext as Uint8Array<ArrayBuffer>,
          ),
        );
      } catch {
        throw new Error('Document redelivery request does not decrypt');
      }
      const signed = decodeSignedDocumentContent(plaintext);
      const body = decodeDocumentRedeliveryRequest(signed.unsigned);
      this.assertCatchUpBinding(binding, body);
      if (from === undefined || body.requesterPeer !== from)
        throw new Error('Document redelivery request is not from its signer');
      const requesterId = documentBytesId(body.requesterId);
      const requester = lease.members.get(requesterId);
      if (
        !requester ||
        documentBytesEqual(body.requesterId, this.options.coordinator.localMemberId)
      )
        throw new Error('Document redelivery requester is unauthorized');
      // Stale or replayed requests are refused before their signature check.
      if (Math.abs(Date.now() - body.issuedAt) > REDELIVERY_FRESHNESS_MS) {
        this.staleRedeliveries++;
        return this.noRedelivery(lease, requesterId);
      }
      if (body.issuedAt <= (this.redelivery.issued.get(requesterId) ?? -1))
        return this.noRedelivery(lease, requesterId);
      await this.verifySigned(signed, requester);
      this.assertPublicationDispatchAllowed(this.rosterBinding, false);
      if (
        !lease.isCurrent() ||
        !documentContextsMatch(context, this.options.coordinator.documentContext)
      )
        throw new Error('Document redelivery request is no longer current');
      return this.chooseRedelivery({ binding, lease }, requesterId, body);
    } finally {
      for (const release of releases.reverse()) release();
    }
  }

  private noRedelivery(
    lease: AuthorityLease,
    requester: string,
  ): CoordinatedRedeliveryAnswer {
    const local = documentBytesId(this.options.coordinator.localMemberId);
    const peers = [...lease.members.keys()]
      .filter((id) => id !== requester)
      .sort();
    return { own: [], others: [], since: Date.now(), rank: Math.max(0, peers.indexOf(local)) };
  }

  private chooseRedelivery(
    stage: Pick<SealedStage, 'binding' | 'lease'>,
    requester: string,
    body: DocumentRedeliveryRequest,
  ): CoordinatedRedeliveryAnswer {
    const context = stage.binding.context;
    const now = Date.now();
    const local = documentBytesId(this.options.coordinator.localMemberId);
    const peers = [...stage.lease.members.keys()]
      .filter((id) => id !== requester)
      .sort();
    const rank = Math.max(0, peers.indexOf(local));
    const none = { own: [], others: [], since: now, rank };
    const state = this.redelivery;
    // A signed, strictly newer and fresh issue time makes a captured request useless later.
    if (
      body.issuedAt <= (state.issued.get(requester) ?? -1) ||
      Math.abs(now - body.issuedAt) > REDELIVERY_FRESHNESS_MS
    ) {
      if (Math.abs(now - body.issuedAt) > REDELIVERY_FRESHNESS_MS)
        this.staleRedeliveries++;
      return none;
    }
    state.issued.set(requester, body.issuedAt);
    const bound = (map: Map<string, number>) => {
      if (map.size > 256) map.delete(map.keys().next().value!);
    };
    bound(state.issued);
    if (now - (state.answered.get(requester) ?? -Infinity) < REDELIVERY_REQUESTER_INTERVAL_MS)
      return none;
    state.answered.set(requester, now);
    bound(state.answered);
    state.tokens = Math.min(
      REDELIVERY_RESPONSE_FRAMES,
      state.tokens +
        (Math.max(0, now - state.refilledAt) * REDELIVERY_FRAMES_PER_SECOND) / 1000,
    );
    state.refilledAt = now;
    const receipts = body.receipts;
    const skip = new Set(
      body.held.map(
        ({ memberId, sequence }) => `${documentBytesId(memberId)}:${sequence}`,
      ),
    );
    const heads = new Map(
      receipts.map((receipt) => [documentBytesId(receipt.memberId), receipt]),
    );
    const accepted = this.sortedReceipts(context);
    const own: Uint8Array[] = [];
    const others: { author: string; sequence: number }[] = [];
    let bytes = 0;
    for (const [author, { sequence: head }] of accepted) {
      if (author === requester) continue;
      const known = heads.get(author);
      const suffix = this.retainedSuffix(
        context,
        author,
        known?.sequence ?? 0,
        known?.hash ?? ZERO_HASH,
        head,
      );
      for (const entry of suffix ?? []) {
        if (skip.has(`${author}:${entry.sequence}`)) continue;
        if (
          state.tokens < 1 ||
          own.length + others.length >= REDELIVERY_RESPONSE_FRAMES ||
          bytes + entry.frame.length > REDELIVERY_RESPONSE_BYTES
        )
          return { own, others, since: now, rank };
        state.tokens--;
        bytes += entry.frame.length;
        if (author === local) {
          entry.observedAt = now;
          own.push(entry.frame.slice());
        }
        else others.push({ author, sequence: entry.sequence });
      }
    }
    return { own, others, since: now, rank };
  }

  /** Frames from an answer that no other replica has resent since `since`. */
  unansweredRedeliveries(answer: CoordinatedRedeliveryAnswer): Uint8Array[] {
    const retained = this.retained;
    if (!retained) return [];
    return answer.others.flatMap(({ author, sequence }) => {
      const entry = retained.authors
        .get(author)
        ?.find((frame) => frame.sequence === sequence);
      if (!entry || entry.observedAt > answer.since) return [];
      // This replica does not receive its own publications, so mark them here.
      entry.observedAt = Date.now();
      return [entry.frame.slice()];
    });
  }

  /**
   * Requests sealed under the current epoch key and ignored, before their
   * signature check, because their issue time was over 60 s from this clock.
   */
  get staleRedeliveryRequests(): number {
    return this.staleRedeliveries;
  }

  createCatchUpRequest(): Promise<Uint8Array> {
    return this.enqueueCatchUp(undefined, 0, 0, (input) =>
      this.runCatchUp(input, async (stage) => {
        const requesterId = this.options.coordinator.localMemberId;
        const member = stage.lease.members.get(documentBytesId(requesterId));
        if (!member) throw new Error('Local member has no document authority');
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const value = await this.sealCatchUp(
          stage,
          'request',
          encodeDocumentCatchUpRequest({
            ...stage.binding,
            requesterId,
            challenge,
            receipts: receiptEntries(this.sortedReceipts(stage.binding.context)),
          }),
          member,
        );
        return {
          value,
          commit: () => {
            this.pendingCatchUp = { roster: stage.roster, challenge };
          },
        };
      }),
    );
  }

  createCatchUpCheckpoint(request: Uint8Array): Promise<Uint8Array> {
    return this.enqueueCatchUp(
      request,
      MAX_DOCUMENT_CATCH_UP_REQUEST_BYTES,
      MAX_DOCUMENT_CONTENT_BYTES + MAX_DOCUMENT_SECURITY_FRAME_BYTES,
      (input) =>
        this.runCatchUp(input, async (stage) => {
          const controllerId = this.options.coordinator.localMemberId;
          this.catchUpController(stage.lease, controllerId);
          const signed = await this.openCatchUp(stage, 'request', input);
          const body = decodeDocumentCatchUpRequest(signed.unsigned);
          this.assertCatchUpBinding(stage.binding, body);
          const requester = stage.lease.members.get(
            documentBytesId(body.requesterId),
          );
          if (!requester || documentBytesEqual(body.requesterId, controllerId))
            throw new Error('Document catch-up requester is unauthorized');
          await this.verifyCatchUp(stage, signed, requester);
          return { value: await this.sealCheckpoint(stage, body, 'checkpoint') };
        }),
    );
  }

  /** Seal the current state, with signed suffixes past the requester's heads, for an authenticated request. */
  private async sealCheckpoint(
    stage: CatchUpWork,
    body: DocumentCatchUpRequest,
    kind: 'checkpoint' | 'topic-checkpoint',
  ): Promise<Uint8Array> {
    const controllerId = this.options.coordinator.localMemberId;
    const controller = this.catchUpController(stage.lease, controllerId);
    stage.assertCurrent();
    const receipts = this.sortedReceipts(stage.binding.context);
    const snapshot = this.serializer.serializeChanges(
      this.crdt.getSnapshot!(this.session.document),
    );
    if (kind === 'topic-checkpoint' && snapshot.length > MAX_DOCUMENT_CONTENT_BYTES) {
      this.oversized = { version: this.contentVersion, bytes: snapshot.length };
      return this.sealRefusal(stage, body, {
        reason: 'snapshot-too-large',
        snapshotBytes: snapshot.length,
      });
    }
    const base = {
      documentId: body.documentId,
      genesisId: body.genesisId,
      authorityHead: body.authorityHead,
      context: body.context,
      requesterId: body.requesterId,
      challenge: body.challenge,
      controllerId,
      receipts: receiptEntries(receipts),
      suffixes: [],
      snapshot,
    };
    const { offered, suffixes } = this.catchUpSuffixes(
      stage.binding.context,
      receipts,
      body.receipts,
      body.requesterId,
      MAX_DOCUMENT_SECURITY_FRAME_BYTES -
        CHECKPOINT_SEAL_BYTES -
        encodeDocumentCatchUpCheckpoint(base, kind).length,
    );
    return this.sealCatchUp(
      stage,
      kind,
      encodeDocumentCatchUpCheckpoint(
        { ...base, receipts: receiptEntries(offered), suffixes },
        kind,
      ),
      controller,
    );
  }

  /** Seal the controller's signed answer that sends no checkpoint for a topic request. */
  private sealRefusal(
    stage: CatchUpWork,
    body: DocumentCatchUpRequest,
    refusal: CoordinatedCatchUpRefusal,
  ): Promise<Uint8Array> {
    const controllerId = this.options.coordinator.localMemberId;
    const controller = this.catchUpController(stage.lease, controllerId);
    stage.assertCurrent();
    return this.sealCatchUp(
      stage,
      'topic-refusal',
      encodeDocumentCatchUpRefusal({
        documentId: body.documentId,
        genesisId: body.genesisId,
        authorityHead: body.authorityHead,
        context: body.context,
        requesterId: body.requesterId,
        challenge: body.challenge,
        controllerId,
        reason: refusal.reason,
        snapshotBytes:
          refusal.reason === 'snapshot-too-large' ? refusal.snapshotBytes : 0,
      }),
      controller,
    );
  }

  /** The application's decision for a member's topic request; failures refuse it. */
  private async authorizesCatchUp(memberId: Uint8Array): Promise<boolean> {
    const authorize = this.options.authorizeCatchUp;
    if (!authorize) return true;
    try {
      return (await authorize(memberId.slice())) === true;
    } catch {
      return false;
    }
  }

  applyCatchUpCheckpoint(checkpoint: Uint8Array): Promise<void> {
    return this.enqueueCatchUp(
      checkpoint,
      MAX_DOCUMENT_SECURITY_FRAME_BYTES,
      MAX_DOCUMENT_CONTENT_BYTES,
      async (input) => {
        const pending = this.pendingCatchUp;
        if (!pending) throw new Error('No document catch-up request is pending');
        await this.mergeCatchUpCheckpoint(
          input,
          'checkpoint',
          pending,
          () => this.pendingCatchUp === pending,
          () => {
            this.pendingCatchUp = undefined;
          },
        );
        this.appliedFrames++;
        await this.releaseHeld();
      },
    );
  }

  /** Whether this replica opened, or a role update reached it, without content, and no checkpoint merged since. */
  needsJoinCatchUp(): boolean {
    return this.joining && this.canRequestCatchUp();
  }

  /**
   * Whether this open replica may ask the controller for a checkpoint: it is a
   * current member other than the controller, and the controller has not
   * refused it since the last explicit request.
   */
  canRequestCatchUp(): boolean {
    if (
      !this.options.enableAuthenticatedCatchUp ||
      this.catchUpRefusal !== undefined ||
      !this.activated ||
      this.closed ||
      this.failed ||
      this.diverged
    )
      return false;
    try {
      const lease = this.authority(this.options.coordinator.documentContext);
      return (
        lease.members.has(
          documentBytesId(this.options.coordinator.localMemberId),
        ) && !this.controlsCatchUp(lease)
      );
    } catch {
      return false;
    }
  }

  /** Ask again after the controller refused; the application decides when. */
  resumeCatchUp(): void {
    this.catchUpRefusal = undefined;
  }

  get topicCatchUpEnabled(): boolean {
    return this.options.enableAuthenticatedCatchUp === true;
  }

  /** Increases each time a held frame applies. */
  get heldProgress(): number {
    return this.heldApplied;
  }

  /**
   * Topic catch-up requests ignored, before their signature check, because
   * their issue time was over 60 s from this clock.
   */
  get staleCatchUpRequests(): number {
    return this.staleCatchUps;
  }

  /**
   * Seal a request for the current controller to answer on the document
   * topic, bound to this node's libp2p PeerId. Up to four requests stay
   * outstanding; the first checkpoint merged for any of them retires all.
   */
  createTopicCatchUpRequest(requesterPeer: string): Promise<Uint8Array> {
    return this.enqueueCatchUp(
      undefined,
      0,
      0,
      (input) =>
        this.runCatchUp(input, async (stage) => {
          const requesterId = this.options.coordinator.localMemberId;
          const member = stage.lease.members.get(documentBytesId(requesterId));
          if (!member) throw new Error('Local member has no document authority');
          if (this.controlsCatchUp(stage.lease))
            throw new Error('The document controller has no catch-up source');
          const challenge = crypto.getRandomValues(new Uint8Array(32));
          const issuedAt = Date.now();
          const value = await this.sealCatchUp(
            stage,
            'topic-request',
            encodeDocumentTopicCatchUpRequest({
              ...stage.binding,
              requesterId,
              challenge,
              requesterPeer,
              issuedAt,
              receipts: receiptEntries(this.sortedReceipts(stage.binding.context)),
            }),
            member,
          );
          return {
            value,
            commit: () => {
              this.topicCatchUps = [
                ...this.topicCatchUps.slice(1 - MAX_TOPIC_CATCH_UPS),
                { roster: stage.roster, challenge, issuedAt },
              ];
            },
          };
        }),
      true,
    );
  }

  /**
   * Answer a current member's topic request, which GossipSub delivered from
   * `from`, with an encrypted checkpoint for the topic. Only the unrestricted
   * current controller answers; other replicas drop the request before
   * decrypting it. The request is authenticated outside the document queue and
   * charged against the received bounds and the sender's share. A fresh issue
   * time newer than the member's last is required, a member gets at most one
   * checkpoint every 10 s, and all documents in the process share a budget.
   */
  async answerTopicCatchUp(
    frame: Uint8Array,
    from: string | undefined,
  ): Promise<Uint8Array | undefined> {
    const length = unsharedUint8ArrayByteLength(
      frame,
      1,
      MAX_DOCUMENT_CATCH_UP_TOPIC_REQUEST_BYTES + 64,
      'document catch-up request',
    );
    if (from !== undefined && (typeof from !== 'string' || from.length > 1024))
      throw new TypeError('Invalid document frame sender');
    if (!this.options.enableAuthenticatedCatchUp) return undefined;
    this.assertUsable();
    this.assertActivated();
    this.assertPublicationDispatchAllowed(this.rosterBinding, false);
    const roster = this.rosterBinding!;
    const context = this.options.coordinator.documentContext;
    const lease = this.authority(context);
    if (!this.controlsCatchUp(lease)) return undefined;
    let request: DocumentTopicCatchUpRequest;
    let refusal: CoordinatedCatchUpRefusal | undefined;
    const releases = this.reserveReceived(length, from);
    try {
      const envelope = decodeEncryptedDocumentCatchUp(
        'topic-request',
        copyUnsharedUint8Array(frame, length, length, 'document catch-up request'),
      );
      const binding: DocumentCatchUpBinding = {
        documentId: this.documentId,
        genesisId: this.genesisId,
        authorityHead: lease.headId,
        context,
      };
      const signed = await this.openTopicCatchUp(
        context,
        documentCatchUpAAD('topic-request', binding),
        envelope,
      );
      if (!signed) throw new Error('Document catch-up request does not decrypt');
      const body = decodeDocumentTopicCatchUpRequest(signed.unsigned);
      this.assertCatchUpBinding(binding, body);
      if (from === undefined || body.requesterPeer !== from)
        throw new Error('Document catch-up request is not from its signer');
      const requesterId = documentBytesId(body.requesterId);
      const requester = lease.members.get(requesterId);
      if (
        !requester ||
        documentBytesEqual(body.requesterId, this.options.coordinator.localMemberId)
      )
        throw new Error('Document catch-up requester is unauthorized');
      const state = this.catchUpAnswer;
      const stale = () =>
        Math.abs(Date.now() - body.issuedAt) > REDELIVERY_FRESHNESS_MS;
      const replayed = () =>
        body.issuedAt <= (state.issued.get(requesterId) ?? -1);
      // Stale or replayed requests are refused before their signature check.
      if (stale()) {
        this.staleCatchUps++;
        return undefined;
      }
      if (replayed()) return undefined;
      await this.verifySigned(signed, requester);
      if (
        !lease.isCurrent() ||
        this.rosterBinding !== roster ||
        !documentContextsMatch(context, this.options.coordinator.documentContext)
      )
        throw new Error('Document catch-up request is no longer current');
      if (stale() || replayed()) return undefined;
      state.issued.set(requesterId, body.issuedAt);
      boundRecent(state.issued);
      if (
        Date.now() - (state.answered.get(requesterId) ?? -Infinity) <
        CATCH_UP_MEMBER_INTERVAL_MS
      )
        return undefined;
      const authorized = await this.authorizesCatchUp(body.requesterId);
      if (
        !lease.isCurrent() ||
        this.rosterBinding !== roster ||
        !documentContextsMatch(context, this.options.coordinator.documentContext)
      )
        throw new Error('Document catch-up request is no longer current');
      const now = Date.now();
      if (now - (state.answered.get(requesterId) ?? -Infinity) < CATCH_UP_MEMBER_INTERVAL_MS)
        return undefined;
      if (!authorized) refusal = { reason: 'denied' };
      else if (this.oversized?.version === this.contentVersion)
        refusal = {
          reason: 'snapshot-too-large',
          snapshotBytes: this.oversized.bytes,
        };
      else if (!takeCatchUpAnswer(this.catchUpShare, now)) return undefined;
      state.answered.set(requesterId, now);
      boundRecent(state.answered);
      request = body;
    } finally {
      for (const release of releases.reverse()) release();
    }
    const work = this.reserveReceived(
      MAX_DOCUMENT_CONTENT_BYTES + MAX_DOCUMENT_SECURITY_FRAME_BYTES,
      from,
    );
    try {
      return await this.receivedTurn(() =>
        this.runCatchUp(new Uint8Array(), async (stage) => {
          if (stage.roster !== roster)
            throw new Error('Document catch-up authority changed');
          this.assertCatchUpBinding(stage.binding, request);
          return {
            value: refusal
              ? await this.sealRefusal(stage, request, refusal)
              : await this.sealCheckpoint(stage, request, 'topic-checkpoint'),
          };
        }),
      );
    } finally {
      for (const release of work.reverse()) release();
    }
  }

  /**
   * Merge a checkpoint carried on the topic that answers one of this
   * replica's outstanding requests. A replica with none drops it unread.
   */
  async receiveTopicCatchUp(
    frame: Uint8Array,
    from: string | undefined,
  ): Promise<boolean> {
    const length = unsharedUint8ArrayByteLength(
      frame,
      1,
      MAX_DOCUMENT_SECURITY_FRAME_BYTES,
      'document catch-up checkpoint',
    );
    if (from !== undefined && (typeof from !== 'string' || from.length > 1024))
      throw new TypeError('Invalid document frame sender');
    if (!this.options.enableAuthenticatedCatchUp) return false;
    this.assertUsable();
    if (this.outstandingCatchUps().length === 0) return false;
    this.assertActivated();
    const releases = this.reserveReceived(
      2 * length + MAX_DOCUMENT_CONTENT_BYTES,
      from,
    );
    try {
      const owned = copyUnsharedUint8Array(
        frame,
        length,
        length,
        'document catch-up checkpoint',
      );
      const context = this.options.coordinator.documentContext;
      const signed = await this.openTopicCatchUp(
        context,
        documentCatchUpAAD('topic-checkpoint', {
          documentId: this.documentId,
          genesisId: this.genesisId,
          authorityHead: this.authority(context).headId,
          context,
        }),
        decodeEncryptedDocumentCatchUp('topic-checkpoint', owned),
      );
      if (!signed) return false;
      const body = decodeDocumentCatchUpCheckpoint(
        signed.unsigned,
        'topic-checkpoint',
      );
      const pending = this.outstandingCatchUps().find((entry) =>
        documentBytesEqual(entry.challenge, body.challenge),
      );
      if (
        !pending ||
        !documentBytesEqual(body.requesterId, this.options.coordinator.localMemberId)
      )
        return false;
      await this.receivedTurn(async () => {
        await this.mergeCatchUpCheckpoint(
          owned,
          'topic-checkpoint',
          pending,
          () => this.topicCatchUps.includes(pending),
          () => {
            this.topicCatchUps = [];
          },
        );
        this.appliedFrames++;
        await this.releaseHeld();
      });
      return true;
    } finally {
      for (const release of releases.reverse()) release();
    }
  }

  /**
   * Accept the controller's signed refusal of one of this replica's
   * outstanding requests. The replica then stops requesting until the
   * application asks again, and reports the refusal.
   */
  async receiveTopicCatchUpRefusal(
    frame: Uint8Array,
    from: string | undefined,
  ): Promise<boolean> {
    const length = unsharedUint8ArrayByteLength(
      frame,
      1,
      MAX_DOCUMENT_CATCH_UP_TOPIC_REQUEST_BYTES + 64,
      'document catch-up refusal',
    );
    if (from !== undefined && (typeof from !== 'string' || from.length > 1024))
      throw new TypeError('Invalid document frame sender');
    if (!this.options.enableAuthenticatedCatchUp) return false;
    this.assertUsable();
    if (this.outstandingCatchUps().length === 0) return false;
    this.assertActivated();
    const releases = this.reserveReceived(length, from);
    try {
      const context = this.options.coordinator.documentContext;
      const lease = this.authority(context);
      const binding: DocumentCatchUpBinding = {
        documentId: this.documentId,
        genesisId: this.genesisId,
        authorityHead: lease.headId,
        context,
      };
      const signed = await this.openTopicCatchUp(
        context,
        documentCatchUpAAD('topic-refusal', binding),
        decodeEncryptedDocumentCatchUp(
          'topic-refusal',
          copyUnsharedUint8Array(frame, length, length, 'document catch-up refusal'),
        ),
      );
      if (!signed) return false;
      const body = decodeDocumentCatchUpRefusal(signed.unsigned);
      this.assertCatchUpBinding(binding, body);
      const pending = this.outstandingCatchUps().find((entry) =>
        documentBytesEqual(entry.challenge, body.challenge),
      );
      if (
        !pending ||
        !documentBytesEqual(body.requesterId, this.options.coordinator.localMemberId)
      )
        return false;
      await this.verifySigned(
        signed,
        this.catchUpController(lease, body.controllerId),
      );
      if (!lease.isCurrent() || !this.topicCatchUps.includes(pending))
        return false;
      this.topicCatchUps = [];
      this.catchUpRefusal =
        body.reason === 'denied'
          ? { reason: 'denied' }
          : { reason: body.reason, snapshotBytes: body.snapshotBytes };
      this.reportRefusal(this.catchUpRefusal);
      return true;
    } finally {
      for (const release of releases.reverse()) release();
    }
  }

  private reportRefusal(refusal: CoordinatedCatchUpRefusal): void {
    const report = this.options.onCatchUpRefused;
    if (!report) {
      console.warn(
        refusal.reason === 'denied'
          ? `[${this.documentId}] the document controller refused catch-up for this member.`
          : `[${this.documentId}] the document snapshot is ${refusal.snapshotBytes} bytes, over the 524288 a catch-up checkpoint carries.`,
      );
      return;
    }
    try {
      report(refusal);
    } catch {
      // The application's handler cannot affect catch-up state.
    }
  }

  /** Requests still bound to the installed roster and recent enough to be answered. */
  private outstandingCatchUps(): TopicCatchUp[] {
    const now = Date.now();
    this.topicCatchUps = this.topicCatchUps.filter(
      (entry) =>
        entry.roster === this.rosterBinding &&
        Math.abs(now - entry.issuedAt) <= 2 * REDELIVERY_FRESHNESS_MS,
    );
    return this.topicCatchUps;
  }

  /** Decrypt a topic catch-up message under the current epoch, or undefined when it does not. */
  private async openTopicCatchUp(
    context: GroupSecurityDocumentContext,
    aad: Uint8Array,
    envelope: { epochTag: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array },
  ): Promise<ReturnType<typeof decodeSignedDocumentContent> | undefined> {
    const material = await this.materialFor(context);
    if (!documentBytesEqual(envelope.epochTag, material.epochTag))
      return undefined;
    let plaintext: Uint8Array;
    try {
      plaintext = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: envelope.nonce as Uint8Array<ArrayBuffer>,
            additionalData: aad as Uint8Array<ArrayBuffer>,
          },
          material.key,
          envelope.ciphertext as Uint8Array<ArrayBuffer>,
        ),
      );
    } catch {
      return undefined;
    }
    return decodeSignedDocumentContent(plaintext);
  }

  /** Charge received input against the process, document and sender bounds. */
  private reserveReceived(
    bytes: number,
    sender: string | undefined,
  ): Array<() => void> {
    const releases: Array<() => void> = [];
    try {
      releases.push(aggregateInbound.reserve(bytes));
      releases.push(this.inbound.reserve(bytes));
      releases.push(
        reserveSender(this.senders, sender ?? '', bytes, SENDER_FRAMES, SENDER_BYTES),
      );
    } catch (error) {
      for (const release of releases.reverse()) release();
      throw error;
    }
    return releases;
  }

  /** Run received work in the document queue; waiting local edits go first. */
  private receivedTurn<Value>(work: () => Promise<Value>): Promise<Value> {
    const result = this.tail.then(async () => {
      await this.serveLocal();
      this.assertUsable();
      this.assertActivated();
      return work();
    });
    this.tail = result.then(
      () => {},
      () => {},
    );
    return result;
  }

  private controlsCatchUp(lease: AuthorityLease): boolean {
    try {
      this.catchUpController(lease, this.options.coordinator.localMemberId);
      return true;
    } catch {
      return false;
    }
  }

  private enqueueCatchUp<Value>(
    frame: Uint8Array | undefined,
    maximum: number,
    workBytes: number,
    run: (input: Uint8Array) => Promise<Value>,
    local = false,
  ): Promise<Value> {
    try {
      if (!this.options.enableAuthenticatedCatchUp)
        throw new Error('Authenticated document catch-up is disabled');
      const length =
        frame === undefined
          ? 0
          : unsharedUint8ArrayByteLength(
              frame,
              1,
              maximum,
              'document catch-up frame',
            );
      return this.enqueue(length + workBytes, () => {
        const owned =
          frame === undefined
            ? new Uint8Array()
            : copyUnsharedUint8Array(
                frame,
                length,
                length,
                'document catch-up frame',
              );
        return () => run(owned);
      }, false, local);
    } catch (error) {
      return Promise.reject(error);
    }
  }

  private async runCatchUp<Value>(
    input: Uint8Array,
    prepare: (
      stage: CatchUpWork,
      input: Uint8Array,
    ) => Promise<CatchUpPreparation<Value>>,
  ): Promise<Value> {
    this.assertActivated();
    const roster = this.rosterBinding;
    if (!roster) throw new Error('Authenticated group roster is unavailable');
    this.assertCurrentGroupRoster(roster);
    let preparation: Promise<PreparedGroupDocumentOperation> | undefined;
    let value!: Value;
    try {
      await this.options.coordinator.runDocumentOperation(
        roster.context,
        input,
        (captured, owned, signal, work) => {
          preparation = (async () => {
            const lease = this.authority(captured);
            const isCurrent = () =>
              !signal.aborted &&
              !this.closed &&
              !this.failed &&
              this.rosterBinding === roster &&
              lease.isCurrent() &&
              roster.isCurrent();
            const assertCurrent = () => {
              if (!isCurrent())
                throw new Error('Document catch-up authority changed');
              this.assertCurrentGroupRoster(roster);
            };
            assertCurrent();
            const staged = await prepare(
              {
                binding: {
                  documentId: this.documentId,
                  genesisId: this.genesisId,
                  authorityHead: lease.headId,
                  context: captured,
                },
                roster,
                lease,
                material: await this.key(captured, work),
                work,
                assertCurrent,
              },
              owned,
            );
            return {
              isAuthorizationCurrent: () =>
                isCurrent() && (staged.isCurrent?.() ?? true),
              commit: () => {
                staged.commit?.();
                value = staged.value;
              },
            };
          })();
          return preparation;
        },
      );
      return value;
    } finally {
      await preparation?.then(
        () => {},
        () => {},
      );
    }
  }

  private catchUpController(
    lease: AuthorityLease,
    memberId: Uint8Array,
  ): CapturedDocumentMember {
    const id = documentBytesId(memberId);
    const member = lease.members.get(id);
    const paths = lease.writePaths.get(id);
    if (
      !member ||
      !contentRolePermits(member.role, true) ||
      (paths !== undefined && !paths.some((path) => path.length === 0))
    )
      throw new Error(
        'Document catch-up requires the unrestricted current controller',
      );
    return member;
  }

  private assertCatchUpBinding(
    expected: DocumentCatchUpBinding,
    value: DocumentCatchUpBinding,
  ): void {
    if (
      value.documentId !== expected.documentId ||
      !documentBytesEqual(value.genesisId, expected.genesisId) ||
      !documentBytesEqual(value.authorityHead, expected.authorityHead) ||
      !documentContextsMatch(value.context, expected.context)
    )
      throw new Error('Document catch-up context mismatch');
  }

  private openCatchUp(
    stage: SealedStage,
    kind: DocumentCatchUpKind,
    frame: Uint8Array,
  ) {
    return this.openSealed(
      stage,
      documentCatchUpAAD(kind, stage.binding),
      kind === 'request' || kind === 'checkpoint'
        ? decodeEncryptedDocumentContent(frame)
        : decodeEncryptedDocumentCatchUp(kind, frame),
    );
  }

  private async openSealed(
    stage: SealedStage,
    aad: Uint8Array,
    envelope: { epochTag: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array },
  ) {
    if (!documentBytesEqual(envelope.epochTag, stage.material.epochTag))
      throw new Error('Document catch-up epoch is unavailable');
    const { value } = await stage.work.observe<ArrayBuffer>(
      (async () =>
        crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: envelope.nonce as Uint8Array<ArrayBuffer>,
            additionalData: aad as Uint8Array<ArrayBuffer>,
          },
          stage.material.key,
          envelope.ciphertext as Uint8Array<ArrayBuffer>,
        ))(),
    );
    return decodeSignedDocumentContent(new Uint8Array(value));
  }

  private verifyCatchUp(
    stage: Pick<SealedStage, 'work'>,
    body: ReturnType<typeof decodeSignedDocumentContent>,
    member: CapturedDocumentMember,
  ): Promise<void> {
    return this.verifySigned(body, member, async <T,>(value: unknown) =>
      (await stage.work.observe<T>(value)).value,
    );
  }

  private async verifySigned(
    body: ReturnType<typeof decodeSignedDocumentContent>,
    member: CapturedDocumentMember,
    observe: <T>(value: unknown) => Promise<T> = async <T,>(value: unknown) =>
      (await value) as T,
  ): Promise<void> {
    const key = await observe<PublicKey>(
      this.auth.deserializePublicKey(member.publicKey),
    );
    const canonical = await observe<string>(this.auth.serializePublicKey(key));
    if (canonical !== member.publicKey)
      throw new Error('Noncanonical document catch-up signer');
    const verified = await observe<boolean>(
      this.auth.verify(body.unsigned.slice(), key, body.signature.slice()),
    );
    if (verified !== true)
      throw new Error('Invalid document catch-up signature');
  }

  private sealCatchUp(
    stage: SealedStage,
    kind: DocumentCatchUpKind,
    unsigned: Uint8Array,
    member: CapturedDocumentMember,
  ): Promise<Uint8Array> {
    return this.sealSigned(
      stage,
      documentCatchUpAAD(kind, stage.binding),
      unsigned,
      member,
      kind === 'request' || kind === 'checkpoint'
        ? encodeEncryptedDocumentContent
        : (epochTag, nonce, ciphertext) =>
            encodeEncryptedDocumentCatchUp(kind, epochTag, nonce, ciphertext),
    );
  }

  private async sealSigned(
    stage: SealedStage,
    aad: Uint8Array,
    unsigned: Uint8Array,
    member: CapturedDocumentMember,
    outer: (
      epochTag: Uint8Array,
      nonce: Uint8Array,
      ciphertext: Uint8Array,
    ) => Uint8Array,
  ): Promise<Uint8Array> {
    const { value: canonical } = await stage.work.observe<string>(
      this.auth.serializePublicKey(this.publicKey),
    );
    if (canonical !== member.publicKey)
      throw new Error('Document signing identity mismatch');
    const { value: rawSignature } = await stage.work.observe<Uint8Array>(
      this.auth.sign(unsigned.slice(), this.privateKey),
    );
    const signature = copyUnsharedUint8Array(
      rawSignature,
      1,
      1024,
      'document catch-up signature',
    );
    const { value: verified } = await stage.work.observe<boolean>(
      this.auth.verify(unsigned.slice(), this.publicKey, signature.slice()),
    );
    if (verified !== true)
      throw new Error('Local catch-up signature does not match its authority');
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const { value: ciphertext } = await stage.work.observe<ArrayBuffer>(
      (async () =>
        crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: aad as Uint8Array<ArrayBuffer>,
          },
          stage.material.key,
          encodeSignedDocumentContent(
            unsigned,
            signature,
          ) as Uint8Array<ArrayBuffer>,
        ))(),
    );
    return outer(stage.material.epochTag, nonce, new Uint8Array(ciphertext));
  }

  private async mergeCatchUpCheckpoint(
    input: Uint8Array,
    kind: 'checkpoint' | 'topic-checkpoint',
    pending: PendingCatchUp,
    isPending: () => boolean,
    consume: () => void,
  ): Promise<void> {
    let plan: PreparedDocumentChange<Changes> | undefined;
    let journal: PreparedDocumentJournal | undefined;
    let phase: DocumentCheckpointPhase = 'private';
    const failAttempt = () => {
      phase = advanceDocumentCheckpoint(phase, 'fail', true);
      if (phase === 'poisoned') this.failed = true;
    };
    try {
      const { context, receipts, lease } = await this.runCatchUp(
        input,
        async (stage, owned) => {
          if (!isPending() || pending.roster !== stage.roster)
            throw new Error('Document catch-up request authority changed');
          const localId = this.options.coordinator.localMemberId;
          if (!stage.lease.members.has(documentBytesId(localId)))
            throw new Error('Local member has no document authority');
          const signed = await this.openCatchUp(stage, kind, owned);
          const body = decodeDocumentCatchUpCheckpoint(signed.unsigned, kind);
          this.assertCatchUpBinding(stage.binding, body);
          if (
            !documentBytesEqual(body.requesterId, localId) ||
            !documentBytesEqual(body.challenge, pending.challenge)
          )
            throw new Error(
              'Document catch-up response has no matching request',
            );
          const controller = this.catchUpController(
            stage.lease,
            body.controllerId,
          );
          await this.verifyCatchUp(stage, signed, controller);
          stage.assertCurrent();
          const context = stage.binding.context;
          const extended = await this.verifiedCatchUpExtensions(stage, body);
          stage.assertCurrent();
          const receipts = this.mergeCatchUpReceipts(
            stage.lease,
            context,
            localId,
            body.receipts,
            extended,
          );
          plan = this.session.prepareMergeSnapshot!(
            this.serializer.deserializeChanges(body.snapshot),
          );
          if (!plan.snapshot)
            throw new Error('CRDT provider cannot checkpoint merged state');
          const { value: carried } = await stage.work.observe<
            DocumentJournalCarriedFrame[]
          >(this.checkpointCarry());
          const { value } = await stage.work.observe<PreparedDocumentJournal>(
            this.options.journal!.prepare({
              checkpoint: true,
              context,
              changes: this.serializer.serializeChanges(plan.snapshot()),
              receipts: receiptEntries(receipts),
              authorityHead: stage.lease.headId,
              authorityRecords: this.options.authority.exportRecords!(),
              ...(carried.length ? { carriedFrames: carried } : {}),
            }),
          );
          journal = value;
          return {
            value: { context, receipts, lease: stage.lease },
            isCurrent: () => plan!.isCurrent(),
          };
        },
      );
      // An uncertain acceptance requires reopen. Do not expose the native merge
      // before the authenticated journal and its independent anchor agree.
      if (!isPending())
        throw new Error('Document catch-up response has no matching request');
      phase = advanceDocumentCheckpoint(
        phase,
        'authorize',
        !this.closed &&
          !this.failed &&
          this.rosterBinding === pending.roster &&
          lease.isCurrent() &&
          documentContextsMatch(context, this.options.coordinator.documentContext),
      );
      if (phase !== 'authorized')
        throw new Error('Document catch-up authority changed before acceptance');
      consume();
      await journal!.commit();
      phase = advanceDocumentCheckpoint(phase, 'anchor', true);
      await this.runCatchUp(new Uint8Array(), async (stage) => {
        if (stage.roster !== pending.roster || !lease.isCurrent())
          throw new Error(
            'Document catch-up authority changed after acceptance',
          );
        return {
          value: undefined,
          isCurrent: () => plan!.isCurrent(),
          commit: () => {
            // Authorize only the synchronous native commit below.
            phase = advanceDocumentCheckpoint(
              phase,
              'expose',
              stage.roster === pending.roster && lease.isCurrent(),
            );
            if (phase !== 'visible')
              throw new Error('Document catch-up authority changed after acceptance');
            try {
              plan!.commit();
            } catch (error) {
              failAttempt();
              throw error;
            }
            this.receipts = receipts;
            this.receiptsContext = context;
            this.persistedAuthorityLease = lease.isCurrent;
            this.holdsContent = true;
            this.contentVersion++;
            this.joining = false;
          },
        };
      });
    } catch (error) {
      failAttempt();
      throw error;
    } finally {
      plan?.discard();
      try {
        await journal?.discard();
      } catch {
        this.failed = true;
        throw new Error('Document journal cleanup failed; reopen is required');
      }
    }
  }

  private mergeCatchUpReceipts(
    lease: AuthorityLease,
    context: GroupSecurityDocumentContext,
    localId: Uint8Array,
    offered: readonly DocumentReplayReceipt[],
    extended: ReadonlySet<string>,
  ): Map<string, Receipt> {
    const receipts = new Map(this.receiptsAt(context));
    const local = documentBytesId(localId);
    for (const { memberId, sequence, hash } of offered) {
      const id = documentBytesId(memberId);
      const writer = lease.members.get(id);
      if (!writer || !contentRolePermits(writer.role, false))
        throw new Error(
          'Document catch-up receipt names an unauthorized writer',
        );
      const current = receipts.get(id);
      const admission = admitDocumentCatchUpReceipt(
        current?.sequence ?? 0,
        sequence,
        current !== undefined && documentBytesEqual(current.hash, hash),
        id !== local,
      );
      const extends_ =
        admission === 'conflict' &&
        id !== local &&
        catchUpReceiptExtends(
          current?.sequence ?? 0,
          sequence,
          extended.has(id),
        );
      // An offer below a head accepted since the request is kept when it is
      // one of the frames this replica retains for that author.
      const behind =
        admission === 'conflict' &&
        current !== undefined &&
        sequence < current.sequence &&
        this.retained !== undefined &&
        documentContextsMatch(this.retained.context, context) &&
        this.retained.authors
          .get(id)
          ?.some(
            (frame) =>
              frame.sequence === sequence && documentBytesEqual(frame.hash, hash),
          ) === true;
      if (admission === 'conflict' && !extends_ && !behind)
        throw new Error(
          'Document catch-up receipt conflicts with the accepted head',
        );
      if (admission === 'adopt' || extends_)
        receipts.set(id, { sequence, hash });
    }
    return receipts;
  }

  private sortedReceipts(
    context: GroupSecurityDocumentContext,
  ): Map<string, Receipt> {
    return new Map(
      [...this.receiptsAt(context)].sort(([a], [b]) =>
        a < b ? -1 : a === b ? 0 : 1,
      ),
    );
  }

  /**
   * Retained signed frames that extend each of the requester's shorter heads,
   * within `room` bytes. A suffix that does not fit, or is not retained, is
   * offered only up to its last included frame, or at the requester's own head,
   * so the requester advances over later rounds instead of conflicting. A
   * retained fork keeps the controller's head and still conflicts.
   */
  private catchUpSuffixes(
    context: GroupSecurityDocumentContext,
    receipts: ReadonlyMap<string, Receipt>,
    requested: readonly DocumentReplayReceipt[],
    requesterId: Uint8Array,
    room: number,
  ): { offered: Map<string, Receipt>; suffixes: Uint8Array[] } {
    const requester = documentBytesId(requesterId);
    const offered = new Map(receipts);
    const suffixes: Uint8Array[] = [];
    let bytes = 0;
    for (const { memberId, sequence, hash } of requested) {
      const author = documentBytesId(memberId);
      const head = receipts.get(author)?.sequence ?? 0;
      if (author === requester || sequence >= head) continue;
      const base = this.retained?.authors
        .get(author)
        ?.find((frame) => frame.sequence === sequence);
      if (base && !documentBytesEqual(base.hash, hash)) continue;
      const suffix =
        this.retainedSuffix(context, author, sequence, hash, head) ?? [];
      let included = 0;
      for (const frame of suffix) {
        const cost = frame.signed.length + 4;
        if (
          suffixes.length >= MAX_DOCUMENT_CATCH_UP_SUFFIX_FRAMES ||
          bytes + cost > room
        )
          break;
        suffixes.push(frame.signed.slice());
        bytes += cost;
        included++;
      }
      if (included < suffix.length || suffix.length === 0)
        offered.set(
          author,
          included === 0
            ? { sequence, hash }
            : {
                sequence: suffix[included - 1].sequence,
                hash: suffix[included - 1].hash,
              },
        );
    }
    return { offered, suffixes };
  }

  /**
   * Authors whose offered head is proven to extend the local head: each suffix
   * frame is signed by that author for this exact binding and links by parent
   * hash from the local receipt to the offered one.
   */
  private async verifiedCatchUpExtensions(
    stage: CatchUpWork,
    body: DocumentCatchUpCheckpoint,
  ): Promise<Set<string>> {
    const current = this.receiptsAt(stage.binding.context);
    const offered = new Map(
      body.receipts.map((receipt) => [documentBytesId(receipt.memberId), receipt]),
    );
    const chains = new Map<
      string,
      { unsigned: Uint8Array; signature: Uint8Array; sequence: number; parent: Uint8Array }[]
    >();
    for (const encoded of body.suffixes) {
      const signed = decodeSignedDocumentContent(encoded);
      const frame = decodeDocumentContent(signed.unsigned);
      if (
        frame.documentId !== this.documentId ||
        !documentBytesEqual(frame.genesisId, this.genesisId) ||
        !documentBytesEqual(frame.authorityHead, stage.binding.authorityHead) ||
        !documentContextsMatch(frame.context, stage.binding.context) ||
        frame.kind !== 'change'
      )
        throw new Error('Document catch-up suffix context mismatch');
      const author = documentBytesId(frame.memberId);
      const chain = chains.get(author) ?? [];
      chain.push({ ...signed, sequence: frame.sequence, parent: frame.parent });
      chains.set(author, chain);
    }
    const extended = new Set<string>();
    for (const [author, chain] of chains) {
      const local = current.get(author);
      const head = offered.get(author);
      const writer = stage.lease.members.get(author);
      if (!local || !head || !writer || !contentRolePermits(writer.role, false))
        continue;
      const links = chain.filter((link) => link.sequence > local.sequence);
      if (links.length !== head.sequence - local.sequence) continue;
      let parent = local.hash;
      for (const [index, link] of links.entries()) {
        if (
          link.sequence !== local.sequence + index + 1 ||
          !documentBytesEqual(link.parent, parent)
        )
          break;
        try {
          await this.verifyCatchUp(stage, link, writer);
        } catch {
          break;
        }
        const { value: digest } = await stage.work.observe<ArrayBuffer>(
          (async () =>
            crypto.subtle.digest(
              'SHA-256',
              link.unsigned as Uint8Array<ArrayBuffer>,
            ))(),
        );
        parent = new Uint8Array(digest);
        if (index === links.length - 1 && documentBytesEqual(parent, head.hash))
          extended.add(author);
      }
    }
    return extended;
  }

  private receiptsAt(
    context: GroupSecurityDocumentContext,
  ): Map<string, Receipt> {
    return this.receiptsContext &&
      documentContextsMatch(this.receiptsContext, context)
      ? this.receipts
      : new Map();
  }

  private authority(context: GroupSecurityDocumentContext) {
    return captureDocumentAuthorityLease(
      this.options.authority.capture(context),
      documentBytesId(this.options.coordinator.localMemberId),
    );
  }

  private async key(
    context: GroupSecurityDocumentContext,
    work: GroupSecurityDocumentPreparation,
  ): Promise<GroupDocumentEncryptionMaterial> {
    if (
      !this.material ||
      !documentContextsMatch(this.material.context, context)
    ) {
      this.material = {
        context,
        value: await work.deriveEncryptionMaterial(this.documentId),
      };
    }
    return this.material.value;
  }

  private async apply(
    input?: Uint8Array,
    change?: Change,
    message = '',
    decrypted?: AdmittedFrame,
    resend?: OwnFrame,
  ): Promise<Uint8Array> {
    const context = this.options.coordinator.documentContext;
    const receipts = this.receiptsAt(context);
    let journal: PreparedDocumentJournal | undefined;
    let commitAttempted = false;
    let acceptedAuthorityLease: (() => boolean) | undefined;
    let plan: PreparedDocumentChange<Changes> | undefined;
    let preparation: Promise<unknown> | undefined;
    // A local frame joins the queued tail publication when it fits, so
    // offline edits share publications instead of filling the outbox.
    let tail: OutboxTail | undefined, rows: number | undefined;
    // Local edits leave the journal's last row free, so re-signs can drain a
    // full retired outbox in order, shrinking each retired row as they go.
    const maxRows =
      this.options.journal && !resend ? MAX_PUBLICATIONS - 1 : MAX_PUBLICATIONS;
    if (input === undefined && this.options.joinPublications) {
      if (this.outboxTail === undefined) await this.loadOutboxTail();
      tail = this.outboxTail ?? undefined;
      rows = tail?.rows ?? 0;
      if (!tail && rows >= maxRows) throw new DocumentPublicationBacklogError();
    }
    let outbound: Uint8Array | undefined,
      merged = false;
    let committed = false,
      replay = false;
    let held: HeldReason | undefined;
    let ownChanges: Uint8Array | undefined,
      ownPaths: DocumentWritePaths | undefined;
    let dependenciesReady: (() => boolean) | undefined;
    let result: Uint8Array = new Uint8Array();
    try {
      await this.options.coordinator.runDocumentOperation(
        context,
        input ?? new Uint8Array(),
        (captured, owned, signal, work) => {
          const task = async () => {
            const lease = this.authority(captured);
            const roster = this.options.requireGroupRosterMatch
              ? await this.prepareGroupRoster(captured, lease, work)
              : undefined;
            const material = await this.key(captured, work);
            const aad = documentContentAAD(
              this.documentId,
              captured,
              lease.headId,
            );
            let unsigned: Uint8Array,
              signedContent: Uint8Array,
              memberId: Uint8Array,
              sequence: number,
              parent: Uint8Array;
            let member: CapturedDocumentMember;
            if (input !== undefined) {
              const envelope = decodeEncryptedDocumentContent(owned);
              if (!documentBytesEqual(envelope.epochTag, material.epochTag))
                throw new Error('Document epoch is unavailable');
              // Pre-authentication already decrypted it under this binding.
              const plaintext =
                decrypted &&
                documentContextsMatch(decrypted.context, captured) &&
                documentBytesEqual(decrypted.aad, aad)
                  ? decrypted.plaintext
                  : new Uint8Array(
                      (
                        await work.observe<ArrayBuffer>(
                          (async () =>
                            crypto.subtle.decrypt(
                              {
                                name: 'AES-GCM',
                                iv: envelope.nonce as Uint8Array<ArrayBuffer>,
                                additionalData: aad as Uint8Array<ArrayBuffer>,
                              },
                              material.key,
                              envelope.ciphertext as Uint8Array<ArrayBuffer>,
                            ))(),
                        )
                      ).value,
                    );
              signedContent = plaintext;
              const signed = decodeSignedDocumentContent(signedContent);
              unsigned = signed.unsigned;
              const frame = decodeDocumentContent(unsigned);
              if (
                frame.documentId !== this.documentId ||
                !documentBytesEqual(frame.genesisId, this.genesisId) ||
                !documentBytesEqual(frame.authorityHead, lease.headId) ||
                !documentContextsMatch(frame.context, captured)
              )
                throw new Error('Document content context mismatch');
              memberId = frame.memberId;
              sequence = frame.sequence;
              parent = frame.parent;
              const found = lease.members.get(documentBytesId(memberId));
              if (
                !found ||
                !contentRolePermits(found.role, frame.kind === 'snapshot')
              )
                throw new Error('Document writer is unauthorized');
              member = found;
              const { value: key } = await work.observe<PublicKey>(
                this.auth.deserializePublicKey(member.publicKey),
              );
              const { value: canonical } = await work.observe<string>(
                this.auth.serializePublicKey(key),
              );
              if (canonical !== member.publicKey)
                throw new Error('Noncanonical document signer');
              const { value: verified } = await work.observe<boolean>(
                this.auth.verify(
                  unsigned.slice(),
                  key,
                  signed.signature.slice(),
                ),
              );
              if (verified !== true)
                throw new Error('Invalid document content signature');
              if (frame.kind !== 'change')
                throw new Error(
                  'Unsolicited document snapshots are not accepted',
                );
              const accepted = receipts.get(documentBytesId(memberId));
              const admission = admitContentSequence(
                sequence,
                accepted?.sequence ?? 0,
                documentBytesEqual(parent, accepted?.hash ?? ZERO_HASH),
              );
              if (admission === 'replay') replay = true;
              else if (admission === 'gap') held = 'gap';
              else if (admission !== 'apply')
                throw new Error('Document causal prefix is missing or forked');
              if (!replay && !held) {
                this.assertCurrentGroupRoster(roster);
                try {
                  plan = this.session.prepareRemote(
                    this.serializer.deserializeChanges(frame.changes),
                    {
                      inspectOperations:
                        lease.writePaths.get(member.id) !== undefined,
                    },
                  );
                } catch (error) {
                  if (!(error instanceof DocumentCausalDependencyError))
                    throw error;
                  held = 'dependency';
                  dependenciesReady = error.ready;
                }
              }
            } else {
              memberId = this.options.coordinator.localMemberId;
              const found = lease.members.get(documentBytesId(memberId));
              if (!found || !contentRolePermits(found.role, false)) {
                if (resend) throw new ResendDeniedError();
                throw new Error('Local document member cannot write');
              }
              member = found;
              const { value: ownKey } = await work.observe<string>(
                this.auth.serializePublicKey(this.publicKey),
              );
              if (ownKey !== member.publicKey)
                throw new Error('Document signing identity mismatch');
              const accepted = receipts.get(documentBytesId(memberId));
              if (accepted?.sequence === Number.MAX_SAFE_INTEGER)
                throw new Error('Document sequence is exhausted');
              sequence = nextContentSequence(accepted?.sequence ?? 0);
              parent = accepted?.hash ?? ZERO_HASH;
              this.assertCurrentGroupRoster(roster);
              const scope = lease.writePaths.get(member.id);
              if (resend === undefined) {
                plan = this.session.prepareLocal(message, change!, {
                  inspectOperations: scope === undefined ? 'record' : true,
                });
                assertDocumentOperationsAllowed(plan, scope);
                ownPaths = plan.operationPaths
                  ? recordDocumentOperationPaths(plan.operationPaths())
                  : WHOLE_DOCUMENT;
              } else {
                // The delta is already local, so check the paths recorded when it was written.
                if (scope !== undefined) {
                  if (uninspected(resend.paths)) throw new ResendDeniedError();
                  try {
                    assertDocumentOperationsAllowed(
                      {
                        operationPaths: () => resend.paths,
                      } as PreparedDocumentChange<Changes>,
                      scope,
                    );
                  } catch {
                    throw new ResendDeniedError();
                  }
                }
                ownPaths = resend.paths;
              }
              const changes = copyUnsharedUint8Array(
                resend?.changes ?? this.serializer.serializeChanges(plan!.changes),
                0,
                MAX_DOCUMENT_CONTENT_BYTES,
                'document delta',
              );
              ownChanges = changes;
              unsigned = encodeDocumentContent({
                documentId: this.documentId,
                genesisId: this.genesisId,
                authorityHead: lease.headId,
                context: captured,
                memberId,
                sequence,
                parent,
                kind: 'change',
                changes,
              });
              const { value: rawSignature } = await work.observe<Uint8Array>(
                this.auth.sign(unsigned.slice(), this.privateKey),
              );
              const signature = copyUnsharedUint8Array(
                rawSignature,
                1,
                1024,
                'document signature',
              );
              const { value: verified } = await work.observe<boolean>(
                this.auth.verify(
                  unsigned.slice(),
                  this.publicKey,
                  signature.slice(),
                ),
              );
              if (verified !== true)
                throw new Error(
                  'Local document signature does not match its authority',
                );
              const signed = encodeSignedDocumentContent(unsigned, signature),
                nonce = crypto.getRandomValues(new Uint8Array(12));
              signedContent = signed;
              const { value: ciphertext } = await work.observe<ArrayBuffer>(
                (async () =>
                  crypto.subtle.encrypt(
                    {
                      name: 'AES-GCM',
                      iv: nonce,
                      additionalData: aad as Uint8Array<ArrayBuffer>,
                    },
                    material.key,
                    signed as Uint8Array<ArrayBuffer>,
                  ))(),
              );
              result = encodeEncryptedDocumentContent(
                material.epochTag,
                nonce,
                new Uint8Array(ciphertext),
              );
              if (this.options.persistPublications) {
                merged =
                  !!this.options.joinPublications &&
                  tail !== undefined &&
                  tail.frames < MAX_DOCUMENT_PUBLICATION_FRAMES &&
                  tail.bytes.length + result.length <=
                    MAX_JOINED_PUBLICATION_BYTES &&
                  documentBytesEqual(tail.aad, aad) &&
                  documentBytesEqual(
                    documentFrameEpochTag(tail.bytes),
                    material.epochTag,
                  ) &&
                  (!!this.options.journal ||
                    (this.publications.length !== 0 &&
                      documentBytesEqual(
                        this.publications.at(-1)!,
                        tail.bytes,
                      )));
                outbound = merged ? concatFrames(tail!.bytes, result) : result;
                if (!merged && rows !== undefined && rows >= maxRows)
                  throw new DocumentPublicationBacklogError();
                // A checkpoint must carry every unsent frame's exact paths.
                if (
                  this.options.journal &&
                  !resend &&
                  this.unsentPathBytes + encodedPathBytes(ownPaths!) >
                    MAX_CARRIED_PATH_BYTES
                )
                  throw new DocumentPublicationBacklogError();
                if (!this.options.journal) {
                  const queued = this.publications.reduce(
                    (sum, frame) => sum + frame.length,
                    0,
                  );
                  if (
                    (!merged && this.publications.length >= MAX_PUBLICATIONS) ||
                    queued -
                      (merged ? tail!.bytes.length : 0) +
                      outbound.length >
                      MAX_PUBLICATION_BYTES
                  )
                    throw new DocumentPublicationBacklogError();
                }
              }
            }
            if (!replay && !held && input !== undefined)
              assertDocumentOperationsAllowed(
                plan!,
                lease.writePaths.get(member.id),
              );
            const { value: digest } = await work.observe<ArrayBuffer>(
              (async () =>
                crypto.subtle.digest(
                  'SHA-256',
                  unsigned as Uint8Array<ArrayBuffer>,
                ))(),
            );
            const hash = new Uint8Array(digest);
            if (held)
              throw new HeldDocumentFrame(
                held,
                captured,
                documentBytesId(memberId),
                sequence,
                hash,
                dependenciesReady,
              );
            const accepted = receipts.get(documentBytesId(memberId));
            if (
              replay &&
              accepted?.sequence === sequence &&
              !documentBytesEqual(accepted.hash, hash)
            )
              throw new Error('Document author equivocated');
            if (!replay && this.options.journal) {
              const checkpoint = this.options.journal.needsCheckpoint;
              const snapshot = plan
                ? plan.snapshot
                : this.crdt.getSnapshot &&
                  (() => this.crdt.getSnapshot!(this.session.document));
              if (checkpoint && !snapshot)
                throw new Error(
                  'CRDT provider cannot checkpoint accepted state',
                );
              const changes = checkpoint
                ? this.serializer.serializeChanges(snapshot!())
                : (resend?.changes ?? this.serializer.serializeChanges(plan!.changes));
              const nextReceipts = new Map(receipts);
              nextReceipts.set(documentBytesId(memberId), { sequence, hash });
              const persistedReceipts = checkpoint
                ? receiptEntries(nextReceipts)
                : [{ memberId, sequence, hash }];
              // A checkpoint folds the entries of unsent own frames, so it
              // keeps them, and the frame it records, re-signable.
              const carriedFrames = checkpoint
                ? (
                    await work.observe<DocumentJournalCarriedFrame[]>(
                      this.checkpointCarry(
                        input === undefined
                          ? {
                              context: captured,
                              sequence,
                              nonce: documentFrameNonce(result),
                              changes: ownChanges!,
                              operationPaths: ownPaths!,
                            }
                          : undefined,
                      ),
                    )
                  ).value
                : undefined;
              const { value } = await work.observe<PreparedDocumentJournal>(
                this.options.journal.prepare({
                  checkpoint,
                  context: captured,
                  changes,
                  receipts: persistedReceipts,
                  authorityHead: lease.headId,
                  authorityRecords:
                    checkpoint || this.persistedAuthorityLease?.() !== true
                      ? (this.options.authority.exportRecords?.() ?? [])
                      : [],
                  ...(checkpoint
                    ? carriedFrames?.length
                      ? { carriedFrames }
                      : {}
                    : {
                        operationPaths: input === undefined ? ownPaths! : [],
                        ...(input === undefined
                          ? { frameNonce: documentFrameNonce(result) }
                          : {}),
                      }),
                  ...(outbound ? { outboundFrame: outbound } : {}),
                  ...(merged ? { replacesPublication: tail!.bytes } : {}),
                }),
              );
              journal = value;
              acceptedAuthorityLease = lease.isCurrent;
            }
            if (signal.aborted) throw new Error('Document preparation aborted');
            return {
              isAuthorizationCurrent: () =>
                !this.closed &&
                !this.failed &&
                lease.isCurrent() &&
                (replay || resend !== undefined || plan!.isCurrent()),
              commit: () => {
                this.rosterBinding = roster;
                if (replay) {
                  this.observeRetained(captured, documentBytesId(memberId), sequence);
                  return;
                }
                commitAttempted = true;
                plan?.commit();
                this.holdsContent = true;
                this.contentVersion++;
                this.receipts = receipts;
                this.receiptsContext = captured;
                this.receipts.set(documentBytesId(memberId), {
                  sequence,
                  hash,
                });
                this.retain(captured, documentBytesId(memberId), {
                  sequence,
                  hash,
                  signed: signedContent,
                  frame: input === undefined ? result.slice() : owned,
                });
                if (input !== undefined) this.markRemote(captured);
                if (input === undefined) {
                  const nonce = documentFrameNonce(result);
                  if (outbound) this.markUnsent(nonce, ownPaths!);
                  this.recordOwn({
                    context: captured,
                    order: resend?.order ?? ++this.ownOrder,
                    sequence,
                    changes: ownChanges!,
                    paths: ownPaths!,
                    nonce,
                  });
                }
                committed = true;
                if (outbound) {
                  if (!this.options.journal) {
                    if (merged) this.publications.pop();
                    this.publications.push(outbound.slice());
                  }
                  this.outboxTail = {
                    bytes: outbound,
                    frames: merged ? tail!.frames + 1 : 1,
                    aad,
                    rows: merged ? rows! : (rows ?? 0) + 1,
                  };
                }
                if (input !== undefined) result = hash;
              },
            };
          };
          preparation = task();
          return preparation as Promise<
            import('./group-document-operation.js').PreparedGroupDocumentOperation
          >;
        },
      );
      if (committed) {
        await journal?.commit();
        if (journal) this.persistedAuthorityLease = acceptedAuthorityLease;
      }
      return result;
    } catch (error) {
      if (commitAttempted) this.failed = true;
      else if (
        outbound &&
        error instanceof DocumentJournalCapacityError &&
        !(error instanceof DocumentPublicationBacklogError) &&
        (await this.outboxIsFull(outbound.length))
      )
        throw new DocumentPublicationBacklogError();
      throw error;
    } finally {
      // The gate can time out before native work settles. Keep the session slot
      // and its private CRDT stage until that work has actually finished.
      await preparation?.then(
        () => {},
        () => {},
      );
      plan?.discard();
      try {
        await journal?.discard();
      } catch {
        this.failed = true;
        throw new Error('Document journal cleanup failed; reopen is required');
      }
    }
  }

  private async recover(): Promise<void> {
    if (this.recovered) return;
    try {
      const records = (await this.options.journal?.restore()) ?? [];
      if (this.options.journal?.diverged) {
        this.diverged = true;
        throw new DocumentDivergedError();
      }
      for (const record of records) {
        if (this.options.authority.extendsHead(record.authorityHead) !== true)
          throw new Error(
            'Configured authority forks the accepted document history',
          );
      }
      const queued =
        this.options.persistPublications && this.options.journal
          ? await this.queuedFrames()
          : undefined;
      // Own frames of contexts the journal moved past. Their copies may have
      // been re-signed already, so only those still in the outbox are queued.
      const retired: Array<NonNullable<typeof this.own>> = [];
      const restoreOwn = (frame: Omit<OwnFrame, 'order'>) => {
        if (queued && outboxHolds(queued, frame.nonce))
          this.markUnsent(frame.nonce!, frame.paths);
        const replaced = this.recordOwn({ ...frame, order: ++this.ownOrder });
        if (replaced) retired.push(replaced);
      };
      for (const record of records) {
        if (record.receipts.length !== 0) this.holdsContent = true;
        this.contentVersion++;
        for (const frame of record.carriedFrames ?? [])
          restoreOwn({
            context: frame.context,
            sequence: frame.sequence,
            changes: frame.changes,
            paths: frame.operationPaths,
            nonce: frame.nonce,
          });
        const changes = this.serializer.deserializeChanges(record.changes);
        if (record.checkpoint && !this.session.prepareSnapshot)
          throw new Error('CRDT provider cannot restore a checkpoint');
        const plan = record.checkpoint
          ? this.session.prepareSnapshot!(changes)
          : this.session.prepareRemote(changes);
        try {
          const same =
            this.receiptsContext &&
            documentContextsMatch(this.receiptsContext, record.context);
          const receipts =
            record.checkpoint || !same
              ? new Map<string, Receipt>()
              : new Map(this.receipts);
          for (const receipt of record.receipts) {
            const id = documentBytesId(receipt.memberId);
            if (
              !record.checkpoint &&
              admitContentSequence(
                receipt.sequence,
                receipts.get(id)?.sequence ?? 0,
                true,
              ) !== 'apply'
            )
              throw new Error('Journal replay prefix is invalid');
            receipts.set(id, {
              sequence: receipt.sequence,
              hash: receipt.hash,
            });
            if (
              !record.checkpoint &&
              id !== documentBytesId(this.options.coordinator.localMemberId)
            )
              this.markRemote(record.context);
            if (
              !record.checkpoint &&
              id === documentBytesId(this.options.coordinator.localMemberId)
            )
              restoreOwn({
                context: record.context,
                sequence: receipt.sequence,
                changes: record.changes,
                paths: record.operationPaths!,
                ...(record.frameNonce ? { nonce: record.frameNonce } : {}),
              });
          }
          if (receipts.size > 256)
            throw new Error('Journal receipt bound exceeded');
          plan.commit();
          this.receipts = receipts;
          this.receiptsContext = record.context;
        } finally {
          plan.discard();
        }
      }
      // The group may have moved on while the document was closed.
      const moved =
        this.own &&
        !documentContextsMatch(
          this.own.context,
          this.options.coordinator.documentContext,
        );
      if ((retired.length !== 0 || moved) && queued) {
        for (const own of retired) this.queueRetired(own, queued, true);
        if (moved) this.queueRetired(this.own, queued);
      }
      this.recovered = true;
    } catch (error) {
      this.failed = true;
      throw error;
    }
  }

  /**
   * A role transition is acknowledged only after its checkpoint is durable.
   * When it starts a new group context, this author's frames from the retired
   * context are re-signed in the new one while its roles and recorded
   * operation paths allow them. A re-sign failure does not fail the update.
   */
  async applyAuthorityUpdate(
    encoded: Uint8Array,
  ): Promise<CoordinatedAuthorityUpdateResult> {
    return (
      (await this.queueAuthorityUpdate(encoded, false)) ?? {
        resent: 0,
        waiting: this.resendQueue.length,
        skipped: 0,
        dropped: 0,
        diverged: false,
      }
    );
  }

  /** Install an authenticated strict role record while leaving activation fenced. */
  async applyAuthorityUpdateBeforeOpen(encoded: Uint8Array): Promise<void> {
    await this.queueAuthorityUpdate(encoded, true);
  }

  private queueAuthorityUpdate(
    encoded: Uint8Array,
    beforeOpen: boolean,
  ): Promise<CoordinatedAuthorityUpdateResult | undefined> {
    try {
      const length = unsharedUint8ArrayByteLength(
        encoded,
        1,
        MAX_DOCUMENT_SECURITY_FRAME_BYTES,
        'authority update',
      );
      return this.enqueue(length, () => {
        const owned = copyUnsharedUint8Array(
          encoded, length, length, 'authority update',
        );
        return async () => {
          if (beforeOpen) {
            if (!this.options.requireGroupRosterMatch || this.activated)
              throw new Error('Only an unopened strict document can recover authority');
            await this.recover();
          } else {
            this.assertActivated();
          }
          const retired = beforeOpen ? undefined : this.own;
          const authority = this.options.authority;
          if (this.options.requireGroupRosterMatch) {
            if (!(authority instanceof DocumentAuthorityLog)) {
              throw new Error(
                'Strict group roster matching requires a signed document authority log',
              );
            }
            const before = beforeOpen ? this.own : undefined;
            await this.applyStrictAuthorityUpdate(authority, owned);
            if (!beforeOpen && !this.holdsContent)
              this.joining = !this.controlsCatchUp(
                this.authority(this.options.coordinator.documentContext),
              );
            if (beforeOpen) {
              this.queueRetired(before, await this.queuedFrames());
              return undefined;
            }
            return this.resendRetired(retired);
          }
          if (!authority.applyUpdate)
            throw new Error('Document authority does not support signed transitions');
          await authority.applyUpdate(this.options.coordinator, owned);
          if (this.options.journal) {
            try {
              await this.checkpointAuthority(this.options.coordinator.documentContext);
            } catch (error) {
              this.failed = true;
              throw error;
            }
          }
          return this.resendRetired(retired);
        };
      });
    } catch (error) {
      return Promise.reject(error);
    }
  }

  private async applyStrictAuthorityUpdate(
    authority: DocumentAuthorityLog<PrivateKey, PublicKey, DocumentKey>,
    encoded: Uint8Array,
  ): Promise<void> {
    const proposal = await authority.prepareRosterUpdate(
      this.options.coordinator,
      encoded,
      {
        readLocalPublicKey: () => this.auth.serializePublicKey(this.publicKey),
        isCurrent: () => !this.closed && !this.failed,
      },
    );
    const binding: DocumentGroupRosterBinding = {
      context: proposal.context,
      authorityHead: proposal.authorityHead,
      isCurrent: proposal.isInstalled,
    };
    try {
      if (this.options.journal)
        await this.checkpointAuthority(proposal.context, proposal);

      // A durable result that became stale is recovered from the accepted journal.
      this.assertUsable();
      if (
        !proposal.isReserved() ||
        !documentContextsMatch(
          proposal.context,
          this.options.coordinator.documentContext,
        )
      ) {
        throw new Error('Document authority changed before live installation');
      }
      proposal.commit();
      this.rosterBinding = binding;
    } catch (error) {
      this.failed = true;
      throw error;
    } finally {
      proposal.discard();
    }
  }

  private async checkpointAuthority(
    context: GroupSecurityDocumentContext,
    proposal?: PreparedDocumentRosterUpdate,
  ): Promise<void> {
    let prepared: PreparedDocumentJournal | undefined;
    let authorityLease: (() => boolean) | undefined;
    let preparation: Promise<unknown> | undefined;
    try {
      await this.options.coordinator.runDocumentOperation(
        context,
        new Uint8Array(),
        (captured, _input, _signal, work) => {
          preparation = (async () => {
            const lease = proposal ? undefined : this.authority(captured);
            authorityLease = proposal?.isInstalled ?? lease!.isCurrent;
            const isAuthorizationCurrent = proposal?.isReserved ?? lease!.isCurrent;
            if (!this.crdt.getSnapshot)
              throw new Error('CRDT provider cannot checkpoint role transitions');
            const changes = this.serializer.serializeChanges(
              this.crdt.getSnapshot(this.session.document),
            );
            const { value: carried } = await work.observe<
              DocumentJournalCarriedFrame[]
            >(this.checkpointCarry());
            const { value } = await work.observe<PreparedDocumentJournal>(
              this.options.journal!.prepare({
                checkpoint: true,
                context: captured,
                changes,
                receipts: [],
                authorityHead: proposal?.authorityHead ?? lease!.headId,
                authorityRecords:
                  proposal?.authorityRecords ??
                  this.options.authority.exportRecords?.() ??
                  [],
                ...(carried.length ? { carriedFrames: carried } : {}),
              }),
            );
            prepared = value;
            return {
              isAuthorizationCurrent: () =>
                !this.closed && !this.failed && isAuthorizationCurrent(),
              commit: () => {
                this.receipts = new Map();
                this.receiptsContext = captured;
                this.dropRetained();
              },
            };
          })();
          return preparation as Promise<
            import('./group-document-operation.js').PreparedGroupDocumentOperation
          >;
        },
      );
      await prepared!.commit();
      this.persistedAuthorityLease = authorityLease;
    } finally {
      await preparation?.then(
        () => {},
        () => {},
      );
      await prepared?.discard();
    }
  }

  /** Record an own frame, returning the frames of a context it replaces. */
  private recordOwn(frame: OwnFrame): typeof this.own {
    let replaced: typeof this.own;
    if (!this.own || !documentContextsMatch(this.own.context, frame.context)) {
      replaced = this.own;
      this.own = {
        context: frame.context,
        frames: [],
        bytes: 0,
        remoteMark: -1,
      };
    }
    const own = this.own;
    own.frames.push(frame);
    own.bytes += ownFrameBytes(frame);
    while (own.frames.length > MAX_OWN_FRAMES || own.bytes > MAX_OWN_BYTES) {
      const index = own.frames.findIndex(
        (value) => !value.nonce || !this.unsent.has(documentBytesId(value.nonce)),
      );
      if (index === -1) break;
      const [oldest] = own.frames.splice(index, 1);
      own.bytes -= ownFrameBytes(oldest);
    }
    return replaced;
  }

  private markUnsent(nonce: Uint8Array, paths: DocumentWritePaths): void {
    const id = documentBytesId(nonce);
    if (this.unsent.has(id)) return;
    const bytes = encodedPathBytes(paths);
    this.unsent.set(id, bytes);
    this.unsentPathBytes += bytes;
  }

  /** Forget the unsent frames a publication held but `kept` does not. */
  private markSent(publication: Uint8Array, kept?: Uint8Array): void {
    const remaining = new Set(
      kept
        ? splitDocumentPublication(kept).map((frame) =>
            documentBytesId(documentFrameNonce(frame)),
          )
        : [],
    );
    for (const frame of splitDocumentPublication(publication)) {
      const id = documentBytesId(documentFrameNonce(frame));
      const bytes = this.unsent.get(id);
      if (bytes === undefined || remaining.has(id)) continue;
      this.unsent.delete(id);
      this.unsentPathBytes -= bytes;
    }
  }

  private markRemote(context: GroupSecurityDocumentContext): void {
    if (this.own && documentContextsMatch(this.own.context, context))
      this.own.remoteMark = this.ownOrder;
  }

  /**
   * Own frames of a retired context that peers may lack: those still in the
   * outbox, and those written after the last frame accepted from a peer there.
   * The controller of the retired context commits its successor itself, so it
   * published every one of its frames there while that context was current
   * for all members; only its unsent frames are carried.
   */
  private carriedRetired(
    retired: typeof this.own,
    queued: QueuedFrames,
    unsentOnly = false,
  ): { carried: OwnFrame[]; skipped: number } | undefined {
    if (
      !this.options.persistPublications ||
      !retired ||
      retired.frames.length === 0 ||
      documentContextsMatch(
        retired.context,
        this.options.coordinator.documentContext,
      )
    )
      return undefined;
    const authority = this.options.authority;
    const controller =
      authority instanceof DocumentAuthorityLog
        ? authority.controllerAtHead(retired.context.controlHead)
        : undefined;
    const committed =
      controller !== undefined &&
      documentBytesEqual(controller, this.options.coordinator.localMemberId);
    const carried = retired.frames.flatMap((frame) => {
      const unsent = outboxHolds(queued, frame.nonce);
      return unsent ||
        (!unsentOnly && !committed && frame.order > retired.remoteMark)
        ? [{ ...frame, unsent }]
        : [];
    });
    return {
      carried,
      skipped:
        retired.frames[0].sequence - 1 + retired.frames.length - carried.length,
    };
  }

  /** Queue a retired context's own frames, in order, behind any still waiting. */
  private queueRetired(
    retired: typeof this.own,
    queued: QueuedFrames,
    unsentOnly = false,
  ): number {
    // Without an outbox, nothing could publish a re-signed frame.
    const selection = this.carriedRetired(retired, queued, unsentOnly);
    if (!selection) return 0;
    const waiting = new Map(
      [...this.resendQueue, ...selection.carried].map((frame) => [frame.order, frame]),
    );
    this.resendQueue = [...waiting.values()].sort((a, b) => a.order - b.order);
    return selection.skipped;
  }

  /** Re-sign this author's frames from the context an update retired. */
  private async resendRetired(
    retired: typeof this.own,
  ): Promise<CoordinatedAuthorityUpdateResult> {
    let skipped = 0;
    try {
      skipped = this.queueRetired(retired, await this.queuedFrames());
      const drained = await this.drainResend();
      return { ...drained, skipped: skipped + drained.skipped };
    } catch {
      // The roles are installed; frames that could not be resolved stay queued.
      return {
        resent: 0,
        waiting: this.resendQueue.length,
        skipped,
        dropped: 0,
        diverged: false,
      };
    }
  }

  private async queuedFrames(): Promise<QueuedFrames> {
    return queueOf(
      this.options.journal
        ? await this.options.journal.pendingPublications()
        : this.publications.map((frame) => frame.slice()),
    );
  }

  /**
   * Own frames a checkpoint keeps re-signable: those still in the outbox,
   * from the current context or waiting to be re-signed, and `current`, the
   * frame the checkpoint itself records.
   */
  private async checkpointCarry(
    current?: DocumentJournalCarriedFrame,
  ): Promise<DocumentJournalCarriedFrame[]> {
    if (!this.options.persistPublications) return [];
    const queued = await this.queuedFrames();
    const frames = new Map<string, OwnFrame>();
    for (const frame of [...(this.own?.frames ?? []), ...this.resendQueue])
      if (outboxHolds(queued, frame.nonce))
        frames.set(documentBytesId(frame.nonce!), frame);
    const carried = [...frames.values()]
      .sort((a, b) => a.order - b.order)
      .map(
        (frame): DocumentJournalCarriedFrame => ({
          context: frame.context,
          sequence: frame.sequence,
          nonce: frame.nonce!,
          changes: frame.changes,
          operationPaths: frame.paths,
        }),
      );
    return current ? [...carried, current] : carried;
  }

  /**
   * Remove frames from the publications that hold them. A publication that
   * keeps other frames is rewritten with the rest, in its place in the outbox.
   */
  private async withdrawFrames(
    queued: QueuedFrames,
    nonces: readonly (Uint8Array | undefined)[],
  ): Promise<void> {
    const byRow = new Map<number, Set<string>>();
    for (const nonce of nonces) {
      if (!nonce) continue;
      const id = documentBytesId(nonce),
        row = queued.rowOf.get(id);
      if (row === undefined) continue;
      const ids = byRow.get(row) ?? new Set<string>();
      ids.add(id);
      byRow.set(row, ids);
    }
    for (const [row, ids] of byRow) {
      const before = queued.rows[row];
      const rest = queued.parts[row].filter(
        (frame) => !ids.has(documentBytesId(documentFrameNonce(frame))),
      );
      const next = rest.length === 0 ? undefined : joinFrames(rest);
      if (next) await this.replacePublication(before, next);
      else {
        await this.removePublication(before);
        this.outboxTail = undefined;
      }
      for (const id of ids) queued.rowOf.delete(id);
      queued.rows[row] = next ?? new Uint8Array();
      queued.parts[row] = rest;
    }
  }

  private async replacePublication(
    frame: Uint8Array,
    next: Uint8Array,
  ): Promise<void> {
    if (this.options.journal)
      await this.options.journal.replacePublication(frame, next);
    else
      this.publications = this.publications.map((value) =>
        documentBytesEqual(value, frame) ? next.slice() : value,
      );
    this.markSent(frame, next);
    if (this.outboxTail && documentBytesEqual(this.outboxTail.bytes, frame))
      this.outboxTail = undefined;
  }

  /**
   * Re-sign one queued frame. A journal's outbox keeps a row free for
   * re-signs, so a retired publication leaves it only frame by frame, after
   * each re-signed copy is durable. A process-local outbox has no such row:
   * when it is full and the publication holding the frame carries only
   * queued frames, that publication is removed first and its frames are
   * re-signed from the queue in turn.
   */
  private async resign(entry: OwnFrame, queued: QueuedFrames): Promise<void> {
    try {
      await this.apply(undefined, undefined, '', undefined, entry);
    } catch (error) {
      if (
        this.options.journal ||
        !(error instanceof DocumentJournalCapacityError) ||
        !entry.nonce
      )
        throw error;
      const row = queued.rowOf.get(documentBytesId(entry.nonce));
      const waiting = new Set(
        this.resendQueue.flatMap((frame) =>
          frame.nonce ? [documentBytesId(frame.nonce)] : [],
        ),
      );
      if (
        row === undefined ||
        !queued.parts[row].every((frame) =>
          waiting.has(documentBytesId(documentFrameNonce(frame))),
        )
      )
        throw error;
      await this.withdrawFrames(
        queued,
        queued.parts[row].map((frame) => documentFrameNonce(frame)),
      );
      await this.apply(undefined, undefined, '', undefined, entry);
    }
  }

  /**
   * Re-sign queued frames in order. Outbox capacity or a transient failure
   * leaves the rest queued. A published frame the current grants deny is
   * skipped. A denied frame still in the outbox reached no one, and every
   * later frame depends on it: they are dropped, and a writer whose grants
   * narrowed has diverged. Each re-signed or dropped frame leaves the
   * publication that held it.
   */
  private async drainResend(): Promise<CoordinatedAuthorityUpdateResult> {
    let resent = 0,
      dropped = 0,
      skipped = 0,
      diverged = false;
    if (this.resendQueue.length === 0)
      return { resent, waiting: 0, skipped, dropped, diverged };
    const queued = await this.queuedFrames();
    while (this.resendQueue.length > 0) {
      const entry = this.resendQueue[0];
      try {
        await this.resign(entry, queued);
      } catch (error) {
        if (!(error instanceof ResendDeniedError)) break;
        if (!entry.unsent) {
          this.resendQueue.shift();
          skipped++;
          continue;
        }
        const denied = this.resendQueue;
        this.resendQueue = [];
        dropped = denied.length;
        this.reportDropped(dropped);
        if (this.localMemberWrites()) {
          diverged = true;
          this.diverged = true;
          try {
            await this.options.journal?.markDiverged();
          } catch {
            this.failed = true;
          }
        }
        await this.withdrawFrames(
          queued,
          denied.map((frame) => frame.nonce),
        ).catch(() => {});
        break;
      }
      this.resendQueue.shift();
      resent++;
      await this.withdrawFrames(queued, [entry.nonce]);
    }
    return { resent, waiting: this.resendQueue.length, skipped, dropped, diverged };
  }

  /** Frames a re-sign can still carry into the current context, by nonce. */
  private resignableFrames(): Set<string> {
    const ids = new Set<string>();
    const add = (frames: readonly OwnFrame[]) => {
      for (const frame of frames)
        if (frame.nonce) ids.add(documentBytesId(frame.nonce));
    };
    add(this.resendQueue);
    // Learning the new roles queues these.
    if (
      this.own &&
      !documentContextsMatch(
        this.own.context,
        this.options.coordinator.documentContext,
      )
    )
      add(this.own.frames);
    return ids;
  }

  private localMemberWrites(): boolean {
    try {
      const member = this.authority(
        this.options.coordinator.documentContext,
      ).members.get(documentBytesId(this.options.coordinator.localMemberId));
      return member !== undefined && contentRolePermits(member.role, false);
    } catch {
      return false;
    }
  }

  /** Re-sign queued retired frames into outbox space freed by publication. */
  continueResend(): Promise<boolean> {
    if (this.resendQueue.length === 0) return Promise.resolve(false);
    return this.enqueue(
      0,
      () => async () => {
        this.assertActivated();
        try {
          return (await this.drainResend()).resent > 0;
        } catch {
          return false;
        }
      },
      false,
      true,
    );
  }

  assertPublicationDispatchAllowed(
    binding = this.rosterBinding,
    draining = true,
  ): void {
    if (!this.options.requireGroupRosterMatch) return;
    this.assertUsable(draining);
    this.assertActivated();
    this.assertCurrentGroupRoster(binding);
  }

  /** Capture the installed strict roster for a delayed application notification. */
  captureStrictNotificationGuard(): (() => boolean) | undefined {
    if (!this.options.requireGroupRosterMatch) return undefined;
    const binding = this.rosterBinding;
    return () => {
      if (!binding || this.rosterBinding !== binding) return false;
      try {
        this.assertPublicationDispatchAllowed(binding, false);
        return true;
      } catch {
        return false;
      }
    };
  }

  pendingPublications(): Promise<ReadonlyArray<Uint8Array>> {
    return this.enqueue(
      0,
      () => async () => {
        this.assertActivated();
        const binding = this.rosterBinding;
        this.assertPublicationDispatchAllowed(binding);
        if (!this.options.journal)
          return this.publications.map((frame) => frame.slice());
        const frames = await this.options.journal.pendingPublications();
        this.assertPublicationDispatchAllowed(binding);
        return frames;
      },
      true,
    );
  }

  publicationSent(frame: Uint8Array): Promise<void> {
    try {
      const length = unsharedUint8ArrayByteLength(
        frame,
        1,
        MAX_DOCUMENT_SECURITY_FRAME_BYTES,
        'published document frame',
      );
      return this.enqueue(length, () => {
        const owned = copyUnsharedUint8Array(
          frame,
          length,
          length,
          'published document frame',
        );
        return async () => {
          this.assertActivated();
          await this.removePublication(owned);
        };
      }, true, true);
    } catch (error) {
      return Promise.reject(error);
    }
  }

  /**
   * Read publications to send now. A publication sealed for an earlier group
   * context or authority head would be rejected by every current member. It
   * stays queued, unsent, while it holds a frame its author can still re-sign
   * into the current context, and `waiting` reports it; otherwise it is
   * removed and its frames are counted as `dropped`. A diverged document
   * still drains what it committed before diverging.
   */
  dispatchablePublications(): Promise<{
    readonly frames: ReadonlyArray<Uint8Array>;
    readonly dropped: number;
    readonly waiting: boolean;
  }> {
    return this.enqueue(
      0,
      () => async () => {
        this.assertActivated();
        const binding = this.rosterBinding;
        this.assertPublicationDispatchAllowed(binding);
        const rows = this.options.journal
          ? await this.options.journal.pendingPublications()
          : this.publications.map((frame) => frame.slice());
        this.assertPublicationDispatchAllowed(binding);
        const frames: Uint8Array[] = [];
        let dropped = 0,
          kept = 0,
          last = 0;
        const key = rows.length === 0 ? undefined : await this.frameKey();
        this.assertPublicationDispatchAllowed(binding);
        const resignable = this.resignableFrames();
        for (const row of rows) {
          // One publication only joins frames sealed under the same binding.
          const parts = splitDocumentPublication(row);
          if (await this.decryptsUnder(parts[0], key!)) {
            frames.push(row);
            last = parts.length;
          } else if (
            parts.some((frame) =>
              resignable.has(documentBytesId(documentFrameNonce(frame))),
            )
          )
            kept++;
          else {
            dropped += parts.length;
            await this.removePublication(row);
          }
        }
        const tail = frames.at(-1);
        this.outboxTail =
          kept === 0 || (tail && documentBytesEqual(tail, rows.at(-1)!))
            ? tail
              ? {
                  bytes: tail,
                  frames: last,
                  aad: key!.aad,
                  rows: frames.length + kept,
                }
              : null
            : undefined;
        if (dropped !== 0) this.reportDropped(dropped);
        return { frames, dropped, waiting: kept !== 0 };
      },
      true,
      true,
    );
  }

  /**
   * Whether publications are queued, from the known outbox tail without
   * reading the outbox; undefined when it must be read.
   */
  hasQueuedPublications(): Promise<boolean | undefined> {
    return this.enqueue(
      0,
      () => async () => {
        this.assertActivated();
        return this.outboxTail === undefined
          ? undefined
          : this.outboxTail !== null;
      },
      true,
      true,
    );
  }

  private reportDropped(frames: number): void {
    const report = this.options.onPublicationsDropped;
    if (!report) {
      console.warn(
        `[${this.documentId}] dropped ${frames} unsent change frame(s) sealed for an earlier group epoch or authority; current members did not receive them.`,
      );
      return;
    }
    try {
      report(frames);
    } catch {
      // The application's handler cannot affect publication state.
    }
  }

  /** Learn the queued tail publication and how many publications are queued. */
  private async loadOutboxTail(): Promise<void> {
    const rows = this.options.journal
      ? await this.options.journal.pendingPublications()
      : this.publications.map((frame) => frame.slice());
    const last = rows.at(-1);
    if (!last) {
      this.outboxTail = null;
      return;
    }
    const parts = splitDocumentPublication(last);
    const key = await this.frameKey();
    this.outboxTail = {
      bytes: last,
      frames: parts.length,
      // A stale tail never matches a new frame's binding.
      aad: (await this.decryptsUnder(parts[0], key))
        ? key.aad
        : new Uint8Array(),
      rows: rows.length,
    };
  }

  private async removePublication(frame: Uint8Array): Promise<void> {
    if (this.options.journal) await this.options.journal.publicationSent(frame);
    else
      this.publications = this.publications.filter(
        (value) => !documentBytesEqual(value, frame),
      );
    this.markSent(frame);
    if (this.outboxTail && documentBytesEqual(this.outboxTail.bytes, frame))
      this.outboxTail = undefined;
  }

  private async outboxIsFull(bytes: number): Promise<boolean> {
    try {
      const rows = await this.options.journal!.pendingPublications();
      const queued = rows.reduce(
        (sum, row) => sum + row.length + STORED_PUBLICATION_OVERHEAD,
        0,
      );
      return (
        rows.length >= MAX_PUBLICATIONS ||
        queued + bytes + STORED_PUBLICATION_OVERHEAD > MAX_PUBLICATION_BYTES
      );
    } catch {
      return false;
    }
  }

  close(): Promise<void> {
    this.closed = true;
    this.activated = false;
    this.clearHeld();
    this.dropRetained();
    this.rosterBinding = undefined;
    this.pendingCatchUp = undefined;
    this.topicCatchUps = [];
    this.material = undefined;
    return this.tail.then(() => {
      this.clearHeld();
      this.session.close();
    });
  }
}
