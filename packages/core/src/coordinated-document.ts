import {
  DocumentJournalCapacityError,
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
  decodeDocumentCatchUpCheckpoint,
  decodeDocumentCatchUpRequest,
  documentCatchUpAAD,
  encodeDocumentCatchUpCheckpoint,
  encodeDocumentCatchUpRequest,
  MAX_DOCUMENT_CATCH_UP_REQUEST_BYTES,
  type DocumentCatchUpBinding,
  type DocumentCatchUpKind,
} from './document-catch-up-wire.js';
import {
  decodeDocumentContent,
  decodeEncryptedDocumentContent,
  decodeSignedDocumentContent,
  documentContentAAD,
  documentContextsMatch,
  documentFrameEpochTag,
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

export interface CoordinatedDocumentOptions {
  readonly coordinator: GroupSecurityCoordinator;
  readonly authority: DocumentAuthority;
  readonly journal?: DocumentReplayJournal;
  readonly persistPublications?: boolean;
  /** Append each local frame to the queued tail publication while it fits. */
  readonly joinPublications?: boolean;
  /** Require the signed roles to enumerate the provider's exact decrypting roster. */
  readonly requireGroupRosterMatch?: boolean;
  /** Allow explicit app-relayed catch-up from the current unrestricted controller. */
  readonly enableAuthenticatedCatchUp?: boolean;
  /**
   * Called with the number of unsent frames dropped because they were sealed
   * for an earlier group context or authority head. Without it, a warning is
   * logged.
   */
  readonly onPublicationsDropped?: (frames: number) => void;
}

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

// One full outbox is 16 publications of up to 1,024 frames and 16 MiB. A
// sender's share holds that backlog plus live edits sent while it drains.
const SENDER_FRAMES = 16 * 1024 + 4096,
  SENDER_BYTES = 24 * 1024 * 1024;
const aggregateInbound = new ReceivedFrameBudget(128 * 1024, 128 * 1024 * 1024);
// One network sender may hold a quarter of the process-wide received queue.
const aggregateSenders = new Map<string, ReceivedFrameBudget>();
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
  readonly release: () => void;
}

// A replacement publication must still fit beside 15 full ones in the
// journal's 16 MiB, counting each row's storage overhead.
const MAX_JOINED_PUBLICATION_BYTES = MAX_DOCUMENT_SECURITY_FRAME_BYTES - 2048;
// Bounds one encoded frame: content plus its identity, context and signature.
const MAX_FRAME_ESTIMATE = MAX_DOCUMENT_CONTENT_BYTES + 32 * 1024;

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
const aggregateHeld = new GroupDocumentOperationBudget(
  1024,
  64 * 1024 * 1024,
);

type HeldReason = 'gap' | 'dependency';

/** An authenticated frame whose author prefix or native dependencies are missing. */
class HeldDocumentFrame extends Error {
  constructor(
    readonly reason: HeldReason,
    readonly context: GroupSecurityDocumentContext,
    readonly author: string,
    readonly sequence: number,
    readonly hash: Uint8Array,
  ) {
    super('Document frame waits for its causal predecessors');
  }
}

interface HeldFrame {
  readonly frame: Uint8Array;
  readonly author: string;
  readonly sequence: number;
  readonly hash: Uint8Array;
  readonly release: () => void;
  reason: HeldReason;
  attemptedAt: number;
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
    32 * 1024,
    64 * 1024 * 1024,
  );
  private readonly senders = new Map<string, ReceivedFrameBudget>();
  // The last queued publication; null when the outbox is known to be empty.
  private outboxTail: OutboxTail | null | undefined;
  private deriving?: {
    readonly context: GroupSecurityDocumentContext;
    readonly value: Promise<GroupDocumentEncryptionMaterial>;
  };
  private tail: Promise<void> = Promise.resolve();
  private receipts = new Map<string, Receipt>();
  private receiptsContext?: GroupSecurityDocumentContext;
  private recovered = false;
  private activated = false;
  private rosterBinding?: DocumentGroupRosterBinding;
  private pendingCatchUp?: PendingCatchUp;
  private persistedAuthorityLease?: () => boolean;
  private publications: Uint8Array[] = [];
  private held?: {
    readonly context: GroupSecurityDocumentContext;
    readonly frames: HeldFrame[];
    bytes: number;
  };
  private appliedFrames = 0;
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
    if (requireGroupRosterMatch && !(authority instanceof DocumentAuthorityLog))
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
    if (
      enableAuthenticatedCatchUp &&
      (!requireGroupRosterMatch ||
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
      requireGroupRosterMatch,
      enableAuthenticatedCatchUp,
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

  private assertUsable(): void {
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

  private enqueue<T>(
    bytes: number,
    capture: () => () => Promise<T>,
  ): Promise<T> {
    let local: (() => void) | undefined, shared: (() => void) | undefined;
    try {
      this.assertUsable();
      shared = aggregate.reserve(bytes);
      local = this.budget.reserve(bytes);
      const work = capture();
      const result = this.tail.then(() => {
        this.assertUsable();
        return work();
      });
      const settled = result.finally(() => {
        local!();
        shared!();
      });
      this.tail = settled.then(
        () => {},
        () => {},
      );
      return settled;
    } catch (error) {
      local?.();
      shared?.();
      return Promise.reject(error);
    }
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
              !this.closed && !this.failed && lease.isCurrent(),
            commit: () => {
              this.rosterBinding = roster;
              this.activated = true;
            },
          };
        },
      );
    });
  }

  change(change: Change, message = ''): Promise<Uint8Array> {
    if (typeof message !== 'string' || message.length > 4096)
      return Promise.reject(new TypeError('Invalid change message'));
    return this.enqueue(MAX_DOCUMENT_CONTENT_BYTES, () => () => {
      this.assertActivated();
      return this.apply(undefined, change, message);
    });
  }

  /**
   * Apply a publication of consecutive frames from one author. Every frame is
   * charged against the received bounds; a `sender` names the network peer,
   * whose share holds one full outbox backlog plus live edits. Each frame
   * must decrypt under the current epoch before the publication waits for its
   * turn, and frames the author already delivered are dropped then, so
   * unauthenticated input and replays cost no signature check.
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
      for (const value of frames) {
        const releases: Array<() => void> = [];
        reserved.push(releases);
        releases.push(aggregateInbound.reserve(value.length));
        releases.push(this.inbound.reserve(value.length));
        if (sender !== undefined) {
          releases.push(
            reserveSender(
              aggregateSenders,
              sender,
              value.length,
              aggregateInbound.maxFrames / 4,
              aggregateInbound.maxBytes / 4,
            ),
          );
          releases.push(
            reserveSender(
              this.senders,
              sender,
              value.length,
              SENDER_FRAMES,
              SENDER_BYTES,
            ),
          );
        }
      }
      const admitted = this.admitFrames(
        frames,
        (index) => () => release(index),
      );
      admitted.then(undefined, () => release());
      const result = this.tail.then(async () => {
        const accepted = await admitted;
        this.assertUsable();
        this.assertActivated();
        let applied = false;
        for (const value of accepted) {
          try {
            if (await this.receiveOwned(value.frame, value)) applied = true;
          } catch (error) {
            if (!applied) throw error;
            break;
          } finally {
            value.release();
          }
        }
        return applied;
      });
      const settled = result.finally(() => release());
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
   * come from one author with consecutive sequences. Frames at or below the
   * author's accepted sequence are released and dropped without a signature
   * check.
   */
  private async admitFrames(
    frames: readonly Uint8Array[],
    releaser: (index: number) => () => void,
  ): Promise<AdmittedFrame[]> {
    const context = this.options.coordinator.documentContext;
    const key = await this.frameKey();
    const admitted: AdmittedFrame[] = [];
    let author: string | undefined,
      first = 0;
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
      const content = decodeDocumentContent(
        decodeSignedDocumentContent(plaintext).unsigned,
      );
      const id = documentBytesId(content.memberId);
      if (index === 0) {
        author = id;
        first = content.sequence;
      } else if (id !== author || content.sequence !== first + index)
        throw new Error(
          'Document publication frames must be one author’s consecutive sequences',
        );
      admitted.push({
        frame,
        plaintext,
        context,
        aad: key.aad,
        release: releaser(index),
      });
    }
    const accepted = this.receiptsAt(context).get(author!)?.sequence ?? 0;
    const delivered = Math.max(
      0,
      Math.min(admitted.length, accepted - first + 1),
    );
    for (const value of admitted.slice(0, delivered)) value.release();
    return admitted.slice(delivered);
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

  /** Keep a bounded set of authenticated frames until their predecessors apply. */
  private hold(frame: Uint8Array, pending: HeldDocumentFrame): void {
    if (
      !this.held ||
      !documentContextsMatch(this.held.context, pending.context)
    ) {
      this.clearHeld();
      this.held = { context: pending.context, frames: [], bytes: 0 };
    }
    const held = this.held;
    const same = held.frames.find(
      (entry) =>
        entry.author === pending.author && entry.sequence === pending.sequence,
    );
    if (same) {
      if (!documentBytesEqual(same.hash, pending.hash))
        throw new Error('Document author equivocated');
      same.reason = pending.reason;
      same.attemptedAt = this.appliedFrames;
      return;
    }
    if (
      held.frames.length >= MAX_HELD_FRAMES ||
      held.bytes + frame.length > MAX_HELD_BYTES ||
      held.frames.filter((entry) => entry.author === pending.author).length >=
        MAX_HELD_FRAMES_PER_AUTHOR
    )
      throw new Error('Document frames waiting for predecessors exceed their bound');
    held.frames.push({
      frame,
      author: pending.author,
      sequence: pending.sequence,
      hash: pending.hash,
      release: aggregateHeld.reserve(frame.length),
      reason: pending.reason,
      attemptedAt: this.appliedFrames,
    });
    held.bytes += frame.length;
  }

  private clearHeld(): void {
    for (const entry of this.held?.frames ?? []) entry.release();
    this.held = undefined;
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
        const accepted =
          this.receiptsAt(held.context).get(entry.author)?.sequence ?? 0;
        if (
          entry.sequence > accepted &&
          (entry.reason === 'gap'
            ? entry.sequence !== accepted + 1
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
            entry.attemptedAt = this.appliedFrames;
            keep = true;
          }
        }
        if (this.held !== held) return;
        if (keep) continue;
        held.frames.splice(held.frames.indexOf(entry), 1);
        held.bytes -= entry.frame.length;
        entry.release();
        if (applied) {
          this.appliedFrames++;
          progressed = true;
        }
      }
    }
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
      MAX_DOCUMENT_CONTENT_BYTES,
      (input) =>
        this.runCatchUp(input, async (stage) => {
          const controllerId = this.options.coordinator.localMemberId;
          const controller = this.catchUpController(stage.lease, controllerId);
          const signed = await this.openCatchUp(stage, 'request', input);
          const body = decodeDocumentCatchUpRequest(signed.unsigned);
          this.assertCatchUpBinding(stage.binding, body);
          const requester = stage.lease.members.get(
            documentBytesId(body.requesterId),
          );
          if (!requester || documentBytesEqual(body.requesterId, controllerId))
            throw new Error('Document catch-up requester is unauthorized');
          await this.verifyCatchUp(stage, signed, requester);
          stage.assertCurrent();
          const receipts = new Map(
            [...this.receiptsAt(stage.binding.context)].sort(([a], [b]) =>
              a < b ? -1 : a === b ? 0 : 1,
            ),
          );
          const snapshot = this.serializer.serializeChanges(
            this.crdt.getSnapshot!(this.session.document),
          );
          const value = await this.sealCatchUp(
            stage,
            'checkpoint',
            encodeDocumentCatchUpCheckpoint({
              ...body,
              controllerId,
              receipts: receiptEntries(receipts),
              snapshot,
            }),
            controller,
          );
          return { value };
        }),
    );
  }

  applyCatchUpCheckpoint(checkpoint: Uint8Array): Promise<void> {
    return this.enqueueCatchUp(
      checkpoint,
      MAX_DOCUMENT_SECURITY_FRAME_BYTES,
      MAX_DOCUMENT_CONTENT_BYTES,
      async (input) => {
        await this.mergeCatchUpCheckpoint(input);
        this.appliedFrames++;
        await this.releaseHeld();
      },
    );
  }

  private enqueueCatchUp<Value>(
    frame: Uint8Array | undefined,
    maximum: number,
    workBytes: number,
    run: (input: Uint8Array) => Promise<Value>,
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
      });
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

  private async openCatchUp(
    stage: CatchUpWork,
    kind: DocumentCatchUpKind,
    frame: Uint8Array,
  ) {
    const envelope = decodeEncryptedDocumentContent(frame);
    if (!documentBytesEqual(envelope.epochTag, stage.material.epochTag))
      throw new Error('Document catch-up epoch is unavailable');
    const { value } = await stage.work.observe<ArrayBuffer>(
      (async () =>
        crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: envelope.nonce as Uint8Array<ArrayBuffer>,
            additionalData: documentCatchUpAAD(
              kind,
              stage.binding,
            ) as Uint8Array<ArrayBuffer>,
          },
          stage.material.key,
          envelope.ciphertext as Uint8Array<ArrayBuffer>,
        ))(),
    );
    return decodeSignedDocumentContent(new Uint8Array(value));
  }

  private async verifyCatchUp(
    stage: CatchUpWork,
    body: ReturnType<typeof decodeSignedDocumentContent>,
    member: CapturedDocumentMember,
  ): Promise<void> {
    const { value: key } = await stage.work.observe<PublicKey>(
      this.auth.deserializePublicKey(member.publicKey),
    );
    const { value: canonical } = await stage.work.observe<string>(
      this.auth.serializePublicKey(key),
    );
    if (canonical !== member.publicKey)
      throw new Error('Noncanonical document catch-up signer');
    const { value: verified } = await stage.work.observe<boolean>(
      this.auth.verify(body.unsigned.slice(), key, body.signature.slice()),
    );
    if (verified !== true)
      throw new Error('Invalid document catch-up signature');
  }

  private async sealCatchUp(
    stage: CatchUpWork,
    kind: DocumentCatchUpKind,
    unsigned: Uint8Array,
    member: CapturedDocumentMember,
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
            additionalData: documentCatchUpAAD(
              kind,
              stage.binding,
            ) as Uint8Array<ArrayBuffer>,
          },
          stage.material.key,
          encodeSignedDocumentContent(
            unsigned,
            signature,
          ) as Uint8Array<ArrayBuffer>,
        ))(),
    );
    return encodeEncryptedDocumentContent(
      stage.material.epochTag,
      nonce,
      new Uint8Array(ciphertext),
    );
  }

  private async mergeCatchUpCheckpoint(input: Uint8Array): Promise<void> {
    const pending = this.pendingCatchUp;
    if (!pending) throw new Error('No document catch-up request is pending');
    let plan: PreparedDocumentChange<Changes> | undefined;
    let journal: PreparedDocumentJournal | undefined;
    let accepting = false;
    try {
      const { context, receipts, lease } = await this.runCatchUp(
        input,
        async (stage, owned) => {
          if (pending.roster !== stage.roster)
            throw new Error('Document catch-up request authority changed');
          const localId = this.options.coordinator.localMemberId;
          if (!stage.lease.members.has(documentBytesId(localId)))
            throw new Error('Local member has no document authority');
          const signed = await this.openCatchUp(stage, 'checkpoint', owned);
          const body = decodeDocumentCatchUpCheckpoint(signed.unsigned);
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
          const receipts = this.mergeCatchUpReceipts(
            stage.lease,
            context,
            localId,
            body.receipts,
          );
          plan = this.session.prepareMergeSnapshot!(
            this.serializer.deserializeChanges(body.snapshot),
          );
          if (!plan.snapshot)
            throw new Error('CRDT provider cannot checkpoint merged state');
          const { value } = await stage.work.observe<PreparedDocumentJournal>(
            this.options.journal!.prepare({
              checkpoint: true,
              context,
              changes: this.serializer.serializeChanges(plan.snapshot()),
              receipts: receiptEntries(receipts),
              authorityHead: stage.lease.headId,
              authorityRecords: this.options.authority.exportRecords!(),
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
      accepting = true;
      this.pendingCatchUp = undefined;
      await journal!.commit();
      await this.runCatchUp(new Uint8Array(), async (stage) => {
        if (stage.roster !== pending.roster || !lease.isCurrent())
          throw new Error(
            'Document catch-up authority changed after acceptance',
          );
        return {
          value: undefined,
          isCurrent: () => plan!.isCurrent(),
          commit: () => {
            plan!.commit();
            this.receipts = receipts;
            this.receiptsContext = context;
            this.persistedAuthorityLease = lease.isCurrent;
          },
        };
      });
    } catch (error) {
      if (accepting) this.failed = true;
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
      if (admission === 'conflict')
        throw new Error(
          'Document catch-up receipt conflicts with the accepted head',
        );
      if (admission === 'adopt') receipts.set(id, { sequence, hash });
    }
    return receipts;
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
    const maxRows = this.options.journal
      ? MAX_PUBLICATIONS - 1
      : MAX_PUBLICATIONS;
    if (input === undefined && this.options.joinPublications) {
      if (
        this.outboxTail === undefined ||
        (this.outboxTail !== null && !this.mayJoin(this.outboxTail))
      )
        await this.loadOutboxTail();
      tail = this.outboxTail ?? undefined;
      rows = tail?.rows ?? 0;
      // The journal stages a replacement beside the publication it replaces,
      // so its last row stays free for that staging.
      if ((!tail || !this.mayJoin(tail)) && rows >= maxRows)
        throw new DocumentPublicationBacklogError();
    }
    let outbound: Uint8Array | undefined,
      merged = false;
    let committed = false,
      replay = false;
    let held: HeldReason | undefined;
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
              const signed = decodeSignedDocumentContent(plaintext);
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
                }
              }
            } else {
              memberId = this.options.coordinator.localMemberId;
              const found = lease.members.get(documentBytesId(memberId));
              if (!found || !contentRolePermits(found.role, false))
                throw new Error('Local document member cannot write');
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
              plan = this.session.prepareLocal(message, change!, {
                inspectOperations:
                  lease.writePaths.get(member.id) !== undefined,
              });
              assertDocumentOperationsAllowed(
                plan,
                lease.writePaths.get(member.id),
              );
              const changes = copyUnsharedUint8Array(
                this.serializer.serializeChanges(plan.changes),
                0,
                MAX_DOCUMENT_CONTENT_BYTES,
                'document delta',
              );
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
              if (checkpoint && !plan!.snapshot)
                throw new Error(
                  'CRDT provider cannot checkpoint accepted state',
                );
              const changes = checkpoint
                ? this.serializer.serializeChanges(plan!.snapshot!())
                : this.serializer.serializeChanges(plan!.changes);
              const nextReceipts = new Map(receipts);
              nextReceipts.set(documentBytesId(memberId), { sequence, hash });
              const persistedReceipts = checkpoint
                ? receiptEntries(nextReceipts)
                : [{ memberId, sequence, hash }];
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
                  ...(outbound ? { outboundFrame: outbound } : {}),
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
                (replay || plan!.isCurrent()),
              commit: () => {
                this.rosterBinding = roster;
                if (replay) return;
                commitAttempted = true;
                plan!.commit();
                this.receipts = receipts;
                this.receiptsContext = captured;
                this.receipts.set(documentBytesId(memberId), {
                  sequence,
                  hash,
                });
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
        // The superseded publication is a prefix of its replacement, so a
        // copy left by a failed removal only replays accepted frames.
        if (merged && this.options.journal)
          await this.options.journal
            .publicationSent(tail!.bytes)
            .catch(() => {});
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
      for (const record of records) {
        if (this.options.authority.extendsHead(record.authorityHead) !== true)
          throw new Error(
            'Configured authority forks the accepted document history',
          );
      }
      for (const record of records) {
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
      this.recovered = true;
    } catch (error) {
      this.failed = true;
      throw error;
    }
  }

  /** A role transition is acknowledged only after its checkpoint is durable. */
  applyAuthorityUpdate(encoded: Uint8Array): Promise<void> {
    return this.queueAuthorityUpdate(encoded, false);
  }

  /** Install an authenticated strict role record while leaving activation fenced. */
  applyAuthorityUpdateBeforeOpen(encoded: Uint8Array): Promise<void> {
    return this.queueAuthorityUpdate(encoded, true);
  }

  private queueAuthorityUpdate(
    encoded: Uint8Array,
    beforeOpen: boolean,
  ): Promise<void> {
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
          const authority = this.options.authority;
          if (this.options.requireGroupRosterMatch) {
            if (!(authority instanceof DocumentAuthorityLog)) {
              throw new Error(
                'Strict group roster matching requires a signed document authority log',
              );
            }
            await this.applyStrictAuthorityUpdate(authority, owned);
            return;
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
              }),
            );
            prepared = value;
            return {
              isAuthorizationCurrent: () =>
                !this.closed && !this.failed && isAuthorizationCurrent(),
              commit: () => {
                this.receipts = new Map();
                this.receiptsContext = captured;
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

  assertPublicationDispatchAllowed(binding = this.rosterBinding): void {
    if (!this.options.requireGroupRosterMatch) return;
    this.assertUsable();
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
        this.assertPublicationDispatchAllowed(binding);
        return true;
      } catch {
        return false;
      }
    };
  }

  pendingPublications(): Promise<ReadonlyArray<Uint8Array>> {
    return this.enqueue(0, () => async () => {
      this.assertActivated();
      const binding = this.rosterBinding;
      this.assertPublicationDispatchAllowed(binding);
      if (!this.options.journal)
        return this.publications.map((frame) => frame.slice());
      const frames = await this.options.journal.pendingPublications();
      this.assertPublicationDispatchAllowed(binding);
      return frames;
    });
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
      });
    } catch (error) {
      return Promise.reject(error);
    }
  }

  /**
   * Read publications to send now. A publication sealed for an earlier group
   * context or authority head would be rejected by every current member, so
   * it is removed and its frames are counted as `dropped`.
   */
  dispatchablePublications(): Promise<{
    readonly frames: ReadonlyArray<Uint8Array>;
    readonly dropped: number;
  }> {
    return this.enqueue(0, () => async () => {
      this.assertActivated();
      const binding = this.rosterBinding;
      this.assertPublicationDispatchAllowed(binding);
      const rows = this.options.journal
        ? await this.options.journal.pendingPublications()
        : this.publications.map((frame) => frame.slice());
      this.assertPublicationDispatchAllowed(binding);
      const frames: Uint8Array[] = [];
      let dropped = 0,
        last = 0;
      const key = rows.length === 0 ? undefined : await this.frameKey();
      this.assertPublicationDispatchAllowed(binding);
      for (const row of rows) {
        // One publication only joins frames sealed under the same binding.
        const parts = splitDocumentPublication(row);
        if (await this.decryptsUnder(parts[0], key!)) {
          frames.push(row);
          last = parts.length;
        } else {
          dropped += parts.length;
          await this.removePublication(row);
        }
      }
      const tail = frames.at(-1);
      this.outboxTail = tail
        ? { bytes: tail, frames: last, aad: key!.aad, rows: frames.length }
        : null;
      if (dropped !== 0) this.reportDropped(dropped);
      return { frames, dropped };
    });
  }

  /**
   * Whether publications are queued, from the known outbox tail without
   * reading the outbox; undefined when it must be read.
   */
  hasQueuedPublications(): Promise<boolean | undefined> {
    return this.enqueue(0, () => async () => {
      this.assertActivated();
      return this.outboxTail === undefined ? undefined : this.outboxTail !== null;
    });
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

  private mayJoin(tail: OutboxTail): boolean {
    return (
      tail.frames < MAX_DOCUMENT_PUBLICATION_FRAMES &&
      tail.bytes.length + MAX_FRAME_ESTIMATE <= MAX_JOINED_PUBLICATION_BYTES
    );
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
      aad: (await this.decryptsUnder(parts[0], key)) ? key.aad : new Uint8Array(),
      rows: rows.length,
    };
  }

  private async removePublication(frame: Uint8Array): Promise<void> {
    if (this.options.journal) await this.options.journal.publicationSent(frame);
    else
      this.publications = this.publications.filter(
        (value) => !documentBytesEqual(value, frame),
      );
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
    this.rosterBinding = undefined;
    this.pendingCatchUp = undefined;
    this.material = undefined;
    return this.tail.then(() => this.session.close());
  }
}
