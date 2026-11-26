import type {
  DocumentReplayJournal,
  DocumentReplayReceipt,
  PreparedDocumentJournal,
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
  MAX_DOCUMENT_CATCH_UP_SUFFIX_BYTES,
  MAX_DOCUMENT_CATCH_UP_SUFFIX_FRAMES,
  type DocumentCatchUpBinding,
  type DocumentCatchUpCheckpoint,
  type DocumentCatchUpKind,
} from './document-catch-up-wire.js';
import {
  decodeDocumentContent,
  decodeEncryptedDocumentContent,
  decodeSignedDocumentContent,
  documentContentAAD,
  documentContextsMatch,
  encodeDocumentContent,
  encodeEncryptedDocumentContent,
  encodeSignedDocumentContent,
  MAX_DOCUMENT_CONTENT_BYTES,
  MAX_DOCUMENT_SECURITY_FRAME_BYTES,
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

/** Outcome for this author's unsent frames from the group context an update retired. */
export interface CoordinatedAuthorityUpdateResult {
  /** Unsent frames re-signed as new frames in the current context. */
  readonly resent: number;
  /** Unsent frames removed because the author can no longer write them here. */
  readonly dropped: number;
}

export interface CoordinatedDocumentOptions {
  readonly coordinator: GroupSecurityCoordinator;
  readonly authority: DocumentAuthority;
  readonly journal?: DocumentReplayJournal;
  readonly persistPublications?: boolean;
  /** Require the signed roles to enumerate the provider's exact decrypting roster. */
  readonly requireGroupRosterMatch?: boolean;
  /** Allow explicit app-relayed catch-up from the current unrestricted controller. */
  readonly enableAuthenticatedCatchUp?: boolean;
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
const ZERO_HASH = new Uint8Array(32);
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

/** An accepted frame kept for catch-up proofs and redelivery. */
interface RetainedFrame {
  readonly sequence: number;
  readonly hash: Uint8Array;
  /** Exact signed content: the unsigned frame and its author's signature. */
  readonly signed: Uint8Array;
  /** Exact encrypted wire frame. */
  readonly frame: Uint8Array;
  readonly order: number;
}

const MAX_RETAINED_FRAMES_PER_AUTHOR = 64;
const MAX_RETAINED_BYTES = 16 * 1024 * 1024;

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
  private retained?: {
    readonly context: GroupSecurityDocumentContext;
    readonly authors: Map<string, RetainedFrame[]>;
    bytes: number;
    order: number;
  };
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
      requireGroupRosterMatch,
      enableAuthenticatedCatchUp,
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
      requireGroupRosterMatch,
      enableAuthenticatedCatchUp,
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

  receive(frame: Uint8Array): Promise<boolean> {
    try {
      const length = unsharedUint8ArrayByteLength(
        frame,
        1,
        MAX_DOCUMENT_SECURITY_FRAME_BYTES,
        'document frame',
      );
      return this.enqueue(length, () => {
        const owned = copyUnsharedUint8Array(
          frame,
          length,
          length,
          'document frame',
        );
        return async () => {
          this.assertActivated();
          return this.receiveOwned(owned);
        };
      });
    } catch (error) {
      return Promise.reject(error);
    }
  }

  private async receiveOwned(frame: Uint8Array): Promise<boolean> {
    try {
      if ((await this.apply(frame)).length === 0) return false;
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

  /** Keep each author's latest accepted frames in the current context, bounded. */
  private retain(
    context: GroupSecurityDocumentContext,
    author: string,
    value: Omit<RetainedFrame, 'order'>,
  ): void {
    if (
      !this.retained ||
      !documentContextsMatch(this.retained.context, context)
    )
      this.retained = { context, authors: new Map(), bytes: 0, order: 0 };
    const retained = this.retained;
    const frames = retained.authors.get(author) ?? [];
    frames.push({ ...value, order: retained.order++ });
    retained.authors.set(author, frames);
    retained.bytes += value.signed.length + value.frame.length;
    const evict = (list: RetainedFrame[], owner: string) => {
      const [oldest] = list.splice(0, 1);
      retained.bytes -= oldest.signed.length + oldest.frame.length;
      if (list.length === 0) retained.authors.delete(owner);
    };
    if (frames.length > MAX_RETAINED_FRAMES_PER_AUTHOR) evict(frames, author);
    while (retained.bytes > MAX_RETAINED_BYTES) {
      let owner: string | undefined;
      for (const [id, list] of retained.authors)
        if (owner === undefined || list[0].order < retained.authors.get(owner)![0].order)
          owner = id;
      evict(retained.authors.get(owner!)!, owner!);
    }
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
    if (!retained || !documentContextsMatch(retained.context, context))
      return undefined;
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
          const receipts = this.sortedReceipts(stage.binding.context);
          const snapshot = this.serializer.serializeChanges(
            this.crdt.getSnapshot!(this.session.document),
          );
          const { receipts: requested, ...request } = body;
          const value = await this.sealCatchUp(
            stage,
            'checkpoint',
            encodeDocumentCatchUpCheckpoint({
              ...request,
              controllerId,
              receipts: receiptEntries(receipts),
              suffixes: this.catchUpSuffixes(
                stage.binding.context,
                receipts,
                requested,
                body.requesterId,
              ),
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
      if (admission === 'conflict' && !extends_)
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

  /** Retained signed frames that extend each of the requester's shorter heads. */
  private catchUpSuffixes(
    context: GroupSecurityDocumentContext,
    receipts: ReadonlyMap<string, Receipt>,
    requested: readonly DocumentReplayReceipt[],
    requesterId: Uint8Array,
  ): Uint8Array[] {
    const requester = documentBytesId(requesterId);
    const suffixes: Uint8Array[] = [];
    let bytes = 0;
    for (const { memberId, sequence, hash } of requested) {
      const author = documentBytesId(memberId);
      const head = receipts.get(author)?.sequence ?? 0;
      if (author === requester || sequence >= head) continue;
      const suffix = this.retainedSuffix(context, author, sequence, hash, head);
      if (!suffix) continue;
      const size = suffix.reduce((total, frame) => total + frame.signed.length, 0);
      if (
        suffixes.length + suffix.length > MAX_DOCUMENT_CATCH_UP_SUFFIX_FRAMES ||
        bytes + size > MAX_DOCUMENT_CATCH_UP_SUFFIX_BYTES
      )
        continue;
      suffixes.push(...suffix.map((frame) => frame.signed.slice()));
      bytes += size;
    }
    return suffixes;
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
    resend?: Uint8Array,
  ): Promise<Uint8Array> {
    const context = this.options.coordinator.documentContext;
    const receipts = this.receiptsAt(context);
    let journal: PreparedDocumentJournal | undefined;
    let commitAttempted = false;
    let acceptedAuthorityLease: (() => boolean) | undefined;
    let plan: PreparedDocumentChange<Changes> | undefined;
    let preparation: Promise<unknown> | undefined;
    if (
      !input &&
      this.options.persistPublications &&
      !this.options.journal &&
      this.publications.length >= 16
    )
      throw new Error('Document publication queue is full');
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
              signedContent: Uint8Array,
              memberId: Uint8Array,
              sequence: number,
              parent: Uint8Array;
            let member: CapturedDocumentMember;
            if (input !== undefined) {
              const envelope = decodeEncryptedDocumentContent(owned);
              if (!documentBytesEqual(envelope.epochTag, material.epochTag))
                throw new Error('Document epoch is unavailable');
              const { value: plaintext } = await work.observe<ArrayBuffer>(
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
              );
              signedContent = new Uint8Array(plaintext);
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
              const scope = lease.writePaths.get(member.id);
              if (resend === undefined) {
                plan = this.session.prepareLocal(message, change!, {
                  inspectOperations: scope !== undefined,
                });
                assertDocumentOperationsAllowed(plan, scope);
              } else if (scope !== undefined) {
                // Re-sent content is already local; inspect it against the current grants only.
                const inspected = this.session.prepareRemote(
                  this.serializer.deserializeChanges(resend),
                  { inspectOperations: true },
                );
                try {
                  assertDocumentOperationsAllowed(inspected, scope);
                } finally {
                  inspected.discard();
                }
              }
              const changes = copyUnsharedUint8Array(
                resend ?? this.serializer.serializeChanges(plan!.changes),
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
                : (resend ?? this.serializer.serializeChanges(plan!.changes));
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
                  ...(input === undefined && this.options.persistPublications
                    ? { outboundFrame: result }
                    : {}),
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
                if (replay) return;
                commitAttempted = true;
                plan?.commit();
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
                committed = true;
                if (
                  input === undefined &&
                  this.options.persistPublications &&
                  !this.options.journal
                )
                  this.publications.push(result.slice());
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

  /**
   * A role transition is acknowledged only after its checkpoint is durable.
   * When it starts a new group context, this author's unsent frames from the
   * retired context are re-signed in the new one while the author can still
   * write them, and removed otherwise.
   */
  async applyAuthorityUpdate(
    encoded: Uint8Array,
  ): Promise<CoordinatedAuthorityUpdateResult> {
    return (
      (await this.queueAuthorityUpdate(encoded, false)) ?? {
        resent: 0,
        dropped: 0,
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
          const retired = beforeOpen ? undefined : this.retained;
          const authority = this.options.authority;
          if (this.options.requireGroupRosterMatch) {
            if (!(authority instanceof DocumentAuthorityLog)) {
              throw new Error(
                'Strict group roster matching requires a signed document authority log',
              );
            }
            await this.applyStrictAuthorityUpdate(authority, owned);
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

  /** Re-sign or remove this author's unsent frames from a retired context. */
  private async resendRetired(
    retired: CoordinatedDocument<
      Document,
      Changes,
      Change,
      PrivateKey,
      PublicKey,
      DocumentKey
    >['retained'],
  ): Promise<CoordinatedAuthorityUpdateResult> {
    let resent = 0,
      dropped = 0;
    if (
      !retired ||
      documentContextsMatch(
        retired.context,
        this.options.coordinator.documentContext,
      )
    )
      return { resent, dropped };
    const own =
      retired.authors.get(
        documentBytesId(this.options.coordinator.localMemberId),
      ) ?? [];
    const pending = this.options.journal
      ? await this.options.journal.pendingPublications()
      : this.publications.map((frame) => frame.slice());
    const remove = async (frame: Uint8Array) => {
      if (this.options.journal) await this.options.journal.publicationSent(frame);
      else
        this.publications = this.publications.filter(
          (value) => !documentBytesEqual(value, frame),
        );
    };
    for (const frame of pending) {
      const entry = own.find((value) =>
        documentBytesEqual(value.frame, frame),
      );
      if (!entry) continue;
      const { changes } = decodeDocumentContent(
        decodeSignedDocumentContent(entry.signed).unsigned,
      );
      let removed = false;
      try {
        await this.apply(undefined, undefined, '', changes);
      } catch {
        // A full outbox needs the retired frame's slot before it can re-sign.
        await remove(frame);
        removed = true;
        try {
          await this.apply(undefined, undefined, '', changes);
        } catch {
          dropped++;
          continue;
        }
      }
      if (!removed) await remove(frame);
      resent++;
    }
    return { resent, dropped };
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
          if (this.options.journal)
            await this.options.journal.publicationSent(owned);
          else
            this.publications = this.publications.filter(
              (value) => !documentBytesEqual(value, owned),
            );
        };
      });
    } catch (error) {
      return Promise.reject(error);
    }
  }

  close(): Promise<void> {
    this.closed = true;
    this.activated = false;
    this.clearHeld();
    this.retained = undefined;
    this.rosterBinding = undefined;
    this.pendingCatchUp = undefined;
    this.material = undefined;
    return this.tail.then(() => this.session.close());
  }
}
