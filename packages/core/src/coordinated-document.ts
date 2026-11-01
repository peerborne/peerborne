import type {
  DocumentReplayJournal,
  PreparedDocumentJournal,
} from './document-replay-journal.js';
import type { AuthProvider } from './auth-provider.js';
import type { ChangesSerializer } from './changes-serializer.js';
import type { CRDTProvider } from './crdt-provider.js';
import type {
  CRDTDocumentSession,
  PreparedDocumentChange,
} from './document-crdt-session.js';
import type {
  GroupDocumentEncryptionMaterial,
  GroupSecurityCoordinator,
  GroupSecurityDocumentContext,
  GroupSecurityDocumentPreparation,
} from './group-security-coordinator.js';
import { GroupDocumentOperationBudget } from './group-document-operation.js';
import {
  documentBytesEqual,
  documentBytesId,
} from './internal/document-binary.js';
import { isWellFormedUtf16 } from './internal/canonical-encoding.js';
import {
  copyUnsharedUint8Array,
  unsharedUint8ArrayByteLength,
} from './utils.js';
import {
  admitContentSequence,
  contentRolePermits,
  nextContentSequence,
} from './policy/document-content.js';
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
}

/** An application-pinned authority. A network-supplied roster is never a trust root. */
export interface DocumentAuthority {
  readonly documentId: string;
  readonly genesisId: Uint8Array;
  assertCoordinator?(coordinator: GroupSecurityCoordinator): void;
  exportRecords?(): ReadonlyArray<Uint8Array>;
  applyUpdate?(
    coordinator: GroupSecurityCoordinator,
    encoded: Uint8Array,
  ): Promise<void>;
  capture(context: GroupSecurityDocumentContext): {
    readonly members: ReadonlyArray<DocumentMemberAuthority>;
    isCurrent(): boolean;
  };
}

export interface CoordinatedDocumentOptions {
  readonly coordinator: GroupSecurityCoordinator;
  readonly authority: DocumentAuthority;
  readonly journal?: DocumentReplayJournal;
  readonly persistPublications?: boolean;
}

interface Receipt {
  sequence: number;
  hash: Uint8Array;
}
const aggregate = new GroupDocumentOperationBudget(64, 64 * 1024 * 1024);
const ZERO_HASH = new Uint8Array(32);

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
  private publications: Uint8Array[] = [];
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
    if (
      !documentId ||
      documentId.length > 4096 ||
      !isWellFormedUtf16(documentId) ||
      options.authority.documentId !== documentId
    )
      throw new TypeError('Invalid coordinated document identity');
    if (typeof crdt.createDocumentSession !== 'function')
      throw new TypeError(
        'Coordinated documents require detached CRDT preparation',
      );
    this.options = {
      coordinator: options.coordinator,
      authority: options.authority,
      journal: options.journal,
      persistPublications: options.persistPublications,
    };
    this.genesisId = copyUnsharedUint8Array(
      options.authority.genesisId,
      32,
      32,
      'document authority root',
    );
    options.authority.assertCoordinator?.(options.coordinator);
    options.journal?.assertBinding(documentId, this.genesisId);
    this.session = crdt.createDocumentSession(initial);
  }

  get document(): Document {
    this.assertUsable();
    if (this.options.journal && !this.recovered)
      throw new Error('Document recovery is not complete');
    return this.session.document;
  }

  get routingId(): string {
    return documentBytesId(this.genesisId);
  }

  async publicKeys(writersOnly: boolean): Promise<PublicKey[]> {
    this.assertUsable();
    const lease = this.authority(this.options.coordinator.documentContext);
    const result: PublicKey[] = [];
    for (const member of lease.members.values()) {
      if (!writersOnly || contentRolePermits(member.role, false))
        result.push(await this.auth.deserializePublicKey(member.publicKey));
    }
    if (!lease.isCurrent()) throw new Error('Document authority changed');
    return result;
  }

  private assertUsable(): void {
    if (this.closed || this.failed)
      throw new Error('Coordinated document must be reopened');
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
      await this.recover();
      const context = this.options.coordinator.documentContext;
      await this.options.coordinator.runDocumentOperation(
        context,
        new Uint8Array(),
        async (_context, _input, _signal, work) => {
          const lease = this.authority(context);
          const own = lease.members.get(
            documentBytesId(this.options.coordinator.localMemberId),
          );
          if (!own) throw new Error('Local member has no document authority');
          const { value } = await work.observe<string>(
            this.auth.serializePublicKey(this.publicKey),
          );
          if (typeof value !== 'string' || value !== own.publicKey)
            throw new Error('Document signing identity mismatch');
          return { isAuthorizationCurrent: lease.isCurrent, commit: () => {} };
        },
      );
    });
  }

  change(change: Change, message = ''): Promise<Uint8Array> {
    if (typeof message !== 'string' || message.length > 4096)
      return Promise.reject(new TypeError('Invalid change message'));
    return this.enqueue(
      MAX_DOCUMENT_CONTENT_BYTES,
      () => () => this.apply(undefined, change, message),
    );
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
          const result = await this.apply(owned);
          return result.length !== 0;
        };
      });
    } catch (error) {
      return Promise.reject(error);
    }
  }

  private authority(context: GroupSecurityDocumentContext) {
    const captured = this.options.authority.capture(context);
    if (
      !Array.isArray(captured.members) ||
      captured.members.length < 1 ||
      captured.members.length > 256 ||
      typeof captured.isCurrent !== 'function'
    )
      throw new Error('Invalid document authority');
    const members = new Map<string, DocumentMemberAuthority>();
    for (const member of captured.members) {
      const id = documentBytesId(
        copyUnsharedUint8Array(member.memberId, 32, 32, 'document member'),
      );
      if (
        members.has(id) ||
        typeof member.publicKey !== 'string' ||
        !member.publicKey ||
        member.publicKey.length > 16 * 1024 ||
        ![1, 2, 3].includes(member.role)
      )
        throw new Error('Invalid document authority member');
      members.set(id, {
        memberId: member.memberId.slice(),
        publicKey: member.publicKey,
        role: member.role,
      });
    }
    if (!members.has(documentBytesId(this.options.coordinator.localMemberId)))
      throw new Error('Local group member has no document access');
    return { members, isCurrent: () => captured.isCurrent() === true };
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
  ): Promise<Uint8Array> {
    await this.recover();
    const context = this.options.coordinator.documentContext;
    const receipts =
      this.receiptsContext &&
      documentContextsMatch(this.receiptsContext, context)
        ? this.receipts
        : new Map<string, Receipt>();
    let journal: PreparedDocumentJournal | undefined;
    let commitAttempted = false;
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
    let result: Uint8Array = new Uint8Array();
    try {
      await this.options.coordinator.runDocumentOperation(
        context,
        input ?? new Uint8Array(),
        (captured, owned, signal, work) => {
          const task = async () => {
            const lease = this.authority(captured);
            const material = await this.key(captured, work);
            const aad = documentContentAAD(this.documentId, captured);
            let unsigned: Uint8Array,
              memberId: Uint8Array,
              sequence: number,
              parent: Uint8Array;
            let member: DocumentMemberAuthority;
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
              const signed = decodeSignedDocumentContent(
                new Uint8Array(plaintext),
              );
              unsigned = signed.unsigned;
              const frame = decodeDocumentContent(unsigned);
              if (
                frame.documentId !== this.documentId ||
                !documentBytesEqual(frame.genesisId, this.genesisId) ||
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
              else if (admission !== 'apply')
                throw new Error('Document causal prefix is missing or forked');
              if (!replay)
                plan = this.session.prepareRemote(
                  this.serializer.deserializeChanges(frame.changes),
                );
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
              plan = this.session.prepareLocal(message, change!);
              const changes = copyUnsharedUint8Array(
                this.serializer.serializeChanges(plan.changes),
                0,
                MAX_DOCUMENT_CONTENT_BYTES,
                'document delta',
              );
              unsigned = encodeDocumentContent({
                documentId: this.documentId,
                genesisId: this.genesisId,
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
            }
            const { value: digest } = await work.observe<ArrayBuffer>(
              (async () =>
                crypto.subtle.digest(
                  'SHA-256',
                  unsigned as Uint8Array<ArrayBuffer>,
                ))(),
            );
            const hash = new Uint8Array(digest);
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
                ? [...nextReceipts].map(([id, receipt]) => ({
                    memberId: Uint8Array.from(id.match(/../g)!, (byte) =>
                      parseInt(byte, 16),
                    ),
                    ...receipt,
                  }))
                : [{ memberId, sequence, hash }];
              const { value } = await work.observe<PreparedDocumentJournal>(
                this.options.journal.prepare({
                  checkpoint,
                  context: captured,
                  changes,
                  receipts: persistedReceipts,
                  authorityRecords:
                    this.options.authority.exportRecords?.() ?? [],
                  ...(input === undefined && this.options.persistPublications
                    ? { outboundFrame: result }
                    : {}),
                }),
              );
              journal = value;
            }
            if (signal.aborted) throw new Error('Document preparation aborted');
            return {
              isAuthorizationCurrent: () =>
                !this.closed &&
                !this.failed &&
                lease.isCurrent() &&
                (replay || plan!.isCurrent()),
              commit: () => {
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
      if (committed) await journal?.commit();
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
    try {
      const length = unsharedUint8ArrayByteLength(
        encoded,
        1,
        MAX_DOCUMENT_SECURITY_FRAME_BYTES,
        'authority update',
      );
      return this.enqueue(length, () => {
        const owned = copyUnsharedUint8Array(
          encoded,
          length,
          length,
          'authority update',
        );
        return async () => {
          await this.recover();
          if (!this.options.authority.applyUpdate)
            throw new Error(
              'Document authority does not support signed transitions',
            );
          await this.options.authority.applyUpdate(
            this.options.coordinator,
            owned,
          );
          if (!this.options.journal) return;
          let prepared: PreparedDocumentJournal | undefined;
          let preparation: Promise<unknown> | undefined;
          try {
            const context = this.options.coordinator.documentContext;
            await this.options.coordinator.runDocumentOperation(
              context,
              new Uint8Array(),
              (captured, _input, _signal, work) => {
                preparation = (async () => {
                  const lease = this.authority(captured);
                  if (!this.crdt.getSnapshot)
                    throw new Error(
                      'CRDT provider cannot checkpoint role transitions',
                    );
                  const changes = this.serializer.serializeChanges(
                    this.crdt.getSnapshot(this.session.document),
                  );
                  const { value } = await work.observe<PreparedDocumentJournal>(
                    this.options.journal!.prepare({
                      checkpoint: true,
                      context: captured,
                      changes,
                      receipts: [],
                      authorityRecords:
                        this.options.authority.exportRecords?.() ?? [],
                    }),
                  );
                  prepared = value;
                  return {
                    isAuthorizationCurrent: lease.isCurrent,
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
          } catch (error) {
            this.failed = true;
            throw error;
          } finally {
            await preparation?.then(
              () => {},
              () => {},
            );
            await prepared?.discard();
          }
        };
      });
    } catch (error) {
      return Promise.reject(error);
    }
  }

  async pendingPublications(): Promise<ReadonlyArray<Uint8Array>> {
    this.assertUsable();
    return this.options.journal
      ? this.options.journal.pendingPublications()
      : this.publications.map((frame) => frame.slice());
  }

  async publicationSent(frame: Uint8Array): Promise<void> {
    if (this.options.journal) await this.options.journal.publicationSent(frame);
    else
      this.publications = this.publications.filter(
        (value) => !documentBytesEqual(value, frame),
      );
  }

  close(): Promise<void> {
    this.closed = true;
    this.material = undefined;
    return this.tail.then(() => this.session.close());
  }
}
