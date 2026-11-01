import type { MembershipControlAuthorizer } from './membership-control-record.js';
import type { GroupSecurityProtocol } from './group-security-provider.js';
import { canAdvanceDocumentAuthority } from './policy/document-journal.js';
import type { AuthProvider } from './auth-provider.js';
import type {
  DocumentAuthority,
  DocumentMemberAuthority,
} from './coordinated-document.js';
import type {
  GroupSecurityCoordinator,
  GroupSecurityDocumentContext,
  GroupSecurityDocumentPreparation,
} from './group-security-coordinator.js';
import {
  DocumentBinaryReader,
  DocumentBinaryWriter,
  documentBytesEqual,
  documentBytesId,
} from './internal/document-binary.js';
import {
  decodeSignedDocumentContent,
  documentContextsMatch,
  encodeSignedDocumentContent,
  readDocumentContext,
  writeDocumentContext,
} from './document-security-wire.js';
import { copyUnsharedUint8Array } from './utils.js';
import {
  admitContentSequence,
  nextContentSequence,
} from './policy/document-content.js';

const DOMAIN = Uint8Array.from('peerborne/document-authority/v1\0', (value) =>
  value.charCodeAt(0),
);
const MAX_RECORDS = 1024,
  MAX_HISTORY_BYTES = 16 * 1024 * 1024;
const ZERO = new Uint8Array(32);

interface AuthorityRecord {
  documentId: string;
  sequence: number;
  parent: Uint8Array;
  context: GroupSecurityDocumentContext;
  members: DocumentMemberAuthority[];
}

function encode(record: AuthorityRecord): Uint8Array {
  const writer = new DocumentBinaryWriter();
  writer
    .fixed(DOMAIN)
    .text(record.documentId)
    .integer(record.sequence, 8)
    .fixed(record.parent);
  writeDocumentContext(writer, record.context);
  writer.integer(record.members.length, 2);
  for (const member of record.members)
    writer
      .fixed(
        copyUnsharedUint8Array(member.memberId, 32, 32, 'authority member'),
      )
      .text(member.publicKey, 4096)
      .integer(member.role, 1);
  return writer.finish();
}

function decode(bytes: Uint8Array): AuthorityRecord {
  const reader = new DocumentBinaryReader(bytes);
  if (!documentBytesEqual(reader.fixed(DOMAIN.length), DOMAIN))
    throw new Error('Invalid document authority domain');
  const documentId = reader.text(),
    sequence = reader.number(8),
    parent = reader.fixed(32),
    context = readDocumentContext(reader),
    count = reader.number(2);
  if (
    !documentId ||
    documentId.length > 4096 ||
    !sequence ||
    count < 1 ||
    count > 256
  )
    throw new Error('Invalid authority record');
  const members: DocumentMemberAuthority[] = [];
  let previous = '',
    controllers = 0;
  const keys = new Set<string>();
  for (let index = 0; index < count; index++) {
    const memberId = reader.fixed(32),
      publicKey = reader.text(4096),
      role = reader.number(1),
      id = documentBytesId(memberId);
    if (
      id <= previous ||
      !publicKey ||
      keys.has(publicKey) ||
      role < 1 ||
      role > 3
    )
      throw new Error('Invalid authority roster');
    previous = id;
    keys.add(publicKey);
    if (role === 3) controllers++;
    members.push({ memberId, publicKey, role: role as 1 | 2 | 3 });
  }
  reader.end();
  if (controllers !== 1)
    throw new Error('Authority roster must have exactly one controller');
  return { documentId, sequence, parent, context, members };
}

function canonicalMembers(
  members: ReadonlyArray<DocumentMemberAuthority>,
): DocumentMemberAuthority[] {
  if (!Array.isArray(members) || members.length < 1 || members.length > 256)
    throw new Error('Invalid authority roster');
  return members
    .map((member) => ({
      memberId: copyUnsharedUint8Array(
        member.memberId,
        32,
        32,
        'authority member',
      ),
      publicKey: member.publicKey,
      role: member.role,
    }))
    .sort((a, b) =>
      documentBytesId(a.memberId) < documentBytesId(b.memberId)
        ? -1
        : documentBytesId(a.memberId) === documentBytesId(b.memberId)
          ? 0
          : 1,
    );
}

async function digest(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', value as Uint8Array<ArrayBuffer>),
  );
}

/** Signed role history, rooted in a genesis hash pinned outside the document transport. */
export class DocumentAuthorityLog<PrivateKey, PublicKey, DocumentKey>
  implements DocumentAuthority
{
  private records: Uint8Array[] = [];
  private historyBytes = 0;
  private revision = 1;
  private head: Uint8Array;
  private root: Uint8Array;
  private current: AuthorityRecord;
  private readonly controllers = new Map<string, Uint8Array>();
  private readonly verifiedHeads = new Set<string>();
  private controlAuthority?: DocumentGroupControlAuthority;

  private constructor(
    root: Uint8Array,
    record: AuthorityRecord,
    encoded: Uint8Array,
    private readonly auth: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  ) {
    this.verifiedHeads.add(documentBytesId(root));
    this.root = root.slice();
    this.head = root.slice();
    this.current = record;
    this.records.push(encoded.slice());
    this.historyBytes = encoded.length;
    this.controllers.set(
      documentBytesId(record.context.controlHead),
      record.members.find((member) => member.role === 3)!.memberId.slice(),
    );
  }

  get documentId(): string {
    return this.current.documentId;
  }
  get genesisId(): Uint8Array {
    return this.root.slice();
  }
  extendsHead(head: Uint8Array): boolean {
    return this.verifiedHeads.has(
      documentBytesId(
        copyUnsharedUint8Array(head, 32, 32, 'accepted authority head'),
      ),
    );
  }

  get headId(): Uint8Array {
    return this.head.slice();
  }
  exportRecords(): Uint8Array[] {
    return this.records.map((value) => value.slice());
  }

  static async create<PrivateKey, PublicKey, DocumentKey>(
    documentId: string,
    context: GroupSecurityDocumentContext,
    members: ReadonlyArray<DocumentMemberAuthority>,
    controllerKey: PrivateKey,
    auth: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
    controlAuthority: DocumentGroupControlAuthority,
  ): Promise<DocumentAuthorityLog<PrivateKey, PublicKey, DocumentKey>> {
    const unsigned = encode({
      documentId,
      sequence: 1,
      parent: ZERO,
      context,
      members: canonicalMembers(members),
    });
    const record = decode(unsigned);
    const signature = copyUnsharedUint8Array(
      await auth.sign(unsigned.slice(), controllerKey),
      1,
      1024,
      'authority signature',
    );
    const encoded = encodeSignedDocumentContent(unsigned, signature);
    return DocumentAuthorityLog.restore(
      [encoded],
      await digest(unsigned),
      auth,
      controlAuthority,
    );
  }

  static async restore<PrivateKey, PublicKey, DocumentKey>(
    records: ReadonlyArray<Uint8Array>,
    pinnedGenesis: Uint8Array,
    auth: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
    controlAuthority: DocumentGroupControlAuthority,
  ): Promise<DocumentAuthorityLog<PrivateKey, PublicKey, DocumentKey>> {
    const pin = copyUnsharedUint8Array(
      pinnedGenesis,
      32,
      32,
      'pinned authority genesis',
    );
    if (
      !Array.isArray(records) ||
      records.length < 1 ||
      records.length > MAX_RECORDS
    )
      throw new Error('Authority history exceeds bounds');
    let bytes = 0;
    const owned = records.map((value) => {
      const copy = copyUnsharedUint8Array(
        value,
        1,
        Math.min(1024 * 1024, MAX_HISTORY_BYTES - bytes),
        'authority record',
      );
      bytes += copy.length;
      return copy;
    });
    const first = decodeSignedDocumentContent(owned[0]),
      root = await digest(first.unsigned),
      initial = decode(first.unsigned);
    if (
      !documentBytesEqual(root, pin) ||
      initial.sequence !== 1 ||
      !documentBytesEqual(initial.parent, ZERO)
    )
      throw new Error('Untrusted authority genesis');
    const result = new DocumentAuthorityLog(root, initial, owned[0], auth);
    await result.verify(initial, first.unsigned, first.signature);
    for (const encoded of owned.slice(1)) {
      const signed = decodeSignedDocumentContent(encoded),
        next = decode(signed.unsigned);
      result.validateNext(next);
      await result.verify(result.current, signed.unsigned, signed.signature);
      result.install(next, encoded, await digest(signed.unsigned));
    }
    controlAuthority.bind(
      result,
      initial.context.state.protocol,
      initial.context.state.groupId,
      initial.members.find((member) => member.role === 3)!.memberId,
    );
    result.controlAuthority = controlAuthority;
    return result;
  }

  assertCoordinator(coordinator: GroupSecurityCoordinator): void {
    if (
      !this.controlAuthority ||
      !coordinator.usesControlAuthorizer(this.controlAuthority.authorize)
    )
      throw new Error(
        'Coordinator must use the document controller history for group authorization',
      );
  }

  controllerAtHead(head: Uint8Array): Uint8Array | undefined {
    return this.controllers.get(documentBytesId(head))?.slice();
  }

  capture(context: GroupSecurityDocumentContext) {
    if (!documentContextsMatch(context, this.current.context))
      throw new Error(
        'Role history does not cover the current authenticated group state',
      );
    const revision = this.revision;
    return {
      headId: this.head.slice(),
      members: this.current.members.map((member) => ({
        ...member,
        memberId: member.memberId.slice(),
      })),
      isCurrent: () => this.revision === revision,
    };
  }

  async signUpdate(
    context: GroupSecurityDocumentContext,
    members: ReadonlyArray<DocumentMemberAuthority>,
    controllerKey: PrivateKey,
  ): Promise<Uint8Array> {
    if (this.revision === Number.MAX_SAFE_INTEGER)
      throw new Error('Authority sequence is exhausted');
    const unsigned = encode({
      documentId: this.documentId,
      sequence: nextContentSequence(this.revision),
      parent: this.head.slice(),
      context,
      members: canonicalMembers(members),
    });
    const next = decode(unsigned);
    this.validateNext(next);
    const signature = copyUnsharedUint8Array(
      await this.auth.sign(unsigned.slice(), controllerKey),
      1,
      1024,
      'authority signature',
    );
    await this.verify(this.current, unsigned, signature);
    return encodeSignedDocumentContent(unsigned, signature);
  }

  async applyUpdate(
    coordinator: GroupSecurityCoordinator,
    encoded: Uint8Array,
  ): Promise<void> {
    this.assertCoordinator(coordinator);
    const context = coordinator.documentContext;
    const revision = this.revision;
    await coordinator.runDocumentOperation(
      context,
      encoded,
      async (captured, input, _signal, work) => {
        const signed = decodeSignedDocumentContent(input),
          next = decode(signed.unsigned);
        this.validateNext(next);
        if (this.historyBytes + input.length > MAX_HISTORY_BYTES)
          throw new Error('Authority history byte bound exceeded');
        if (!documentContextsMatch(next.context, captured))
          throw new Error(
            'Authority update names an unauthenticated group state',
          );
        await this.verify(
          this.current,
          signed.unsigned,
          signed.signature,
          work,
        );
        const { value: hash } = await work.observe<Uint8Array>(
          digest(signed.unsigned),
        );
        return {
          isAuthorizationCurrent: () => revision === this.revision,
          commit: () => this.install(next, input, hash),
        };
      },
    );
  }

  private validateNext(next: AuthorityRecord): void {
    const previous = this.current.context.state,
      state = next.context.state;
    if (
      this.records.length >= MAX_RECORDS ||
      next.documentId !== this.documentId ||
      admitContentSequence(
        next.sequence,
        this.revision,
        documentBytesEqual(next.parent, this.head),
      ) !== 'apply'
    )
      throw new Error('Authority history is full, replayed, or forked');
    if (
      !canAdvanceDocumentAuthority(
        previous.epoch,
        state.epoch,
        previous.protocol.id === state.protocol.id &&
          previous.protocol.version === state.protocol.version &&
          documentBytesEqual(previous.groupId, state.groupId),
        !documentBytesEqual(
          next.context.controlHead,
          this.current.context.controlHead,
        ),
      )
    )
      throw new Error(
        'Role transitions require a fresh authenticated group epoch',
      );
  }

  private async verify(
    authority: AuthorityRecord,
    unsigned: Uint8Array,
    signature: Uint8Array,
    work?: GroupSecurityDocumentPreparation,
  ): Promise<void> {
    const controller = authority.members.find((member) => member.role === 3)!;
    const key = work
      ? (
          await work.observe<PublicKey>(
            this.auth.deserializePublicKey(controller.publicKey),
          )
        ).value
      : await this.auth.deserializePublicKey(controller.publicKey);
    const canonical = work
      ? (await work.observe<string>(this.auth.serializePublicKey(key))).value
      : await this.auth.serializePublicKey(key);
    const verified = work
      ? (
          await work.observe<boolean>(
            this.auth.verify(unsigned.slice(), key, signature.slice()),
          )
        ).value
      : await this.auth.verify(unsigned.slice(), key, signature.slice());
    if (canonical !== controller.publicKey || verified !== true)
      throw new Error('Invalid document controller signature');
  }

  private install(
    next: AuthorityRecord,
    encoded: Uint8Array,
    hash: Uint8Array,
  ): void {
    if (this.historyBytes + encoded.length > MAX_HISTORY_BYTES)
      throw new Error('Authority history byte bound exceeded');
    this.records.push(encoded.slice());
    this.historyBytes += encoded.length;
    this.revision = next.sequence;
    this.current = next;
    this.head = hash.slice();
    this.verifiedHeads.add(documentBytesId(this.head));
    this.controllers.set(
      documentBytesId(next.context.controlHead),
      next.members.find((member) => member.role === 3)!.memberId.slice(),
    );
  }
}

/** Install before coordinator bootstrap/restore, then bind a pinned role history. */
export class DocumentGroupControlAuthority {
  readonly authorize: MembershipControlAuthorizer;
  private log?: { controllerAtHead(head: Uint8Array): Uint8Array | undefined };
  private readonly groupId: Uint8Array;
  private readonly controller: Uint8Array;
  private readonly protocol: GroupSecurityProtocol;
  constructor(
    protocol: GroupSecurityProtocol,
    groupId: Uint8Array,
    initialController: Uint8Array,
  ) {
    this.protocol = { id: protocol.id, version: protocol.version };
    this.groupId = copyUnsharedUint8Array(groupId, 1, 512, 'authority group');
    this.controller = copyUnsharedUint8Array(
      initialController,
      32,
      32,
      'initial controller',
    );
    this.authorize = async ({ record, previousRecordId }) => {
      if (
        record.protocol.id !== this.protocol.id ||
        record.protocol.version !== this.protocol.version ||
        !documentBytesEqual(record.groupId, this.groupId)
      )
        return false;
      const controller = previousRecordId
        ? this.log?.controllerAtHead(previousRecordId)
        : record.action === 'create'
          ? this.controller
          : undefined;
      return (
        controller !== undefined &&
        documentBytesEqual(record.actorId, controller)
      );
    };
  }
  bind(
    log: { controllerAtHead(head: Uint8Array): Uint8Array | undefined },
    protocol: GroupSecurityProtocol,
    groupId: Uint8Array,
    controller: Uint8Array,
  ): void {
    if (
      this.log ||
      protocol.id !== this.protocol.id ||
      protocol.version !== this.protocol.version ||
      !documentBytesEqual(groupId, this.groupId) ||
      !documentBytesEqual(controller, this.controller)
    )
      throw new Error('Document control authority binding mismatch');
    this.log = log;
  }
}
