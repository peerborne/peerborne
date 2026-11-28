import {
  isDocumentAuthorityRosterValid,
  exactDocumentMemberRoster,
  canBindDocumentController,
  bindDocumentController,
} from './policy/document-authority.js';
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
} from './internal/document-binary.js';
import { bytesToHex } from './internal/hex.js';
import {
  decodeSignedDocumentContent,
  documentContextsMatch,
  encodeSignedDocumentContent,
  readDocumentContext,
  writeDocumentContext,
} from './document-security-wire.js';
import { copyUnsharedUint8Array, equalBytes } from './internal/bytes.js';
import {
  captureDocumentWritePaths,
  copyDocumentFieldPaths,
  DocumentFieldScopeBudget,
} from './document-field-authorization.js';
import {
  admitContentSequence,
  nextContentSequence,
} from './policy/document-content.js';

const DOMAIN = Uint8Array.from('peerborne/document-authority/v2\0', (value) =>
  value.charCodeAt(0),
);
const MAX_RECORDS = 1024,
  MAX_HISTORY_BYTES = 16 * 1024 * 1024;
const ZERO = new Uint8Array(32);

/** @internal Compare signed member IDs with a detached, sorted provider roster. */
export function assertDocumentGroupRoster(
  authorityIds: Iterable<string>,
  groupIds: readonly string[],
): void {
  if (!exactDocumentMemberRoster([...authorityIds].sort(), groupIds)) {
    throw new Error(
      'Document authority does not match the authenticated group roster',
    );
  }
}

/** @internal Detached strict role record reserved until its checkpoint is durable. */
export interface PreparedDocumentRosterUpdate {
  readonly context: GroupSecurityDocumentContext;
  readonly authorityHead: Uint8Array;
  readonly authorityRecords: readonly Uint8Array[];
  isReserved(): boolean;
  isInstalled(): boolean;
  commit(): void;
  discard(): void;
}

interface DocumentRosterUpdateAdmission {
  readLocalPublicKey(): Promise<string>;
  isCurrent(): boolean;
}

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
  for (const member of record.members) {
    writer
      .fixed(
        copyUnsharedUint8Array(member.memberId, 32, 32, 'authority member'),
      )
      .text(member.publicKey, 4096)
      .integer(member.role, 1);
    writer.integer(member.writePaths === undefined ? 0 : 1, 1);
    if (member.writePaths !== undefined) {
      writer.integer(member.writePaths.length, 2);
      for (const path of member.writePaths) {
        writer.integer(path.length, 1);
        for (const segment of path) writer.text(segment, 4096);
      }
    }
  }
  return writer.finish();
}

function decode(bytes: Uint8Array): AuthorityRecord {
  const reader = new DocumentBinaryReader(bytes);
  if (!equalBytes(reader.fixed(DOMAIN.length), DOMAIN))
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
  const scopeBudget = new DocumentFieldScopeBudget();
  let previous = '';
  const ids: string[] = [],
    keys: string[] = [],
    roles: number[] = [];
  for (let index = 0; index < count; index++) {
    const memberId = reader.fixed(32),
      publicKey = reader.text(4096),
      role = reader.number(1),
      id = bytesToHex(memberId);
    if (id <= previous) throw new Error('Invalid authority roster');
    previous = id;
    ids.push(id);
    keys.push(publicKey);
    roles.push(role);
    const restricted = reader.number(1);
    if (restricted !== 0 && restricted !== 1)
      throw new Error('Invalid document field authorization');
    let writePaths;
    if (restricted === 1) {
      const pathCount = reader.number(2);
      if (pathCount > 64)
        throw new Error('Document field authorization exceeds bounds');
      scopeBudget.charge(pathCount, 0, 0);
      const paths: string[][] = [];
      for (let path = 0; path < pathCount; path++) {
        const depth = reader.number(1);
        if (depth > 32)
          throw new Error('Document field authorization exceeds bounds');
        scopeBudget.charge(0, depth, 0);
        const segments: string[] = [];
        for (let segment = 0; segment < depth; segment++) {
          const value = reader.text(4096);
          scopeBudget.charge(0, 0, value.length);
          segments.push(value);
        }
        paths.push(segments);
      }
      writePaths = copyDocumentFieldPaths(paths);
    }
    members.push({
      memberId,
      publicKey,
      role: role as 1 | 2 | 3,
      ...(writePaths === undefined ? {} : { writePaths }),
    });
  }
  reader.end();
  if (!isDocumentAuthorityRosterValid(ids, keys, roles))
    throw new Error('Invalid authority roster or controller');
  return { documentId, sequence, parent, context, members };
}

function canonicalMembers(
  members: ReadonlyArray<DocumentMemberAuthority>,
): DocumentMemberAuthority[] {
  if (!Array.isArray(members) || members.length < 1 || members.length > 256)
    throw new Error('Invalid authority roster');
  const scopeBudget = new DocumentFieldScopeBudget();
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
      writePaths: captureDocumentWritePaths(member, scopeBudget),
    }))
    .sort((a, b) =>
      bytesToHex(a.memberId) < bytesToHex(b.memberId)
        ? -1
        : bytesToHex(a.memberId) === bytesToHex(b.memberId)
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
export class DocumentAuthorityLog<
  PrivateKey,
  PublicKey,
  DocumentKey,
> implements DocumentAuthority {
  private records: Uint8Array[] = [];
  private historyBytes = 0;
  private revision = 1;
  private head: Uint8Array;
  private root: Uint8Array;
  private current: AuthorityRecord;
  private controllers = new Map<string, Uint8Array>();
  private readonly verifiedHeads = new Set<string>();
  private controlAuthority?: DocumentGroupControlAuthority;
  private reservedRosterUpdate?: object;

  private constructor(
    root: Uint8Array,
    record: AuthorityRecord,
    encoded: Uint8Array,
    private readonly auth: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  ) {
    this.verifiedHeads.add(bytesToHex(root));
    this.root = root.slice();
    this.head = root.slice();
    this.current = record;
    this.records.push(encoded.slice());
    this.historyBytes = encoded.length;
    this.controllers = bindDocumentController(
      this.controllers,
      bytesToHex(record.context.controlHead),
      record.members.find((member) => member.role === 3)!.memberId.slice(),
      MAX_RECORDS,
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
      bytesToHex(
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
      !equalBytes(root, pin) ||
      initial.sequence !== 1 ||
      !equalBytes(initial.parent, ZERO)
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
    return this.controllers.get(bytesToHex(head))?.slice();
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
    await this.admitUpdate(coordinator, encoded);
  }

  /** @internal Validate an exact roster and reserve its detached role update. */
  async prepareRosterUpdate(
    coordinator: GroupSecurityCoordinator,
    encoded: Uint8Array,
    admission: DocumentRosterUpdateAdmission,
  ): Promise<PreparedDocumentRosterUpdate> {
    const prepared = await this.admitUpdate(coordinator, encoded, admission);
    if (!prepared) throw new Error('Authenticated role update was not reserved');
    return prepared;
  }

  private async admitUpdate(
    coordinator: GroupSecurityCoordinator,
    encoded: Uint8Array,
    admission?: DocumentRosterUpdateAdmission,
  ): Promise<PreparedDocumentRosterUpdate | undefined> {
    this.assertCoordinator(coordinator);
    if (this.reservedRosterUpdate)
      throw new Error('An authenticated role update is already reserved');
    const context = coordinator.documentContext;
    const revision = this.revision;
    let prepared: PreparedDocumentRosterUpdate | undefined;
    await coordinator.runDocumentOperation(
      context,
      encoded,
      async (captured, input, signal, work) => {
        const signed = decodeSignedDocumentContent(input);
        const next = decode(signed.unsigned);
        this.validateNext(next);
        if (this.historyBytes + input.length > MAX_HISTORY_BYTES)
          throw new Error('Authority history byte bound exceeded');
        if (!documentContextsMatch(next.context, captured)) {
          throw new Error(
            'Authority update names an unauthenticated group state',
          );
        }
        await this.verify(
          this.current,
          signed.unsigned,
          signed.signature,
          work,
        );
        if (admission) {
          assertDocumentGroupRoster(
            next.members.map((member) => bytesToHex(member.memberId)),
            await work.readAuthenticatedMemberIds(),
          );
          if (signal.aborted || !admission.isCurrent())
            throw new Error('Document authority preparation is no longer current');
          const localId = coordinator.localMemberId;
          const local = next.members.find((member) =>
            equalBytes(member.memberId, localId),
          );
          const { value: publicKey } = await work.observe<string>(
            admission.readLocalPublicKey(),
          );
          if (!local || publicKey !== local.publicKey)
            throw new Error('Document signing identity mismatch');
        }
        const { value: hash } = await work.observe<Uint8Array>(
          digest(signed.unsigned),
        );
        const current = () =>
          revision === this.revision &&
          this.reservedRosterUpdate === undefined &&
          (admission === undefined || admission.isCurrent());
        const install = this.prepareInstall(next, input, hash);
        if (!admission) {
          return { isAuthorizationCurrent: current, commit: install };
        }

        const token = {};
        const isReserved = () =>
          this.reservedRosterUpdate === token && revision === this.revision;
        const proposal: PreparedDocumentRosterUpdate = {
          context: captured,
          authorityHead: hash.slice(),
          authorityRecords: [...this.exportRecords(), input.slice()],
          isReserved,
          isInstalled: () =>
            this.revision === next.sequence && equalBytes(this.head, hash),
          commit: () => {
            if (!isReserved())
              throw new Error('Authenticated role update reservation was lost');
            install();
            this.reservedRosterUpdate = undefined;
          },
          discard: () => {
            if (this.reservedRosterUpdate === token)
              this.reservedRosterUpdate = undefined;
          },
        };
        return {
          isAuthorizationCurrent: current,
          commit: () => {
            this.reservedRosterUpdate = token;
            prepared = proposal;
          },
        };
      },
    );
    return prepared;
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
        equalBytes(next.parent, this.head),
      ) !== 'apply'
    )
      throw new Error('Authority history is full, replayed, or forked');
    if (
      !canAdvanceDocumentAuthority(
        previous.epoch,
        state.epoch,
        previous.protocol.id === state.protocol.id &&
          previous.protocol.version === state.protocol.version &&
          equalBytes(previous.groupId, state.groupId),
        !equalBytes(
          next.context.controlHead,
          this.current.context.controlHead,
        ),
      )
    )
      throw new Error(
        'Role transitions require a fresh authenticated group epoch',
      );
    if (
      !canBindDocumentController(
        this.controllers,
        bytesToHex(next.context.controlHead),
        MAX_RECORDS,
      )
    )
      throw new Error('Authority control head is already bound');
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
    this.prepareInstall(next, encoded, hash)();
  }

  private prepareInstall(
    next: AuthorityRecord,
    encoded: Uint8Array,
    hash: Uint8Array,
  ): () => void {
    if (this.historyBytes + encoded.length > MAX_HISTORY_BYTES)
      throw new Error('Authority history byte bound exceeded');
    const controllers = bindDocumentController(
      this.controllers,
      bytesToHex(next.context.controlHead),
      next.members.find((member) => member.role === 3)!.memberId.slice(),
      MAX_RECORDS,
    );
    const record = encoded.slice();
    const head = hash.slice();
    const id = bytesToHex(head);
    return () => {
      this.records.push(record);
      this.historyBytes += record.length;
      this.revision = next.sequence;
      this.current = next;
      this.head = head;
      this.verifiedHeads.add(id);
      this.controllers = controllers;
    };
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
        !equalBytes(record.groupId, this.groupId)
      )
        return false;
      const controller = previousRecordId
        ? this.log?.controllerAtHead(previousRecordId)
        : record.action === 'create'
          ? this.controller
          : undefined;
      return (
        controller !== undefined &&
        equalBytes(record.actorId, controller)
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
      !equalBytes(groupId, this.groupId) ||
      !equalBytes(controller, this.controller)
    )
      throw new Error('Document control authority binding mismatch');
    this.log = log;
  }
}
