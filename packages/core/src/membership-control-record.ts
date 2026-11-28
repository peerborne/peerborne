import type { GroupSecurityProtocol } from './group-security-provider.js';
import {
  classifyControlAppend,
  isControlActionValid,
} from './policy/control-chain.js';
import { boundedFieldEnd } from './policy/frame-layout.js';
import {
  bufferOf,
  byteLengthOf,
  byteOffsetOf,
  concatBytes,
  copyUnsharedUint8Array,
  equalBytes,
} from './internal/bytes.js';
import {
  optionalOwnDataProperty,
  ownDataProperty,
} from './internal/data-property.js';
import { bytesToHex } from './internal/hex.js';
import {
  encodeU16,
  encodeU64,
  encodeU8,
  lengthPrefixed16,
  lengthPrefixed32,
  requireU64,
} from './internal/big-endian.js';
import {
  isCanonicalIdentifier,
  isCanonicalProtocol,
  sameProtocol,
} from './internal/protocol-identifier.js';

const MEMBERSHIP_CONTROL_MAGIC = new Uint8Array([
  0x53, 0x57, 0x4d, 0x4d, 0x43, 0x52, 0x30, 0x31,
]);

export const MEMBERSHIP_CONTROL_VERSION = 1;
export const MEMBERSHIP_CONTROL_ID_LENGTH = 32;
export const MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES = 4 * 1024 * 1024;

const MAX_IDENTITY_BYTES = 512;
const MAX_GROUP_ID_BYTES = 1024;
const MAX_CONTROL_PAYLOAD_BYTES = 2 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 4096;

const objectGetPrototypeOf = Object.getPrototypeOf;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const reflectApply = Reflect.apply;
const uint8ArrayConstructor = Uint8Array;
const dataViewConstructor = DataView;
const stringCharCodeAt = String.prototype.charCodeAt;
const stringFromCharCode = String.fromCharCode;
const uint8ArraySubarray = Uint8Array.prototype.subarray;
const dataViewGetBigUint64 = DataView.prototype.getBigUint64;
const dataViewGetUint16 = DataView.prototype.getUint16;
const dataViewGetUint32 = DataView.prototype.getUint32;

export type MembershipControlAction = 'create' | 'add' | 'remove' | 'update';

export interface UnsignedMembershipControlRecord {
  readonly version: number;
  readonly protocol: GroupSecurityProtocol;
  readonly groupId: Uint8Array;
  readonly epoch: bigint;
  readonly parentRecordId?: Uint8Array;
  readonly operationId: Uint8Array;
  readonly action: MembershipControlAction;
  readonly actorId: Uint8Array;
  readonly subjectId: Uint8Array;
  readonly controlPayload: Uint8Array;
}

export interface MembershipControlRecord
  extends UnsignedMembershipControlRecord {
  readonly signature: Uint8Array;
}

export type MembershipControlSigner = (
  canonicalPayload: Uint8Array,
  actorId: Uint8Array,
) => Promise<Uint8Array>;

export type MembershipControlSignatureVerifier = (
  canonicalPayload: Uint8Array,
  signature: Uint8Array,
  actorId: Uint8Array,
) => Promise<boolean>;

export interface MembershipControlAuthorizationContext {
  readonly record: MembershipControlRecord;
  readonly recordId: Uint8Array;
  readonly previousRecord?: MembershipControlRecord;
  readonly previousRecordId?: Uint8Array;
}

export type MembershipControlAuthorizer = (
  context: MembershipControlAuthorizationContext,
) => Promise<boolean>;

export interface MembershipControlChainConfig {
  readonly protocol: GroupSecurityProtocol;
  readonly groupId: Uint8Array;
  readonly initialEpoch?: bigint;
  readonly verifySignature: MembershipControlSignatureVerifier;
  readonly authorize: MembershipControlAuthorizer;
}

export type MembershipControlRejectReason =
  | 'malformed-record'
  | 'protocol-mismatch'
  | 'group-mismatch'
  | 'bad-signature'
  | 'unauthorized-actor'
  | 'parent-mismatch'
  | 'epoch-out-of-order'
  | 'operation-id-conflict'
  | 'fork-detected';

export type MembershipControlIngestResult =
  | { readonly status: 'accepted'; readonly recordId: Uint8Array }
  | { readonly status: 'duplicate'; readonly recordId: Uint8Array }
  | {
      readonly status: 'rejected';
      readonly reason: MembershipControlRejectReason;
      readonly message: string;
    };

/** Strict canonical bytes covered by the signature and record identity. */
export function canonicalMembershipControlPayload(
  record: UnsignedMembershipControlRecord,
): Uint8Array {
  return canonicalMembershipControlPayloadFromSnapshot(
    snapshotUnsignedRecord(record),
  );
}

function canonicalMembershipControlPayloadFromSnapshot(
  record: UnsignedMembershipControlRecord,
): Uint8Array {
  const protocolId = encodeProtocolId(record.protocol.id);
  return concatBytes([
    MEMBERSHIP_CONTROL_MAGIC,
    encodeU16(record.version),
    lengthPrefixed16(protocolId),
    encodeU16(record.protocol.version),
    lengthPrefixed16(record.groupId),
    encodeU64(record.epoch),
    record.parentRecordId === undefined
      ? encodeU8(0)
      : concatBytes([encodeU8(1), record.parentRecordId]),
    record.operationId,
    encodeU8(actionToCode(record.action)),
    lengthPrefixed16(record.actorId),
    lengthPrefixed16(record.subjectId),
    lengthPrefixed32(record.controlPayload),
  ]);
}

export async function membershipControlRecordId(
  record: UnsignedMembershipControlRecord,
): Promise<Uint8Array> {
  const snapshot = snapshotUnsignedRecord(record);
  return new uint8ArrayConstructor(
    await crypto.subtle.digest(
      'SHA-256',
      canonicalMembershipControlPayloadFromSnapshot(snapshot) as BufferSource,
    ),
  );
}

export async function signMembershipControlRecord(
  record: UnsignedMembershipControlRecord,
  sign: MembershipControlSigner,
): Promise<MembershipControlRecord> {
  const snapshot = snapshotUnsignedRecord(record, false);
  const canonical = canonicalMembershipControlPayloadFromSnapshot(snapshot);
  const signature = copyUnsharedUint8Array(
    await sign(
      new uint8ArrayConstructor(canonical),
      new uint8ArrayConstructor(snapshot.actorId),
    ),
    1,
    MAX_SIGNATURE_BYTES,
    'signature',
  );
  return {
    ...snapshot,
    signature,
  };
}

export function serializeMembershipControlRecord(
  record: MembershipControlRecord,
): Uint8Array {
  const snapshot = snapshotRecord(record);
  const out = concatBytes([
    canonicalMembershipControlPayloadFromSnapshot(snapshot),
    lengthPrefixed16(snapshot.signature),
  ]);
  if (byteLengthOf(out) > MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES) {
    throw new Error('membership control record exceeds its serialized limit');
  }
  return out;
}

export function deserializeMembershipControlRecord(
  bytes: Uint8Array,
): MembershipControlRecord {
  const reader = new Reader(
    copyUnsharedUint8Array(
      bytes,
      0,
      MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES,
      'membership control record',
    ),
  );
  reader.expect(MEMBERSHIP_CONTROL_MAGIC, 'magic');
  const version = reader.u16('version');
  if (version !== MEMBERSHIP_CONTROL_VERSION) {
    throw new Error(`unsupported membership control version ${version}`);
  }
  const record: MembershipControlRecord = {
    version,
    protocol: {
      id: reader.protocolId(),
      version: reader.u16('protocol.version'),
    },
    groupId: reader.bytes16('groupId', 1, MAX_GROUP_ID_BYTES),
    epoch: reader.u64('epoch'),
    parentRecordId: readParent(reader),
    operationId: reader.fixed(MEMBERSHIP_CONTROL_ID_LENGTH, 'operationId'),
    action: codeToAction(reader.u8('action')),
    actorId: reader.bytes16('actorId', 1, MAX_IDENTITY_BYTES),
    subjectId: reader.bytes16('subjectId', 1, MAX_IDENTITY_BYTES),
    controlPayload: reader.bytes32(
      'controlPayload',
      1,
      MAX_CONTROL_PAYLOAD_BYTES,
    ),
    signature: reader.bytes16('signature', 1, MAX_SIGNATURE_BYTES),
  };
  reader.done();
  return snapshotRecord(record);
}

/** Sequential verifier for a complete, in-memory control chain. */
export class MembershipControlChain {
  private readonly recordsValue: MembershipControlRecord[] = [];
  private readonly recordIds: Uint8Array[] = [];
  private readonly recordIdSet = new Set<string>();
  private readonly operationToRecord = new Map<string, string>();
  private readonly slotToRecordIndex = new Map<string, number>();
  private tail: Promise<unknown> = Promise.resolve();
  private forkDetected = false;
  private readonly config: MembershipControlChainConfig;
  private readonly initialEpoch: bigint;

  constructor(config: MembershipControlChainConfig) {
    validateProtocol(config.protocol);
    const groupId = copyUnsharedUint8Array(
      config.groupId,
      1,
      MAX_GROUP_ID_BYTES,
      'groupId',
    );
    this.initialEpoch = config.initialEpoch ?? 0n;
    requireU64(this.initialEpoch, 'initialEpoch');
    this.config = {
      ...config,
      protocol: { ...config.protocol },
      groupId,
    };
  }

  get length(): number {
    return this.recordsValue.length;
  }

  get headRecordId(): Uint8Array | undefined {
    const value = this.recordIds[this.recordIds.length - 1];
    return value === undefined ? undefined : new uint8ArrayConstructor(value);
  }

  records(): ReadonlyArray<MembershipControlRecord> {
    return this.recordsValue.map(cloneRecord);
  }

  ingest(record: MembershipControlRecord): Promise<MembershipControlIngestResult> {
    let snapshot: MembershipControlRecord;
    try {
      snapshot = deserializeMembershipControlRecord(
        serializeMembershipControlRecord(record),
      );
    } catch (error) {
      return Promise.resolve(rejected('malformed-record', errorMessage(error)));
    }
    const task = this.tail.then(
      () => this.ingestInternal(snapshot),
      () => this.ingestInternal(snapshot),
    );
    this.tail = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  private async ingestInternal(
    input: MembershipControlRecord,
  ): Promise<MembershipControlIngestResult> {
    if (this.forkDetected) {
      return rejected(
        'fork-detected',
        'membership control chain is stopped after a same-parent fork',
      );
    }
    const record = input;
    let canonical: Uint8Array;
    let recordId: Uint8Array;
    try {
      canonical = canonicalMembershipControlPayload(record);
      recordId = await membershipControlRecordId(record);
    } catch (error) {
      return rejected('malformed-record', errorMessage(error));
    }

    let valid: unknown = false;
    try {
      valid = await this.config.verifySignature(
        new uint8ArrayConstructor(canonical),
        new uint8ArrayConstructor(record.signature),
        new uint8ArrayConstructor(record.actorId),
      );
    } catch {
      return rejected('bad-signature', 'control signature verification failed');
    }
    if (valid !== true) {
      return rejected('bad-signature', 'invalid control signature');
    }

    const recordHex = bytesToHex(recordId);
    if (this.recordIdSet.has(recordHex)) {
      return {
        status: 'duplicate',
        recordId: new uint8ArrayConstructor(recordId),
      };
    }
    if (!sameProtocol(record.protocol, this.config.protocol)) {
      return rejected('protocol-mismatch', 'record protocol does not match');
    }
    if (!equalBytes(record.groupId, this.config.groupId)) {
      return rejected('group-mismatch', 'record group does not match');
    }

    const occupiedSlotIndex = this.slotToRecordIndex.get(
      membershipControlSlotKey(record.epoch, record.parentRecordId),
    );
    if (occupiedSlotIndex !== undefined) {
      const parentIndex = occupiedSlotIndex - 1;
      const parent = this.recordsValue[parentIndex];
      const parentId = this.recordIds[parentIndex];
      if (
        !isControlActionValid(parent !== undefined, record.action === 'create')
      ) {
        return rejected(
          'epoch-out-of-order',
          parent === undefined
            ? 'first record must create the configured initial epoch'
            : 'record epoch is not next',
        );
      }
      let authorized: unknown = false;
      try {
        authorized = await this.config.authorize({
          record: cloneRecord(record),
          recordId: new uint8ArrayConstructor(recordId),
          previousRecord:
            parent === undefined ? undefined : cloneRecord(parent),
          previousRecordId:
            parentId === undefined
              ? undefined
              : new uint8ArrayConstructor(parentId),
        });
      } catch {
        return rejected('unauthorized-actor', 'control authorization failed');
      }
      if (authorized !== true) {
        return rejected('unauthorized-actor', 'control actor is unauthorized');
      }
      this.forkDetected = true;
      return rejected(
        'fork-detected',
        'two authorized control records share one parent and epoch',
      );
    }
    const operationHex = bytesToHex(record.operationId);
    const previous = this.recordsValue[this.recordsValue.length - 1];
    const previousId = this.recordIds[this.recordIds.length - 1];
    const admission = classifyControlAppend(
      previous !== undefined,
      previous?.epoch ?? 0n,
      this.initialEpoch,
      record.epoch,
      record.action === 'create',
      record.parentRecordId !== undefined,
      record.parentRecordId !== undefined &&
        previousId !== undefined &&
        equalBytes(record.parentRecordId, previousId),
      this.operationToRecord.has(operationHex),
    );
    if (admission !== 'ready') {
      const messages = {
        'operation-id-conflict':
          'operationId is already bound to another record',
        'epoch-out-of-order':
          previous === undefined
            ? 'first record must create the configured initial epoch'
            : 'record epoch is not next',
        'parent-mismatch':
          previous === undefined
            ? 'genesis must not have a parent'
            : 'record parent is not the head',
      };
      return rejected(admission, messages[admission]);
    }

    let authorized: unknown = false;
    try {
      authorized = await this.config.authorize({
        record: cloneRecord(record),
        recordId: new uint8ArrayConstructor(recordId),
        previousRecord:
          previous === undefined ? undefined : cloneRecord(previous),
        previousRecordId:
          previousId === undefined
            ? undefined
            : new uint8ArrayConstructor(previousId),
      });
    } catch {
      return rejected('unauthorized-actor', 'control authorization failed');
    }
    if (authorized !== true) {
      return rejected('unauthorized-actor', 'control actor is unauthorized');
    }

    const recordIndex = this.recordsValue.length;
    this.recordsValue.push(cloneRecord(record));
    this.recordIds.push(new uint8ArrayConstructor(recordId));
    this.recordIdSet.add(recordHex);
    this.operationToRecord.set(operationHex, recordHex);
    this.slotToRecordIndex.set(
      membershipControlSlotKey(record.epoch, record.parentRecordId),
      recordIndex,
    );
    return {
      status: 'accepted',
      recordId: new uint8ArrayConstructor(recordId),
    };
  }
}

function membershipControlSlotKey(
  epoch: bigint,
  parentRecordId: Uint8Array | undefined,
): string {
  const encodedEpoch = bytesToHex(encodeU64(epoch));
  return `${encodedEpoch}:${
    parentRecordId === undefined ? 'genesis' : bytesToHex(parentRecordId)
  }`;
}

function readParent(reader: Reader): Uint8Array | undefined {
  const flag = reader.u8('parent flag');
  if (flag === 0) return undefined;
  if (flag !== 1) throw new Error('parent flag must be 0 or 1');
  return reader.fixed(MEMBERSHIP_CONTROL_ID_LENGTH, 'parentRecordId');
}

function validateProtocol(protocol: GroupSecurityProtocol): void {
  if (
    protocol === null ||
    typeof protocol !== 'object' ||
    !isCanonicalProtocol(protocol.id, protocol.version)
  ) {
    throw new Error('invalid canonical protocol identifier');
  }
}

function encodeProtocolId(value: string): Uint8Array {
  const output = new uint8ArrayConstructor(value.length);
  for (let index = 0; index < value.length; index++) {
    output[index] = reflectApply(stringCharCodeAt, value, [index]);
  }
  return output;
}

function decodeProtocolId(value: Uint8Array): string {
  const length = byteLengthOf(value);
  let output = '';
  for (let index = 0; index < length; index++) {
    output += stringFromCharCode(value[index]);
  }
  return output;
}

function actionToCode(action: MembershipControlAction): number {
  if (action === 'create') return 0;
  if (action === 'add') return 1;
  if (action === 'remove') return 2;
  if (action === 'update') return 3;
  throw new Error('unknown membership control action');
}

function codeToAction(code: number): MembershipControlAction {
  if (code === 0) return 'create';
  if (code === 1) return 'add';
  if (code === 2) return 'remove';
  if (code === 3) return 'update';
  throw new Error(`unknown membership control action code ${code}`);
}

function cloneRecord(record: MembershipControlRecord): MembershipControlRecord {
  return snapshotRecord(record);
}

function snapshotRecord(record: MembershipControlRecord): MembershipControlRecord {
  const unsigned = snapshotUnsignedRecord(record);
  const signature = copyUnsharedUint8Array(
    ownDataProperty(record, 'signature', 'membership control record'),
    1,
    MAX_SIGNATURE_BYTES,
    'signature',
  );
  return { ...unsigned, signature };
}

function snapshotUnsignedRecord(
  record: UnsignedMembershipControlRecord,
  allowSignature = true,
): UnsignedMembershipControlRecord {
  assertPlainRecord(record, 'membership control record');
  if (
    !allowSignature &&
    objectGetOwnPropertyDescriptor(record, 'signature') !== undefined
  ) {
    throw new Error('unsigned membership control record must not contain a signature');
  }
  const version = ownDataProperty(
    record,
    'version',
    'membership control record',
  );
  if (version !== MEMBERSHIP_CONTROL_VERSION) {
    throw new Error('unsupported membership control version');
  }
  const protocol = snapshotProtocol(
    ownDataProperty(record, 'protocol', 'membership control record'),
  );
  const groupId = copyUnsharedUint8Array(
    ownDataProperty(record, 'groupId', 'membership control record'),
    1,
    MAX_GROUP_ID_BYTES,
    'groupId',
  );
  const epoch = ownDataProperty(record, 'epoch', 'membership control record');
  requireU64(epoch, 'epoch');
  const parentValue = optionalOwnDataProperty(
    record,
    'parentRecordId',
    'membership control record',
  );
  const parentRecordId =
    parentValue === undefined
      ? undefined
      : copyUnsharedUint8Array(
          parentValue,
          MEMBERSHIP_CONTROL_ID_LENGTH,
          MEMBERSHIP_CONTROL_ID_LENGTH,
          'parentRecordId',
        );
  const operationId = copyUnsharedUint8Array(
    ownDataProperty(record, 'operationId', 'membership control record'),
    MEMBERSHIP_CONTROL_ID_LENGTH,
    MEMBERSHIP_CONTROL_ID_LENGTH,
    'operationId',
  );
  const action = ownDataProperty(
    record,
    'action',
    'membership control record',
  ) as MembershipControlAction;
  actionToCode(action);
  const actorId = copyUnsharedUint8Array(
    ownDataProperty(record, 'actorId', 'membership control record'),
    1,
    MAX_IDENTITY_BYTES,
    'actorId',
  );
  const subjectId = copyUnsharedUint8Array(
    ownDataProperty(record, 'subjectId', 'membership control record'),
    1,
    MAX_IDENTITY_BYTES,
    'subjectId',
  );
  const controlPayload = copyUnsharedUint8Array(
    ownDataProperty(record, 'controlPayload', 'membership control record'),
    1,
    MAX_CONTROL_PAYLOAD_BYTES,
    'controlPayload',
  );
  return {
    version,
    protocol,
    groupId,
    epoch: epoch as bigint,
    parentRecordId,
    operationId,
    action,
    actorId,
    subjectId,
    controlPayload,
  };
}

function snapshotProtocol(value: unknown): GroupSecurityProtocol {
  assertPlainRecord(value, 'membership control protocol');
  const protocol = {
    id: ownDataProperty(value, 'id', 'membership control protocol'),
    version: ownDataProperty(value, 'version', 'membership control protocol'),
  } as GroupSecurityProtocol;
  validateProtocol(protocol);
  return protocol;
}

function assertPlainRecord(value: unknown, field: string): asserts value is object {
  if (value === null || typeof value !== 'object') {
    throw new Error(`${field} must be a plain object`);
  }
  let prototype: object | null;
  try {
    prototype = objectGetPrototypeOf(value);
  } catch {
    throw new Error(`${field} must be a plain object`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${field} must be a plain object`);
  }
}

function rejected(
  reason: MembershipControlRejectReason,
  message: string,
): MembershipControlIngestResult {
  return { status: 'rejected', reason, message };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'non-Error failure';
}

class Reader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  expect(expected: Uint8Array, field: string): void {
    if (!equalBytes(this.fixed(byteLengthOf(expected), field), expected)) {
      throw new Error(`invalid ${field}`);
    }
  }

  u8(field: string): number {
    return this.fixed(1, field)[0];
  }

  u16(field: string): number {
    const start = this.reserve(2, field);
    return reflectApply(
      dataViewGetUint16,
      new dataViewConstructor(
        bufferOf(this.bytes),
        byteOffsetOf(this.bytes) + start,
        2,
      ),
      [0, false],
    );
  }

  u32(field: string): number {
    const start = this.reserve(4, field);
    return reflectApply(
      dataViewGetUint32,
      new dataViewConstructor(
        bufferOf(this.bytes),
        byteOffsetOf(this.bytes) + start,
        4,
      ),
      [0, false],
    );
  }

  u64(field: string): bigint {
    const start = this.reserve(8, field);
    return reflectApply(
      dataViewGetBigUint64,
      new dataViewConstructor(
        bufferOf(this.bytes),
        byteOffsetOf(this.bytes) + start,
        8,
      ),
      [0, false],
    );
  }

  fixed(length: number, field: string): Uint8Array {
    const start = this.reserve(length, field);
    return new uint8ArrayConstructor(
      reflectApply(uint8ArraySubarray, this.bytes, [start, start + length]),
    );
  }

  bytes16(field: string, minimum: number, maximum: number): Uint8Array {
    return this.bounded(this.u16(`${field} length`), field, minimum, maximum);
  }

  bytes32(field: string, minimum: number, maximum: number): Uint8Array {
    return this.bounded(this.u32(`${field} length`), field, minimum, maximum);
  }

  protocolId(): string {
    const value = decodeProtocolId(this.bytes16('protocol.id', 1, 128));
    if (!isCanonicalIdentifier(value)) {
      throw new Error('invalid canonical protocol identifier');
    }
    return value;
  }

  done(): void {
    if (this.offset !== byteLengthOf(this.bytes)) {
      throw new Error('membership control record has trailing bytes');
    }
  }

  private bounded(
    length: number,
    field: string,
    minimum: number,
    maximum: number,
  ): Uint8Array {
    if (length < minimum || length > maximum) {
      throw new Error(`${field} has an invalid length ${length}`);
    }
    return this.fixed(length, field);
  }

  private reserve(length: number, field: string): number {
    const end = boundedFieldEnd(
      byteLengthOf(this.bytes),
      this.offset,
      length,
      0,
      0xffffffff,
      0,
    );
    if (end === -1) {
      throw new Error(`membership control record is truncated at ${field}`);
    }
    const start = this.offset;
    this.offset = end;
    return start;
  }
}
