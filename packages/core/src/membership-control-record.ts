import type { GroupSecurityProtocol } from './group-security-provider.js';

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
const MAX_U64 = (1n << 64n) - 1n;

const objectGetPrototypeOf = Object.getPrototypeOf;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const uint8ArraySet = Uint8Array.prototype.set;
const typedArrayPrototype = objectGetPrototypeOf(Uint8Array.prototype);
const typedArrayByteLength = objectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteLength',
)?.get;
const typedArrayBuffer = objectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  'buffer',
)?.get;
const typedArrayTag = objectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
)?.get;
const sharedArrayBufferByteLength =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : objectGetOwnPropertyDescriptor(
        SharedArrayBuffer.prototype,
        'byteLength',
      )?.get;

if (
  typedArrayByteLength === undefined ||
  typedArrayBuffer === undefined ||
  typedArrayTag === undefined
) {
  throw new Error('membership control Uint8Array intrinsics are unavailable');
}
const typedArrayByteLengthGetter = typedArrayByteLength;
const typedArrayBufferGetter = typedArrayBuffer;
const typedArrayTagGetter = typedArrayTag;

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
  const protocolId = new TextEncoder().encode(record.protocol.id);
  return concat([
    MEMBERSHIP_CONTROL_MAGIC,
    u16(record.version),
    bytes16(protocolId),
    u16(record.protocol.version),
    bytes16(record.groupId),
    u64(record.epoch),
    record.parentRecordId === undefined
      ? new Uint8Array([0])
      : concat([new Uint8Array([1]), record.parentRecordId]),
    record.operationId,
    new Uint8Array([actionToCode(record.action)]),
    bytes16(record.actorId),
    bytes16(record.subjectId),
    bytes32(record.controlPayload),
  ]);
}

export async function membershipControlRecordId(
  record: UnsignedMembershipControlRecord,
): Promise<Uint8Array> {
  const snapshot = snapshotUnsignedRecord(record);
  return new Uint8Array(
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
  const signature = snapshotBytes(
    await sign(
      new Uint8Array(canonical),
      new Uint8Array(snapshot.actorId),
    ),
    'signature',
    1,
    MAX_SIGNATURE_BYTES,
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
  const out = concat([
    canonicalMembershipControlPayloadFromSnapshot(snapshot),
    bytes16(snapshot.signature),
  ]);
  if (out.byteLength > MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES) {
    throw new Error('membership control record exceeds its serialized limit');
  }
  return out;
}

export function deserializeMembershipControlRecord(
  bytes: Uint8Array,
): MembershipControlRecord {
  const reader = new Reader(
    snapshotBytes(
      bytes,
      'membership control record',
      0,
      MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES,
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
    const groupId = snapshotBytes(
      config.groupId,
      'groupId',
      1,
      MAX_GROUP_ID_BYTES,
    );
    this.initialEpoch = config.initialEpoch ?? 0n;
    validateU64(this.initialEpoch, 'initialEpoch');
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
    return value === undefined ? undefined : new Uint8Array(value);
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
    let record: MembershipControlRecord;
    let canonical: Uint8Array;
    let recordId: Uint8Array;
    try {
      record = deserializeMembershipControlRecord(
        serializeMembershipControlRecord(input),
      );
      canonical = canonicalMembershipControlPayload(record);
      recordId = await membershipControlRecordId(record);
    } catch (error) {
      return rejected('malformed-record', errorMessage(error));
    }

    let valid: unknown = false;
    try {
      valid = await this.config.verifySignature(
        new Uint8Array(canonical),
        new Uint8Array(record.signature),
        new Uint8Array(record.actorId),
      );
    } catch {
      return rejected('bad-signature', 'control signature verification failed');
    }
    if (valid !== true) {
      return rejected('bad-signature', 'invalid control signature');
    }

    const recordHex = toHex(recordId);
    if (this.recordIdSet.has(recordHex)) {
      return { status: 'duplicate', recordId: new Uint8Array(recordId) };
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
        (parent === undefined && record.action !== 'create') ||
        (parent !== undefined && record.action === 'create')
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
          recordId: new Uint8Array(recordId),
          previousRecord:
            parent === undefined ? undefined : cloneRecord(parent),
          previousRecordId:
            parentId === undefined ? undefined : new Uint8Array(parentId),
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
    const operationHex = toHex(record.operationId);
    if (this.operationToRecord.has(operationHex)) {
      return rejected(
        'operation-id-conflict',
        'operationId is already bound to another record',
      );
    }
    const previous = this.recordsValue[this.recordsValue.length - 1];
    const previousId = this.recordIds[this.recordIds.length - 1];
    if (previous === undefined) {
      if (
        record.action !== 'create' ||
        record.epoch !== this.initialEpoch
      ) {
        return rejected(
          'epoch-out-of-order',
          'first record must create the configured initial epoch',
        );
      }
      if (record.parentRecordId !== undefined) {
        return rejected('parent-mismatch', 'genesis must not have a parent');
      }
    } else {
      if (
        previous.epoch === MAX_U64 ||
        record.epoch !== previous.epoch + 1n ||
        record.action === 'create'
      ) {
        return rejected('epoch-out-of-order', 'record epoch is not next');
      }
      if (
        record.parentRecordId === undefined ||
        previousId === undefined ||
        !equalBytes(record.parentRecordId, previousId)
      ) {
        return rejected('parent-mismatch', 'record parent is not the head');
      }
    }

    let authorized: unknown = false;
    try {
      authorized = await this.config.authorize({
        record: cloneRecord(record),
        recordId: new Uint8Array(recordId),
        previousRecord:
          previous === undefined ? undefined : cloneRecord(previous),
        previousRecordId:
          previousId === undefined ? undefined : new Uint8Array(previousId),
      });
    } catch {
      return rejected('unauthorized-actor', 'control authorization failed');
    }
    if (authorized !== true) {
      return rejected('unauthorized-actor', 'control actor is unauthorized');
    }

    const recordIndex = this.recordsValue.length;
    this.recordsValue.push(cloneRecord(record));
    this.recordIds.push(new Uint8Array(recordId));
    this.recordIdSet.add(recordHex);
    this.operationToRecord.set(operationHex, recordHex);
    this.slotToRecordIndex.set(
      membershipControlSlotKey(record.epoch, record.parentRecordId),
      recordIndex,
    );
    return { status: 'accepted', recordId: new Uint8Array(recordId) };
  }
}

function membershipControlSlotKey(
  epoch: bigint,
  parentRecordId: Uint8Array | undefined,
): string {
  const encodedEpoch = epoch.toString(16).padStart(16, '0');
  return `${encodedEpoch}:${
    parentRecordId === undefined ? 'genesis' : toHex(parentRecordId)
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
    typeof protocol.id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(protocol.id) ||
    !Number.isInteger(protocol.version) ||
    protocol.version < 0 ||
    protocol.version > 0xffff
  ) {
    throw new Error('invalid canonical protocol identifier');
  }
}

function validateU64(value: bigint, field: string): void {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new Error(`${field} must be an unsigned 64-bit bigint`);
  }
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
  const signature = snapshotBytes(
    ownDataValue(record, 'signature', 'membership control record'),
    'signature',
    1,
    MAX_SIGNATURE_BYTES,
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
  const version = ownDataValue(
    record,
    'version',
    'membership control record',
  );
  if (version !== MEMBERSHIP_CONTROL_VERSION) {
    throw new Error('unsupported membership control version');
  }
  const protocol = snapshotProtocol(
    ownDataValue(record, 'protocol', 'membership control record'),
  );
  const groupId = snapshotBytes(
    ownDataValue(record, 'groupId', 'membership control record'),
    'groupId',
    1,
    MAX_GROUP_ID_BYTES,
  );
  const epoch = ownDataValue(record, 'epoch', 'membership control record');
  validateU64(epoch as bigint, 'epoch');
  const parentValue = optionalOwnDataValue(
    record,
    'parentRecordId',
    'membership control record',
  );
  const parentRecordId =
    parentValue === undefined
      ? undefined
      : snapshotBytes(
          parentValue,
          'parentRecordId',
          MEMBERSHIP_CONTROL_ID_LENGTH,
          MEMBERSHIP_CONTROL_ID_LENGTH,
        );
  const operationId = snapshotBytes(
    ownDataValue(record, 'operationId', 'membership control record'),
    'operationId',
    MEMBERSHIP_CONTROL_ID_LENGTH,
    MEMBERSHIP_CONTROL_ID_LENGTH,
  );
  const action = ownDataValue(
    record,
    'action',
    'membership control record',
  ) as MembershipControlAction;
  actionToCode(action);
  const actorId = snapshotBytes(
    ownDataValue(record, 'actorId', 'membership control record'),
    'actorId',
    1,
    MAX_IDENTITY_BYTES,
  );
  const subjectId = snapshotBytes(
    ownDataValue(record, 'subjectId', 'membership control record'),
    'subjectId',
    1,
    MAX_IDENTITY_BYTES,
  );
  const controlPayload = snapshotBytes(
    ownDataValue(record, 'controlPayload', 'membership control record'),
    'controlPayload',
    1,
    MAX_CONTROL_PAYLOAD_BYTES,
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
    id: ownDataValue(value, 'id', 'membership control protocol'),
    version: ownDataValue(value, 'version', 'membership control protocol'),
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

function ownDataValue(
  value: object,
  property: string,
  field: string,
): unknown {
  const descriptor = objectGetOwnPropertyDescriptor(value, property);
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !('value' in descriptor)
  ) {
    throw new Error(`${field} ${property} must be an enumerable own data property`);
  }
  return descriptor.value;
}

function optionalOwnDataValue(
  value: object,
  property: string,
  field: string,
): unknown {
  const descriptor = objectGetOwnPropertyDescriptor(value, property);
  if (descriptor === undefined) return undefined;
  if (!descriptor.enumerable || !('value' in descriptor)) {
    throw new Error(`${field} ${property} must be an enumerable own data property`);
  }
  return descriptor.value;
}

function snapshotBytes(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): Uint8Array {
  let length: number;
  let buffer: ArrayBufferLike;
  let tag: unknown;
  try {
    length = Reflect.apply(typedArrayByteLengthGetter, value, []) as number;
    buffer = Reflect.apply(typedArrayBufferGetter, value, []) as ArrayBufferLike;
    tag = Reflect.apply(typedArrayTagGetter, value, []);
  } catch {
    throw new Error(`${field} must be a genuine Uint8Array`);
  }
  let shared = false;
  if (sharedArrayBufferByteLength !== undefined) {
    try {
      Reflect.apply(sharedArrayBufferByteLength, buffer, []);
      shared = true;
    } catch {
      shared = false;
    }
  }
  if (
    tag !== 'Uint8Array' ||
    length < minimum ||
    length > maximum ||
    shared
  ) {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  const snapshot = new Uint8Array(length);
  try {
    Reflect.apply(uint8ArraySet, snapshot, [value]);
  } catch {
    throw new Error(`${field} could not be copied safely`);
  }
  return snapshot;
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

function bytes16(value: Uint8Array): Uint8Array {
  return concat([u16(value.byteLength), value]);
}

function bytes32(value: Uint8Array): Uint8Array {
  return concat([u32(value.byteLength), value]);
}

function u16(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error('value does not fit in u16');
  }
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, false);
  return out;
}

function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('value does not fit in u32');
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function u64(value: bigint): Uint8Array {
  validateU64(value, 'epoch');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function concat(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  const out = new Uint8Array(
    parts.reduce((total, part) => total + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function sameProtocol(
  a: GroupSecurityProtocol,
  b: GroupSecurityProtocol,
): boolean {
  return a.id === b.id && a.version === b.version;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let different = 0;
  for (let i = 0; i < a.byteLength; i++) different |= a[i] ^ b[i];
  return different === 0;
}

function toHex(bytes: Uint8Array): string {
  let result = '';
  for (const value of bytes) result += value.toString(16).padStart(2, '0');
  return result;
}

class Reader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  expect(expected: Uint8Array, field: string): void {
    if (!equalBytes(this.fixed(expected.byteLength, field), expected)) {
      throw new Error(`invalid ${field}`);
    }
  }

  u8(field: string): number {
    return this.fixed(1, field)[0];
  }

  u16(field: string): number {
    const start = this.reserve(2, field);
    return new DataView(
      this.bytes.buffer,
      this.bytes.byteOffset + start,
      2,
    ).getUint16(0, false);
  }

  u32(field: string): number {
    const start = this.reserve(4, field);
    return new DataView(
      this.bytes.buffer,
      this.bytes.byteOffset + start,
      4,
    ).getUint32(0, false);
  }

  u64(field: string): bigint {
    const start = this.reserve(8, field);
    return new DataView(
      this.bytes.buffer,
      this.bytes.byteOffset + start,
      8,
    ).getBigUint64(0, false);
  }

  fixed(length: number, field: string): Uint8Array {
    const start = this.reserve(length, field);
    return new Uint8Array(this.bytes.subarray(start, start + length));
  }

  bytes16(field: string, minimum: number, maximum: number): Uint8Array {
    return this.bounded(this.u16(`${field} length`), field, minimum, maximum);
  }

  bytes32(field: string, minimum: number, maximum: number): Uint8Array {
    return this.bounded(this.u32(`${field} length`), field, minimum, maximum);
  }

  protocolId(): string {
    const value = new TextDecoder('utf-8', { fatal: true }).decode(
      this.bytes16('protocol.id', 1, 128),
    );
    if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(value)) {
      throw new Error('invalid canonical protocol identifier');
    }
    return value;
  }

  done(): void {
    if (this.offset !== this.bytes.byteLength) {
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
    if (length < 0 || this.offset + length > this.bytes.byteLength) {
      throw new Error(`membership control record is truncated at ${field}`);
    }
    const start = this.offset;
    this.offset += length;
    return start;
  }
}
