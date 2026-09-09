import type { GroupWelcome } from './group-security-provider.js';
import {
  MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES,
  MEMBERSHIP_CONTROL_VERSION,
  MEMBERSHIP_CONTROL_ID_LENGTH,
  type MembershipControlRecord,
  deserializeMembershipControlRecord,
  membershipControlRecordId,
  serializeMembershipControlRecord,
} from './membership-control-record.js';

export const MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS = 4096;
export const MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES = 512;

const MAX_GROUP_ID_BYTES = 1024;
const MAX_IDENTITY_BYTES = 512;
const MAX_CONTROL_PAYLOAD_BYTES = 2 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 4096;
const MAX_WELCOME_PAYLOAD_BYTES = 1024 * 1024;
const MAX_CANONICAL_WELCOME_SET_BYTES = 1024 * 1024;
const CANONICAL_WELCOME_SET_DOMAIN_BYTES =
  'peerborne/group-security-welcome-set/v1\0'.length;
const MAX_U64 = (1n << 64n) - 1n;
const typedArrayPrototype = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const typedArrayByteLengthGetter = intrinsicGetter(
  typedArrayPrototype,
  'byteLength',
);
const typedArrayBufferGetter = intrinsicGetter(
  typedArrayPrototype,
  'buffer',
);
const typedArrayTagGetter = intrinsicGetter(
  typedArrayPrototype,
  Symbol.toStringTag,
);
const uint8ArraySet = Uint8Array.prototype.set;
const sharedArrayBufferByteLengthGetter =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : Object.getOwnPropertyDescriptor(
        SharedArrayBuffer.prototype,
        'byteLength',
      )?.get;

/**
 * A receiver's explicit durable acceptance of one group-security delivery.
 *
 * A network delivery callback may return this value only after the receiver
 * has authenticated and authorized the control record, validated the group
 * transition, and durably persisted both the accepted state and the metadata
 * needed for replay/idempotency checks. Transport delivery alone is not
 * durable acceptance.
 */
export interface GroupSecurityDurableAcceptance {
  readonly controlRecordId: Uint8Array;
  readonly recipientKeyPackageRefs: ReadonlyArray<Uint8Array>;
}

/** The portion of a group-security delivery covered by durable acceptance. */
export interface GroupSecurityAcceptanceDelivery {
  readonly controlRecord: MembershipControlRecord;
  readonly welcomes: ReadonlyArray<GroupWelcome>;
}

/**
 * Constructs the canonical acceptance value for a delivery.
 *
 * This function only constructs the bound value; it does not authenticate or
 * persist the delivery. Callers must satisfy the durable-acceptance contract
 * above before returning the result from a network delivery callback.
 */
export async function createGroupSecurityDurableAcceptance(
  delivery: GroupSecurityAcceptanceDelivery,
): Promise<GroupSecurityDurableAcceptance> {
  const snapshot = snapshotDelivery(delivery);
  const controlRecordId = await membershipControlRecordId(
    snapshot.controlRecord,
  );
  return makeAcceptance(controlRecordId, snapshot.recipientKeyPackageRefs);
}

/** Strictly validates, canonicalizes, and defensively clones an acceptance. */
export function cloneGroupSecurityDurableAcceptance(
  value: unknown,
): GroupSecurityDurableAcceptance {
  const object = exactPlainObject(value, [
    'controlRecordId',
    'recipientKeyPackageRefs',
  ]);
  const controlRecordId = cloneBytes(
    dataProperty(object, 'controlRecordId'),
    'durable acceptance controlRecordId',
    MEMBERSHIP_CONTROL_ID_LENGTH,
    MEMBERSHIP_CONTROL_ID_LENGTH,
  );
  const recipientKeyPackageRefs = cloneCanonicalReferences(
    dataProperty(object, 'recipientKeyPackageRefs'),
    'durable acceptance recipientKeyPackageRefs',
  );
  return makeAcceptance(controlRecordId, recipientKeyPackageRefs);
}

/**
 * Verifies that an acceptance binds the exact control-record identity and the
 * complete unique set of Welcome recipient KeyPackage references.
 *
 * Both arguments are synchronously snapshotted before hashing so mutations
 * made while the digest is pending cannot change what is validated.
 */
export async function validateGroupSecurityDurableAcceptance(
  value: unknown,
  delivery: GroupSecurityAcceptanceDelivery,
): Promise<GroupSecurityDurableAcceptance> {
  const acceptance = cloneGroupSecurityDurableAcceptance(value);
  const deliverySnapshot = snapshotDelivery(delivery);
  const expectedRecordId = await membershipControlRecordId(
    deliverySnapshot.controlRecord,
  );
  if (!equalBytes(acceptance.controlRecordId, expectedRecordId)) {
    throw new Error(
      'durable acceptance controlRecordId does not match the delivery',
    );
  }
  if (
    !equalReferenceSets(
      acceptance.recipientKeyPackageRefs,
      deliverySnapshot.recipientKeyPackageRefs,
    )
  ) {
    throw new Error(
      'durable acceptance recipient KeyPackage references do not exactly match the delivery Welcomes',
    );
  }
  return makeAcceptance(
    acceptance.controlRecordId,
    acceptance.recipientKeyPackageRefs,
  );
}

interface DeliverySnapshot {
  readonly controlRecord: MembershipControlRecord;
  readonly recipientKeyPackageRefs: ReadonlyArray<Uint8Array>;
}

function snapshotDelivery(
  delivery: GroupSecurityAcceptanceDelivery,
): DeliverySnapshot {
  const object = snapshotDataObject(
    delivery,
    ['controlRecord', 'welcomes', 'commit'],
    'group-security acceptance delivery',
    ['controlRecord', 'welcomes'],
  );
  const controlRecordValue = dataProperty(object, 'controlRecord');
  const welcomesValue = dataProperty(object, 'welcomes');
  const controlRecordSnapshot = snapshotControlRecord(controlRecordValue);
  const serializedControlRecord = serializeMembershipControlRecord(
    controlRecordSnapshot,
  );
  const serializedView = byteView(
    serializedControlRecord,
    'serialized membership control record',
    1,
    MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES,
  );
  const controlRecord = deserializeMembershipControlRecord(
    copyByteView(serializedView),
  );
  const recipientKeyPackageRefs = cloneWelcomeReferences(
    welcomesValue,
    controlRecord,
  );
  return { controlRecord, recipientKeyPackageRefs };
}

function cloneWelcomeReferences(
  value: unknown,
  controlRecord: MembershipControlRecord,
): ReadonlyArray<Uint8Array> {
  const welcomes = strictArray(
    value,
    'group-security delivery Welcomes',
    MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS,
  );
  let canonicalBytes = CANONICAL_WELCOME_SET_DOMAIN_BYTES + 2;
  const references = welcomes.map((welcomeValue, index) => {
    const welcome = snapshotDataObject(
      welcomeValue,
      [
        'protocol',
        'groupId',
        'epoch',
        'recipientKeyPackageRef',
        'payload',
      ],
      `group-security delivery Welcome ${index}`,
    );
    const protocol = snapshotProtocol(
      dataProperty(welcome, 'protocol'),
      `group-security delivery Welcome ${index} protocol`,
    );
    const groupId = cloneBytes(
      dataProperty(welcome, 'groupId'),
      `group-security delivery Welcome ${index} groupId`,
      1,
      MAX_GROUP_ID_BYTES,
    );
    const epoch = u64Value(
      dataProperty(welcome, 'epoch'),
      `group-security delivery Welcome ${index} epoch`,
    );
    const reference = cloneBytes(
      dataProperty(welcome, 'recipientKeyPackageRef'),
      `group-security delivery Welcome ${index} recipientKeyPackageRef`,
      1,
      MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES,
    );
    const payload = byteView(
      dataProperty(welcome, 'payload'),
      `group-security delivery Welcome ${index} payload`,
      1,
      MAX_WELCOME_PAYLOAD_BYTES,
    );
    if (
      protocol.id !== controlRecord.protocol.id ||
      protocol.version !== controlRecord.protocol.version ||
      !equalBytes(groupId, controlRecord.groupId) ||
      epoch !== controlRecord.epoch
    ) {
      throw new Error(
        `group-security delivery Welcome ${index} metadata does not match the control record`,
      );
    }
    canonicalBytes = claimBoundedTotal(
      canonicalBytes,
      2 +
        protocol.id.length +
        2 +
        2 +
        groupId.byteLength +
        8 +
        2 +
        reference.byteLength +
        4 +
        payload.byteLength,
      MAX_CANONICAL_WELCOME_SET_BYTES,
      'group-security delivery Welcome set',
    );
    return reference;
  });
  return canonicalizeUniqueReferences(
    references,
    'group-security delivery Welcomes',
  );
}

function cloneCanonicalReferences(
  value: unknown,
  field: string,
): ReadonlyArray<Uint8Array> {
  const values = strictArray(
    value,
    field,
    MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS,
  );
  const references = values.map((reference, index) =>
    cloneBytes(
      reference,
      `${field}[${index}]`,
      1,
      MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES,
    ),
  );
  return canonicalizeUniqueReferences(references, field);
}

function canonicalizeUniqueReferences(
  references: Uint8Array[],
  field: string,
): ReadonlyArray<Uint8Array> {
  references.sort(compareBytes);
  for (let index = 1; index < references.length; index++) {
    if (equalBytes(references[index - 1], references[index])) {
      throw new Error(`${field} contains a duplicate KeyPackage reference`);
    }
  }
  return references;
}

function makeAcceptance(
  controlRecordId: Uint8Array,
  recipientKeyPackageRefs: ReadonlyArray<Uint8Array>,
): GroupSecurityDurableAcceptance {
  return {
    controlRecordId: new Uint8Array(controlRecordId),
    recipientKeyPackageRefs: recipientKeyPackageRefs.map(
      (reference) => new Uint8Array(reference),
    ),
  };
}

function exactPlainObject(
  value: unknown,
  expectedKeys: ReadonlyArray<string>,
): Record<PropertyKey, unknown> {
  try {
    return snapshotDataObject(value, expectedKeys, 'durable acceptance');
  } catch (error) {
    if (
      error instanceof Error &&
      /unexpected or missing fields/.test(error.message)
    ) {
      throw new Error(
        'durable acceptance must contain exactly controlRecordId and recipientKeyPackageRefs',
      );
    }
    throw error;
  }
}

function snapshotDataObject(
  value: unknown,
  expectedKeys: ReadonlyArray<string>,
  field: string,
  requiredKeys: ReadonlyArray<string> = expectedKeys,
): Record<PropertyKey, unknown> {
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype =
      value !== null && typeof value === 'object'
        ? Object.getPrototypeOf(value)
        : null;
    keys =
      value !== null && typeof value === 'object' ? Reflect.ownKeys(value) : [];
  } catch {
    throw new Error(`${field} must be a plain data object`);
  }
  if (value === null || typeof value !== 'object') {
    throw new Error(`${field} must be an object`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${field} must be a plain object`);
  }
  if (
    keys.some(
      (key) => typeof key !== 'string' || !expectedKeys.includes(key),
    ) ||
    requiredKeys.some((key) => !keys.includes(key))
  ) {
    throw new Error(`${field} has unexpected or missing fields`);
  }
  const snapshot = Object.create(null) as Record<PropertyKey, unknown>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${String(key)} must be an enumerable own data property`);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function dataProperty(
  object: Record<PropertyKey, unknown>,
  key: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !('value' in descriptor)) {
    throw new Error(`${key} must be an own data property`);
  }
  return descriptor.value;
}

function optionalDataProperty(
  object: Record<PropertyKey, unknown>,
  key: string,
): unknown {
  return Object.prototype.hasOwnProperty.call(object, key)
    ? dataProperty(object, key)
    : undefined;
}

function strictArray(
  value: unknown,
  field: string,
  maximumLength: number,
): unknown[] {
  let isArray: boolean;
  let prototype: object | null;
  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    isArray = Array.isArray(value);
    prototype = isArray ? Object.getPrototypeOf(value) : null;
    lengthDescriptor = isArray
      ? Object.getOwnPropertyDescriptor(value, 'length')
      : undefined;
  } catch {
    throw new Error(`${field} must be a bounded plain array`);
  }
  if (
    !isArray ||
    prototype !== Array.prototype ||
    lengthDescriptor === undefined ||
    !('value' in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > maximumLength
  ) {
    throw new Error(`${field} must be a bounded plain array`);
  }
  const length = lengthDescriptor.value as number;
  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(value as object);
  } catch {
    throw new Error(`${field} must be a bounded plain array`);
  }
  if (keys.length !== length + 1 || !keys.includes('length')) {
    throw new Error(`${field} must not be sparse or contain extra properties`);
  }
  const result = new Array<unknown>(length);
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${field} must contain only own data properties`);
    }
    result[index] = descriptor.value;
  }
  return result;
}

function cloneBytes(
  value: unknown,
  field: string,
  minimumLength: number,
  maximumLength: number,
): Uint8Array {
  return copyByteView(
    byteView(value, field, minimumLength, maximumLength),
  );
}

interface ByteView {
  readonly value: Uint8Array;
  readonly byteLength: number;
}

function byteView(
  value: unknown,
  field: string,
  minimumLength: number,
  maximumLength: number,
): ByteView {
  let tag: unknown;
  let byteLength: unknown;
  let buffer: unknown;
  try {
    tag = Reflect.apply(typedArrayTagGetter, value, []);
    byteLength = Reflect.apply(typedArrayByteLengthGetter, value, []);
    buffer = Reflect.apply(typedArrayBufferGetter, value, []);
  } catch {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  if (
    tag !== 'Uint8Array' ||
    typeof byteLength !== 'number' ||
    !Number.isSafeInteger(byteLength) ||
    byteLength < minimumLength ||
    byteLength > maximumLength ||
    isSharedBuffer(buffer)
  ) {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  return { value: value as Uint8Array, byteLength };
}

function copyByteView(view: ByteView): Uint8Array {
  const copy = new Uint8Array(view.byteLength);
  Reflect.apply(uint8ArraySet, copy, [view.value, 0]);
  return copy;
}

function isSharedBuffer(buffer: unknown): boolean {
  if (sharedArrayBufferByteLengthGetter === undefined) return false;
  try {
    Reflect.apply(sharedArrayBufferByteLengthGetter, buffer, []);
    return true;
  } catch {
    return false;
  }
}

function snapshotControlRecord(value: unknown): MembershipControlRecord {
  const record = snapshotDataObject(
    value,
    [
      'version',
      'protocol',
      'groupId',
      'epoch',
      'parentRecordId',
      'operationId',
      'action',
      'actorId',
      'subjectId',
      'controlPayload',
      'signature',
    ],
    'group-security delivery controlRecord',
    [
      'version',
      'protocol',
      'groupId',
      'epoch',
      'operationId',
      'action',
      'actorId',
      'subjectId',
      'controlPayload',
      'signature',
    ],
  );
  const version = dataProperty(record, 'version');
  if (version !== MEMBERSHIP_CONTROL_VERSION) {
    throw new Error('group-security delivery controlRecord version is invalid');
  }
  const action = dataProperty(record, 'action');
  if (
    action !== 'create' &&
    action !== 'add' &&
    action !== 'remove' &&
    action !== 'update'
  ) {
    throw new Error('group-security delivery controlRecord action is invalid');
  }
  const parentRecordId = optionalDataProperty(record, 'parentRecordId');
  return {
    version,
    protocol: snapshotProtocol(
      dataProperty(record, 'protocol'),
      'group-security delivery controlRecord protocol',
    ),
    groupId: cloneBytes(
      dataProperty(record, 'groupId'),
      'group-security delivery controlRecord groupId',
      1,
      MAX_GROUP_ID_BYTES,
    ),
    epoch: u64Value(
      dataProperty(record, 'epoch'),
      'group-security delivery controlRecord epoch',
    ),
    parentRecordId:
      parentRecordId === undefined
        ? undefined
        : cloneBytes(
            parentRecordId,
            'group-security delivery controlRecord parentRecordId',
            MEMBERSHIP_CONTROL_ID_LENGTH,
            MEMBERSHIP_CONTROL_ID_LENGTH,
          ),
    operationId: cloneBytes(
      dataProperty(record, 'operationId'),
      'group-security delivery controlRecord operationId',
      MEMBERSHIP_CONTROL_ID_LENGTH,
      MEMBERSHIP_CONTROL_ID_LENGTH,
    ),
    action,
    actorId: cloneBytes(
      dataProperty(record, 'actorId'),
      'group-security delivery controlRecord actorId',
      1,
      MAX_IDENTITY_BYTES,
    ),
    subjectId: cloneBytes(
      dataProperty(record, 'subjectId'),
      'group-security delivery controlRecord subjectId',
      1,
      MAX_IDENTITY_BYTES,
    ),
    controlPayload: cloneBytes(
      dataProperty(record, 'controlPayload'),
      'group-security delivery controlRecord controlPayload',
      1,
      MAX_CONTROL_PAYLOAD_BYTES,
    ),
    signature: cloneBytes(
      dataProperty(record, 'signature'),
      'group-security delivery controlRecord signature',
      1,
      MAX_SIGNATURE_BYTES,
    ),
  };
}

function snapshotProtocol(
  value: unknown,
  field: string,
): MembershipControlRecord['protocol'] {
  const protocol = snapshotDataObject(value, ['id', 'version'], field);
  const id = dataProperty(protocol, 'id');
  const version = dataProperty(protocol, 'version');
  if (
    typeof id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(id) ||
    typeof version !== 'number' ||
    !Number.isInteger(version) ||
    version < 0 ||
    version > 0xffff
  ) {
    throw new Error(`${field} is invalid`);
  }
  return { id, version };
}

function u64Value(value: unknown, field: string): bigint {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    throw new Error(`${field} must be an unsigned 64-bit bigint`);
  }
  return value;
}

function claimBoundedTotal(
  total: number,
  additional: number,
  maximum: number,
  field: string,
): number {
  if (
    !Number.isSafeInteger(additional) ||
    additional < 0 ||
    additional > maximum - total
  ) {
    throw new Error(`${field} exceeds its byte bound`);
  }
  return total + additional;
}

function intrinsicGetter(
  prototype: object,
  key: PropertyKey,
): (this: unknown) => unknown {
  const getter = Object.getOwnPropertyDescriptor(prototype, key)?.get;
  if (getter === undefined) {
    throw new Error(`missing Uint8Array intrinsic ${String(key)}`);
  }
  return getter;
}

function equalReferenceSets(
  left: ReadonlyArray<Uint8Array>,
  right: ReadonlyArray<Uint8Array>,
): boolean {
  return (
    left.length === right.length &&
    left.every((reference, index) => equalBytes(reference, right[index]))
  );
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const sharedLength = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < sharedLength; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.byteLength - right.byteLength;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let different = 0;
  for (let index = 0; index < left.byteLength; index++) {
    different |= left[index] ^ right[index];
  }
  return different === 0;
}
