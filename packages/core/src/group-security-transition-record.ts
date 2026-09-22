import {
  MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES,
  MEMBERSHIP_CONTROL_VERSION,
  MembershipControlRecord,
  deserializeMembershipControlRecord,
  serializeMembershipControlRecord,
} from './membership-control-record.js';
import { copyUnsharedUint8Array } from './utils.js';

const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const objectCreate = Object.create;
const objectFreeze = Object.freeze;
const objectIs = Object.is;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const numberIsInteger = Number.isInteger;
const stringCharCodeAt = String.prototype.charCodeAt;
const stringFromCharCode = String.fromCharCode;
const uint8ArrayConstructor = Uint8Array;
const dataViewConstructor = DataView;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayByteLengthGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteLength',
)?.get;
const typedArrayByteOffsetGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteOffset',
)?.get;
const typedArrayBufferGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'buffer',
)?.get;
const uint8ArraySet = Uint8Array.prototype.set;
const dataViewGetUint16 = DataView.prototype.getUint16;
const dataViewGetUint32 = DataView.prototype.getUint32;
const dataViewSetUint16 = DataView.prototype.setUint16;
const dataViewSetUint32 = DataView.prototype.setUint32;

if (
  typedArrayByteLengthGetterValue === undefined ||
  typedArrayByteOffsetGetterValue === undefined ||
  typedArrayBufferGetterValue === undefined
) {
  throw new Error('group-security transition byte intrinsics are unavailable');
}
const typedArrayByteLengthGetter = typedArrayByteLengthGetterValue;
const typedArrayByteOffsetGetter = typedArrayByteOffsetGetterValue;
const typedArrayBufferGetter = typedArrayBufferGetterValue;

const GROUP_SECURITY_TRANSITION_MAGIC = new Uint8Array([
  0x50, 0x42, 0x47, 0x54, 0x52, 0x30, 0x30, 0x31,
]);
const GROUP_SECURITY_TRANSITION_MAGIC_BYTES = byteLength(
  GROUP_SECURITY_TRANSITION_MAGIC,
);

export const GROUP_SECURITY_TRANSITION_RECORD_VERSION = 1;
export const MAX_GROUP_SECURITY_TRANSITION_CODEC_ID_BYTES = 128;
export const MAX_GROUP_SECURITY_TRANSITION_DELIVERY_BYTES = 16 * 1024 * 1024;
export const MAX_GROUP_SECURITY_TRANSITION_RECORD_BYTES =
  GROUP_SECURITY_TRANSITION_MAGIC_BYTES +
  2 +
  2 +
  MAX_GROUP_SECURITY_TRANSITION_CODEC_ID_BYTES +
  2 +
  4 +
  MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES +
  4 +
  MAX_GROUP_SECURITY_TRANSITION_DELIVERY_BYTES;

/**
 * Persistable framing for one group-security transition.
 *
 * `deliveryPayload` is the exact output of the coordinator's configured
 * delivery codec, including an empty output. `deliveryCodec` selects an application-allowlisted decoder;
 * it is distinct from the group-security protocol and is not authenticated by
 * this frame. Restoring code must treat decoder selection as untrusted, decode
 * the payload, and verify that the decoded Commit and Welcome set match the
 * signed `controlRecord` before applying it.
 *
 * The verified membership-control record ID is the semantic transition
 * identity; this outer frame does not authenticate an opaque codec encoding.
 * It provides strict framing and durable bytes only. It does not choose between
 * same-parent controls, make independent stores linearizable, or provide
 * replication and availability.
 *
 * Decoded records are detached from their serialized input, but nested records
 * and byte arrays remain mutable. Before its first `await` or untrusted codec
 * call, an asynchronous consumer must synchronously take one private canonical
 * snapshot of the complete transition, use only that snapshot for identity,
 * authentication, semantic validation, and application, and pass separate byte
 * copies to callbacks that could mutate them.
 */
export interface GroupSecurityTransitionRecord {
  readonly version: number;
  readonly deliveryCodec: GroupSecurityTransitionDeliveryCodec;
  readonly controlRecord: MembershipControlRecord;
  readonly deliveryPayload: Uint8Array;
}

export interface GroupSecurityTransitionDeliveryCodec {
  readonly id: string;
  readonly version: number;
}

/**
 * Strict deterministic framing suitable for an append-only transition archive.
 * All integers are big-endian:
 * `[magic][version:u16][codec-id:bytes16][codec-version:u16]`
 * `[control:bytes32][delivery:bytes32]`.
 */
export function serializeGroupSecurityTransitionRecord(
  value: GroupSecurityTransitionRecord,
): Uint8Array {
  const record = snapshotTransitionRecord(value);
  const codecId = encodeDeliveryCodecId(record.deliveryCodec.id);
  const controlRecord = serializeMembershipControlRecord(record.controlRecord);
  const codecIdLength = byteLength(codecId);
  const controlLength = byteLength(controlRecord);
  const deliveryLength = byteLength(record.deliveryPayload);
  const output = new uint8ArrayConstructor(
    GROUP_SECURITY_TRANSITION_MAGIC_BYTES +
      2 +
      2 +
      codecIdLength +
      2 +
      4 +
      controlLength +
      4 +
      deliveryLength,
  );
  const view = dataView(output);
  let offset = 0;
  setBytes(output, GROUP_SECURITY_TRANSITION_MAGIC, offset);
  offset += GROUP_SECURITY_TRANSITION_MAGIC_BYTES;
  reflectApply(dataViewSetUint16, view, [offset, record.version, false]);
  offset += 2;
  reflectApply(dataViewSetUint16, view, [offset, codecIdLength, false]);
  offset += 2;
  setBytes(output, codecId, offset);
  offset += codecIdLength;
  reflectApply(dataViewSetUint16, view, [
    offset,
    record.deliveryCodec.version,
    false,
  ]);
  offset += 2;
  reflectApply(dataViewSetUint32, view, [offset, controlLength, false]);
  offset += 4;
  setBytes(output, controlRecord, offset);
  offset += controlLength;
  reflectApply(dataViewSetUint32, view, [offset, deliveryLength, false]);
  offset += 4;
  setBytes(output, record.deliveryPayload, offset);
  return output;
}

/** Decode, bound, validate the canonical control, and detach a transition. */
export function deserializeGroupSecurityTransitionRecord(
  value: Uint8Array,
): GroupSecurityTransitionRecord {
  const input = copyUnsharedUint8Array(
    value,
    GROUP_SECURITY_TRANSITION_MAGIC_BYTES + 2 + 2 + 1 + 2 + 4 + 1 + 4,
    MAX_GROUP_SECURITY_TRANSITION_RECORD_BYTES,
    'group-security transition record',
  );
  const inputLength = byteLength(input);
  const view = dataView(input);
  let offset = 0;
  for (let index = 0; index < GROUP_SECURITY_TRANSITION_MAGIC_BYTES; index++) {
    if (input[offset + index] !== GROUP_SECURITY_TRANSITION_MAGIC[index]) {
      throw new Error('invalid group-security transition magic');
    }
  }
  offset += GROUP_SECURITY_TRANSITION_MAGIC_BYTES;
  const version = reflectApply(dataViewGetUint16, view, [offset, false]);
  offset += 2;
  if (version !== GROUP_SECURITY_TRANSITION_RECORD_VERSION) {
    throw new Error(`unsupported group-security transition version ${version}`);
  }
  const codecIdLength = reflectApply(dataViewGetUint16, view, [offset, false]);
  offset += 2;
  if (
    codecIdLength === 0 ||
    codecIdLength > MAX_GROUP_SECURITY_TRANSITION_CODEC_ID_BYTES ||
    codecIdLength > inputLength - offset - 2 - 4 - 1 - 4
  ) {
    throw new Error('invalid group-security transition delivery codec length');
  }
  const codecId = decodeDeliveryCodecId(
    copyRange(input, offset, codecIdLength),
  );
  offset += codecIdLength;
  const codecVersion = reflectApply(dataViewGetUint16, view, [offset, false]);
  offset += 2;
  const controlLength = reflectApply(dataViewGetUint32, view, [offset, false]);
  offset += 4;
  if (
    controlLength === 0 ||
    controlLength > MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES ||
    controlLength > inputLength - offset - 4
  ) {
    throw new Error('invalid group-security transition control length');
  }
  const serializedControl = copyRange(input, offset, controlLength);
  offset += controlLength;
  const deliveryLength = reflectApply(dataViewGetUint32, view, [offset, false]);
  offset += 4;
  if (
    deliveryLength > MAX_GROUP_SECURITY_TRANSITION_DELIVERY_BYTES ||
    deliveryLength !== inputLength - offset
  ) {
    throw new Error('invalid group-security transition delivery length');
  }
  const controlRecord = deserializeMembershipControlRecord(serializedControl);
  if (
    controlRecord.version !== MEMBERSHIP_CONTROL_VERSION ||
    !equalBytes(
      serializeMembershipControlRecord(controlRecord),
      serializedControl,
    )
  ) {
    throw new Error('group-security transition control is not canonical');
  }
  return objectFreeze({
    version,
    deliveryCodec: objectFreeze({ id: codecId, version: codecVersion }),
    controlRecord,
    deliveryPayload: copyRange(input, offset, deliveryLength),
  });
}

function snapshotTransitionRecord(
  value: GroupSecurityTransitionRecord,
): GroupSecurityTransitionRecord {
  const object = exactRecord(
    value,
    ['version', 'deliveryCodec', 'controlRecord', 'deliveryPayload'],
    'group-security transition',
  );
  const version = object.version;
  if (version !== GROUP_SECURITY_TRANSITION_RECORD_VERSION) {
    throw new Error('unsupported group-security transition version');
  }
  const deliveryCodec = snapshotDeliveryCodec(object.deliveryCodec);
  const controlRecord = deserializeMembershipControlRecord(
    serializeMembershipControlRecord(
      object.controlRecord as MembershipControlRecord,
    ),
  );
  const deliveryPayload = copyUnsharedUint8Array(
    object.deliveryPayload,
    0,
    MAX_GROUP_SECURITY_TRANSITION_DELIVERY_BYTES,
    'group-security transition delivery payload',
  );
  return { version, deliveryCodec, controlRecord, deliveryPayload };
}

function snapshotDeliveryCodec(
  value: unknown,
): GroupSecurityTransitionDeliveryCodec {
  const object = exactRecord(
    value,
    ['id', 'version'],
    'group-security transition delivery codec',
  );
  const id = object.id;
  if (typeof id !== 'string') {
    throw new TypeError(
      'group-security transition delivery codec id must be a string',
    );
  }
  encodeDeliveryCodecId(id);
  const version = object.version;
  if (
    typeof version !== 'number' ||
    !numberIsInteger(version) ||
    version < 0 ||
    version > 0xffff ||
    objectIs(version, -0)
  ) {
    throw new TypeError(
      'group-security transition delivery codec version must be an unsigned 16-bit integer',
    );
  }
  return objectFreeze({ id, version });
}

function exactRecord(
  value: unknown,
  expected: ReadonlyArray<string>,
  field: string,
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null) {
    throw new TypeError(`${field} must be an object`);
  }
  let descriptors: PropertyDescriptorMap;
  try {
    descriptors = objectGetOwnPropertyDescriptors(value);
  } catch {
    throw new TypeError(`${field} properties are invalid`);
  }
  const keys = reflectOwnKeys(descriptors);
  if (keys.length !== expected.length) {
    throw new TypeError(`${field} has unexpected properties`);
  }
  for (let index = 0; index < keys.length; index++) {
    const key = keys[index];
    if (typeof key !== 'string' || !containsString(expected, key)) {
      throw new TypeError(`${field} has unexpected properties`);
    }
  }
  const result = objectCreate(null) as Record<string, unknown>;
  for (let index = 0; index < expected.length; index++) {
    const key = expected[index];
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor)
    ) {
      throw new TypeError(
        `${field} must contain enumerable own data properties`,
      );
    }
    result[key] = descriptor.value;
  }
  return result;
}

function containsString(
  values: ReadonlyArray<string>,
  candidate: string,
): boolean {
  for (let index = 0; index < values.length; index++) {
    if (values[index] === candidate) return true;
  }
  return false;
}

function encodeDeliveryCodecId(value: string): Uint8Array {
  if (
    value.length === 0 ||
    value.length > MAX_GROUP_SECURITY_TRANSITION_CODEC_ID_BYTES
  ) {
    throw new TypeError(
      'group-security transition delivery codec id has an invalid length',
    );
  }
  const output = new uint8ArrayConstructor(value.length);
  for (let index = 0; index < value.length; index++) {
    const code = reflectApply(stringCharCodeAt, value, [index]);
    if (!isCodecIdCode(code, index === 0)) {
      throw new TypeError(
        'group-security transition delivery codec id is not canonical ASCII',
      );
    }
    output[index] = code;
  }
  return output;
}

function decodeDeliveryCodecId(value: Uint8Array): string {
  const length = byteLength(value);
  let result = '';
  for (let index = 0; index < length; index++) {
    const code = value[index];
    if (!isCodecIdCode(code, index === 0)) {
      throw new Error(
        'group-security transition delivery codec id is not canonical ASCII',
      );
    }
    result += stringFromCharCode(code);
  }
  return result;
}

function isCodecIdCode(code: number, first: boolean): boolean {
  const alphanumeric =
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a);
  return (
    alphanumeric ||
    (!first &&
      (code === 0x2d || code === 0x2e || code === 0x2f || code === 0x5f))
  );
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  const leftLength = byteLength(left);
  if (leftLength !== byteLength(right)) return false;
  let difference = 0;
  for (let index = 0; index < leftLength; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function byteLength(value: Uint8Array): number {
  return reflectApply(typedArrayByteLengthGetter, value, []) as number;
}

function byteOffset(value: Uint8Array): number {
  return reflectApply(typedArrayByteOffsetGetter, value, []) as number;
}

function buffer(value: Uint8Array): ArrayBufferLike {
  return reflectApply(typedArrayBufferGetter, value, []) as ArrayBufferLike;
}

function dataView(value: Uint8Array): DataView {
  return new dataViewConstructor(
    buffer(value) as ArrayBuffer,
    byteOffset(value),
    byteLength(value),
  );
}

function setBytes(
  target: Uint8Array,
  source: Uint8Array,
  offset: number,
): void {
  reflectApply(uint8ArraySet, target, [source, offset]);
}

function copyRange(
  input: Uint8Array,
  offset: number,
  length: number,
): Uint8Array {
  const source = new uint8ArrayConstructor(
    buffer(input),
    byteOffset(input) + offset,
    length,
  );
  const output = new uint8ArrayConstructor(length);
  setBytes(output, source, 0);
  return output;
}
