/**
 * @internal Shared strict-decoding helpers for the explicitly-versioned
 * BeeKEM V2 wire codecs (`beekem-welcome-wire.ts`, `path-update-wire.ts`).
 */

import { Base64 } from 'js-base64';
import {
  copyUnsharedUint8Array,
  snapshotEnumerableOwnDataObject,
  tryDecodeCanonicalBase64,
} from './utils.js';

const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;

/** Per-codec limits and the type name used in error messages. */
export interface V2WireCodec {
  readonly typeName: string;
  readonly maxAggregateDecodedBytes: number;
  readonly maxAggregateWorkItems: number;
}

/** Aggregate decode budget for one V2 value. */
export interface V2DecodeBudget {
  readonly codec: V2WireCodec;
  decodedBytes: number;
  workItems: number;
}

export function createV2DecodeBudget(codec: V2WireCodec): V2DecodeBudget {
  return { codec, decodedBytes: 0, workItems: 0 };
}

/**
 * Detach a plain object whose own fields are all enumerable data properties
 * drawn from `allowedKeys`. The snapshot has a null prototype so absent
 * fields never resolve through `Object.prototype`.
 */
export function snapshotPlainObject(
  value: unknown,
  allowedKeys: readonly string[],
  context: string,
): Record<string, unknown> {
  let detached: Record<string, unknown>;
  try {
    detached = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
      value,
      context,
    );
  } catch (err) {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new Error(
        `${context}: expected a plain object, got ${describe(value)}`,
      );
    }
    throw new Error(
      `${context}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const allowed = new Set(allowedKeys);
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of reflectOwnKeys(detached) as string[]) {
    if (!allowed.has(key)) {
      throw new Error(`${context}: unexpected field '${key}'`);
    }
    snapshot[key] = detached[key];
  }
  return snapshot;
}

/**
 * Detach a dense array of at most `maxLength` own data entries and charge its
 * length to the work budget.
 */
export function snapshotBoundedArray(
  value: unknown,
  maxLength: number,
  context: string,
  budget: V2DecodeBudget,
  maxLengthError = `${context} exceeds ${maxLength} entries`,
): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`${context} must be an array (got ${describe(value)})`);
  }
  const lengthDescriptor = reflectApply(
    objectGetOwnPropertyDescriptor,
    Object,
    [value, 'length'],
  ) as PropertyDescriptor | undefined;
  const length = lengthDescriptor?.value;
  if (
    lengthDescriptor === undefined ||
    !('value' in lengthDescriptor) ||
    !Number.isSafeInteger(length) ||
    (length as number) < 0
  ) {
    throw new Error(`${context} must have an own non-negative integer length`);
  }
  if ((length as number) > maxLength) {
    throw new Error(maxLengthError);
  }
  reserveV2Work(budget, length as number, context);
  if (reflectOwnKeys(value).length !== (length as number) + 1) {
    throw new Error(
      `${context} must be a dense array without extra properties`,
    );
  }
  const snapshot = new Array<unknown>(length as number);
  for (let index = 0; index < snapshot.length; index++) {
    const descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
      value,
      String(index),
    ]) as PropertyDescriptor | undefined;
    if (
      descriptor === undefined ||
      !('value' in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new Error(
        `${context}[${index}] must be an own enumerable data property`,
      );
    }
    snapshot[index] = descriptor.value;
  }
  return snapshot;
}

export function reserveV2Work(
  budget: V2DecodeBudget,
  count: number,
  context: string,
): void {
  if (count > budget.codec.maxAggregateWorkItems - budget.workItems) {
    throw new Error(
      `Invalid ${budget.codec.typeName}: aggregate work budget exceeded at ${context}`,
    );
  }
  budget.workItems += count;
}

function reserveV2DecodedBytes(
  budget: V2DecodeBudget,
  encodedLength: number,
  fieldName: string,
): void {
  const decodedUpperBound = Math.ceil(encodedLength / 4) * 3;
  if (
    decodedUpperBound >
    budget.codec.maxAggregateDecodedBytes - budget.decodedBytes
  ) {
    throw new Error(
      `Invalid ${budget.codec.typeName}: aggregate decoded-byte budget exceeded at '${fieldName}'`,
    );
  }
  budget.decodedBytes += decodedUpperBound;
}

/**
 * Detach runtime bytes for encoding and return their canonical base64,
 * charging the encoded size to the budget.
 */
export function encodeRuntimeBytes(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  fieldName: string,
  budget: V2DecodeBudget,
): string {
  const { typeName } = budget.codec;
  let bytes: Uint8Array;
  try {
    bytes = copyUnsharedUint8Array(
      value,
      minimumLength,
      maximumLength,
      `${typeName}.${fieldName}`,
    );
  } catch {
    throw new Error(
      `Invalid ${typeName}: '${fieldName}' must be an unshared Uint8Array from ${minimumLength} to ${maximumLength} bytes`,
    );
  }
  reserveV2DecodedBytes(budget, Math.ceil(bytes.byteLength / 3) * 4, fieldName);
  return Base64.fromUint8Array(bytes);
}

/**
 * Decode a canonical base64 field of `minimumLength` to `maximumLength`
 * bytes, charging it to the budget before decoding.
 */
export function decodeV2Bytes(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  fieldName: string,
  budget: V2DecodeBudget,
): Uint8Array {
  const { typeName } = budget.codec;
  if (typeof value !== 'string') {
    throw new Error(
      `Invalid ${typeName}: '${fieldName}' must be a base64 string (got ${describe(value)})`,
    );
  }
  if (value.length > Math.ceil(maximumLength / 3) * 4) {
    throw new Error(`Invalid ${typeName}: '${fieldName}' exceeds size limit`);
  }
  reserveV2DecodedBytes(budget, value.length, fieldName);
  const decoded = tryDecodeCanonicalBase64(value);
  if (decoded === undefined) {
    throw new Error(
      `Invalid ${typeName}: '${fieldName}' must use canonical padded base64`,
    );
  }
  if (
    decoded.byteLength < minimumLength ||
    decoded.byteLength > maximumLength
  ) {
    throw new Error(
      minimumLength === maximumLength
        ? `Invalid ${typeName}: '${fieldName}' must decode to ${minimumLength} bytes`
        : `Invalid ${typeName}: '${fieldName}' must decode to ${minimumLength} to ${maximumLength} bytes`,
    );
  }
  return decoded;
}

export function requireNonNegativeInteger(
  value: unknown,
  field: string,
  typeName: string,
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    Object.is(value, -0)
  ) {
    throw new Error(
      `Invalid ${typeName}: '${field}' must be a non-negative safe integer (got ${describe(value)})`,
    );
  }
  return value;
}

export function requirePositiveInteger(
  value: unknown,
  field: string,
  typeName: string,
): number {
  requireNonNegativeInteger(value, field, typeName);
  if (value === 0) {
    throw new Error(`Invalid ${typeName}: '${field}' must be positive`);
  }
  return value as number;
}

export function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}
