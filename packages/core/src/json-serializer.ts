import { Base64 } from 'js-base64';
import { EPOCH_ID_LENGTH } from './epoch.js';
import { TIPS_HASH_LENGTH } from './tips-hash.js';
import { ECIES_P256_PUBLIC_KEY_LENGTH } from './ecies.js';
import {
  copyUnsharedUint8Array,
  MAX_SHARED_PROTOCOL_REQUEST_BYTES,
} from './utils.js';
import {
  serializeLoadSecurityCommitmentsForWire,
  deserializeLoadSecurityCommitmentsFromWire,
} from './load-security-state-wire.js';
import type { LoadSecurityCommitments } from './load-security-state.js';
import { ChangesSerializer } from './changes-serializer.js';
import { CRDTChangeBlock } from './crdt-change-block.js';
import { CRDTLoadRequest } from './crdt-load-request.js';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import {
  LoadMessageSerializer,
  LoadRequestCompletionDetector,
} from './load-request-serializer.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import {
  deserializeInitialLoadChallengeFromWire,
  serializeInitialLoadChallengeForWire,
} from './initial-load-challenge.js';
import {
  CRDTChangeNodeWire,
  deserializeChangeNodeFromJSON,
  serializeChangeNodeForJSON,
} from './merkle-dag-serialization.js';

function syncBinaryFieldBounds(
  field: string,
): readonly [number, number] | undefined {
  switch (field) {
    case 'welcomeEpochId':
    case 'pathUpdateEpochId':
      return [EPOCH_ID_LENGTH, EPOCH_ID_LENGTH];
    case 'tipsHash':
      return [TIPS_HASH_LENGTH, TIPS_HASH_LENGTH];
    case 'welcomeRecipientKemPublicKey':
      return [ECIES_P256_PUBLIC_KEY_LENGTH, ECIES_P256_PUBLIC_KEY_LENGTH];
    case 'eciesSealed':
      return [1, MAX_SHARED_PROTOCOL_REQUEST_BYTES];
    default:
      return undefined;
  }
}

function serializeSyncBinaryField(field: string, value: unknown): unknown {
  if (value === undefined) return value;
  if (field === 'loadChallenge')
    return serializeInitialLoadChallengeForWire(value as Uint8Array);
  if (field === 'loadSecurityState')
    return serializeLoadSecurityCommitmentsForWire(
      value as LoadSecurityCommitments,
    );
  const bounds = syncBinaryFieldBounds(field);
  return bounds === undefined
    ? value
    : Base64.fromUint8Array(
        copyUnsharedUint8Array(value, bounds[0], bounds[1], field),
      );
}

function deserializeSyncBinaryField(field: string, value: unknown): unknown {
  if (value === undefined) return value;
  if (field === 'loadChallenge')
    return deserializeInitialLoadChallengeFromWire(value);
  if (field === 'loadSecurityState')
    return deserializeLoadSecurityCommitmentsFromWire(value);
  const bounds = syncBinaryFieldBounds(field);
  if (bounds === undefined) return value;
  if (
    typeof value !== 'string' ||
    value.length < Math.ceil(bounds[0] / 3) * 4 ||
    value.length > Math.ceil(bounds[1] / 3) * 4 ||
    value.length % 4 !== 0
  ) {
    throw new TypeError(`${field} must be bounded canonical base64`);
  }
  let decoded: Uint8Array;
  try {
    decoded = Base64.toUint8Array(value);
  } catch {
    throw new TypeError(`${field} must be bounded canonical base64`);
  }
  if (
    decoded.byteLength < bounds[0] ||
    decoded.byteLength > bounds[1] ||
    Base64.fromUint8Array(decoded) !== value
  ) {
    throw new TypeError(`${field} must be bounded canonical base64`);
  }
  return decoded;
}

/**
 * Dangerous property keys that should be stripped from deserialized objects
 * to prevent prototype pollution attacks.
 */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const INVALID_SERIALIZED_JSON = 'Invalid serialized JSON';
const numberValueOf = Number.prototype.valueOf;
const stringValueOf = String.prototype.valueOf;
const booleanValueOf = Boolean.prototype.valueOf;
const bigintValueOf = BigInt.prototype.valueOf;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;

function isJSONWhitespace(byte: number): boolean {
  return byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d;
}

/**
 * Scan top-level JSON-object framing one byte at a time. JSON.parse remains
 * responsible for syntax and schema validation; this scanner only identifies
 * the first point at which parsing cannot be an incomplete-input retry. UTF-8
 * bytes above ASCII cannot affect JSON structural delimiters.
 */
function createJSONObjectCompletionDetector(): LoadRequestCompletionDetector {
  let started = false;
  let depth = 0;
  let inString = false;
  let escaped = false;
  let complete = false;

  return (chunk: Uint8Array): boolean => {
    for (const byte of chunk) {
      if (complete) {
        if (!isJSONWhitespace(byte)) {
          throw new SyntaxError('Unexpected data after JSON load request');
        }
        continue;
      }

      if (!started) {
        if (isJSONWhitespace(byte)) continue;
        if (byte !== 0x7b) {
          throw new SyntaxError('JSON load request must be an object');
        }
        started = true;
        depth = 1;
        continue;
      }

      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (byte === 0x5c) {
          escaped = true;
        } else if (byte === 0x22) {
          inString = false;
        } else if (byte < 0x20) {
          throw new SyntaxError('Unescaped control byte in JSON string');
        }
        continue;
      }

      if (byte === 0x22) {
        inString = true;
      } else if (byte === 0x7b || byte === 0x5b) {
        depth++;
      } else if (byte === 0x7d || byte === 0x5d) {
        depth--;
        if (depth < 0) {
          throw new SyntaxError('Unexpected JSON closing delimiter');
        }
        complete = depth === 0;
      }
    }
    return complete;
  };
}

type PreparedJSONValue =
  | { readonly kind: 'omitted' }
  | { readonly kind: 'primitive'; readonly serialized: string }
  | { readonly kind: 'object'; readonly value: object };

function prepareJSONValue(holder: object, key: string): PreparedJSONValue {
  let value = Reflect.get(holder, key);
  // Native JSON.stringify uniquely consults BigInt.prototype.toJSON for a
  // primitive bigint before applying its otherwise-throwing bigint rule.
  if (
    (typeof value === 'object' && value !== null) ||
    typeof value === 'function' ||
    typeof value === 'bigint'
  ) {
    const toJSON = Reflect.get(
      typeof value === 'bigint' ? Object(value) : (value as object),
      'toJSON',
    );
    if (typeof toJSON === 'function') {
      value = Reflect.apply(toJSON, value, [key]);
    }
  }

  if (typeof value === 'object' && value !== null) {
    let isBoxedNumber = false;
    try {
      Reflect.apply(numberValueOf, value, []);
      isBoxedNumber = true;
    } catch {
      // Prototype lookalikes and Proxies are ordinary objects to JSON.stringify.
    }
    if (isBoxedNumber) {
      value = Number(value);
    } else {
      let isBoxedString = false;
      try {
        Reflect.apply(stringValueOf, value, []);
        isBoxedString = true;
      } catch {
        // Prototype lookalikes and Proxies are ordinary objects to JSON.stringify.
      }
      if (isBoxedString) {
        value = String(value);
      } else {
        try {
          value = Reflect.apply(booleanValueOf, value, []);
        } catch {
          try {
            value = Reflect.apply(bigintValueOf, value, []);
          } catch {
            // Other objects retain their ordinary JSON.stringify behavior.
          }
        }
      }
    }
  }

  switch (typeof value) {
    case 'string':
    case 'number':
    case 'boolean':
      return {
        kind: 'primitive',
        serialized: JSON.stringify(value)!,
      };
    case 'bigint':
      throw new TypeError('Do not know how to serialize a BigInt');
    case 'undefined':
    case 'function':
    case 'symbol':
      return { kind: 'omitted' };
    case 'object':
      return value === null
        ? { kind: 'primitive', serialized: 'null' }
        : { kind: 'object', value };
  }
}

function isStackOverflowError(err: unknown): boolean {
  // V8 and JavaScriptCore throw RangeError; SpiderMonkey throws InternalError.
  return (
    err instanceof RangeError ||
    (err instanceof Error && err.name === 'InternalError')
  );
}

function requireJSONObject(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${what} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Stack-safe equivalent of `JSON.stringify(value)` without a replacer or
 * indentation. Primitive encoding is delegated to the native implementation;
 * arrays and objects are walked explicitly so a legitimate long Merkle
 * history cannot exhaust the JavaScript call stack. Object keys retain native
 * `Object.keys` order, unsupported array values become `null`, unsupported
 * object values are omitted, `toJSON` is honored, and ancestor cycles fail.
 */
function stringifyJSONIteratively(value: unknown): string | undefined {
  type ObjectFrame = {
    readonly kind: 'object';
    readonly value: object;
    readonly keys: string[];
    index: number;
    wroteValue: boolean;
  };
  type ArrayFrame = {
    readonly kind: 'array';
    readonly value: unknown[];
    readonly length: number;
    index: number;
  };
  type Task =
    | { readonly kind: 'value'; readonly value: PreparedJSONValue }
    | ObjectFrame
    | ArrayFrame;

  const rootHolder = { '': value };
  const root = prepareJSONValue(rootHolder, '');
  if (root.kind === 'omitted') return undefined;

  const output: string[] = [];
  const active = new WeakSet<object>();
  const pending: Task[] = [{ kind: 'value', value: root }];
  while (pending.length > 0) {
    const task = pending.pop()!;
    if (task.kind === 'value') {
      if (task.value.kind === 'primitive') {
        output.push(task.value.serialized);
        continue;
      }
      if (task.value.kind === 'omitted') {
        // Only container frames enqueue omitted values, and arrays translate
        // them to `null` before enqueueing. Object frames skip them entirely.
        continue;
      }
      const objectValue = task.value.value;
      if (active.has(objectValue)) {
        throw new TypeError('Converting circular structure to JSON');
      }
      active.add(objectValue);
      if (Array.isArray(objectValue)) {
        output.push('[');
        pending.push({
          kind: 'array',
          value: objectValue,
          length: objectValue.length,
          index: 0,
        });
      } else {
        output.push('{');
        pending.push({
          kind: 'object',
          value: objectValue,
          keys: Object.keys(objectValue),
          index: 0,
          wroteValue: false,
        });
      }
      continue;
    }

    if (task.kind === 'array') {
      if (task.index >= task.length) {
        output.push(']');
        active.delete(task.value);
        continue;
      }
      const index = task.index++;
      if (index > 0) output.push(',');
      pending.push(task);
      const prepared = prepareJSONValue(task.value, String(index));
      pending.push(
        prepared.kind === 'omitted'
          ? { kind: 'value', value: { kind: 'primitive', serialized: 'null' } }
          : { kind: 'value', value: prepared },
      );
      continue;
    }

    let prepared: PreparedJSONValue | undefined;
    let key: string | undefined;
    while (task.index < task.keys.length && prepared === undefined) {
      key = task.keys[task.index++]!;
      const candidate = prepareJSONValue(task.value, key);
      if (candidate.kind !== 'omitted') prepared = candidate;
    }
    if (prepared === undefined || key === undefined) {
      output.push('}');
      active.delete(task.value);
      continue;
    }
    if (task.wroteValue) output.push(',');
    task.wroteValue = true;
    output.push(JSON.stringify(key), ':');
    pending.push(task, { kind: 'value', value: prepared });
  }
  return output.join('');
}

/**
 * Transform enumerable own fields without changing their insertion order.
 *
 * Wire signatures cover the exact JSON bytes, so rebuilding an object in
 * schema order is not safe. Defining data properties also keeps keys such as
 * `__proto__` inert. Descriptors let us snapshot values without invoking
 * peer-controlled accessors.
 */
function transformOwnFieldsInOrder(
  source: object,
  transform: (field: string, value: unknown) => unknown,
): Record<string, unknown> {
  const descriptors = Reflect.apply(objectGetOwnPropertyDescriptors, Object, [
    source,
  ]) as PropertyDescriptorMap;
  const result: Record<string, unknown> = {};
  for (const field of Object.keys(descriptors)) {
    const descriptor = descriptors[field]!;
    if (descriptor.enumerable !== true) continue;
    if (!('value' in descriptor)) {
      throw new TypeError(
        `wire field ${JSON.stringify(field)} must be a data property`,
      );
    }
    Object.defineProperty(result, field, {
      configurable: true,
      enumerable: true,
      value: transform(field, descriptor.value),
      writable: true,
    });
  }
  return result;
}

/**
 * Validate and sanitize keyID and blindIndexTokens fields from a deserialized
 * change block. Shared across JSONSerializer, YjsJSONSerializer, and
 * AutomergeJSONSerializer to avoid duplicating validation logic.
 *
 * Mutates the result object in place by setting keyID and blindIndexTokens
 * if present and valid on the deserialized input.
 *
 * @internal
 * @throws {Error} If keyID is not a string, or blindIndexTokens is not a
 *   plain object with string values.
 */
export function validateChangeBlockMetadata<ChangesType>(
  deserialized: { keyID?: unknown; blindIndexTokens?: unknown },
  result: CRDTChangeBlock<ChangesType>,
): void {
  if (Object.prototype.hasOwnProperty.call(deserialized, 'keyID')) {
    if (typeof deserialized.keyID !== 'string') {
      throw new Error('keyID must be a string');
    }
    result.keyID = deserialized.keyID;
  }
  if (Object.prototype.hasOwnProperty.call(deserialized, 'blindIndexTokens')) {
    const tokens = deserialized.blindIndexTokens;
    // Validate blindIndexTokens shape: must be a plain object mapping string keys to string values
    if (
      tokens === null ||
      typeof tokens !== 'object' ||
      Array.isArray(tokens)
    ) {
      throw new Error('blindIndexTokens must be a plain object');
    }
    const proto = Object.getPrototypeOf(tokens);
    if (proto !== Object.prototype && proto !== null) {
      throw new Error('blindIndexTokens must be a plain object');
    }
    const sanitized: Record<string, string> = {};
    for (const [key, val] of Object.entries(
      tokens as Record<string, unknown>,
    )) {
      if (DANGEROUS_KEYS.has(key)) {
        continue; // silently drop dangerous keys
      }
      if (typeof key !== 'string' || typeof val !== 'string') {
        throw new Error(
          `blindIndexTokens values must be strings, got non-string at key "${key}"`,
        );
      }
      sanitized[key] = val;
    }
    result.blindIndexTokens = sanitized;
  }
}

export class JSONSerializer<ChangesType, PublicKey = unknown>
  implements
    ChangesSerializer<ChangesType>,
    SyncMessageSerializer<ChangesType, PublicKey>,
    LoadMessageSerializer
{
  createLoadRequestCompletionDetector(): LoadRequestCompletionDetector {
    return createJSONObjectCompletionDetector();
  }

  serialize(message: unknown): string {
    const serialized = JSON.stringify(message);
    if (serialized === undefined) {
      throw new TypeError('Top-level value is not JSON-serializable');
    }
    return serialized;
  }

  /**
   * Stack-safe writer for schema-normalized sync-message wire objects.
   *
   * Keep this separate from the public generic serializer: `JSON.stringify`
   * has observable cross-realm and boxed-primitive semantics that a focused
   * protocol writer must not claim to reproduce for arbitrary caller values.
   */
  protected serializeNormalizedSyncWireValue(message: unknown): string {
    // Native stringify is far faster; the iterative writer only exists for
    // histories deep enough to exhaust the call stack.
    try {
      return JSON.stringify(message) as string;
    } catch (err) {
      if (!isStackOverflowError(err)) throw err;
    }
    return stringifyJSONIteratively(message) as string;
  }
  deserialize(message: string): unknown {
    try {
      return JSON.parse(message);
    } catch {
      console.error(INVALID_SERIALIZED_JSON);
      throw new SyntaxError(INVALID_SERIALIZED_JSON);
    }
  }

  encode(message: string): Uint8Array {
    const encoder = new TextEncoder();
    return encoder.encode(message);
  }
  decode(message: Uint8Array): string {
    const decoder = new TextDecoder();
    return decoder.decode(message);
  }

  serializeChanges(changes: ChangesType): Uint8Array {
    return this.encode(this.serialize(changes));
  }
  deserializeChanges(changes: Uint8Array): ChangesType {
    // Shape validated by subclass overrides; base class trusts JSON.parse output matches ChangesType
    return this.deserialize(this.decode(changes)) as ChangesType;
  }
  serializeChangeBlock(changes: CRDTChangeBlock<ChangesType>): string {
    const obj: Record<string, unknown> = {
      changes: changes.changes,
      nonce: Base64.fromUint8Array(changes.nonce),
    };
    if (changes.keyID !== undefined) obj.keyID = changes.keyID;
    if ('blindIndexTokens' in changes) {
      obj.blindIndexTokens = changes.blindIndexTokens;
    }
    return this.serialize(obj);
  }
  deserializeChangeBlock(changes: string): CRDTChangeBlock<ChangesType> {
    // Shape validated by subclass overrides; base class trusts JSON.parse output matches ChangesType
    const deserialized = this.deserialize(changes) as {
      changes: ChangesType;
      nonce: string;
      keyID?: string;
      blindIndexTokens?: Record<string, string>;
    };
    const result: CRDTChangeBlock<ChangesType> = {
      changes: deserialized.changes,
      nonce: Base64.toUint8Array(deserialized.nonce),
    };
    validateChangeBlockMetadata(deserialized, result);
    return result;
  }
  serializeSyncMessage(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Uint8Array {
    const wire = transformOwnFieldsInOrder(message, (field, value) =>
      field === 'changes' && value !== undefined
        ? serializeChangeNodeForJSON(
            value as NonNullable<
              CRDTSyncMessage<ChangesType, PublicKey>['changes']
            >,
            (change) => change,
          )
        : serializeSyncBinaryField(field, value),
    );
    return this.encode(this.serializeNormalizedSyncWireValue(wire));
  }
  deserializeSyncMessage(
    message: Uint8Array,
  ): CRDTSyncMessage<ChangesType, PublicKey> {
    const raw = requireJSONObject(
      this.deserialize(this.decode(message)),
      'Sync message',
    );
    return transformOwnFieldsInOrder(raw, (field, value) =>
      field === 'changes' && value !== undefined
        ? deserializeChangeNodeFromJSON(
            value as CRDTChangeNodeWire<ChangesType>,
            (change) => change,
          )
        : deserializeSyncBinaryField(field, value),
    ) as CRDTSyncMessage<ChangesType, PublicKey>;
  }
  serializeLoadRequest(message: CRDTLoadRequest): Uint8Array {
    const wire = transformOwnFieldsInOrder(message, (field, value) =>
      field === 'loadChallenge' && value !== undefined
        ? serializeInitialLoadChallengeForWire(value as Uint8Array)
        : value,
    );
    return this.encode(this.serialize(wire));
  }
  deserializeLoadRequest(message: Uint8Array): CRDTLoadRequest {
    const raw = requireJSONObject(
      this.deserialize(this.decode(message)),
      'Load request',
    );
    return transformOwnFieldsInOrder(raw, (field, value) =>
      field === 'loadChallenge' && value !== undefined
        ? deserializeInitialLoadChallengeFromWire(value)
        : value,
    ) as CRDTLoadRequest;
  }
}
