import { Base64 } from 'js-base64';
import { ChangesSerializer } from './changes-serializer.js';
import { CRDTChangeBlock } from './crdt-change-block.js';
import { CRDTLoadRequest } from './crdt-load-request.js';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import { LoadMessageSerializer } from './load-request-serializer.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';

/**
 * Dangerous property keys that should be stripped from deserialized objects
 * to prevent prototype pollution attacks.
 */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

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
    if (tokens === null || typeof tokens !== 'object' || Array.isArray(tokens)) {
      throw new Error('blindIndexTokens must be a plain object');
    }
    const proto = Object.getPrototypeOf(tokens);
    if (proto !== Object.prototype && proto !== null) {
      throw new Error('blindIndexTokens must be a plain object');
    }
    const sanitized: Record<string, string> = {};
    for (const [key, val] of Object.entries(tokens as Record<string, unknown>)) {
      if (DANGEROUS_KEYS.has(key)) {
        continue; // silently drop dangerous keys
      }
      if (typeof key !== 'string' || typeof val !== 'string') {
        throw new Error(`blindIndexTokens values must be strings, got non-string at key "${key}"`);
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
  serialize(message: unknown): string {
    return JSON.stringify(message);
  }
  deserialize(message: string): unknown {
    try {
      return JSON.parse(message);
    } catch (err) {
      console.error('Failed to parse message:', message, err);
      throw err;
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
  serializeSyncMessage(message: CRDTSyncMessage<ChangesType, PublicKey>): Uint8Array {
    return this.encode(this.serialize(message));
  }
  deserializeSyncMessage(message: Uint8Array): CRDTSyncMessage<ChangesType, PublicKey> {
    // Shape validated by subclass overrides; base class trusts JSON.parse output matches CRDTSyncMessage
    return this.deserialize(this.decode(message)) as CRDTSyncMessage<ChangesType, PublicKey>;
  }
  serializeLoadRequest(message: CRDTLoadRequest): Uint8Array {
    return this.encode(this.serialize(message));
  }
  deserializeLoadRequest(message: Uint8Array): CRDTLoadRequest {
    // Shape validated by subclass overrides; base class trusts JSON.parse output matches CRDTLoadRequest
    return this.deserialize(this.decode(message)) as CRDTLoadRequest;
  }
}
