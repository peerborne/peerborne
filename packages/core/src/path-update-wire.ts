/**
 * Wire serialization for BeeKEM `PathUpdate`s.
 *
 * `BeeKEM.removeMember` / `BeeKEM.update` / `BeeKEM.processPathUpdate`
 * deal in the runtime `PathUpdate` shape from
 * `packages/core/src/beekem/types.ts`, which is a small
 * record of `Uint8Array`s. The `beekemPathUpdateV1` wire protocol
 * carries this record as a JSON-safe payload inside a
 * `CRDTSyncMessage`, so we need a base64-encoded shape per
 * `Uint8Array` and the matching encoder/decoder pair.
 *
 * The shape and helpers live here (not in the BeeKEM module
 * itself) so the in-flight PR #281 is free to evolve
 * `beekem/types.ts` without touching this file.
 */

import { Base64 } from 'js-base64';
import { PathNodeUpdate, PathUpdate } from './beekem/types.js';

/** JSON-safe encoding of a single `PathNodeUpdate`. */
export interface SerializedPathNodeUpdate {
  /** Tree node index. */
  nodeIndex: number;
  /** Base64-encoded raw P-256 SEC1-uncompressed public key. */
  publicKey: string;
  /** Base64-encoded ECIES ciphertext (BeeKEM internal format). */
  encryptedPrivateKey: string;
}

/** JSON-safe encoding of a `PathUpdate`. */
export interface SerializedPathUpdate {
  senderLeafIndex: number;
  /** Base64-encoded raw P-256 SEC1-uncompressed leaf public key. */
  senderLeafPublicKey: string;
  nodes: SerializedPathNodeUpdate[];
}

/** Convert a `PathUpdate` to a JSON-safe wire representation. */
export function serializePathUpdateForWire(
  update: PathUpdate,
): SerializedPathUpdate {
  return {
    senderLeafIndex: update.senderLeafIndex,
    senderLeafPublicKey: Base64.fromUint8Array(update.senderLeafPublicKey),
    nodes: update.nodes.map((n) => ({
      nodeIndex: n.nodeIndex,
      publicKey: Base64.fromUint8Array(n.publicKey),
      encryptedPrivateKey: Base64.fromUint8Array(n.encryptedPrivateKey),
    })),
  };
}

/**
 * Decode a wire-format `SerializedPathUpdate` back into a `PathUpdate`.
 *
 * Validates the input shape so a malformed peer payload (missing
 * fields, wrong types, etc.) surfaces as a descriptive error
 * instead of a confusing crash inside `BeeKEM.processPathUpdate`.
 * Mirrors the validation posture used by the sync-message
 * deserializers (`YjsJSONSerializer`, `AutomergeJSONSerializer`).
 */
export function deserializePathUpdateFromWire(
  wire: unknown,
): PathUpdate {
  if (typeof wire !== 'object' || wire === null || Array.isArray(wire)) {
    throw new Error(
      `Invalid PathUpdate: expected a plain object, got ${describe(wire)}`,
    );
  }
  const raw = wire as Record<string, unknown>;

  if (
    typeof raw.senderLeafIndex !== 'number' ||
    !Number.isInteger(raw.senderLeafIndex) ||
    raw.senderLeafIndex < 0
  ) {
    throw new Error(
      `Invalid PathUpdate: 'senderLeafIndex' must be a non-negative integer (got ${describe(raw.senderLeafIndex)})`,
    );
  }
  if (typeof raw.senderLeafPublicKey !== 'string') {
    throw new Error(
      `Invalid PathUpdate: 'senderLeafPublicKey' must be a base64 string (got ${describe(raw.senderLeafPublicKey)})`,
    );
  }
  if (!Array.isArray(raw.nodes)) {
    throw new Error(
      `Invalid PathUpdate: 'nodes' must be an array (got ${describe(raw.nodes)})`,
    );
  }

  const nodes: PathNodeUpdate[] = raw.nodes.map((n, i) => {
    if (typeof n !== 'object' || n === null || Array.isArray(n)) {
      throw new Error(
        `Invalid PathUpdate: node[${i}] must be a plain object, got ${describe(n)}`,
      );
    }
    const nn = n as Record<string, unknown>;
    if (
      typeof nn.nodeIndex !== 'number' ||
      !Number.isInteger(nn.nodeIndex) ||
      nn.nodeIndex < 0
    ) {
      throw new Error(
        `Invalid PathUpdate: node[${i}].nodeIndex must be a non-negative integer (got ${describe(nn.nodeIndex)})`,
      );
    }
    if (typeof nn.publicKey !== 'string') {
      throw new Error(
        `Invalid PathUpdate: node[${i}].publicKey must be a base64 string (got ${describe(nn.publicKey)})`,
      );
    }
    if (typeof nn.encryptedPrivateKey !== 'string') {
      throw new Error(
        `Invalid PathUpdate: node[${i}].encryptedPrivateKey must be a base64 string (got ${describe(nn.encryptedPrivateKey)})`,
      );
    }
    return {
      nodeIndex: nn.nodeIndex,
      publicKey: decodeBase64(nn.publicKey, `node[${i}].publicKey`),
      encryptedPrivateKey: decodeBase64(
        nn.encryptedPrivateKey,
        `node[${i}].encryptedPrivateKey`,
      ),
    };
  });

  return {
    senderLeafIndex: raw.senderLeafIndex,
    senderLeafPublicKey: decodeBase64(
      raw.senderLeafPublicKey,
      'senderLeafPublicKey',
    ),
    nodes,
  };
}

/**
 * Decode a base64 string with field-level error context. A malformed
 * peer payload that survives the per-field type checks above but
 * carries syntactically-invalid base64 in one of the `Uint8Array`
 * fields would otherwise throw a generic decoder error with no
 * indication of which field failed. Wrap each decode so the message
 * names the field, making protocol-level debugging tractable.
 */
function decodeBase64(value: string, fieldName: string): Uint8Array {
  try {
    return Base64.toUint8Array(value);
  } catch (err) {
    throw new Error(
      `path-update wire: invalid base64 for field ${fieldName}: ${
        err instanceof Error ? err.message : String(err)
      }`,
      { cause: err },
    );
  }
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `array(length=${value.length})`;
  return typeof value;
}
