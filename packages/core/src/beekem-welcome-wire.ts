/**
 * Wire serialization for BeeKEM `BeeKEMWelcome` payloads.
 *
 * The `BeeKEMWelcome` runtime shape (from `beekem/types.ts`) is a small
 * record of `Uint8Array`s plus a leaf index. This module is the JSON-safe
 * encoder/decoder pair so a Welcome can be carried inside the sealed
 * `eciesSealed` payload of a `CRDTSyncMessage` together with the keychain
 * delta (see `welcome-sealed-payload.ts`).
 *
 * The shape mirrors the structure used by `path-update-wire.ts`: each
 * `Uint8Array` field is base64-encoded so the result survives a
 * `JSON.stringify` round-trip without binary loss.
 */
import { Base64 } from 'js-base64';
import {
  BeeKEMWelcome,
  PathNodeUpdate,
  WelcomeNodePublicKey,
} from './beekem/types.js';

/** JSON-safe encoding of `PathNodeUpdate` (mirrors path-update-wire). */
export interface SerializedWelcomePathNodeUpdate {
  nodeIndex: number;
  publicKey: string; // base64
  encryptedPrivateKey: string; // base64
}

/** JSON-safe encoding of `WelcomeNodePublicKey`. `publicKey` is `null` for blanked nodes. */
export interface SerializedWelcomeNodePublicKey {
  nodeIndex: number;
  publicKey: string | null; // base64 or null
}

/** JSON-safe encoding of `BeeKEMWelcome`. */
export interface SerializedBeeKEMWelcome {
  leafIndex: number;
  pathKeys: SerializedWelcomePathNodeUpdate[];
  treeNodePublicKeys: SerializedWelcomeNodePublicKey[];
  treeHash: string; // base64
}

/** Convert a runtime `BeeKEMWelcome` to its JSON-safe wire form. */
export function serializeBeeKEMWelcomeForWire(
  welcome: BeeKEMWelcome,
): SerializedBeeKEMWelcome {
  return {
    leafIndex: welcome.leafIndex,
    pathKeys: welcome.pathKeys.map((n) => ({
      nodeIndex: n.nodeIndex,
      publicKey: Base64.fromUint8Array(n.publicKey),
      encryptedPrivateKey: Base64.fromUint8Array(n.encryptedPrivateKey),
    })),
    treeNodePublicKeys: welcome.treeNodePublicKeys.map((e) => ({
      nodeIndex: e.nodeIndex,
      publicKey:
        e.publicKey === null ? null : Base64.fromUint8Array(e.publicKey),
    })),
    treeHash: Base64.fromUint8Array(welcome.treeHash),
  };
}

/**
 * Decode a wire-format `SerializedBeeKEMWelcome` back into a runtime
 * `BeeKEMWelcome`. Surfaces a descriptive error for malformed inputs,
 * mirroring the validation posture used by `path-update-wire.ts`.
 */
export function deserializeBeeKEMWelcomeFromWire(
  wire: unknown,
): BeeKEMWelcome {
  if (typeof wire !== 'object' || wire === null || Array.isArray(wire)) {
    throw new Error(
      `Invalid BeeKEMWelcome: expected a plain object, got ${describe(wire)}`,
    );
  }
  const raw = wire as Record<string, unknown>;

  if (
    typeof raw.leafIndex !== 'number' ||
    !Number.isInteger(raw.leafIndex) ||
    raw.leafIndex < 0
  ) {
    throw new Error(
      `Invalid BeeKEMWelcome: 'leafIndex' must be a non-negative integer (got ${describe(
        raw.leafIndex,
      )})`,
    );
  }
  if (!Array.isArray(raw.pathKeys)) {
    throw new Error(
      `Invalid BeeKEMWelcome: 'pathKeys' must be an array (got ${describe(
        raw.pathKeys,
      )})`,
    );
  }
  if (!Array.isArray(raw.treeNodePublicKeys)) {
    throw new Error(
      `Invalid BeeKEMWelcome: 'treeNodePublicKeys' must be an array (got ${describe(
        raw.treeNodePublicKeys,
      )})`,
    );
  }
  if (typeof raw.treeHash !== 'string') {
    throw new Error(
      `Invalid BeeKEMWelcome: 'treeHash' must be a base64 string (got ${describe(
        raw.treeHash,
      )})`,
    );
  }

  const pathKeys: PathNodeUpdate[] = raw.pathKeys.map((n, i) => {
    if (typeof n !== 'object' || n === null || Array.isArray(n)) {
      throw new Error(
        `Invalid BeeKEMWelcome: pathKeys[${i}] must be a plain object, got ${describe(n)}`,
      );
    }
    const nn = n as Record<string, unknown>;
    if (
      typeof nn.nodeIndex !== 'number' ||
      !Number.isInteger(nn.nodeIndex) ||
      nn.nodeIndex < 0
    ) {
      throw new Error(
        `Invalid BeeKEMWelcome: pathKeys[${i}].nodeIndex must be a non-negative integer (got ${describe(
          nn.nodeIndex,
        )})`,
      );
    }
    if (typeof nn.publicKey !== 'string') {
      throw new Error(
        `Invalid BeeKEMWelcome: pathKeys[${i}].publicKey must be a base64 string (got ${describe(
          nn.publicKey,
        )})`,
      );
    }
    if (typeof nn.encryptedPrivateKey !== 'string') {
      throw new Error(
        `Invalid BeeKEMWelcome: pathKeys[${i}].encryptedPrivateKey must be a base64 string (got ${describe(
          nn.encryptedPrivateKey,
        )})`,
      );
    }
    return {
      nodeIndex: nn.nodeIndex,
      publicKey: decodeBase64(nn.publicKey, `pathKeys[${i}].publicKey`),
      encryptedPrivateKey: decodeBase64(
        nn.encryptedPrivateKey,
        `pathKeys[${i}].encryptedPrivateKey`,
      ),
    };
  });

  const treeNodePublicKeys: WelcomeNodePublicKey[] = raw.treeNodePublicKeys.map(
    (n, i) => {
      if (typeof n !== 'object' || n === null || Array.isArray(n)) {
        throw new Error(
          `Invalid BeeKEMWelcome: treeNodePublicKeys[${i}] must be a plain object, got ${describe(
            n,
          )}`,
        );
      }
      const nn = n as Record<string, unknown>;
      if (
        typeof nn.nodeIndex !== 'number' ||
        !Number.isInteger(nn.nodeIndex) ||
        nn.nodeIndex < 0
      ) {
        throw new Error(
          `Invalid BeeKEMWelcome: treeNodePublicKeys[${i}].nodeIndex must be a non-negative integer (got ${describe(
            nn.nodeIndex,
          )})`,
        );
      }
      if (nn.publicKey === null) {
        return { nodeIndex: nn.nodeIndex, publicKey: null };
      }
      if (typeof nn.publicKey !== 'string') {
        throw new Error(
          `Invalid BeeKEMWelcome: treeNodePublicKeys[${i}].publicKey must be a base64 string or null (got ${describe(
            nn.publicKey,
          )})`,
        );
      }
      return {
        nodeIndex: nn.nodeIndex,
        publicKey: decodeBase64(
          nn.publicKey,
          `treeNodePublicKeys[${i}].publicKey`,
        ),
      };
    },
  );

  return {
    leafIndex: raw.leafIndex,
    pathKeys,
    treeNodePublicKeys,
    treeHash: decodeBase64(raw.treeHash, 'treeHash'),
  };
}

function decodeBase64(value: string, fieldName: string): Uint8Array {
  try {
    return Base64.toUint8Array(value);
  } catch (err) {
    throw new Error(
      `BeeKEMWelcome wire: invalid base64 for field ${fieldName}: ${
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
