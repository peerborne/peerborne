/**
 * Sealed-payload envelope for BeeKEM Welcomes.
 *
 * PR #281 introduced an ECIES-sealed plaintext that carried the
 * keychain delta only. To make Welcomes useful for actually
 * bootstrapping the joiner's BeeKEM ratchet state (so subsequent
 * `processPathUpdate` calls work in production), this envelope adds
 * the BeeKEM `Welcome` returned by `BeeKEM.addMember` alongside the
 * keychain delta.
 *
 * Wire shape (JSON-encoded inside the ECIES seal):
 *
 *   {
 *     "k": "<base64 keychain-delta bytes>",
 *     "bk": <SerializedBeeKEMWelcome | null>
 *   }
 *
 * The plaintext of `eciesSealed` is now this JSON envelope encoded as
 * UTF-8 bytes. The wire-level field `eciesSealed` on `CRDTSyncMessage`
 * is still a single `Uint8Array`; only its decoded shape grows, so
 * pre-existing tests that inspect the field type continue to pass.
 *
 * The recipient opens the seal, parses the JSON envelope, deserializes
 * the keychain bytes via the CRDT-specific `ChangesSerializer`, and (if
 * present) deserializes the BeeKEM welcome via
 * `deserializeBeeKEMWelcomeFromWire` and bootstraps the local BeeKEM
 * instance via `BeeKEM.processWelcome(welcome, privateKey, publicKey)`.
 *
 * The `bk` field is OPTIONAL so a sealed payload that pre-dates this
 * change (or a Welcome to a recipient that does not need BeeKEM
 * bootstrap, e.g. a future writer-onboarding flow) still parses
 * cleanly. Receivers that find `bk === null` skip the
 * `processWelcome` step.
 */
import { Base64 } from 'js-base64';
import { BeeKEMWelcome } from './beekem/types.js';
import {
  SerializedBeeKEMWelcome,
  deserializeBeeKEMWelcomeFromWire,
  serializeBeeKEMWelcomeForWire,
} from './beekem-welcome-wire.js';

/** Parsed shape of the sealed-payload envelope. */
export interface WelcomeSealedPayload {
  /** Provider-specific serialized keychain delta (raw bytes). */
  keychainChanges: Uint8Array;
  /**
   * Optional BeeKEM `Welcome` (the inviter's `addMember` output) so the
   * recipient can bootstrap their local BeeKEM ratchet state and
   * process subsequent PathUpdates.
   */
  beekemWelcome: BeeKEMWelcome | null;
}

/**
 * Encode a sealed-payload envelope for sealing under ECIES. The output
 * bytes are the JSON encoding of `{ k, bk }` (see module doc-comment).
 */
export function encodeWelcomeSealedPayload(
  payload: WelcomeSealedPayload,
): Uint8Array {
  const envelope: { k: string; bk: SerializedBeeKEMWelcome | null } = {
    k: Base64.fromUint8Array(payload.keychainChanges),
    bk:
      payload.beekemWelcome === null
        ? null
        : serializeBeeKEMWelcomeForWire(payload.beekemWelcome),
  };
  return new TextEncoder().encode(JSON.stringify(envelope));
}

/**
 * Decode a sealed-payload envelope. Throws on malformed JSON or fields,
 * with descriptive errors that name the bad field.
 *
 * `bk` may be omitted or `null` to indicate no BeeKEM welcome payload
 * was attached (e.g. a Welcome to a peer that won't need to process
 * PathUpdates locally).
 */
export function decodeWelcomeSealedPayload(
  bytes: Uint8Array,
): WelcomeSealedPayload {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (err) {
    throw new Error(
      `welcome-sealed-payload: plaintext is not valid UTF-8: ${
        err instanceof Error ? err.message : String(err)
      }`,
      { cause: err },
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(
      `welcome-sealed-payload: plaintext is not valid JSON: ${
        err instanceof Error ? err.message : String(err)
      }`,
      { cause: err },
    );
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(
      `welcome-sealed-payload: expected a plain object envelope, got ${describe(
        parsed,
      )}`,
    );
  }
  const raw = parsed as Record<string, unknown>;
  if (typeof raw.k !== 'string') {
    throw new Error(
      `welcome-sealed-payload: 'k' (keychain bytes) must be a base64 string (got ${describe(
        raw.k,
      )})`,
    );
  }

  let keychainChanges: Uint8Array;
  try {
    keychainChanges = Base64.toUint8Array(raw.k);
  } catch (err) {
    throw new Error(
      `welcome-sealed-payload: invalid base64 for field 'k': ${
        err instanceof Error ? err.message : String(err)
      }`,
      { cause: err },
    );
  }

  let beekemWelcome: BeeKEMWelcome | null = null;
  if (raw.bk !== undefined && raw.bk !== null) {
    try {
      beekemWelcome = deserializeBeeKEMWelcomeFromWire(raw.bk);
    } catch (err) {
      // `deserializeBeeKEMWelcomeFromWire` throws its own field-level
      // errors but they don't mention the envelope-level field name --
      // surface that here so the malformed field is identifiable from
      // the envelope's perspective ("bk"), matching the module
      // docstring's "name the bad field" contract.
      throw new Error(
        `welcome-sealed-payload: invalid 'bk' (BeeKEM welcome): ${
          err instanceof Error ? err.message : String(err)
        }`,
        { cause: err },
      );
    }
  }

  return { keychainChanges, beekemWelcome };
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `array(length=${value.length})`;
  return typeof value;
}
