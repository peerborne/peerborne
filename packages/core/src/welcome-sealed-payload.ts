/**
 * Sealed-payload envelope for BeeKEM Welcomes.
 *
 * The envelope carries provider-specific keychain bytes alongside an optional
 * legacy BeeKEM Welcome. V2 uses a distinct strict envelope with a required,
 * generation-bearing Welcome.
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
 * On the legacy V1 protocol, `bk` remains optional so an older or key-only
 * payload still parses. The V2 envelope is a separate compatibility boundary:
 * it requires exactly `{ k, bk }` and `bk` must be a non-null, generation- and
 * leaf-count-bearing `BeeKEMWelcomeV2`. Callers choose the decoder from the
 * negotiated protocol and own all state-transition checks.
 */
import { Base64 } from 'js-base64';
import { BeeKEMWelcome, BeeKEMWelcomeV2 } from './beekem/types.js';
import {
  SerializedBeeKEMWelcome,
  SerializedBeeKEMWelcomeV2,
  deserializeBeeKEMWelcomeFromWire,
  deserializeBeeKEMWelcomeV2FromWire,
  serializeBeeKEMWelcomeForWire,
  serializeBeeKEMWelcomeV2ForWire,
} from './beekem-welcome-wire.js';
import {
  assertSharedProtocolRequestSize,
  copyUnsharedUint8Array,
} from './utils.js';

const MAX_V2_KEYCHAIN_CHANGES_BYTES = 10 * 1024 * 1024;
const V2_ENVELOPE_FIXED_JSON_BYTES = '{"k":"","bk":'.length + '}'.length;

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

export interface WelcomeSealedPayloadV2 extends WelcomeSealedPayload {
  beekemWelcome: BeeKEMWelcomeV2;
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

export function encodeWelcomeSealedPayloadV2(
  payload: WelcomeSealedPayloadV2,
): Uint8Array {
  const raw = snapshotV2Payload(payload);
  let keychainChanges: Uint8Array;
  try {
    keychainChanges = copyUnsharedUint8Array(
      raw.keychainChanges,
      0,
      MAX_V2_KEYCHAIN_CHANGES_BYTES,
      'welcome-sealed-payload v2 keychainChanges',
    );
  } catch {
    throw new Error(
      `welcome-sealed-payload v2: 'keychainChanges' must be an unshared Uint8Array no larger than ${MAX_V2_KEYCHAIN_CHANGES_BYTES} bytes`,
    );
  }
  const beekemWelcome = serializeBeeKEMWelcomeV2ForWire(
    raw.beekemWelcome as BeeKEMWelcomeV2,
  );
  const beekemWelcomeJson = JSON.stringify(beekemWelcome);
  const projectedEnvelopeBytes =
    V2_ENVELOPE_FIXED_JSON_BYTES +
    Math.ceil(keychainChanges.byteLength / 3) * 4 +
    beekemWelcomeJson.length;
  // The v2 shape contains only ASCII JSON. Check the exact final plaintext
  // length before allocating the potentially large keychain Base64 string.
  assertSharedProtocolRequestSize(
    projectedEnvelopeBytes,
    'BeeKEM Welcome v2 sealed payload',
  );
  const envelope: { k: string; bk: SerializedBeeKEMWelcomeV2 } = {
    k: Base64.fromUint8Array(keychainChanges),
    bk: beekemWelcome,
  };
  const encoded = new TextEncoder().encode(JSON.stringify(envelope));
  assertSharedProtocolRequestSize(
    encoded.byteLength,
    'BeeKEM Welcome v2 sealed payload',
  );
  return encoded;
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
  } catch {
    throw new Error('welcome-sealed-payload: plaintext is not valid UTF-8');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('welcome-sealed-payload: plaintext is not valid JSON');
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
  } catch {
    throw new Error("welcome-sealed-payload: invalid base64 for field 'k'");
  }

  let beekemWelcome: BeeKEMWelcome | null = null;
  if (raw.bk !== undefined && raw.bk !== null) {
    try {
      beekemWelcome = deserializeBeeKEMWelcomeFromWire(raw.bk);
    } catch {
      // `deserializeBeeKEMWelcomeFromWire` throws its own field-level
      // errors but they don't mention the envelope-level field name --
      // surface that here so the malformed field is identifiable from
      // the envelope's perspective ("bk"), matching the module
      // docstring's "name the bad field" contract.
      throw new Error(
        "welcome-sealed-payload: invalid 'bk' (BeeKEM welcome)",
      );
    }
  }

  return { keychainChanges, beekemWelcome };
}

export function decodeWelcomeSealedPayloadV2(
  bytes: Uint8Array,
): WelcomeSealedPayloadV2 {
  const raw = parseV2Envelope(bytes);
  const keys = Object.keys(raw);
  if (
    keys.length !== 2 ||
    !Object.prototype.hasOwnProperty.call(raw, 'k') ||
    !Object.prototype.hasOwnProperty.call(raw, 'bk')
  ) {
    throw new Error(
      keys.some((key) => key !== 'k' && key !== 'bk')
        ? 'welcome-sealed-payload v2: unexpected field'
        : "welcome-sealed-payload v2: exact fields 'k' and 'bk' are required",
    );
  }
  if (typeof raw.k !== 'string') {
    throw new Error(
      "welcome-sealed-payload v2: 'k' must be a base64 string",
    );
  }
  if (
    raw.k.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      raw.k,
    )
  ) {
    throw new Error(
      "welcome-sealed-payload v2: 'k' must use canonical padded base64",
    );
  }
  let keychainChanges: Uint8Array;
  try {
    keychainChanges = Base64.toUint8Array(raw.k);
  } catch {
    throw new Error(
      "welcome-sealed-payload v2: invalid base64 for field 'k'",
    );
  }
  if (Base64.fromUint8Array(keychainChanges) !== raw.k) {
    throw new Error(
      "welcome-sealed-payload v2: 'k' must use canonical padded base64",
    );
  }
  if (raw.bk === null || raw.bk === undefined) {
    throw new Error(
      "welcome-sealed-payload v2: required non-null field 'bk' is missing",
    );
  }
  let beekemWelcome: BeeKEMWelcomeV2;
  try {
    beekemWelcome = deserializeBeeKEMWelcomeV2FromWire(raw.bk);
  } catch {
    throw new Error(
      "welcome-sealed-payload v2: invalid 'bk' (BeeKEM Welcome v2)",
    );
  }
  return { keychainChanges, beekemWelcome };
}

function parseV2Envelope(bytes: Uint8Array): Record<string, unknown> {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(
      'welcome-sealed-payload v2: plaintext is not valid UTF-8',
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      'welcome-sealed-payload v2: plaintext is not valid JSON',
    );
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed) ||
    (Object.getPrototypeOf(parsed) !== Object.prototype &&
      Object.getPrototypeOf(parsed) !== null)
  ) {
    throw new Error(
      `welcome-sealed-payload v2: expected a plain object envelope, got ${describe(parsed)}`,
    );
  }
  return parsed as Record<string, unknown>;
}

function snapshotV2Payload(value: unknown): Record<string, unknown> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value)
  ) {
    throw new Error(
      'welcome-sealed-payload v2: payload must be a plain object',
    );
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(
      'welcome-sealed-payload v2: payload must be a plain object',
    );
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 2 ||
    !keys.includes('keychainChanges') ||
    !keys.includes('beekemWelcome') ||
    keys.some((key) => typeof key !== 'string')
  ) {
    throw new Error(
      "welcome-sealed-payload v2: exact fields 'keychainChanges' and 'beekemWelcome' are required",
    );
  }
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of ['keychainChanges', 'beekemWelcome']) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
      descriptor.enumerable !== true
    ) {
      throw new Error(
        `welcome-sealed-payload v2: field '${key}' must be an own enumerable data property`,
      );
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `array(length=${value.length})`;
  return typeof value;
}
