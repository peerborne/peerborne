import { DistributedSearchAuthorizer, DistributedSearchSigner, validateApplicationId } from './distributed-auth.js';
import {
  assertExactKeys,
  canonicalBytes,
  decodeBase64Url,
  encodeBase64Url,
  isRecord,
  parseBoundedJson,
  validateBoundedText,
  validateUint64,
} from './distributed-codec.js';

const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_MANIFEST_LIFETIME_MS = 24 * 60 * 60 * 1000;

export interface DistributedIndexManifestV1 {
  version: 1;
  collectionId: string;
  indexName: string;
  schemaHash: string;
  generation: string;
  keyEpoch: string;
  sequence: string;
  issuedAt: number;
  expiresAt: number;
  discovery:
    | { mode: 'direct' }
    | { mode: 'blind-bloom'; bitLength: number; hashCount: number };
  limits: {
    maxCandidates: number;
    maxRequestBytes: number;
    advertisementTtlMs: number;
  };
}

export interface SignedDistributedIndexManifestV1 {
  manifest: DistributedIndexManifestV1;
  signerApplicationId: string;
  signature: string;
}

export interface VerifiedDistributedIndexManifest {
  manifest: DistributedIndexManifestV1;
  signerApplicationId: string;
  manifestHash: string;
}

export type ManifestAcceptResult = 'accepted' | 'stale' | 'capacity';

export class DistributedManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DistributedManifestError';
  }
}

export function validateDistributedIndexManifest(
  input: unknown,
  now = Date.now(),
): DistributedIndexManifestV1 {
  if (!isRecord(input)) throw new DistributedManifestError('manifest must be an object');
  try {
    assertExactKeys(input, [
      'version', 'collectionId', 'indexName', 'schemaHash', 'generation', 'keyEpoch',
      'sequence', 'issuedAt', 'expiresAt', 'discovery', 'limits',
    ]);
    if (input.version !== 1) throw new TypeError('manifest version must be 1');
    validateBoundedText(input.collectionId, 'collectionId', 512);
    validateBoundedText(input.indexName, 'indexName', 128);
    if (typeof input.schemaHash !== 'string' || !/^[0-9a-f]{64}$/.test(input.schemaHash)) {
      throw new TypeError('schemaHash must be a lowercase SHA-256 digest');
    }
    validateBoundedText(input.generation, 'generation', 128);
    validateBoundedText(input.keyEpoch, 'keyEpoch', 128);
    validateUint64(input.sequence, 'sequence');
    validateTimestamp(input.issuedAt, 'issuedAt');
    validateTimestamp(input.expiresAt, 'expiresAt');
    if (input.issuedAt > now + 30_000 || input.expiresAt <= input.issuedAt ||
        input.expiresAt - input.issuedAt > MAX_MANIFEST_LIFETIME_MS ||
        input.expiresAt <= now) {
      throw new TypeError('manifest validity window is invalid or expired');
    }
    if (!isRecord(input.discovery)) throw new TypeError('discovery must be an object');
    if (input.discovery.mode === 'direct') {
      assertExactKeys(input.discovery, ['mode']);
    } else if (input.discovery.mode === 'blind-bloom') {
      assertExactKeys(input.discovery, ['mode', 'bitLength', 'hashCount']);
      validateInteger(input.discovery.bitLength, 1024, 8 * 1024 * 1024, 'bitLength');
      validateInteger(input.discovery.hashCount, 1, 32, 'hashCount');
    } else {
      throw new TypeError('unknown discovery mode');
    }
    if (!isRecord(input.limits)) throw new TypeError('limits must be an object');
    assertExactKeys(input.limits, ['maxCandidates', 'maxRequestBytes', 'advertisementTtlMs']);
    validateInteger(input.limits.maxCandidates, 1, 4096, 'maxCandidates');
    validateInteger(input.limits.maxRequestBytes, 1024, 2 * 1024 * 1024, 'maxRequestBytes');
    validateInteger(input.limits.advertisementTtlMs, 1000, MAX_MANIFEST_LIFETIME_MS, 'advertisementTtlMs');
    return structuredClone(input) as DistributedIndexManifestV1;
  } catch (error) {
    if (error instanceof DistributedManifestError) throw error;
    throw new DistributedManifestError(error instanceof Error ? error.message : 'invalid manifest');
  }
}

export async function signDistributedIndexManifest(
  manifestInput: DistributedIndexManifestV1,
  signer: DistributedSearchSigner,
  now = Date.now(),
): Promise<SignedDistributedIndexManifestV1> {
  const manifest = validateDistributedIndexManifest(manifestInput, now);
  validateApplicationId(signer.applicationId);
  const signature = await signer.sign(manifestSigningBytes(signer.applicationId, manifest));
  return { manifest, signerApplicationId: signer.applicationId, signature: encodeBase64Url(signature) };
}

export async function verifyDistributedIndexManifest(
  input: unknown,
  authorizer: DistributedSearchAuthorizer,
  now = Date.now(),
): Promise<VerifiedDistributedIndexManifest> {
  let parsed: unknown;
  try {
    parsed = parseBoundedJson(input, MAX_MANIFEST_BYTES);
    if (!isRecord(parsed)) throw new TypeError('signed manifest must be an object');
    assertExactKeys(parsed, ['manifest', 'signerApplicationId', 'signature']);
    validateApplicationId(parsed.signerApplicationId);
    const manifest = validateDistributedIndexManifest(parsed.manifest, now);
    const signature = decodeBase64Url(parsed.signature, 1024);
    if (!await authorizer.authorize(parsed.signerApplicationId, 'manage', manifest.collectionId)) {
      throw new TypeError('manifest signer is not authorized');
    }
    if (!await authorizer.verify(
      parsed.signerApplicationId,
      manifestSigningBytes(parsed.signerApplicationId, manifest),
      signature,
    )) {
      throw new TypeError('manifest signature is invalid');
    }
    return {
      manifest,
      signerApplicationId: parsed.signerApplicationId,
      manifestHash: await sha256(canonicalBytes(manifest)),
    };
  } catch (error) {
    if (error instanceof DistributedManifestError) throw error;
    throw new DistributedManifestError(error instanceof Error ? error.message : 'invalid signed manifest');
  }
}

/** Monotonic manifest registry. Expired entries remain rollback tombstones. */
export class DistributedManifestRegistry {
  private readonly _latest = new Map<string, VerifiedDistributedIndexManifest>();
  private readonly _lastSequences = new Map<string, bigint>();

  constructor(private readonly _maxEntries = 256) {
    if (!Number.isSafeInteger(_maxEntries) || _maxEntries < 1 || _maxEntries > 100_000) {
      throw new RangeError('max manifest entries must be an integer from 1-100000');
    }
  }

  async accept(
    input: unknown,
    authorizer: DistributedSearchAuthorizer,
    now = Date.now(),
  ): Promise<ManifestAcceptResult> {
    const verified = await verifyDistributedIndexManifest(input, authorizer, now);
    const key = manifestKey(verified.manifest.collectionId, verified.manifest.indexName);
    const sequence = BigInt(verified.manifest.sequence);
    if (sequence <= (this._lastSequences.get(key) ?? -1n)) return 'stale';
    if (!this._lastSequences.has(key) && this._lastSequences.size >= this._maxEntries) {
      return 'capacity';
    }
    this._lastSequences.set(key, sequence);
    this._latest.set(key, verified);
    return 'accepted';
  }

  get(collectionId: string, indexName: string, now = Date.now()): VerifiedDistributedIndexManifest | undefined {
    const value = this._latest.get(manifestKey(collectionId, indexName));
    return value && value.manifest.expiresAt > now ? structuredClone(value) : undefined;
  }
}

function manifestSigningBytes(
  signerApplicationId: string,
  manifest: DistributedIndexManifestV1,
): Uint8Array {
  return canonicalBytes({ domain: 'peerborne-index-manifest-v1', signerApplicationId, manifest });
}

function manifestKey(collectionId: string, indexName: string): string {
  return `${collectionId}\u0000${indexName}`;
}

function validateTimestamp(value: unknown, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a timestamp`);
  }
}

function validateInteger(value: unknown, min: number, max: number, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${label} must be an integer from ${min}-${max}`);
  }
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
