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
import { VerifiedDistributedIndexManifest } from './distributed-manifest.js';

const MAX_ADVERTISEMENT_BYTES = 2 * 1024 * 1024;

export interface RoutingAdvertisementV1 {
  version: 1;
  manifestHash: string;
  collectionId: string;
  indexName: string;
  schemaHash: string;
  generation: string;
  keyEpoch: string;
  sourcePeerId: string;
  sequence: string;
  issuedAt: number;
  expiresAt: number;
  bitLength: number;
  hashCount: number;
  filter: string;
}

export interface SignedRoutingAdvertisementV1 {
  advertisement: RoutingAdvertisementV1;
  signerApplicationId: string;
  signature: string;
}

export interface RoutingPeerState {
  advertisement: RoutingAdvertisementV1;
  signerApplicationId: string;
  fillRatio: number;
}

export interface RoutingAdvertisementRegistryConfig {
  maxPeers?: number;
  maxFilterBytes?: number;
  maxFillRatio?: number;
  minUpdateIntervalMs?: number;
}

export type RoutingAdvertisementRejectReason =
  | 'invalid'
  | 'unauthorized'
  | 'wrong-peer'
  | 'wrong-manifest'
  | 'stale'
  | 'rate-limited'
  | 'capacity'
  | 'saturated';

export type RoutingAdvertisementAcceptResult =
  | { accepted: true }
  | { accepted: false; reason: RoutingAdvertisementRejectReason };

export async function signRoutingAdvertisement(
  advertisementInput: RoutingAdvertisementV1,
  manifest: VerifiedDistributedIndexManifest,
  signer: DistributedSearchSigner,
  now = Date.now(),
): Promise<SignedRoutingAdvertisementV1> {
  const advertisement = validateAdvertisement(advertisementInput, manifest, now);
  validateApplicationId(signer.applicationId);
  const signature = await signer.sign(advertisementSigningBytes(signer.applicationId, advertisement));
  return {
    advertisement,
    signerApplicationId: signer.applicationId,
    signature: encodeBase64Url(signature),
  };
}

/** Stores bounded replacement snapshots; it never OR-merges untrusted filters. */
export class RoutingAdvertisementRegistry {
  private readonly _maxPeers: number;
  private readonly _maxFilterBytes: number;
  private readonly _maxFillRatio: number;
  private readonly _minUpdateIntervalMs: number;
  private readonly _states = new Map<string, RoutingPeerState>();
  private readonly _lastSequences = new Map<string, bigint>();
  private readonly _lastIssuedAt = new Map<string, number>();

  constructor(config: RoutingAdvertisementRegistryConfig = {}) {
    this._maxPeers = config.maxPeers ?? 256;
    this._maxFilterBytes = config.maxFilterBytes ?? 128 * 1024;
    this._maxFillRatio = config.maxFillRatio ?? 0.75;
    this._minUpdateIntervalMs = config.minUpdateIntervalMs ?? 1000;
    if (!Number.isSafeInteger(this._maxPeers) || this._maxPeers < 1 || this._maxPeers > 100_000) {
      throw new RangeError('maxPeers must be an integer from 1-100000');
    }
    if (!Number.isSafeInteger(this._maxFilterBytes) ||
        this._maxFilterBytes < 128 || this._maxFilterBytes > MAX_ADVERTISEMENT_BYTES) {
      throw new RangeError(`maxFilterBytes must be an integer from 128-${MAX_ADVERTISEMENT_BYTES}`);
    }
    if (typeof this._maxFillRatio !== 'number' || !Number.isFinite(this._maxFillRatio) ||
        this._maxFillRatio <= 0 || this._maxFillRatio >= 1) {
      throw new RangeError('maxFillRatio must be greater than 0 and less than 1');
    }
    if (!Number.isSafeInteger(this._minUpdateIntervalMs) ||
        this._minUpdateIntervalMs < 0 || this._minUpdateIntervalMs > 24 * 60 * 60 * 1000) {
      throw new RangeError('minUpdateIntervalMs must be an integer from 0-86400000');
    }
  }

  async accept(
    input: unknown,
    transportPeerId: string,
    manifest: VerifiedDistributedIndexManifest,
    authorizer: DistributedSearchAuthorizer,
    now = Date.now(),
  ): Promise<RoutingAdvertisementAcceptResult> {
    let parsed: unknown;
    try {
      this._prune(now);
      parsed = parseBoundedJson(input, MAX_ADVERTISEMENT_BYTES);
      if (!isRecord(parsed)) return { accepted: false, reason: 'invalid' };
      assertExactKeys(parsed, ['advertisement', 'signerApplicationId', 'signature']);
      validateApplicationId(parsed.signerApplicationId);
      const advertisement = validateAdvertisement(parsed.advertisement, manifest, now);
      if (advertisement.sourcePeerId !== transportPeerId) return { accepted: false, reason: 'wrong-peer' };
      if (!sameManifest(advertisement, manifest)) return { accepted: false, reason: 'wrong-manifest' };
      const filter = decodeBase64Url(advertisement.filter, this._maxFilterBytes);
      if (filter.byteLength !== Math.ceil(advertisement.bitLength / 8)) {
        return { accepted: false, reason: 'invalid' };
      }
      if (!await authorizer.authorize(parsed.signerApplicationId, 'advertise', advertisement.collectionId)) {
        return { accepted: false, reason: 'unauthorized' };
      }
      const signature = decodeBase64Url(parsed.signature, 1024);
      if (!await authorizer.verify(
        parsed.signerApplicationId,
        advertisementSigningBytes(parsed.signerApplicationId, advertisement),
        signature,
      )) return { accepted: false, reason: 'invalid' };

      const fillRatio = countBits(filter) / advertisement.bitLength;
      if (fillRatio > this._maxFillRatio) return { accepted: false, reason: 'saturated' };
      const key = stateKey(advertisement.collectionId, advertisement.indexName, transportPeerId);
      const sequence = BigInt(advertisement.sequence);
      if (sequence <= (this._lastSequences.get(key) ?? -1n)) return { accepted: false, reason: 'stale' };
      const previousIssuedAt = this._lastIssuedAt.get(key);
      if (previousIssuedAt !== undefined &&
          advertisement.issuedAt - previousIssuedAt < this._minUpdateIntervalMs) {
        return { accepted: false, reason: 'rate-limited' };
      }
      if (!this._states.has(key) && this._states.size >= this._maxPeers) {
        return { accepted: false, reason: 'capacity' };
      }
      this._makeTombstoneRoom(key);
      this._lastSequences.set(key, sequence);
      this._lastIssuedAt.set(key, advertisement.issuedAt);
      this._states.set(key, {
        advertisement,
        signerApplicationId: parsed.signerApplicationId,
        fillRatio,
      });
      return { accepted: true };
    } catch {
      return { accepted: false, reason: 'invalid' };
    }
  }

  get(
    collectionId: string,
    indexName: string,
    peerId: string,
    now = Date.now(),
  ): RoutingPeerState | undefined {
    const key = stateKey(collectionId, indexName, peerId);
    const state = this._states.get(key);
    if (!state) return undefined;
    if (state.advertisement.expiresAt <= now) {
      this._states.delete(key);
      return undefined;
    }
    return structuredClone(state);
  }

  private _prune(now: number): void {
    for (const [key, state] of this._states) {
      if (state.advertisement.expiresAt <= now) this._states.delete(key);
    }
  }

  private _makeTombstoneRoom(key: string): void {
    if (this._lastSequences.has(key) || this._lastSequences.size < this._maxPeers) return;
    for (const retainedKey of this._lastSequences.keys()) {
      if (!this._states.has(retainedKey)) {
        this._lastSequences.delete(retainedKey);
        this._lastIssuedAt.delete(retainedKey);
        return;
      }
    }
  }
}

function validateAdvertisement(
  input: unknown,
  manifest: VerifiedDistributedIndexManifest,
  now: number,
): RoutingAdvertisementV1 {
  if (!isRecord(input)) throw new TypeError('advertisement must be an object');
  assertExactKeys(input, [
    'version', 'manifestHash', 'collectionId', 'indexName', 'schemaHash', 'generation',
    'keyEpoch', 'sourcePeerId', 'sequence', 'issuedAt', 'expiresAt', 'bitLength',
    'hashCount', 'filter',
  ]);
  if (input.version !== 1) throw new TypeError('advertisement version must be 1');
  for (const [label, value, max] of [
    ['collectionId', input.collectionId, 512],
    ['indexName', input.indexName, 128],
    ['generation', input.generation, 128],
    ['keyEpoch', input.keyEpoch, 128],
    ['sourcePeerId', input.sourcePeerId, 512],
  ] as const) validateBoundedText(value, label, max);
  if (typeof input.manifestHash !== 'string' || !/^[0-9a-f]{64}$/.test(input.manifestHash) ||
      typeof input.schemaHash !== 'string' || !/^[0-9a-f]{64}$/.test(input.schemaHash)) {
    throw new TypeError('advertisement hashes are invalid');
  }
  validateUint64(input.sequence, 'sequence');
  if (!Number.isSafeInteger(input.issuedAt) || !Number.isSafeInteger(input.expiresAt) ||
      input.issuedAt > now + 30_000 || input.expiresAt <= now || input.expiresAt <= input.issuedAt ||
      input.expiresAt > input.issuedAt + manifest.manifest.limits.advertisementTtlMs ||
      input.expiresAt > manifest.manifest.expiresAt) {
    throw new TypeError('advertisement validity window is invalid');
  }
  if (!Number.isSafeInteger(input.bitLength) || input.bitLength < 1024 ||
      !Number.isSafeInteger(input.hashCount) || input.hashCount < 1 || input.hashCount > 32) {
    throw new TypeError('advertisement filter parameters are invalid');
  }
  if (manifest.manifest.discovery.mode !== 'blind-bloom' ||
      input.bitLength !== manifest.manifest.discovery.bitLength ||
      input.hashCount !== manifest.manifest.discovery.hashCount) {
    throw new TypeError('advertisement filter does not match manifest');
  }
  if (typeof input.filter !== 'string') throw new TypeError('filter must be base64url');
  const filter = decodeBase64Url(input.filter, Math.ceil(input.bitLength / 8));
  if (filter.byteLength !== Math.ceil(input.bitLength / 8)) {
    throw new TypeError('filter byte length does not match bitLength');
  }
  return structuredClone(input) as RoutingAdvertisementV1;
}

function sameManifest(
  advertisement: RoutingAdvertisementV1,
  manifest: VerifiedDistributedIndexManifest,
): boolean {
  const value = manifest.manifest;
  return advertisement.manifestHash === manifest.manifestHash &&
    advertisement.collectionId === value.collectionId && advertisement.indexName === value.indexName &&
    advertisement.schemaHash === value.schemaHash && advertisement.generation === value.generation &&
    advertisement.keyEpoch === value.keyEpoch;
}

function advertisementSigningBytes(
  signerApplicationId: string,
  advertisement: RoutingAdvertisementV1,
): Uint8Array {
  return canonicalBytes({ domain: 'peerborne-routing-advertisement-v1', signerApplicationId, advertisement });
}

function stateKey(collectionId: string, indexName: string, peerId: string): string {
  return `${collectionId}\u0000${indexName}\u0000${peerId}`;
}

function countBits(bytes: Uint8Array): number {
  let count = 0;
  for (const byte of bytes) {
    let value = byte;
    while (value) {
      value &= value - 1;
      count++;
    }
  }
  return count;
}
