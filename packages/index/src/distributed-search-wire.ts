import { QueryAst } from './types.js';
import { DistributedSearchAuthorizer, DistributedSearchSigner, validateApplicationId } from './distributed-auth.js';
import {
  assertExactKeys,
  canonicalBytes,
  decodeBase64Url,
  encodeBase64Url,
  encodeJson,
  isRecord,
  parseBoundedJson,
  validateBoundedText,
} from './distributed-codec.js';
import { VerifiedDistributedIndexManifest } from './distributed-manifest.js';

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_REQUEST_LIFETIME_MS = 30_000;

export type DistributedSearchRequestPayload =
  | { mode: 'query'; query: QueryAst }
  | { mode: 'blind-equality'; blindTerms: string[]; first: number };

export interface DistributedSearchRequestV1 {
  version: 1;
  manifestHash: string;
  collectionId: string;
  indexName: string;
  schemaHash: string;
  generation: string;
  keyEpoch: string;
  sourcePeerId: string;
  recipientPeerId: string;
  requestId: string;
  issuedAt: number;
  deadline: number;
  candidateLimit: number;
  payload: DistributedSearchRequestPayload;
}

export interface SignedDistributedSearchRequestV1 {
  request: DistributedSearchRequestV1;
  signerApplicationId: string;
  signature: string;
}

export interface VerifiedDistributedSearchRequest {
  request: DistributedSearchRequestV1;
  signerApplicationId: string;
  requestHash: string;
}

export interface DistributedSearchCandidateV1 {
  documentPath: string;
  revision?: string;
}

export interface DistributedSearchResponseV1 {
  version: 1;
  requestHash: string;
  requestId: string;
  sourcePeerId: string;
  recipientPeerId: string;
  issuedAt: number;
  candidates: DistributedSearchCandidateV1[];
  exhausted: boolean;
  continuation?: string;
}

export interface SignedDistributedSearchResponseV1 {
  response: DistributedSearchResponseV1;
  signerApplicationId: string;
  signature: string;
}

export interface VerifiedDistributedSearchResponse {
  response: DistributedSearchResponseV1;
  signerApplicationId: string;
}

export type SearchWireRejectReason =
  | 'invalid'
  | 'expired'
  | 'unauthorized'
  | 'wrong-peer'
  | 'wrong-manifest'
  | 'replay';

export class SearchWireError extends Error {
  constructor(readonly reason: SearchWireRejectReason, message: string) {
    super(message);
    this.name = 'SearchWireError';
  }
}

export function createDistributedSearchRequestId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return encodeBase64Url(bytes);
}

export async function signDistributedSearchRequest(
  requestInput: DistributedSearchRequestV1,
  manifest: VerifiedDistributedIndexManifest,
  signer: DistributedSearchSigner,
  now = Date.now(),
): Promise<SignedDistributedSearchRequestV1> {
  const request = validateRequest(JSON.parse(JSON.stringify(requestInput)), manifest, now);
  validateApplicationId(signer.applicationId);
  return {
    request,
    signerApplicationId: signer.applicationId,
    signature: encodeBase64Url(await signer.sign(requestSigningBytes(signer.applicationId, request))),
  };
}

export async function verifyDistributedSearchRequest(
  input: unknown,
  transportPeerId: string,
  recipientPeerId: string,
  manifest: VerifiedDistributedIndexManifest,
  authorizer: DistributedSearchAuthorizer,
  now = Date.now(),
): Promise<VerifiedDistributedSearchRequest> {
  try {
    const parsed = parseBoundedJson(input, Math.min(MAX_REQUEST_BYTES, manifest.manifest.limits.maxRequestBytes));
    if (!isRecord(parsed)) throw new SearchWireError('invalid', 'request envelope must be an object');
    assertExactKeys(parsed, ['request', 'signerApplicationId', 'signature']);
    validateApplicationId(parsed.signerApplicationId);
    const request = validateRequest(parsed.request, manifest, now);
    if (request.sourcePeerId !== transportPeerId || request.recipientPeerId !== recipientPeerId) {
      throw new SearchWireError('wrong-peer', 'request peer binding is invalid');
    }
    if (!await authorizer.authorize(parsed.signerApplicationId, 'query', request.collectionId)) {
      throw new SearchWireError('unauthorized', 'request signer is not authorized');
    }
    if (!await authorizer.verify(
      parsed.signerApplicationId,
      requestSigningBytes(parsed.signerApplicationId, request),
      decodeBase64Url(parsed.signature, 1024),
    )) throw new SearchWireError('invalid', 'request signature is invalid');
    return {
      request,
      signerApplicationId: parsed.signerApplicationId,
      requestHash: await sha256(canonicalBytes(request)),
    };
  } catch (error) {
    if (error instanceof SearchWireError) throw error;
    throw new SearchWireError('invalid', error instanceof Error ? error.message : 'invalid request');
  }
}

export async function signDistributedSearchResponse(
  responseInput: DistributedSearchResponseV1,
  request: VerifiedDistributedSearchRequest,
  signer: DistributedSearchSigner,
  now = Date.now(),
): Promise<SignedDistributedSearchResponseV1> {
  const response = validateResponse(JSON.parse(JSON.stringify(responseInput)), request, now);
  validateApplicationId(signer.applicationId);
  return {
    response,
    signerApplicationId: signer.applicationId,
    signature: encodeBase64Url(await signer.sign(responseSigningBytes(signer.applicationId, response))),
  };
}

export async function verifyDistributedSearchResponse(
  input: unknown,
  transportPeerId: string,
  request: VerifiedDistributedSearchRequest,
  authorizer: DistributedSearchAuthorizer,
  now = Date.now(),
): Promise<VerifiedDistributedSearchResponse> {
  try {
    const parsed = parseBoundedJson(input, MAX_RESPONSE_BYTES);
    if (!isRecord(parsed)) throw new SearchWireError('invalid', 'response envelope must be an object');
    assertExactKeys(parsed, ['response', 'signerApplicationId', 'signature']);
    validateApplicationId(parsed.signerApplicationId);
    const response = validateResponse(parsed.response, request, now);
    if (response.sourcePeerId !== transportPeerId) {
      throw new SearchWireError('wrong-peer', 'response source does not match the transport peer');
    }
    if (!await authorizer.authorize(
      parsed.signerApplicationId,
      'advertise',
      request.request.collectionId,
    )) throw new SearchWireError('unauthorized', 'response signer is not authorized');
    if (!await authorizer.verify(
      parsed.signerApplicationId,
      responseSigningBytes(parsed.signerApplicationId, response),
      decodeBase64Url(parsed.signature, 1024),
    )) throw new SearchWireError('invalid', 'response signature is invalid');
    return { response, signerApplicationId: parsed.signerApplicationId };
  } catch (error) {
    if (error instanceof SearchWireError) throw error;
    throw new SearchWireError('invalid', error instanceof Error ? error.message : 'invalid response');
  }
}

export function encodeDistributedSearchRequest(value: SignedDistributedSearchRequestV1): Uint8Array {
  const encoded = encodeJson(value);
  if (encoded.byteLength > MAX_REQUEST_BYTES) throw new SearchWireError('invalid', 'request is too large');
  return encoded;
}

export function encodeDistributedSearchResponse(value: SignedDistributedSearchResponseV1): Uint8Array {
  const encoded = encodeJson(value);
  if (encoded.byteLength > MAX_RESPONSE_BYTES) throw new SearchWireError('invalid', 'response is too large');
  return encoded;
}

/** Bounded replay cache. Expired requests are rejected before pruning. */
export class DistributedSearchRequestReplayGuard {
  private readonly _seen = new Map<string, number>();

  constructor(private readonly _maxEntries = 4096) {
    if (!Number.isSafeInteger(_maxEntries) || _maxEntries < 1 || _maxEntries > 1_000_000) {
      throw new RangeError('max replay entries must be an integer from 1-1000000');
    }
  }

  accept(request: VerifiedDistributedSearchRequest, now = Date.now()): boolean {
    if (request.request.deadline <= now) return false;
    for (const [key, deadline] of this._seen) {
      if (deadline <= now) this._seen.delete(key);
    }
    const key = `${request.signerApplicationId}\u0000${request.request.requestId}`;
    if (this._seen.has(key) || this._seen.size >= this._maxEntries) return false;
    this._seen.set(key, request.request.deadline);
    return true;
  }
}

function validateRequest(
  input: unknown,
  manifest: VerifiedDistributedIndexManifest,
  now: number,
): DistributedSearchRequestV1 {
  if (!isRecord(input)) throw new SearchWireError('invalid', 'request must be an object');
  assertExactKeys(input, [
    'version', 'manifestHash', 'collectionId', 'indexName', 'schemaHash', 'generation',
    'keyEpoch', 'sourcePeerId', 'recipientPeerId', 'requestId', 'issuedAt', 'deadline',
    'candidateLimit', 'payload',
  ]);
  if (input.version !== 1) throw new SearchWireError('invalid', 'request version must be 1');
  for (const [label, value, max] of [
    ['collectionId', input.collectionId, 512], ['indexName', input.indexName, 128],
    ['generation', input.generation, 128], ['keyEpoch', input.keyEpoch, 128],
    ['sourcePeerId', input.sourcePeerId, 512], ['recipientPeerId', input.recipientPeerId, 512],
    ['requestId', input.requestId, 128],
  ] as const) validateBoundedText(value, label, max);
  if (!sameRequestManifest(input, manifest)) {
    throw new SearchWireError('wrong-manifest', 'request does not match the manifest');
  }
  if (manifest.manifest.expiresAt <= now || input.deadline > manifest.manifest.expiresAt) {
    throw new SearchWireError('expired', 'request exceeds the manifest validity window');
  }
  if (!Number.isSafeInteger(input.issuedAt) || !Number.isSafeInteger(input.deadline) ||
      input.issuedAt > now + 30_000 || input.deadline <= now || input.deadline <= input.issuedAt ||
      input.deadline - input.issuedAt > MAX_REQUEST_LIFETIME_MS) {
    throw new SearchWireError('expired', 'request deadline is invalid or expired');
  }
  if (!Number.isSafeInteger(input.candidateLimit) || input.candidateLimit < 1 ||
      input.candidateLimit > manifest.manifest.limits.maxCandidates) {
    throw new SearchWireError('invalid', 'candidateLimit is invalid');
  }
  validatePayload(input.payload);
  if (input.payload.mode === 'query' && input.payload.query.indexName !== input.indexName) {
    throw new SearchWireError('wrong-manifest', 'query index does not match the request manifest');
  }
  if (input.payload.mode === 'query' && input.payload.query.first !== undefined &&
      input.payload.query.first > input.candidateLimit) {
    throw new SearchWireError('invalid', 'query first exceeds the candidate limit');
  }
  if (input.payload.mode === 'blind-equality' && input.payload.first > input.candidateLimit) {
    throw new SearchWireError('invalid', 'blind first exceeds the candidate limit');
  }
  return structuredClone(input) as DistributedSearchRequestV1;
}

function validatePayload(input: unknown): void {
  if (!isRecord(input)) throw new TypeError('request payload must be an object');
  if (input.mode === 'query') {
    assertExactKeys(input, ['mode', 'query']);
    validateWireQuery(input.query);
    return;
  }
  if (input.mode === 'blind-equality') {
    assertExactKeys(input, ['mode', 'blindTerms', 'first']);
    if (!Array.isArray(input.blindTerms) || input.blindTerms.length === 0 || input.blindTerms.length > 256 ||
        input.blindTerms.some((term) => typeof term !== 'string' || !/^[A-Za-z0-9_-]{16,512}$/.test(term))) {
      throw new TypeError('blind terms are invalid');
    }
    if (!Number.isSafeInteger(input.first) || input.first < 1 || input.first > 10_000) {
      throw new TypeError('blind first is invalid');
    }
    return;
  }
  throw new TypeError('unknown request payload mode');
}

function validateWireQuery(input: unknown): void {
  if (!isRecord(input) || input.version !== 2) throw new TypeError('wire query version must be 2');
  assertExactKeys(input, ['version'], [
    'indexName', 'collectionPrefix', 'where', 'orderBy', 'first',
    'count', 'allowScan', 'consistency',
  ]);
  if (input.indexName !== undefined) validateBoundedText(input.indexName, 'query indexName', 128);
  if (input.collectionPrefix !== undefined) {
    validateBoundedText(input.collectionPrefix, 'query collectionPrefix', 4096);
  }
  if (input.first !== undefined &&
      (!Number.isSafeInteger(input.first) || input.first < 0 || input.first > 10_000)) {
    throw new TypeError('wire query first is invalid');
  }
  if (input.where !== undefined) validateWireExpression(input.where, 1, { count: 0 });
  if (input.orderBy !== undefined) {
    if (!Array.isArray(input.orderBy) || input.orderBy.length > 8) {
      throw new TypeError('wire query orderBy is invalid');
    }
    for (const clause of input.orderBy) {
      if (!isRecord(clause)) throw new TypeError('wire query order clause is invalid');
      assertExactKeys(clause, ['path', 'direction']);
      validateWirePath(clause.path);
      if (clause.direction !== 'asc' && clause.direction !== 'desc') {
        throw new TypeError('wire query order direction is invalid');
      }
    }
  }
  if (input.count !== undefined && input.count !== 'exact' && input.count !== 'none') {
    throw new TypeError('wire query count is invalid');
  }
  if (input.allowScan !== undefined && typeof input.allowScan !== 'boolean') {
    throw new TypeError('wire query allowScan is invalid');
  }
  if (input.allowScan === true) throw new TypeError('distributed queries cannot opt in to full scans');
  if (input.count === 'exact') throw new TypeError('distributed candidate queries cannot request exact counts');
  if (input.consistency !== undefined && input.consistency !== 'eventual') {
    throw new TypeError('wire query consistency is invalid');
  }
}

function validateWireExpression(input: unknown, depth: number, state: { count: number }): void {
  if (!isRecord(input) || depth > 16 || ++state.count > 128) throw new TypeError('wire query is too complex');
  if (input.kind === 'field') {
    assertExactKeys(input, ['kind', 'path', 'operator', 'value']);
    validateWirePath(input.path);
    if (typeof input.operator !== 'string' ||
        !['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'prefix', 'in', 'contains'].includes(
          input.operator,
        )) throw new TypeError('wire query operator is invalid');
    if (input.operator === 'in') {
      if (!Array.isArray(input.value) || input.value.length === 0 || input.value.length > 256) {
        throw new TypeError('wire query in value is invalid');
      }
      for (const value of input.value) validateWireScalar(value);
    } else {
      validateWireScalar(input.value);
    }
    if ((input.operator === 'prefix' || input.operator === 'contains') &&
        typeof input.value !== 'string') throw new TypeError('wire string operator value is invalid');
    return;
  }
  if (input.kind !== 'and' && input.kind !== 'or') throw new TypeError('unknown wire expression');
  assertExactKeys(input, ['kind', 'expressions']);
  if (!Array.isArray(input.expressions) || input.expressions.length === 0) {
    throw new TypeError('wire expression cannot be empty');
  }
  for (const child of input.expressions) validateWireExpression(child, depth + 1, state);
}

function validateResponse(
  input: unknown,
  request: VerifiedDistributedSearchRequest,
  now: number,
): DistributedSearchResponseV1 {
  if (request.request.deadline <= now) {
    throw new SearchWireError('expired', 'response arrived after the request deadline');
  }
  if (!isRecord(input)) throw new SearchWireError('invalid', 'response must be an object');
  assertExactKeys(input, [
    'version', 'requestHash', 'requestId', 'sourcePeerId', 'recipientPeerId', 'issuedAt',
    'candidates', 'exhausted',
  ], ['continuation']);
  if (input.version !== 1 || input.requestHash !== request.requestHash ||
      input.requestId !== request.request.requestId ||
      input.sourcePeerId !== request.request.recipientPeerId ||
      input.recipientPeerId !== request.request.sourcePeerId) {
    throw new SearchWireError('wrong-peer', 'response request binding is invalid');
  }
  if (!Number.isSafeInteger(input.issuedAt) || input.issuedAt > now + 30_000 ||
      input.issuedAt < request.request.issuedAt || input.issuedAt > request.request.deadline) {
    throw new SearchWireError('invalid', 'response timestamp is invalid');
  }
  if (!Array.isArray(input.candidates) || input.candidates.length > request.request.candidateLimit) {
    throw new SearchWireError('invalid', 'response candidate count is invalid');
  }
  for (const candidate of input.candidates) {
    if (!isRecord(candidate)) throw new TypeError('candidate must be an object');
    assertExactKeys(candidate, ['documentPath'], ['revision']);
    validateBoundedText(candidate.documentPath, 'candidate documentPath', 4096);
    if (candidate.revision !== undefined) validateBoundedText(candidate.revision, 'candidate revision', 512);
  }
  if (typeof input.exhausted !== 'boolean' ||
      (input.exhausted && input.continuation !== undefined) ||
      (!input.exhausted && input.continuation === undefined)) {
    throw new TypeError('response continuation semantics are invalid');
  }
  if (input.continuation !== undefined) validateBoundedText(input.continuation, 'continuation', 4096);
  return structuredClone(input) as DistributedSearchResponseV1;
}

function validateWirePath(value: unknown): asserts value is string {
  validateBoundedText(value, 'query path', 512);
  if (value.startsWith('.') || value.endsWith('.') || value.includes('..') ||
      value.startsWith('__peerborne_internal_') ||
      value.split('.').some((segment) =>
        segment === '__proto__' || segment === 'prototype' || segment === 'constructor')) {
    throw new TypeError('wire query path is invalid');
  }
}

function validateWireScalar(value: unknown): void {
  if (typeof value === 'string') {
    if (value.length > 16_384 || /[\u0000-\u001f]/.test(value)) {
      throw new TypeError('wire query string value is invalid');
    }
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('wire query number value is invalid');
    return;
  }
  if (typeof value !== 'boolean') throw new TypeError('wire query value must be a scalar');
}

function sameRequestManifest(
  request: Record<string, unknown>,
  manifest: VerifiedDistributedIndexManifest,
): boolean {
  const value = manifest.manifest;
  return request.manifestHash === manifest.manifestHash && request.collectionId === value.collectionId &&
    request.indexName === value.indexName && request.schemaHash === value.schemaHash &&
    request.generation === value.generation && request.keyEpoch === value.keyEpoch;
}

function requestSigningBytes(applicationId: string, request: DistributedSearchRequestV1): Uint8Array {
  return canonicalBytes({ domain: 'peerborne-search-request-v1', applicationId, request });
}

function responseSigningBytes(applicationId: string, response: DistributedSearchResponseV1): Uint8Array {
  return canonicalBytes({ domain: 'peerborne-search-response-v1', applicationId, response });
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
