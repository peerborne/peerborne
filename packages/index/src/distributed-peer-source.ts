import { searchQueryV1 } from '@peerborne/core';
import {
  CandidateSearchRequest,
  CandidateSearchResult,
  QueryCandidateSource,
} from './candidate-source.js';
import { DistributedSearchAuthorizer, DistributedSearchSigner } from './distributed-auth.js';
import { canonicalBytes } from './distributed-codec.js';
import { VerifiedDistributedIndexManifest } from './distributed-manifest.js';
import {
  createDistributedSearchRequestId,
  DistributedSearchRequestPayload,
  encodeDistributedSearchRequest,
  signDistributedSearchRequest,
  verifyDistributedSearchResponse,
} from './distributed-search-wire.js';
import { QueryAst } from './types.js';

export interface DistributedSearchTransport {
  request(
    peerId: string,
    protocol: string,
    payload: Uint8Array,
    options: { deadline: number },
  ): Promise<Uint8Array>;
}

export interface DistributedSearchRequestEncoder {
  encode(query: QueryAst, candidateLimit: number): Promise<DistributedSearchRequestPayload>;
}

/** Explicitly reveals the validated query AST to the remote peer. */
export class PlaintextDistributedQueryEncoder implements DistributedSearchRequestEncoder {
  async encode(query: QueryAst, candidateLimit: number): Promise<DistributedSearchRequestPayload> {
    return {
      mode: 'query',
      query: {
        ...structuredClone(query),
        after: undefined,
        select: undefined,
        count: 'none',
        allowScan: false,
        consistency: 'eventual',
        first: candidateLimit,
      },
    };
  }
}

/** Sends only caller-produced blind equality tokens, never plaintext predicates. */
export class BlindEqualityRequestEncoder implements DistributedSearchRequestEncoder {
  constructor(private readonly _encodeTerms: (query: QueryAst) => Promise<string[]>) {}

  async encode(query: QueryAst, candidateLimit: number): Promise<DistributedSearchRequestPayload> {
    return {
      mode: 'blind-equality',
      blindTerms: await this._encodeTerms(query),
      first: Math.min(query.first ?? candidateLimit, candidateLimit),
    };
  }
}

export interface DistributedPeerCandidateSourceOptions {
  localPeerId: string;
  remotePeerId: string;
  manifest: VerifiedDistributedIndexManifest;
  signer: DistributedSearchSigner;
  authorizer: DistributedSearchAuthorizer;
  transport: DistributedSearchTransport;
  encoder: DistributedSearchRequestEncoder;
}

/** Candidate-source adapter for the signed search-query/1.0.0 protocol. */
export class DistributedPeerCandidateSource implements QueryCandidateSource {
  readonly id: string;
  readonly binding: { indexName: string; schemaHash: string; generation: string };

  constructor(private readonly _options: DistributedPeerCandidateSourceOptions) {
    this.id = `peer:${_options.remotePeerId}`;
    this.binding = {
      indexName: _options.manifest.manifest.indexName,
      schemaHash: _options.manifest.manifest.schemaHash,
      generation: _options.manifest.manifest.generation,
    };
  }

  async search(request: CandidateSearchRequest): Promise<CandidateSearchResult> {
    const { manifest, localPeerId, remotePeerId } = this._options;
    const issuedAt = Date.now();
    const deadline = Math.min(request.deadline, issuedAt + 30_000);
    const candidateLimit = Math.min(
      request.candidateLimit,
      manifest.manifest.limits.maxCandidates,
    );
    const encodedPayload = await this._options.encoder.encode(request.query, candidateLimit);
    const payload: DistributedSearchRequestPayload = encodedPayload.mode === 'query'
      ? {
        mode: 'query',
        query: {
          ...structuredClone(encodedPayload.query),
          indexName: manifest.manifest.indexName,
        },
      }
      : encodedPayload;
    const signed = await signDistributedSearchRequest({
      version: 1,
      manifestHash: manifest.manifestHash,
      collectionId: manifest.manifest.collectionId,
      indexName: manifest.manifest.indexName,
      schemaHash: manifest.manifest.schemaHash,
      generation: manifest.manifest.generation,
      keyEpoch: manifest.manifest.keyEpoch,
      sourcePeerId: localPeerId,
      recipientPeerId: remotePeerId,
      requestId: createDistributedSearchRequestId(),
      issuedAt,
      deadline,
      candidateLimit,
      payload,
    }, manifest, this._options.signer, issuedAt);
    const requestHash = await sha256Canonical(signed.request);
    const requestBytes = encodeDistributedSearchRequest(signed);
    if (requestBytes.byteLength > manifest.manifest.limits.maxRequestBytes) {
      throw new RangeError('distributed search request exceeds the manifest byte limit');
    }
    const responseBytes = await this._options.transport.request(
      remotePeerId,
      searchQueryV1,
      requestBytes,
      { deadline },
    );
    const verified = await verifyDistributedSearchResponse(
      responseBytes,
      remotePeerId,
      {
        request: signed.request,
        signerApplicationId: signed.signerApplicationId,
        requestHash,
      },
      this._options.authorizer,
    );
    return {
      candidates: verified.response.candidates.map((candidate) => ({ ...candidate })),
      exhausted: verified.response.exhausted,
    };
  }
}

async function sha256Canonical(value: unknown): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    canonicalBytes(value).buffer as ArrayBuffer,
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
