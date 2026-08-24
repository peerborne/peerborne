import { describe, expect, test } from '@jest/globals';
import { searchQueryV1 } from '@peerborne/core';
import { DistributedSearchAuthorizer, DistributedSearchSigner } from './distributed-auth.js';
import {
  BlindEqualityRequestEncoder,
  DistributedPeerCandidateSource,
  DistributedSearchTransport,
  PlaintextDistributedQueryEncoder,
} from './distributed-peer-source.js';
import {
  DistributedIndexManifestV1,
  signDistributedIndexManifest,
  verifyDistributedIndexManifest,
} from './distributed-manifest.js';
import {
  encodeDistributedSearchResponse,
  signDistributedSearchResponse,
  verifyDistributedSearchRequest,
} from './distributed-search-wire.js';
import { encodeBase64Url } from './distributed-codec.js';

const signer: DistributedSearchSigner = {
  applicationId: 'app:test',
  async sign(payload) {
    return new Uint8Array(await globalThis.crypto.subtle.digest(
      'SHA-256',
      payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength) as ArrayBuffer,
    ));
  },
};

const authorizer: DistributedSearchAuthorizer = {
  async authorize() { return true; },
  async verify(_applicationId, payload, signature) {
    const expected = await signer.sign(payload);
    return expected.length === signature.length && expected.every((byte, index) => byte === signature[index]);
  },
};

describe('DistributedPeerCandidateSource', () => {
  test('uses the core protocol and verifies the bound response', async () => {
    const now = Date.now();
    const manifest = await verifiedManifest(now);
    const transport: DistributedSearchTransport = {
      async request(peerId, protocol, payload) {
        expect(peerId).toBe('peer-server');
        expect(protocol).toBe(searchQueryV1);
        const request = await verifyDistributedSearchRequest(
          payload,
          'peer-client',
          'peer-server',
          manifest,
          authorizer,
        );
        const response = await signDistributedSearchResponse({
          version: 1,
          requestHash: request.requestHash,
          requestId: request.request.requestId,
          sourcePeerId: 'peer-server',
          recipientPeerId: 'peer-client',
          issuedAt: Date.now(),
          candidates: [{ documentPath: '/articles/one', revision: 'r1' }],
          exhausted: true,
        }, request, signer);
        return encodeDistributedSearchResponse(response);
      },
    };
    const source = new DistributedPeerCandidateSource({
      localPeerId: 'peer-client',
      remotePeerId: 'peer-server',
      manifest,
      signer,
      authorizer,
      transport,
      encoder: new PlaintextDistributedQueryEncoder(),
    });
    const result = await source.search({
      query: {
        version: 2,
        indexName: 'articles',
        where: { kind: 'field', path: 'title', operator: 'eq', value: 'hello' },
      },
      candidateLimit: 10,
      deadline: Date.now() + 5000,
    });
    expect(result).toEqual({
      candidates: [{ documentPath: '/articles/one', revision: 'r1' }],
      exhausted: true,
    });
  });

  test('blind encoder keeps plaintext values off the wire', async () => {
    const now = Date.now();
    const manifest = await verifiedManifest(now);
    let wire = '';
    const transport: DistributedSearchTransport = {
      async request(_peerId, _protocol, payload) {
        wire = new TextDecoder().decode(payload);
        const request = await verifyDistributedSearchRequest(
          payload,
          'peer-client',
          'peer-server',
          manifest,
          authorizer,
        );
        return encodeDistributedSearchResponse(await signDistributedSearchResponse({
          version: 1,
          requestHash: request.requestHash,
          requestId: request.request.requestId,
          sourcePeerId: 'peer-server',
          recipientPeerId: 'peer-client',
          issuedAt: Date.now(),
          candidates: [],
          exhausted: true,
        }, request, signer));
      },
    };
    const source = new DistributedPeerCandidateSource({
      localPeerId: 'peer-client',
      remotePeerId: 'peer-server',
      manifest,
      signer,
      authorizer,
      transport,
      encoder: new BlindEqualityRequestEncoder(async () => [
        encodeBase64Url(new Uint8Array(32).fill(9)),
      ]),
    });
    await source.search({
      query: {
        version: 2,
        indexName: 'articles',
        where: { kind: 'field', path: 'title', operator: 'eq', value: 'secret-title' },
      },
      candidateLimit: 10,
      deadline: Date.now() + 5000,
    });
    expect(wire).not.toContain('secret-title');
    expect(wire).toContain('blind-equality');
  });

  test('applies the manifest candidate limit before encoding the payload', async () => {
    const now = Date.now();
    const manifest = await verifiedManifest(now);
    const transport: DistributedSearchTransport = {
      async request(_peerId, _protocol, payload) {
        const request = await verifyDistributedSearchRequest(
          payload,
          'peer-client',
          'peer-server',
          manifest,
          authorizer,
        );
        expect(request.request.candidateLimit).toBe(32);
        expect(request.request.payload).toMatchObject({
          mode: 'query',
          query: { indexName: 'articles', first: 32 },
        });
        return encodeDistributedSearchResponse(await signDistributedSearchResponse({
          version: 1,
          requestHash: request.requestHash,
          requestId: request.request.requestId,
          sourcePeerId: 'peer-server',
          recipientPeerId: 'peer-client',
          issuedAt: Date.now(),
          candidates: [],
          exhausted: true,
        }, request, signer));
      },
    };
    const source = new DistributedPeerCandidateSource({
      localPeerId: 'peer-client',
      remotePeerId: 'peer-server',
      manifest,
      signer,
      authorizer,
      transport,
      encoder: new PlaintextDistributedQueryEncoder(),
    });
    await source.search({
      query: { version: 2, where: undefined },
      candidateLimit: 64,
      deadline: Date.now() + 5000,
    });
  });
});

async function verifiedManifest(now: number) {
  const value: DistributedIndexManifestV1 = {
    version: 1,
    collectionId: 'collection:articles',
    indexName: 'articles',
    schemaHash: 'a'.repeat(64),
    generation: 'one',
    keyEpoch: 'epoch-1',
    sequence: '1',
    issuedAt: now,
    expiresAt: now + 60_000,
    discovery: { mode: 'blind-bloom', bitLength: 1024, hashCount: 4 },
    limits: { maxCandidates: 32, maxRequestBytes: 64 * 1024, advertisementTtlMs: 5000 },
  };
  return verifyDistributedIndexManifest(
    await signDistributedIndexManifest(value, signer, now),
    authorizer,
    now,
  );
}
