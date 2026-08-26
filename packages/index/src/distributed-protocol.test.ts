import { describe, expect, test } from '@jest/globals';
import { DistributedSearchAuthorizer, DistributedSearchSigner } from './distributed-auth.js';
import {
  DistributedIndexManifestV1,
  DistributedManifestRegistry,
  signDistributedIndexManifest,
  verifyDistributedIndexManifest,
} from './distributed-manifest.js';
import { encodeBase64Url } from './distributed-codec.js';
import {
  RoutingAdvertisementRegistry,
  RoutingAdvertisementV1,
  signRoutingAdvertisement,
} from './routing-advertisement.js';
import {
  DistributedSearchRequestReplayGuard,
  DistributedSearchRequestV1,
  encodeDistributedSearchRequest,
  encodeDistributedSearchResponse,
  signDistributedSearchRequest,
  signDistributedSearchResponse,
  verifyDistributedSearchRequest,
  verifyDistributedSearchResponse,
} from './distributed-search-wire.js';

const secret = new TextEncoder().encode('test-secret');

const signer: DistributedSearchSigner = {
  applicationId: 'app:alice',
  async sign(payload) {
    return digest(payload);
  },
};

const authorizer: DistributedSearchAuthorizer = {
  async authorize(applicationId) {
    return applicationId === signer.applicationId;
  },
  async verify(applicationId, payload, signature) {
    if (applicationId !== signer.applicationId) return false;
    const expected = await digest(payload);
    return expected.length === signature.length && expected.every((byte, index) => byte === signature[index]);
  },
};

function manifest(now: number, sequence = '1'): DistributedIndexManifestV1 {
  return {
    version: 1,
    collectionId: 'collection:articles',
    indexName: 'articles',
    schemaHash: 'a'.repeat(64),
    generation: 'one',
    keyEpoch: 'epoch-1',
    sequence,
    issuedAt: now,
    expiresAt: now + 10_000,
    discovery: { mode: 'blind-bloom', bitLength: 1024, hashCount: 4 },
    limits: { maxCandidates: 32, maxRequestBytes: 64 * 1024, advertisementTtlMs: 5000 },
  };
}

describe('signed distributed index protocols', () => {
  test('verifies authorized manifests, rejects tampering, and keeps rollback tombstones', async () => {
    const now = 1_000_000;
    const signed = await signDistributedIndexManifest(manifest(now), signer, now);
    const verified = await verifyDistributedIndexManifest(signed, authorizer, now);
    expect(verified.manifestHash).toMatch(/^[0-9a-f]{64}$/);

    const tampered = structuredClone(signed);
    tampered.manifest.generation = 'attacker';
    await expect(verifyDistributedIndexManifest(tampered, authorizer, now)).rejects.toThrow('signature');

    const registry = new DistributedManifestRegistry();
    expect(await registry.accept(signed, authorizer, now)).toBe('accepted');
    expect(registry.get('collection:articles', 'articles', now)).toBeDefined();
    const stale = await signDistributedIndexManifest({
      ...manifest(now, '0'),
      expiresAt: now + 20_000,
    }, signer, now);
    expect(await registry.accept(stale, authorizer, now + 11_000)).toBe('stale');

    const bounded = new DistributedManifestRegistry(1);
    expect(await bounded.accept(signed, authorizer, now)).toBe('accepted');
    const anotherCollection = await signDistributedIndexManifest({
      ...manifest(now),
      collectionId: 'collection:other',
    }, signer, now);
    expect(await bounded.accept(anotherCollection, authorizer, now)).toBe('capacity');
  });

  test('uses source-bound replacement routing snapshots with replay and saturation defenses', async () => {
    const now = 2_000_000;
    const verified = await verifyDistributedIndexManifest(
      await signDistributedIndexManifest(manifest(now), signer, now),
      authorizer,
      now,
    );
    const filter = new Uint8Array(128);
    filter[0] = 1;
    const advertisement = routingAdvertisement(verified.manifestHash, now, '1', filter);
    const signed = await signRoutingAdvertisement(advertisement, verified, signer, now);
    const registry = new RoutingAdvertisementRegistry({ minUpdateIntervalMs: 0 });
    expect(await registry.accept(signed, 'peer-one', verified, authorizer, now)).toEqual({ accepted: true });
    expect(await registry.accept(signed, 'peer-two', verified, authorizer, now))
      .toEqual({ accepted: false, reason: 'wrong-peer' });
    expect(await registry.accept(signed, 'peer-one', verified, authorizer, now))
      .toEqual({ accepted: false, reason: 'stale' });

    const replacementFilter = new Uint8Array(128);
    replacementFilter[127] = 2;
    const replacement = await signRoutingAdvertisement(
      routingAdvertisement(verified.manifestHash, now + 1, '2', replacementFilter),
      verified,
      signer,
      now + 1,
    );
    expect(await registry.accept(replacement, 'peer-one', verified, authorizer, now + 1)).toEqual({ accepted: true });
    expect(registry.get('collection:articles', 'articles', 'peer-one', now + 1)?.advertisement.filter)
      .toBe(encodeBase64Url(replacementFilter));

    const saturated = new Uint8Array(128).fill(0xff);
    const saturatedSigned = await signRoutingAdvertisement(
      routingAdvertisement(verified.manifestHash, now + 2, '3', saturated),
      verified,
      signer,
      now + 2,
    );
    expect(await registry.accept(saturatedSigned, 'peer-one', verified, authorizer, now + 2))
      .toEqual({ accepted: false, reason: 'saturated' });

    const bounded = new RoutingAdvertisementRegistry({ maxPeers: 1, minUpdateIntervalMs: 0 });
    expect(await bounded.accept(signed, 'peer-one', verified, authorizer, now))
      .toEqual({ accepted: true });
    const activeOtherPeer = await signRoutingAdvertisement({
      ...routingAdvertisement(verified.manifestHash, now + 1, '1', replacementFilter),
      sourcePeerId: 'peer-two',
    }, verified, signer, now + 1);
    expect(await bounded.accept(activeOtherPeer, 'peer-two', verified, authorizer, now + 1))
      .toEqual({ accepted: false, reason: 'capacity' });
    const expiredReplacement = await signRoutingAdvertisement({
      ...routingAdvertisement(verified.manifestHash, now + 1001, '1', replacementFilter),
      sourcePeerId: 'peer-two',
    }, verified, signer, now + 1001);
    expect(await bounded.accept(expiredReplacement, 'peer-two', verified, authorizer, now + 1001))
      .toEqual({ accepted: true });
  });

  test('binds signed requests and responses to manifests, peers, deadlines, and request hashes', async () => {
    const now = 3_000_000;
    const verifiedManifest = await verifyDistributedIndexManifest(
      await signDistributedIndexManifest(manifest(now), signer, now),
      authorizer,
      now,
    );
    const request = requestFor(verifiedManifest.manifestHash, now);
    const signedRequest = await signDistributedSearchRequest(request, verifiedManifest, signer, now);
    const verifiedRequest = await verifyDistributedSearchRequest(
      encodeDistributedSearchRequest(signedRequest),
      'peer-client',
      'peer-server',
      verifiedManifest,
      authorizer,
      now,
    );
    expect(verifiedRequest.requestHash).toMatch(/^[0-9a-f]{64}$/);
    await expect(verifyDistributedSearchRequest(
      signedRequest,
      'peer-forwarder',
      'peer-server',
      verifiedManifest,
      authorizer,
      now,
    )).rejects.toMatchObject({ reason: 'wrong-peer' });

    const replay = new DistributedSearchRequestReplayGuard();
    expect(replay.accept(verifiedRequest, now)).toBe(true);
    expect(replay.accept(verifiedRequest, now)).toBe(false);
    expect(replay.accept(verifiedRequest, request.deadline)).toBe(false);

    const signedResponse = await signDistributedSearchResponse({
      version: 1,
      requestHash: verifiedRequest.requestHash,
      requestId: request.requestId,
      sourcePeerId: 'peer-server',
      recipientPeerId: 'peer-client',
      issuedAt: now + 1,
      candidates: [{ documentPath: '/articles/one', revision: 'rev-1' }],
      exhausted: true,
    }, verifiedRequest, signer, now + 1);
    const verifiedResponse = await verifyDistributedSearchResponse(
      encodeDistributedSearchResponse(signedResponse),
      'peer-server',
      verifiedRequest,
      authorizer,
      now + 1,
    );
    expect(verifiedResponse.response.candidates).toHaveLength(1);
    await expect(verifyDistributedSearchResponse(
      signedResponse,
      'peer-server',
      verifiedRequest,
      authorizer,
      request.deadline,
    )).rejects.toMatchObject({ reason: 'expired' });
    const tampered = structuredClone(signedResponse);
    tampered.response.requestHash = 'f'.repeat(64);
    await expect(verifyDistributedSearchResponse(
      tampered,
      'peer-server',
      verifiedRequest,
      authorizer,
      now + 1,
    )).rejects.toThrow();
  });

  test('blind request payloads contain no plaintext query value', async () => {
    const now = 4_000_000;
    const verified = await verifyDistributedIndexManifest(
      await signDistributedIndexManifest(manifest(now), signer, now), authorizer, now,
    );
    const request = requestFor(verified.manifestHash, now);
    request.payload = {
      mode: 'blind-equality',
      blindTerms: [encodeBase64Url(new Uint8Array(32).fill(7))],
      first: 10,
    };
    const encoded = encodeDistributedSearchRequest(
      await signDistributedSearchRequest(request, verified, signer, now),
    );
    expect(new TextDecoder().decode(encoded)).not.toContain('classified-title');
  });

  test('normalizes dates before signing and rejects non-scalar wire predicates', async () => {
    const now = 5_000_000;
    const verified = await verifyDistributedIndexManifest(
      await signDistributedIndexManifest(manifest(now), signer, now), authorizer, now,
    );
    const dated = requestFor(verified.manifestHash, now);
    if (dated.payload.mode !== 'query' || dated.payload.query.where?.kind !== 'field') {
      throw new Error('unexpected fixture shape');
    }
    dated.payload.query.where.value = new Date('2025-01-02T03:04:05.000Z');
    const verifiedDated = await verifyDistributedSearchRequest(
      encodeDistributedSearchRequest(
        await signDistributedSearchRequest(dated, verified, signer, now),
      ),
      'peer-client',
      'peer-server',
      verified,
      authorizer,
      now,
    );
    expect((verifiedDated.request.payload as { mode: 'query'; query: {
      where: { value: unknown };
    } }).query.where.value).toBe('2025-01-02T03:04:05.000Z');

    const hostile = requestFor(verified.manifestHash, now);
    if (hostile.payload.mode !== 'query' || hostile.payload.query.where?.kind !== 'field') {
      throw new Error('unexpected fixture shape');
    }
    hostile.payload.query.where.value = { nested: 'value' };
    await expect(signDistributedSearchRequest(hostile, verified, signer, now))
      .rejects.toThrow('scalar');
  });

  test('requires the plaintext target and blind page size to match the signed request', async () => {
    const now = 6_000_000;
    const verified = await verifyDistributedIndexManifest(
      await signDistributedIndexManifest(manifest(now), signer, now), authorizer, now,
    );
    const missingTarget = requestFor(verified.manifestHash, now);
    if (missingTarget.payload.mode !== 'query') throw new Error('unexpected fixture shape');
    delete missingTarget.payload.query.indexName;
    await expect(signDistributedSearchRequest(missingTarget, verified, signer, now))
      .rejects.toMatchObject({ reason: 'wrong-manifest' });

    const oversizedBlind = requestFor(verified.manifestHash, now);
    oversizedBlind.candidateLimit = 1;
    oversizedBlind.payload = {
      mode: 'blind-equality',
      blindTerms: [encodeBase64Url(new Uint8Array(32).fill(3))],
      first: 2,
    };
    await expect(signDistributedSearchRequest(oversizedBlind, verified, signer, now))
      .rejects.toThrow('blind first');
  });

  test('rejects global cursors, projections, and indexed waits on candidate requests', async () => {
    const now = 7_000_000;
    const verified = await verifyDistributedIndexManifest(
      await signDistributedIndexManifest(manifest(now), signer, now), authorizer, now,
    );
    for (const forbidden of [
      { after: 'global-cursor' },
      { select: ['title'] },
      { consistency: 'indexed' as const },
    ]) {
      const request = requestFor(verified.manifestHash, now);
      if (request.payload.mode !== 'query') throw new Error('unexpected fixture shape');
      Object.assign(request.payload.query, forbidden);
      await expect(signDistributedSearchRequest(request, verified, signer, now)).rejects.toThrow();
    }
  });
});

function routingAdvertisement(
  manifestHash: string,
  now: number,
  sequence: string,
  filter: Uint8Array,
): RoutingAdvertisementV1 {
  return {
    version: 1,
    manifestHash,
    collectionId: 'collection:articles',
    indexName: 'articles',
    schemaHash: 'a'.repeat(64),
    generation: 'one',
    keyEpoch: 'epoch-1',
    sourcePeerId: 'peer-one',
    sequence,
    issuedAt: now,
    expiresAt: now + 1000,
    bitLength: 1024,
    hashCount: 4,
    filter: encodeBase64Url(filter),
  };
}

function requestFor(manifestHash: string, now: number): DistributedSearchRequestV1 {
  return {
    version: 1,
    manifestHash,
    collectionId: 'collection:articles',
    indexName: 'articles',
    schemaHash: 'a'.repeat(64),
    generation: 'one',
    keyEpoch: 'epoch-1',
    sourcePeerId: 'peer-client',
    recipientPeerId: 'peer-server',
    requestId: 'request-one',
    issuedAt: now,
    deadline: now + 5000,
    candidateLimit: 10,
    payload: {
      mode: 'query',
      query: {
        version: 2,
        indexName: 'articles',
        where: { kind: 'field', path: 'title', operator: 'eq', value: 'classified-title' },
      },
    },
  };
}

async function digest(payload: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(secret.length + payload.length);
  combined.set(secret);
  combined.set(payload, secret.length);
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', combined));
}
