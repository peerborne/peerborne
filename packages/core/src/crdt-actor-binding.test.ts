import { describe, expect, test } from '@jest/globals';
import {
  CRDTActorBindingError,
  CRDTActorBindings,
  CRDT_ACTOR_NONCE_BYTES,
  MAX_CRDT_ACTORS_PER_SIGNER,
  MAX_CRDT_ACTOR_BINDINGS,
  attachCRDTActorPrefix,
  crdtActorRegistrationPayload,
  crdtChangeAuthorPayload,
  decodeCRDTActorManifest,
  decodeCRDTChangeAuthor,
  deriveCRDTActorDigest,
  detachCRDTActorPrefix,
  encodeCRDTActorManifest,
  encodeCRDTChangeAuthor,
  isCRDTActorPrefix,
  type CRDTSignedActorRegistration,
} from './crdt-actor-binding';

const nonce = (fill: number) =>
  new Uint8Array(CRDT_ACTOR_NONCE_BYTES).fill(fill);
const registration = (
  signer: string,
  fill: number,
): CRDTSignedActorRegistration => ({
  signer,
  nonce: nonce(fill),
  registrationSignature: new Uint8Array([fill]),
});
const indexed = (signer: string, index: number) => {
  const value = new Uint8Array(CRDT_ACTOR_NONCE_BYTES);
  new DataView(value.buffer).setUint32(0, index);
  return [
    `${signer}-${index}`,
    { signer, nonce: value, registrationSignature: new Uint8Array([1]) },
  ] as const;
};

describe('CRDT actor derivation', () => {
  test('binds the document, signer and nonce', async () => {
    const base = await deriveCRDTActorDigest('/doc', registration('alice', 1));
    expect(base).toHaveLength(32);
    await expect(
      deriveCRDTActorDigest('/doc', registration('alice', 1)),
    ).resolves.toEqual(base);
    for (const [path, other] of [
      ['/other', registration('alice', 1)],
      ['/doc', registration('bob', 1)],
      ['/doc', registration('alice', 2)],
    ] as const)
      await expect(deriveCRDTActorDigest(path, other)).resolves.not.toEqual(
        base,
      );
  });

  test('rejects a nonce of the wrong length', async () => {
    await expect(
      deriveCRDTActorDigest('/doc', { signer: 'a', nonce: new Uint8Array(15) }),
    ).rejects.toBeInstanceOf(CRDTActorBindingError);
  });

  test('a registration signature covers the document path, signer and nonce', () => {
    const payload = crdtActorRegistrationPayload(
      '/doc',
      registration('alice', 1),
    );
    for (const [path, other] of [
      ['/other', registration('alice', 1)],
      ['/doc', registration('bob', 1)],
      ['/doc', registration('alice', 2)],
    ] as const)
      expect(crdtActorRegistrationPayload(path, other)).not.toEqual(payload);
    expect(
      crdtChangeAuthorPayload(
        '/doc',
        registration('alice', 1),
        new Uint8Array(),
      ),
    ).not.toEqual(payload);
  });

  test('signs the document path, registration and change bytes', () => {
    const author = registration('alice', 1);
    const payload = crdtChangeAuthorPayload(
      '/doc',
      author,
      new Uint8Array([7]),
    );
    expect(
      crdtChangeAuthorPayload('/doc', author, new Uint8Array([8])),
    ).not.toEqual(payload);
    expect(
      crdtChangeAuthorPayload(
        '/doc',
        registration('alice', 2),
        new Uint8Array([7]),
      ),
    ).not.toEqual(payload);
    expect(
      crdtChangeAuthorPayload('/other', author, new Uint8Array([7])),
    ).not.toEqual(payload);
  });
});

describe('authored change envelopes', () => {
  test('round-trip and reject truncated, trailing or oversized fields', () => {
    const author = {
      ...registration('alice', 3),
      signature: new Uint8Array([1, 2]),
    };
    const encoded = encodeCRDTChangeAuthor(author);
    expect(isCRDTActorPrefix(encoded)).toBe(true);
    expect(decodeCRDTChangeAuthor(encoded)).toEqual(author);
    for (const malformed of [
      encoded.slice(0, -1),
      new Uint8Array([...encoded, 0]),
      new Uint8Array([0, ...encoded.slice(1)]),
      encodeCRDTActorManifest([]),
    ])
      expect(() => decodeCRDTChangeAuthor(malformed)).toThrow(
        CRDTActorBindingError,
      );
    expect(() => encodeCRDTChangeAuthor({ ...author, signer: '' })).toThrow(
      CRDTActorBindingError,
    );
    expect(() =>
      encodeCRDTChangeAuthor({ ...author, signature: new Uint8Array(1025) }),
    ).toThrow(CRDTActorBindingError);
    expect(() =>
      encodeCRDTChangeAuthor({
        ...author,
        registrationSignature: new Uint8Array(1025),
      }),
    ).toThrow(CRDTActorBindingError);
  });

  test('a prefix attaches to bytes and requires its magic to detach', () => {
    const prefix = encodeCRDTChangeAuthor({
      ...registration('alice', 3),
      signature: new Uint8Array(),
    });
    const wrapped = attachCRDTActorPrefix(new Uint8Array([9, 8]), prefix);
    expect(detachCRDTActorPrefix(wrapped)).toEqual([
      prefix,
      new Uint8Array([9, 8]),
    ]);
    expect(() => detachCRDTActorPrefix(new Uint8Array([9, 8]))).toThrow(
      CRDTActorBindingError,
    );
    expect(() => detachCRDTActorPrefix(wrapped.slice(0, 10))).toThrow(
      CRDTActorBindingError,
    );
  });
});

describe('actor manifests', () => {
  test('encode equal registration sets identically', () => {
    const entries = [
      registration('bob', 2),
      registration('alice', 9),
      registration('alice', 1),
      registration('alice', 1),
    ];
    const encoded = encodeCRDTActorManifest(entries);
    expect(encodeCRDTActorManifest([...entries].reverse())).toEqual(encoded);
    expect(decodeCRDTActorManifest(encoded)).toEqual([
      registration('alice', 1),
      registration('alice', 9),
      registration('bob', 2),
    ]);
  });

  test('reject noncanonical order and trailing bytes', () => {
    const encoded = encodeCRDTActorManifest([
      registration('alice', 1),
      registration('alice', 2),
    ]);
    const swapped = encoded.slice();
    const entry = 4 + CRDT_ACTOR_NONCE_BYTES + 2 + 1;
    const first = swapped.length - 2 * entry + 4;
    swapped.set(nonce(2), first);
    swapped.set(nonce(1), first + entry);
    for (const malformed of [
      swapped,
      new Uint8Array([...encoded, 0]),
      encoded.slice(0, -1),
    ])
      expect(() => decodeCRDTActorManifest(malformed)).toThrow(
        CRDTActorBindingError,
      );
  });
});

describe('first-seen actor bindings', () => {
  test('keep the first registration of an actor', () => {
    const bindings = new CRDTActorBindings();
    bindings.record([['actor', registration('bob', 1)]]);
    bindings.record([['actor', registration('bob', 1)]]);
    expect(bindings.size).toBe(1);
    for (const other of [registration('mallory', 1), registration('bob', 2)])
      expect(() => bindings.check([['actor', other]])).toThrow(/already bound/);
    expect(bindings.get('actor')).toEqual(registration('bob', 1));
  });

  test('reject a set that conflicts with itself without recording any of it', () => {
    const bindings = new CRDTActorBindings();
    expect(() =>
      bindings.record([
        ['one', registration('bob', 1)],
        ['two', registration('bob', 2)],
        ['one', registration('mallory', 1)],
      ]),
    ).toThrow(/already bound/);
    expect(bindings.size).toBe(0);
  });

  test(`forget one signer's least recently used binding beyond ${MAX_CRDT_ACTORS_PER_SIGNER}`, () => {
    const bindings = new CRDTActorBindings();
    bindings.record([['bob', registration('bob', 1)]]);
    bindings.record(
      Array.from({ length: MAX_CRDT_ACTORS_PER_SIGNER }, (_, index) =>
        indexed('mallory', index),
      ),
    );
    bindings.record([indexed('mallory', 0)]);
    bindings.record([indexed('mallory', MAX_CRDT_ACTORS_PER_SIGNER)]);
    expect(bindings.signerCount('mallory')).toBe(MAX_CRDT_ACTORS_PER_SIGNER);
    expect(bindings.get('mallory-0')).toBeDefined();
    expect(bindings.get('mallory-1')).toBeUndefined();
    expect(bindings.get('bob')).toEqual(registration('bob', 1));
    expect(() => bindings.check([indexed('mallory', 1)])).not.toThrow();
  });

  test(`forget the least recently used binding beyond ${MAX_CRDT_ACTOR_BINDINGS} in all`, () => {
    const bindings = new CRDTActorBindings();
    const signers = Math.ceil(MAX_CRDT_ACTOR_BINDINGS / 1024) + 1;
    for (let signer = 0; signer < signers; signer++)
      bindings.record(
        Array.from({ length: 1024 }, (_, index) =>
          indexed(`signer-${signer}`, index),
        ),
      );
    expect(bindings.size).toBe(MAX_CRDT_ACTOR_BINDINGS);
    expect(bindings.get('signer-0-0')).toBeUndefined();
    expect(bindings.signerCount('signer-0')).toBe(0);
    expect(bindings.get(`signer-${signers - 1}-1023`)).toBeDefined();
  });

  test('list remembered registrations only', () => {
    const bindings = new CRDTActorBindings();
    bindings.record([['actor', registration('bob', 1)]]);
    expect(bindings.registrations(['actor', 'unknown'])).toEqual([
      registration('bob', 1),
    ]);
  });
});
