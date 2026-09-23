import { describe, expect, jest, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import { JSONSerializer } from './json-serializer.js';
import { evaluateBeeKEMWelcome } from './beekem-welcome-handler.js';
import { MAX_SHARED_PROTOCOL_REQUEST_BYTES } from './utils.js';

const serializer = new JSONSerializer<unknown, CryptoKey>();

describe('JSON sync security fields', () => {
  test('redacts a base64 decoder failure with the field contract', () => {
    const decoder = jest.spyOn(Base64, 'toUint8Array').mockImplementation(() => {
      throw new Error('opaque decoder detail');
    });
    try {
      expect(() => serializer.deserializeSyncMessage(new TextEncoder().encode(
        JSON.stringify({ signatureContext: 'security-advertisement-v1' as const, documentId: '/doc', tipsHash: 'A'.repeat(43) + '=' }),
      ))).toThrow(new TypeError('tipsHash must be bounded canonical base64'));
    } finally {
      decoder.mockRestore();
    }
  });

  test('round-trips a complete signed Welcome through the admission validator', async () => {
    const keys = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const unsigned = {
      signatureContext: 'beekem-welcome-v1' as const,
      welcomeEpochId: new Uint8Array(32).fill(1),
      documentId: '/welcome',
      welcomeRecipient: 'recipient',
      welcomeRecipientKemPublicKey: new Uint8Array(65).fill(4),
      eciesSealed: new Uint8Array([1, 2, 3]),
    };
    const signedBytes = serializer.serializeSyncMessage(unsigned);
    const signature = Base64.fromUint8Array(
      new Uint8Array(
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-384' },
          keys.privateKey,
          signedBytes as Uint8Array<ArrayBuffer>,
        ),
      ),
    );
    const message = { ...unsigned, signature };
    const wire = serializer.serializeSyncMessage(message);
    const raw = JSON.parse(serializer.decode(wire));
    expect(raw.welcomeEpochId).toBe(
      Base64.fromUint8Array(unsigned.welcomeEpochId),
    );
    expect(raw.welcomeRecipientKemPublicKey).toBe(
      Base64.fromUint8Array(unsigned.welcomeRecipientKemPublicKey),
    );
    expect(raw.eciesSealed).toBe('AQID');
    const decoded = serializer.deserializeSyncMessage(wire);
    expect(decoded).toEqual(message);
    expect(serializer.serializeSyncMessage(decoded)).toEqual(wire);
    const result = await evaluateBeeKEMWelcome(decoded, {
      documentPath: '/welcome',
      localUserPublicKey: keys.publicKey,
      localSerializedPublicKey: 'recipient',
      isReader: async () => true,
      syncMessageSerializer: serializer,
      verifyWriterSignature: (payload, value) =>
        crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-384' },
          keys.publicKey,
          Base64.toUint8Array(value) as Uint8Array<ArrayBuffer>,
          payload as Uint8Array<ArrayBuffer>,
        ),
    });
    expect(result.kind).toBe('accept');
  });

  test.each([
    ['welcomeEpochId', 32],
    ['pathUpdateEpochId', 32],
    ['tipsHash', 32],
    ['welcomeRecipientKemPublicKey', 65],
    ['eciesSealed', 3],
  ] as const)(
    'rejects malformed %s bytes and wire encodings',
    (field, length) => {
      const message = (value: unknown) => ({ signatureContext: 'ordinary-sync-v1' as const,
        documentId: '/doc',
        [field]: value,
      });
      const wire = (value: unknown) =>
        serializer.encode(JSON.stringify(message(value)));
      const canonical = Base64.fromUint8Array(new Uint8Array(length).fill(1));
      expect(() =>
        serializer.deserializeSyncMessage(wire(canonical)),
      ).not.toThrow();
      for (const invalid of [
        { 0: 1 },
        '',
        `${canonical} `,
        canonical.replace(/=/g, ''),
        '!'.repeat(canonical.length),
      ]) {
        if (invalid === canonical) continue;
        expect(() => serializer.deserializeSyncMessage(wire(invalid))).toThrow(
          /base64/,
        );
      }
      for (const invalid of [
        new Uint16Array(length),
        new Uint8Array(new SharedArrayBuffer(length)),
        new Uint8Array(),
      ]) {
        expect(() =>
          serializer.serializeSyncMessage(message(invalid)),
        ).toThrow();
      }
    },
  );

  test('rejects oversized wire bytes before the decoder allocates', () => {
    const decode = jest.spyOn(Base64, 'toUint8Array');
    try {
      for (const [field, length] of [
        ['welcomeEpochId', 48],
        [
          'eciesSealed',
          Math.ceil(MAX_SHARED_PROTOCOL_REQUEST_BYTES / 3) * 4 + 4,
        ],
      ] as const) {
        const wire = serializer.encode(
          JSON.stringify({ signatureContext: 'ordinary-sync-v1' as const, documentId: '/doc', [field]: 'A'.repeat(length) }),
        );
        expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
          /bounded canonical base64/,
        );
      }
      expect(decode).not.toHaveBeenCalled();
    } finally {
      decode.mockRestore();
    }
  });
});
