import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  decodeDocumentContent,
  decodeEncryptedDocumentContent,
  decodeSignedDocumentContent,
  encodeDocumentContent,
  encodeEncryptedDocumentContent,
  encodeSignedDocumentContent,
} from './document-security-wire.js';
import { publicState, id } from './__testutils__/group-security-coordinator.js';

describe('bounded coordinated document wire boundaries', () => {
  test('round trips exact owned content and opaque encrypted framing across safe integer and uint64 boundaries', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.string({ minLength: 1, maxLength: 60 }),
          fc.constant('\ufeffdocument'),
          fc.constant('\ufeff'),
        ),
        fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
        fc.integer({ min: 1, max: Number.MAX_SAFE_INTEGER }),
        fc.uint8Array({ maxLength: 2048 }),
        (documentId, epoch, sequence, changes) => {
          const context = { state: publicState(epoch), controlHead: id(9) };
          const encoded = encodeDocumentContent({
            documentId,
            context,
            sequence,
            changes,
            genesisId: id(1),
            memberId: id(2),
            parent: id(3),
            kind: 'change',
          });
          const decoded = decodeDocumentContent(encoded);
          expect(encodeDocumentContent(decoded)).toEqual(encoded);
          decoded.changes.fill(0xff);
          expect(decodeDocumentContent(encoded).changes).toEqual(changes);
          const signed = encodeSignedDocumentContent(encoded, id(7));
          expect(decodeSignedDocumentContent(signed)).toEqual({
            unsigned: encoded,
            signature: id(7),
          });
          const encrypted = encodeEncryptedDocumentContent(
            id(5).slice(0, 16),
            id(6).slice(0, 12),
            id(8),
          );
          const envelope = decodeEncryptedDocumentContent(encrypted);
          expect(
            encodeEncryptedDocumentContent(
              envelope.epochTag,
              envelope.nonce,
              envelope.ciphertext,
            ),
          ).toEqual(encrypted);
        },
      ),
      { seed: 2011161, numRuns: 250 },
    );
  });

  test('rejects arbitrary malformed frames or accepts only canonical bounded encodings', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 4096 }), (bytes) => {
        for (const [decode, encode] of [
          [decodeDocumentContent, (value: any) => encodeDocumentContent(value)],
          [
            decodeSignedDocumentContent,
            (value: any) =>
              encodeSignedDocumentContent(value.unsigned, value.signature),
          ],
          [
            decodeEncryptedDocumentContent,
            (value: any) =>
              encodeEncryptedDocumentContent(
                value.epochTag,
                value.nonce,
                value.ciphertext,
              ),
          ],
        ] as const) {
          let value: unknown;
          try {
            value = decode(bytes);
          } catch {
            continue;
          }
          expect(encode(value)).toEqual(bytes);
        }
      }),
      { seed: 2011162, numRuns: 1200 },
    );
  });
});
