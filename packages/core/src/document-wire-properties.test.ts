import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  decodeDocumentContent,
  decodeEncryptedDocumentContent,
  decodeSignedDocumentContent,
  encodeDocumentContent,
  encodeEncryptedDocumentContent,
  encodeSignedDocumentContent,
  MAX_DOCUMENT_PUBLICATION_FRAMES,
  splitDocumentPublication,
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
            authorityHead: id(4),
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

  test('splits concatenated encrypted frames exactly and rejects truncated, trailing or oversized publications', () => {
    const frame = fc
      .tuple(
        fc.uint8Array({ minLength: 16, maxLength: 16 }),
        fc.uint8Array({ minLength: 12, maxLength: 12 }),
        fc.uint8Array({ minLength: 16, maxLength: 300 }),
      )
      .map(([tag, nonce, ciphertext]) =>
        encodeEncryptedDocumentContent(tag, nonce, ciphertext),
      );
    const join = (frames: readonly Uint8Array[]) => {
      const bytes = new Uint8Array(
        frames.reduce((sum, value) => sum + value.length, 0),
      );
      let offset = 0;
      for (const value of frames) {
        bytes.set(value, offset);
        offset += value.length;
      }
      return bytes;
    };
    fc.assert(
      fc.property(
        fc.array(frame, { minLength: 1, maxLength: 8 }),
        fc.nat(),
        fc.uint8Array({ minLength: 1, maxLength: 40 }),
        (frames, cut, trailer) => {
          const publication = join(frames);
          expect(splitDocumentPublication(publication)).toEqual(frames);
          const length = cut % publication.length || 1;
          const boundary = frames.findIndex(
            (_, index) => join(frames.slice(0, index + 1)).length === length,
          );
          if (boundary === -1)
            expect(() =>
              splitDocumentPublication(publication.slice(0, length)),
            ).toThrow();
          else
            expect(
              splitDocumentPublication(publication.slice(0, length)),
            ).toEqual(frames.slice(0, boundary + 1));
          expect(() =>
            splitDocumentPublication(join([publication, trailer])),
          ).toThrow();
        },
      ),
      { seed: 2011163, numRuns: 300 },
    );
    const smallest = encodeEncryptedDocumentContent(
      new Uint8Array(16),
      new Uint8Array(12),
      new Uint8Array(16),
    );
    const most = Array(MAX_DOCUMENT_PUBLICATION_FRAMES).fill(smallest);
    expect(splitDocumentPublication(join(most))).toHaveLength(most.length);
    expect(() => splitDocumentPublication(join([...most, smallest]))).toThrow(
      'too many frames',
    );
    expect(() => splitDocumentPublication(new Uint8Array())).toThrow();
  });
});
