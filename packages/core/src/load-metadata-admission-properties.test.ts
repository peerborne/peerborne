import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { initialLoadRequestSignaturePayload } from './initial-load-challenge.js';
import { cloneLoadSecurityCommitments } from './load-security-state.js';
import { loadResponseManifestHash } from './load-response-manifest.js';
import * as encoding from './internal/canonical-encoding.js';
import * as byteUtilities from './utils.js';
import * as treeWalk from './change-tree-walk.js';

const commitments = (groupId: string) => ({
  version: 1 as const,
  groupId,
  epoch: 0n,
  controlHead: new Uint8Array(32),
  treeHash: new Uint8Array(32),
  confirmedTranscriptHash: new Uint8Array(32),
});

test.each(['oversized', 'malformed', 'non-string'] as const)(
  'a %s snapshot boundary is rejected before payload copies or graph capture',
  async (kind) => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 128 }),
        async (payload) => {
          const snapshot = {
            stateBytes: payload,
            lastChangeNodeCID:
              kind === 'oversized'
                ? 'x'.repeat(1025)
                : kind === 'malformed'
                  ? '\udc00'
                  : (7 as unknown as string),
          };
          let copied = 0;
          const original = byteUtilities.copyUnsharedUint8Array;
          const spy = jest
            .spyOn(byteUtilities, 'copyUnsharedUint8Array')
            .mockImplementation((...args: Parameters<typeof original>) => {
              const result = original(...args);
              if (
                args[3] === 'snapshot state' ||
                args[3] === 'keychain changes'
              )
                copied += result.byteLength;
              return result;
            });
          const walk = jest.spyOn(treeWalk, 'snapshotBoundedChangeTree');
          try {
            await expect(
              loadResponseManifestHash({
                changeId: 'ROOT',
                changes: { kind: 'document', change: payload },
                snapshot,
                keychainChangesBytes: payload,
              }),
            ).rejects.toThrow();
            expect(copied).toBe(0);
            expect(walk).not.toHaveBeenCalled();
          } finally {
            walk.mockRestore();
            spy.mockRestore();
          }
        },
      ),
      { seed: 2011801, numRuns: 16 },
    );
  },
);

test.each(['challenge', 'responder', 'commitments', 'manifest'] as const)(
  'over-limit %s text is rejected without UTF-8 allocation or an unbounded scan',
  async (kind) => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 128 }),
        fc.boolean(),
        async (extra, wide) => {
          const maximum =
            kind === 'challenge' ? 4096 : kind === 'responder' ? 128 : 1024;
          const value = wide
            ? 'あ'.repeat(Math.floor(maximum / 3) + extra)
            : 'x'.repeat(maximum + extra);
          const scanOriginal = encoding.isWellFormedUtf16;
          const encodeOriginal = TextEncoder.prototype.encode;
          let scans = 0,
            encoded = 0;
          const scanSpy = jest
            .spyOn(encoding, 'isWellFormedUtf16')
            .mockImplementation((text) => {
              if (text === value) scans++;
              return scanOriginal(text);
            });

          const encodeSpy = jest
            .spyOn(TextEncoder.prototype, 'encode')
            .mockImplementation(function (this: TextEncoder, text) {
              if (text === value) encoded++;
              return Reflect.apply(encodeOriginal, this, [text]);
            });
          try {
            const call = () =>
              kind === 'challenge'
                ? initialLoadRequestSignaturePayload(
                    value,
                    new Uint8Array(32),
                    'responder',
                  )
                : kind === 'responder'
                  ? initialLoadRequestSignaturePayload(
                      '/doc',
                      new Uint8Array(32),
                      value,
                    )
                : kind === 'commitments'
                  ? cloneLoadSecurityCommitments(commitments(value))
                  : loadResponseManifestHash({
                      changeId: value,
                      changes: { kind: 'document' },
                    });
            await expect(Promise.resolve().then(call)).rejects.toThrow();
            expect(scans).toBe(0);
            expect(encoded).toBe(0);
          } finally {
            scanSpy.mockRestore();
            encodeSpy.mockRestore();
          }
        },
      ),
      { seed: 2011802, numRuns: 16 },
    );
  },
);

const utf16 = fc
  .array(fc.integer({ min: 0, max: 65535 }), { maxLength: 96 })
  .map((units) => String.fromCharCode(...units));

test('bounded UTF-8 sizing agrees with native encoding without invoking an encoder', () => {
  fc.assert(
    fc.property(utf16, fc.integer({ min: 0, max: 400 }), (value, maximum) => {
      const expected = value.isWellFormed()
        ? new TextEncoder().encode(value).byteLength
        : undefined;
      const encodeSpy = jest
        .spyOn(TextEncoder.prototype, 'encode')
        .mockImplementation(() => {
          throw new Error('Unexpected UTF-8 allocation');
        });
      const original = String.prototype.charCodeAt;
      let reads = 0;
      const readSpy = jest
        .spyOn(String.prototype, 'charCodeAt')
        .mockImplementation(function (this: string, position) {
          if (String(this) === value) reads++;
          return Reflect.apply(original, this, [position]);
        });
      try {
        const actual = encoding.boundedUtf8ByteLength(value, maximum);
        if (expected === undefined || expected > maximum)
          expect(actual).toBeLessThan(0);
        else expect(actual).toBe(expected);
        if (value.length > maximum) expect(reads).toBe(0);
        else expect(reads).toBeLessThanOrEqual(3 * value.length);
        expect(encodeSpy).not.toHaveBeenCalled();
      } finally {
        readSpy.mockRestore();
        encodeSpy.mockRestore();
      }
    }),
    {
      seed: 2011803,
      numRuns: 1000,
      examples: [
        ['', 0],
        ['a', 1],
        ['\u07ff', 2],
        ['\u0800', 3],
        ['\ud83d\ude00', 4],
        ['\ud83d\ude00', 3],
        ['\ud800', 3],
        ['\ufeff', 3],
      ],
    },
  );
});

test('valid text retains canonical challenge bytes and needs no encoding during tuple validation', () => {
  fc.assert(
    fc.property(
      fc
        .array(fc.constantFrom('a', 'é', 'あ', '😀', '\ufeff', '\0'), {
          minLength: 1,
          maxLength: 40,
        })
        .map((parts) => parts.join('')),
      fc.uint8Array({ minLength: 32, maxLength: 32 }),
      fc.stringMatching(/^[1-9A-HJ-NP-Za-km-z]{1,128}$/),
      (value, nonce, responderText) => {
        const document = new TextEncoder().encode(value);
        const responder = new TextEncoder().encode(responderText);
        const domain = new TextEncoder().encode(
          'peerborne/initial-load-request/v4\0',
        );
        const responderOffset = domain.length + 4 + document.length + 32;
        const expected = new Uint8Array(responderOffset + 4 + responder.length);
        const view = new DataView(expected.buffer);
        expected.set(domain);
        view.setUint32(domain.length, document.length, false);
        expected.set(document, domain.length + 4);
        expected.set(nonce, domain.length + 4 + document.length);
        view.setUint32(responderOffset, responder.length, false);
        expected.set(responder, responderOffset + 4);
        expect(
          initialLoadRequestSignaturePayload(value, nonce, responderText),
        ).toEqual(expected);
        const spy = jest.spyOn(TextEncoder.prototype, 'encode');
        try {
          const original = commitments(value);
          const cloned = cloneLoadSecurityCommitments(original);
          expect(cloned.groupId).toBe(value);
          expect(spy).not.toHaveBeenCalled();
          original.controlHead.fill(7);
          expect(cloned.controlHead).toEqual(new Uint8Array(32));
        } finally {
          spy.mockRestore();
        }
      },
    ),
    { seed: 2011804, numRuns: 80 },
  );
});

test('validated metadata and payloads stay captured when the input mutates across digest yields', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 128 }),
      async (payload) => {
        const make = () => ({
          changeId: 'ROOT',
          changes: {
            kind: 'document' as const,
            change: new Uint8Array([1]),
            children: { CHILD: { kind: 'writer' as const } } as Record<
              string,
              { kind: 'writer' | 'reader' }
            >,
          },
          snapshot: {
            stateBytes: payload.slice(),
            lastChangeNodeCID: 'ROOT',
          },
          keychainChangesBytes: payload.slice(),
        });
        const expected = await loadResponseManifestHash(make());
        const input = make();
        const pending = loadResponseManifestHash(input);
        input.changeId = 'OTHER';
        input.changes.children.CHILD.kind = 'reader';
        input.changes.children.ATTACKER = { kind: 'writer' };
        input.snapshot.lastChangeNodeCID = 'x'.repeat(1025);
        input.snapshot.stateBytes.fill(0);
        input.keychainChangesBytes.fill(0);
        expect(await pending).toEqual(expected);
      },
    ),
    { seed: 2011805, numRuns: 24 },
  );
});

test('invalid UTF-8 limits and forbidden empty values reject before allocation', () => {
  fc.assert(
    fc.property(
      fc.constantFrom(-1, NaN, Infinity, 0.5, 0x100000000),
      utf16,
      (maximum, value) => {
        const spy = jest.spyOn(TextEncoder.prototype, 'encode');
        try {
          expect(() =>
            encoding.assertBoundedUtf8(value, maximum, 'synthetic text', true),
          ).toThrow();
          expect(() =>
            encoding.assertBoundedUtf8('', 0, 'synthetic text'),
          ).toThrow();
          expect(() =>
            encoding.assertBoundedUtf8('', 0, 'synthetic text', true),
          ).not.toThrow();
          expect(spy).not.toHaveBeenCalled();
        } finally {
          spy.mockRestore();
        }
      },
    ),
    { seed: 2011806, numRuns: 80 },
  );
});

test('invalid roots fail before graph capture or payload copies', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom('absent-tree', 'empty', 'long', 'malformed', 'type'),
      fc.uint8Array({ minLength: 1, maxLength: 64 }),
      async (kind, payload) => {
        const input = {
          changeId:
            kind === 'empty'
              ? ''
              : kind === 'long'
                ? 'x'.repeat(1025)
                : kind === 'malformed'
                  ? '\ud800'
                  : kind === 'type'
                    ? 42
                    : 'ROOT',
          changes:
            kind === 'absent-tree'
              ? undefined
              : { kind: 'document' as const, change: payload },
          snapshot: {
            stateBytes: payload,
            lastChangeNodeCID: 'ROOT',
          },
          keychainChangesBytes: payload,
        };
        const copies = jest.spyOn(byteUtilities, 'copyUnsharedUint8Array');
        const walk = jest.spyOn(treeWalk, 'snapshotBoundedChangeTree');
        try {
          await expect(
            loadResponseManifestHash(
              input as unknown as Parameters<
                typeof loadResponseManifestHash
              >[0],
            ),
          ).rejects.toThrow();
          expect(walk).not.toHaveBeenCalled();
          expect(copies).not.toHaveBeenCalled();
        } finally {
          walk.mockRestore();
          copies.mockRestore();
        }
      },
    ),
    { seed: 2011807, numRuns: 30 },
  );
});
