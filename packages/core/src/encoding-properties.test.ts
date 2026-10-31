import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  concatenate,
  encodeUtf8,
  isWellFormedUtf16,
  uint32,
} from './internal/canonical-encoding.js';
import {
  base64EncodedLength,
  base64DecodedUpperBound,
} from './policy/encoded-size.js';
import {
  encodeInvitationProtocolFrame,
  readInvitationProtocolFrame,
} from './invitation-framing.js';
import {
  createV2DecodeBudget,
  reserveV2Work,
  type V2WireCodec,
} from './wire-v2-validation.js';
import {
  CAPABILITY_HIERARCHY,
  NON_HIERARCHICAL_CAPABILITIES,
} from './capabilities.js';

const utf16 = fc
  .array(fc.integer({ min: 0, max: 0xffff }), { maxLength: 120 })
  .map((units) => String.fromCharCode(...units));
async function* fragmented(
  data: Uint8Array,
  widths: number[],
): AsyncGenerator<Uint8Array> {
  yield new Uint8Array();
  let offset = 0,
    turn = 0;
  while (offset < data.length) {
    const width = widths[turn++ % widths.length];
    yield data.subarray(offset, offset + width);
    offset += width;
  }
}

describe('native encoding and verified-model calibration', () => {
  test('UTF-16 policy agrees with the native runtime on arbitrary code units', () => {
    fc.assert(
      fc.property(utf16, (value) => {
        expect(isWellFormedUtf16(value)).toBe(value.isWellFormed());
        if (value.isWellFormed()) {
          expect(
            new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
              encodeUtf8(value),
            ),
          ).toBe(value);
        }
      }),
      {
        seed: 9510,
        numRuns: 2000,
        examples: [['\ud800'], ['\udfff'], ['\ud83d\ude00'], ['\ufeff']],
      },
    );
  });

  test('base64 sizing agrees with exact BigInt arithmetic at uint32 boundaries', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 0xffffffff }), (length) => {
        expect(BigInt(base64EncodedLength(length))).toBe(
          4n * ((BigInt(length) + 2n) / 3n),
        );
        expect(BigInt(base64DecodedUpperBound(length))).toBe(
          3n * ((BigInt(length) + 3n) / 4n),
        );
        const encoded = uint32(length);
        expect([...encoded]).toEqual(
          [24n, 16n, 8n, 0n].map((shift) =>
            Number((BigInt(length) >> shift) & 255n),
          ),
        );
        expect(new DataView(encoded.buffer).getUint32(0, false)).toBe(length);
      }),
      {
        seed: 9511,
        numRuns: 1500,
        examples: [[0], [1], [2], [3], [0xffffffff]],
      },
    );
  });

  test('concatenation preserves order, length and ownership across arbitrary slices', () => {
    fc.assert(
      fc.property(
        fc.array(fc.uint8Array({ maxLength: 128 }), { maxLength: 30 }),
        (parts) => {
          const views = parts.map((part) =>
            new Uint8Array([255, ...part, 254]).subarray(1, part.length + 1),
          );
          const expected = parts.flatMap((part) => [...part]);
          const combined = concatenate(views);
          expect([...combined]).toEqual(expected);
          views.forEach((part) => part.fill(17));
          expect([...combined]).toEqual(expected);
        },
      ),
      { seed: 9512, numRuns: 500 },
    );
  });

  test('exported hierarchy tables cannot invalidate the verified constant model', () => {
    expect(Object.isFrozen(CAPABILITY_HIERARCHY)).toBe(true);
    expect(Object.isFrozen(NON_HIERARCHICAL_CAPABILITIES)).toBe(true);
    expect(() =>
      (CAPABILITY_HIERARCHY as unknown as string[]).reverse(),
    ).toThrow(TypeError);
  });
});

describe('generated streaming and admission boundaries', () => {
  test('framing round trips across arbitrary network chunk boundaries', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 2048 }),
        fc.array(fc.integer({ min: 1, max: 80 }), {
          minLength: 1,
          maxLength: 20,
        }),
        async (payload, widths) => {
          const input = new Uint8Array(payload);
          const frame = encodeInvitationProtocolFrame(input, 2048);
          input.fill(19);
          const result = await readInvitationProtocolFrame(
            fragmented(frame, widths),
            2048,
          );
          expect([...result]).toEqual([...payload]);
        },
      ),
      { seed: 9513, numRuns: 300 },
    );
  });

  test('every truncation and over-limit header fails for arbitrary fragmentation', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 512 }),
        fc.nat(),
        fc.array(fc.integer({ min: 1, max: 20 }), {
          minLength: 1,
          maxLength: 10,
        }),
        async (payload, cut, widths) => {
          const frame = encodeInvitationProtocolFrame(payload, 512);
          await expect(
            readInvitationProtocolFrame(
              fragmented(frame.subarray(0, cut % frame.length), widths),
              512,
            ),
          ).rejects.toThrow();
          const header = new Uint8Array(4);
          new DataView(header.buffer).setUint32(0, 513, false);
          await expect(
            readInvitationProtocolFrame(fragmented(header, widths), 512),
          ).rejects.toThrow(RangeError);
        },
      ),
      { seed: 9514, numRuns: 300 },
    );
  });

  test('runtime work admission rejects invalid counts and leaves counters unchanged on rejection', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 10000 }),
        fc.array(
          fc.oneof(
            fc.integer({ min: 0, max: 1000 }),
            fc.constantFrom(
              -1,
              NaN,
              Infinity,
              1.5,
              Number.MAX_SAFE_INTEGER + 1,
            ),
          ),
          { maxLength: 40 },
        ),
        (limit, counts) => {
          const codec = {
            typeName: 'property',
            maxAggregateWorkItems: limit,
          } as V2WireCodec;
          const budget = createV2DecodeBudget(codec);
          let used = 0;
          for (const count of counts) {
            const valid =
              Number.isSafeInteger(count) &&
              count >= 0 &&
              count <= limit - used;
            if (valid) {
              reserveV2Work(budget, count, 'generated');
              used += count;
            } else
              expect(() => reserveV2Work(budget, count, 'generated')).toThrow();
            expect(budget.workItems).toBe(used);
          }
        },
      ),
      { seed: 9515, numRuns: 300 },
    );
  });
});
