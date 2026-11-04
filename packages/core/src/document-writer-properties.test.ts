import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { DocumentBinaryWriter } from './internal/document-binary.js';
import * as byteUtilities from './utils.js';

function copies() {
  const original = byteUtilities.copyUnsharedUint8Array;
  let bytes = 0;
  const spy = jest
    .spyOn(byteUtilities, 'copyUnsharedUint8Array')
    .mockImplementation((...args: Parameters<typeof original>) => {
      const result = original(...args);
      bytes += result.byteLength;
      return result;
    });
  return {
    get bytes() {
      return bytes;
    },
    restore: () => spy.mockRestore(),
  };
}

function retainedParts(writer: DocumentBinaryWriter): readonly Uint8Array[] {
  return Object.getOwnPropertyDescriptor(writer, 'parts')!.value;
}

test('a rejected length-prefixed field leaves no prefix or owned payload behind', () => {
  fc.assert(
    fc.property(
      fc.uint8Array({ minLength: 1, maxLength: 32 }),
      fc.uint8Array({ minLength: 1, maxLength: 128 }),
      (prefix, payload) => {
        const writer = new DocumentBinaryWriter(
          prefix.length + payload.length + 3,
        );
        writer.fixed(prefix);
        const trace = copies();
        try {
          expect(() => writer.bytes(payload)).toThrow();
          expect(writer.finish()).toEqual(prefix);
          expect(trace.bytes).toBe(0);
          writer.integer(77, 1);
          expect(writer.finish()).toEqual(new Uint8Array([...prefix, 77]));
        } finally {
          trace.restore();
        }
      },
    ),
    { seed: 2011701, numRuns: 32 },
  );
});

test('an admitted length-prefixed field owns its payload exactly once', () => {
  fc.assert(
    fc.property(
      fc.uint8Array({ minLength: 1, maxLength: 65536 }),
      (payload) => {
        const expected = new Uint8Array(4 + payload.length);
        new DataView(expected.buffer).setUint32(0, payload.length, false);
        expected.set(payload, 4);
        const writer = new DocumentBinaryWriter(expected.length);
        const trace = copies();
        try {
          writer.bytes(payload);
          expect(trace.bytes).toBe(payload.length);
          payload.fill(0);
          expect(writer.finish()).toEqual(expected);
          writer.finish().fill(0);
          expect(writer.finish()).toEqual(expected);
        } finally {
          trace.restore();
        }
      },
    ),
    {
      seed: 2011702,
      numRuns: 32,
      examples: [255, 256, 65535, 65536].map((length): [Uint8Array] => [
        new Uint8Array(length).fill(7),
      ]),
    },
  );
});

test('zero-length fixed fields cannot grow retained storage outside the byte budget', () => {
  fc.assert(
    fc.property(fc.integer({ min: 1, max: 1000 }), (count) => {
      const writer = new DocumentBinaryWriter(0);
      const trace = copies();
      try {
        for (let index = 0; index < count; index++)
          writer.fixed(new Uint8Array());
        expect(writer.finish()).toEqual(new Uint8Array());
        expect(retainedParts(writer)).toHaveLength(0);
        expect(trace.bytes).toBe(0);
      } finally {
        trace.restore();
      }
    }),
    { seed: 2011703, numRuns: 24 },
  );
});

test('mixed write histories preserve exact wire bytes and bounded retained storage across rejections', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: 512 }),
      fc.array(
        fc.record({
          framed: fc.boolean(),
          payload: fc.uint8Array({ maxLength: 32 }),
          maximum: fc.integer({ min: 0, max: 64 }),
        }),
        { maxLength: 40 },
      ),
      (capacity, attempts) => {
        const writer = new DocumentBinaryWriter(capacity);
        let expected: number[] = [];
        const trace = copies();
        try {
          for (const attempt of attempts) {
            const field = attempt.framed
              ? [
                  ...new Uint8Array([
                    (attempt.payload.length >>> 24) & 255,
                    (attempt.payload.length >>> 16) & 255,
                    (attempt.payload.length >>> 8) & 255,
                    attempt.payload.length & 255,
                  ]),
                  ...attempt.payload,
                ]
              : [...attempt.payload];
            const accepted =
              field.length <= capacity - expected.length &&
              (!attempt.framed || attempt.payload.length <= attempt.maximum);
            const before = trace.bytes;
            const write = () =>
              attempt.framed
                ? writer.bytes(attempt.payload, attempt.maximum)
                : writer.fixed(attempt.payload);
            if (accepted) {
              write();
              expected = [...expected, ...field];
            } else expect(write).toThrow();
            expect(trace.bytes - before).toBe(
              accepted ? attempt.payload.length : 0,
            );
            expect(writer.finish()).toEqual(new Uint8Array(expected));
            const parts = retainedParts(writer);
            expect(parts.every((part) => part.byteLength > 0)).toBe(true);
            expect(parts.reduce((sum, part) => sum + part.byteLength, 0)).toBe(
              expected.length,
            );
            expect(parts.length).toBeLessThanOrEqual(expected.length);
            expect(trace.bytes).toBeLessThanOrEqual(expected.length);
          }
        } finally {
          trace.restore();
        }
      },
    ),
    { seed: 2011704, numRuns: 80 },
  );
});

test('a native payload-copy failure preserves the previous frame and permits a later write', () => {
  fc.assert(
    fc.property(
      fc.uint8Array({ minLength: 1, maxLength: 32 }),
      fc.uint8Array({ minLength: 1, maxLength: 64 }),
      (prefix, payload) => {
        const writer = new DocumentBinaryWriter(
          prefix.length + payload.length + 4,
        );
        writer.fixed(prefix);
        const before = retainedParts(writer).slice();
        const spy = jest
          .spyOn(byteUtilities, 'copyUnsharedUint8Array')
          .mockImplementationOnce(() => {
            throw new Error('Synthetic copy failure');
          });
        try {
          expect(() => writer.bytes(payload)).toThrow('Synthetic copy failure');
          expect(writer.finish()).toEqual(prefix);
          expect(retainedParts(writer)).toEqual(before);
        } finally {
          spy.mockRestore();
        }
        writer.bytes(payload);
        const expected = new Uint8Array(prefix.length + payload.length + 4);
        expected.set(prefix);
        new DataView(expected.buffer).setUint32(
          prefix.length,
          payload.length,
          false,
        );
        expected.set(payload, prefix.length + 4);
        expect(writer.finish()).toEqual(expected);
      },
    ),
    { seed: 2011705, numRuns: 32 },
  );
});

test('invalid capacities and field bounds reject without modifying the writer', () => {
  fc.assert(
    fc.property(
      fc.constantFrom(
        NaN,
        Infinity,
        -Infinity,
        -1,
        0.5,
        0x100000000,
        Number.MAX_SAFE_INTEGER,
      ),
      fc.uint8Array({ maxLength: 32 }),
      (invalid, payload) => {
        expect(() => new DocumentBinaryWriter(invalid)).toThrow();
        const writer = new DocumentBinaryWriter(64);
        writer.integer(77, 1);
        const trace = copies();
        try {
          expect(() => writer.bytes(payload, invalid)).toThrow();
          expect(writer.finish()).toEqual(new Uint8Array([77]));
          expect(trace.bytes).toBe(0);
        } finally {
          trace.restore();
        }
      },
    ),
    { seed: 2011706, numRuns: 32 },
  );
});

test('native byte-view validation ignores hooks and rejects shared or detached backing before mutation', () => {
  fc.assert(
    fc.property(
      fc.uint8Array({ minLength: 1, maxLength: 64 }),
      fc.constantFrom('hooks', 'shared', 'detached'),
      (payload, kind) => {
        const expected = payload.slice();
        const writer = new DocumentBinaryWriter(128);
        writer.integer(77, 1);
        let source: Uint8Array;
        if (kind === 'shared') {
          source = new Uint8Array(new SharedArrayBuffer(payload.length));
          source.set(payload);
        } else {
          source = payload.slice();
          if (kind === 'detached')
            structuredClone(source.buffer, { transfer: [source.buffer] });
          else {
            const unexpected = () => {
              throw new Error('Byte-view hook was invoked');
            };
            for (const name of [
              'length',
              'byteLength',
              'buffer',
              Symbol.iterator,
              'slice',
            ])
              Object.defineProperty(source, name, { get: unexpected });
          }
        }
        if (kind === 'hooks') {
          writer.bytes(source);
          const encoded = new Uint8Array(5 + expected.length);
          encoded[0] = 77;
          new DataView(encoded.buffer).setUint32(1, expected.length, false);
          encoded.set(expected, 5);
          expect(writer.finish()).toEqual(encoded);
        } else {
          expect(() => writer.bytes(source)).toThrow();
          expect(writer.finish()).toEqual(new Uint8Array([77]));
        }
      },
    ),
    { seed: 2011707, numRuns: 48 },
  );
});
