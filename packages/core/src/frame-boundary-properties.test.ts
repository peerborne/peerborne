import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { boundedFieldEnd, frameCopyLength } from './policy/frame-layout.js';
import {
  serializeGroupSecurityTransitionRecord,
  deserializeGroupSecurityTransitionRecord,
} from './group-security-transition-record.js';
import {
  MEMBERSHIP_CONTROL_VERSION,
  serializeMembershipControlRecord,
} from './membership-control-record.js';

const u32 = fc.integer({ min: 0, max: 0xffffffff });

describe('generated binary framing boundaries', () => {
  test('calibrates native range and copy arithmetic against BigInt at uint32/safe-integer limits', () => {
    fc.assert(
      fc.property(
        u32,
        u32,
        u32,
        u32,
        u32,
        u32,
        fc.maxSafeNat(),
        (total, position, length, lower, upper, trailer, available) => {
          const offset = Math.min(total, position);
          const minimum = Math.min(lower, upper);
          const maximum = Math.max(lower, upper);
          const end = BigInt(offset) + BigInt(length);
          const valid =
            length >= minimum &&
            length <= maximum &&
            end + BigInt(trailer) <= BigInt(total);
          expect(
            boundedFieldEnd(total, offset, length, minimum, maximum, trailer),
          ).toBe(valid ? Number(end) : -1);
          const remaining = BigInt(total) - BigInt(offset);
          expect(frameCopyLength(offset, total, available)).toBe(
            Number(
              remaining < BigInt(available) ? remaining : BigInt(available),
            ),
          );
        },
      ),
      {
        seed: 9705,
        numRuns: 2000,
        examples: [
          [16, 4, 8, 1, 8, 4, 0],
          [16, 4, 9, 1, 9, 4, Number.MAX_SAFE_INTEGER],
          [
            0xffffffff,
            0xfffffffe,
            1,
            0,
            0xffffffff,
            0,
            Number.MAX_SAFE_INTEGER,
          ],
          [0, 0, 0, 0, 0, 0, 0],
        ],
      },
    );
  });

  test('checks native ESM stream chunk properties', async () => {
    await promisify(execFile)(
      process.execPath,
      [
        '--import',
        'tsx',
        '--test',
        `${__dirname}/frame-native-properties.fixture.mjs`,
      ],
      { timeout: 60_000 },
    );
  }, 70_000);

  test('rejects hostile transition field lengths, truncations and suffixes while detaching accepted records', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
        fc.uint8Array({ minLength: 1, maxLength: 256 }),
        fc.uint8Array({ maxLength: 512 }),
        fc.integer({ min: 0, max: 0xffff }),
        fc.nat(),
        fc.oneof(
          fc.constant('p'.repeat(128)),
          fc
            .array(fc.constantFrom('a', 'Z', '1', '-', '.', '/', '_'), {
              maxLength: 127,
            })
            .map((tail) => `p${tail.join('')}`),
        ),
        (
          epoch,
          controlPayload,
          deliveryPayload,
          codecVersion,
          cut,
          codecId,
        ) => {
          const value = {
            version: 1,
            deliveryCodec: { id: codecId, version: codecVersion },
            controlRecord: {
              version: MEMBERSHIP_CONTROL_VERSION,
              protocol: { id: 'property.protocol', version: 1 },
              groupId: new Uint8Array([1]),
              epoch,
              parentRecordId: undefined,
              operationId: new Uint8Array(32),
              action: 'create' as const,
              actorId: new Uint8Array([1]),
              subjectId: new Uint8Array([2]),
              controlPayload,
              signature: new Uint8Array([3]),
            },
            deliveryPayload,
          };
          const controlBytes = serializeMembershipControlRecord(
            value.controlRecord,
          );
          const frame = serializeGroupSecurityTransitionRecord(value);
          const padded = new Uint8Array(frame.length + 4);
          padded.set(frame, 2);
          const input = padded.subarray(2, 2 + frame.length);
          const decoded = deserializeGroupSecurityTransitionRecord(input);
          input.fill(0xff);
          expect(serializeGroupSecurityTransitionRecord(decoded)).toEqual(
            frame,
          );
          const second = deserializeGroupSecurityTransitionRecord(frame);
          decoded.deliveryPayload.fill(0xff);
          decoded.controlRecord.controlPayload.fill(0xff);
          expect(serializeGroupSecurityTransitionRecord(second)).toEqual(frame);
          const codecLength = value.deliveryCodec.id.length;
          const controlOffset = 14 + codecLength;
          const deliveryOffset = 18 + codecLength + controlBytes.length;
          for (const [offset, width, length] of [
            [10, 2, 0],
            [10, 2, 0xffff],
            [controlOffset, 4, 0],
            [controlOffset, 4, 0xffffffff],
            [deliveryOffset, 4, deliveryPayload.length + 1],
            [deliveryOffset, 4, 0xffffffff],
          ]) {
            const hostile = new Uint8Array(frame);
            const view = new DataView(hostile.buffer);
            if (width === 2) view.setUint16(offset, length, false);
            else view.setUint32(offset, length, false);
            expect(() =>
              deserializeGroupSecurityTransitionRecord(hostile),
            ).toThrow();
          }
          expect(() =>
            deserializeGroupSecurityTransitionRecord(
              frame.subarray(0, cut % frame.length),
            ),
          ).toThrow();
          const trailing = new Uint8Array(frame.length + 1);
          trailing.set(frame);
          expect(() =>
            deserializeGroupSecurityTransitionRecord(trailing),
          ).toThrow();
        },
      ),
      { seed: 9707, numRuns: 300 },
    );
  });
});
