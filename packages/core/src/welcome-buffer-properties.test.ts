import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  PendingWelcomeBuffer,
  PENDING_WELCOME_MAX_BODY_BYTES,
  PENDING_WELCOMES_MAX_ENTRIES,
  PENDING_WELCOMES_MAX_RETAINED_BYTES,
} from './pending-welcome-buffer.js';

type ModelEntry = {
  key: string;
  size: number;
  authenticated: boolean;
  at: number;
  byte: number;
};
const mutation = fc.record({
  key: fc.integer({ min: 0, max: 23 }).map(String),
  size: fc.integer({ min: 1, max: 2048 }),
  authenticated: fc.boolean(),
  byte: fc.integer({ min: 0, max: 255 }),
  remove: fc.boolean(),
});

describe('Welcome buffer generated retention histories', () => {
  test('preserves ownership and matches count, replacement and prioritized eviction semantics', () => {
    fc.assert(
      fc.property(fc.array(mutation, { maxLength: 100 }), (program) => {
        const buffer = new PendingWelcomeBuffer();
        let model: ModelEntry[] = [];
        program.forEach((step, at) => {
          const previous = model.find((entry) => entry.key === step.key);
          if (step.remove) {
            expect(buffer.delete(step.key)).toBe(previous !== undefined);
            model = model.filter((entry) => entry.key !== step.key);
          } else {
            const body = new Uint8Array(step.size).fill(step.byte);
            const result = buffer.store(step.key, body, at, step.authenticated);
            body[0] ^= 0xff;
            if (previous && !step.authenticated)
              expect(result).toEqual({
                stored: false,
                replaced: false,
                evictedKeys: [],
              });
            else {
              model = model.filter((entry) => entry.key !== step.key);
              const evicted: string[] = [];
              while (
                model.length >= PENDING_WELCOMES_MAX_ENTRIES ||
                model.reduce((sum, entry) => sum + entry.size, 0) + step.size >
                  PENDING_WELCOMES_MAX_RETAINED_BYTES
              ) {
                const untrusted = model.findIndex(
                  (entry) => !entry.authenticated,
                );
                evicted.push(
                  model.splice(untrusted === -1 ? 0 : untrusted, 1)[0].key,
                );
              }
              model.push({
                key: step.key,
                size: step.size,
                authenticated: step.authenticated,
                at,
                byte: step.byte,
              });
              expect(result).toEqual({
                stored: true,
                replaced: previous !== undefined,
                evictedKeys: evicted,
              });
            }
          }
          expect(buffer.keysSnapshot()).toEqual(
            model.map((entry) => entry.key),
          );
          expect(buffer.retainedBytes).toBe(
            model.reduce((sum, entry) => sum + entry.size, 0),
          );
          expect(buffer.size).toBeLessThanOrEqual(PENDING_WELCOMES_MAX_ENTRIES);
          expect(buffer.retainedBytes).toBeLessThanOrEqual(
            PENDING_WELCOMES_MAX_RETAINED_BYTES,
          );
          const expected = model.find((entry) => entry.key === step.key);
          const owned = buffer.get(step.key);
          expect(owned === undefined).toBe(expected === undefined);
          if (owned && expected) {
            expect(owned.body.byteLength).toBe(expected.size);
            expect(owned.body[0]).toBe(expected.byte);
            expect(owned.authenticated).toBe(expected.authenticated);
            expect(owned.bufferedAtMs).toBe(expected.at);
            owned.body[0] ^= 0xff;
            expect(buffer.get(step.key)!.body[0]).toBe(expected.byte);
          }
        });
      }),
      { seed: 9505, numRuns: 150 },
    );
  });

  test('byte pressure evicts an unauthenticated body before an older authenticated body', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 255 }), (byte) => {
        const buffer = new PendingWelcomeBuffer();
        const body = new Uint8Array(PENDING_WELCOME_MAX_BODY_BYTES).fill(byte);
        buffer.store('trusted', body, 0, true);
        buffer.store('untrusted', body, 1, false);
        const result = buffer.store('new', body, 2, true);
        expect(result.evictedKeys).toEqual(['untrusted']);
        expect(buffer.keysSnapshot()).toEqual(['trusted', 'new']);
        expect(buffer.retainedBytes).toBe(2 * body.byteLength);
      }),
      { seed: 9506, numRuns: 8 },
    );
  });
});
