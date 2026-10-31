import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  InitialLoadAuthenticationBudget,
  MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS,
  MAX_INITIAL_LOAD_AUTHENTICATION_WORK_BYTES,
  identifyInitialLoadSigner,
} from './initial-load-auth.js';
import { createInitialLoadSignerLookup } from './initial-load-trust.js';

const amount = fc.oneof(
  fc.integer({ min: 0, max: MAX_INITIAL_LOAD_AUTHENTICATION_WORK_BYTES + 1 }),
  fc.constantFrom(0, 1, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER),
);

describe('generated authentication runtime boundaries', () => {
  test('native budget histories preserve both counters on every refusal', () => {
    fc.assert(
      fc.property(fc.array(amount, { maxLength: 400 }), (amounts) => {
        const budget = new InitialLoadAuthenticationBudget();
        let attempts = 0n;
        let bytes = 0n;
        for (const value of [...amounts, ...Array(257).fill(0)]) {
          const valid = Number.isSafeInteger(value) && value >= 0;
          const accepted =
            valid &&
            attempts < BigInt(MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS) &&
            bytes + BigInt(value) <=
              BigInt(MAX_INITIAL_LOAD_AUTHENTICATION_WORK_BYTES);
          expect(budget.reserve(value)).toBe(accepted);
          if (accepted) {
            attempts++;
            bytes += BigInt(value);
          }
        }
      }),
      { seed: 9701, numRuns: 500 },
    );
  });

  test('concurrent verification shares a budget and owns bytes across callback and abort schedules', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.boolean(),
        fc.array(
          fc.record({
            trusted: fc.boolean(),
            outcome: fc.constantFrom('valid', 'invalid', 'throw', 'truthy'),
            abort: fc.boolean(),
            order: fc.nat({ max: 1000 }),
            payload: fc.uint8Array({ minLength: 1, maxLength: 40 }),
          }),
          { minLength: 257, maxLength: 290 },
        ),
        async (flood, requests) => {
          const budget = new InitialLoadAuthenticationBudget();
          const trustedSigners = createInitialLoadSignerLookup([
            { authorityId: 'writer', publicKey: 'local-key' },
          ]);
          const releases: Array<{ release: () => void; order: number }> = [];
          const observed: Array<{
            key: string;
            payload: Uint8Array;
            signature: Uint8Array;
            expected: Uint8Array;
          }> = [];
          let verifications = 0;
          let eligible = 0;
          const jobs = requests.map((request) => {
            const trusted = flood || request.trusted;
            const controller = new AbortController();
            const payload = new Uint8Array(request.payload);
            const signature = new Uint8Array([1, 2, 3]);
            const reserved =
              trusted && eligible++ < MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS;
            const job = identifyInitialLoadSigner({
              payload,
              signature,
              signerAuthority: trusted ? 'writer' : 'stranger',
              trustedSigners,
              budget,
              signal: controller.signal,
              verify: async (ownedPayload, key, ownedSignature) => {
                verifications++;
                await new Promise<void>((release) =>
                  releases.push({ release, order: request.order }),
                );
                observed.push({
                  key,
                  payload: new Uint8Array(ownedPayload),
                  signature: new Uint8Array(ownedSignature),
                  expected: request.payload,
                });
                ownedPayload.fill(0);
                ownedSignature.fill(0);
                if (request.outcome === 'throw')
                  throw new Error('synthetic verification failure');
                return (
                  request.outcome === 'truthy' ? 1 : request.outcome === 'valid'
                ) as boolean;
              },
            });
            payload.fill(0xff);
            signature.fill(0xff);
            if (request.abort) controller.abort();
            return { job, reserved, request };
          });
          expect(verifications).toBe(
            Math.min(eligible, MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS),
          );
          releases
            .sort((a, b) => a.order - b.order)
            .forEach(({ release }) => release());
          const results = await Promise.all(jobs.map(({ job }) => job));
          expect(observed).toHaveLength(verifications);
          observed.forEach(({ key, payload, signature, expected }) => {
            expect(key).toBe('local-key');
            expect(payload).toEqual(expected);
            expect(signature).toEqual(new Uint8Array([1, 2, 3]));
          });
          jobs.forEach(({ reserved, request }, index) => {
            expect(results[index]).toEqual(
              reserved && !request.abort && request.outcome === 'valid'
                ? { publicKey: 'local-key', keyIndex: 0 }
                : null,
            );
          });
        },
      ),
      { seed: 9702, numRuns: 80 },
    );
  });
});
