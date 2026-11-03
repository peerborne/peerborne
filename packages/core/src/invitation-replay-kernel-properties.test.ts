import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  advanceInvitationReplayClock,
  collectExpiredInvitationClaims,
  nextInvitationReplayExpiry,
  recordInvitationReplayAcceptance,
  recordInvitationReplayJoin,
  retireInvitationReplayClaim,
  shouldSweepInvitationReplays,
  type InvitationReplayClaim,
  type InvitationReplayEnvelope,
} from './policy/replay-admission.js';

const label = (id: number) =>
  ['__proto__', 'constructor', '\ud800', '', '\uffff'][id] ?? `key-${id}`;
const timestamp = fc.oneof(
  fc.nat(1000000),
  fc.constant(Number.MAX_SAFE_INTEGER),
);

test('native replay indexes keep distinct owned maps and detach completed claim records', () => {
  fc.assert(
    fc.property(
      fc.uniqueArray(fc.integer({ min: 0, max: 40 }), { maxLength: 24 }),
      fc.array(fc.boolean(), { minLength: 4, maxLength: 4 }),
      timestamp,
      (ids, rebound, expiry) => {
        const claims = new Map<string, InvitationReplayClaim>();
        const offers = new Map<string, string>();
        const requests = new Map<string, InvitationReplayEnvelope>();
        const acceptances = new Map<string, InvitationReplayEnvelope>();
        const refs = [claims, offers, requests, acceptances];
        expect(new Set(refs).size).toBe(4);
        for (const id of ids) {
          const offer = label(id),
            invitation = `invitation:${offer}`,
            request = `request:${offer}`,
            accepted = rebound[3] ? `accepted:${offer}` : '';
          const recorded = recordInvitationReplayJoin(
            claims,
            offers,
            requests,
            acceptances,
            invitation,
            offer,
            expiry,
            request,
            `join-digest:${offer}`,
          );
          expect(
            [
              recorded.claims,
              recorded.offers,
              recorded.requests,
              recorded.acceptances,
            ].every((map, index) => map === refs[index]),
          ).toBe(true);
          const before = claims.get(offer)!;
          expect(before).toEqual({
            invitationId: invitation,
            offerDigest: offer,
            expiresAtMs: expiry,
            requestId: request,
            requestDigest: `join-digest:${offer}`,
            accepted: false,
            acceptanceId: '',
            acceptanceDigest: '',
          });
          if (rebound[3]) {
            const completed = recordInvitationReplayAcceptance(
              claims,
              offers,
              requests,
              acceptances,
              offer,
              accepted,
              `acceptance-digest:${offer}`,
            );
            expect(
              [
                completed.claims,
                completed.offers,
                completed.requests,
                completed.acceptances,
              ].every((map, index) => map === refs[index]),
            ).toBe(true);
            const current = claims.get(offer)!;
            expect(current).not.toBe(before);
            expect(current).toEqual({
              ...before,
              accepted: true,
              acceptanceId: accepted,
              acceptanceDigest: `acceptance-digest:${offer}`,
            });
            Reflect.set(before, 'requestId', 'mutated-obsolete-claim');
            expect(current.requestId).toBe(request);
          }
        }
        expect(claims.size).toBe(ids.length);
        for (const id of ids) {
          const offer = label(id),
            invitation = `invitation:${offer}`,
            request = `request:${offer}`,
            accepted = rebound[3] ? `accepted:${offer}` : '';
          const other = `unrelated:${offer}`;
          if (rebound[0]) offers.set(invitation, other);
          if (rebound[1])
            requests.set(request, {
              offerDigest: other,
              envelopeDigest: 'unrelated-request',
            });
          if (rebound[2])
            acceptances.set(accepted, {
              offerDigest: rebound[3] ? other : offer,
              envelopeDigest: 'unrelated-acceptance',
            });
          const retired = retireInvitationReplayClaim(
            claims,
            offers,
            requests,
            acceptances,
            offer,
          );
          expect(
            [
              retired.claims,
              retired.offers,
              retired.requests,
              retired.acceptances,
            ].every((map, index) => map === refs[index]),
          ).toBe(true);
          expect(claims.has(offer)).toBe(false);
          expect(offers.get(invitation)).toBe(rebound[0] ? other : undefined);
          expect(requests.get(request)).toEqual(
            rebound[1]
              ? { offerDigest: other, envelopeDigest: 'unrelated-request' }
              : undefined,
          );
          expect(acceptances.get(accepted)).toEqual(
            rebound[2]
              ? {
                  offerDigest: rebound[3] ? other : offer,
                  envelopeDigest: 'unrelated-acceptance',
                }
              : undefined,
          );
          const snapshot = [
            [...claims],
            [...offers],
            [...requests],
            [...acceptances],
          ];
          retireInvitationReplayClaim(
            claims,
            offers,
            requests,
            acceptances,
            offer,
          );
          expect([
            [...claims],
            [...offers],
            [...requests],
            [...acceptances],
          ]).toEqual(snapshot);
        }
      },
    ),
    {
      seed: 2011305,
      numRuns: 100,
      examples: [
        [[0, 1, 2, 3, 4], [true, true, true, true], Number.MAX_SAFE_INTEGER],
      ],
    },
  );
});

test('native expiry projections own their arrays and match independent BigInt time oracles', () => {
  fc.assert(
    fc.property(
      fc.uniqueArray(
        fc.record({ id: fc.integer({ min: 0, max: 100 }), expires: timestamp }),
        { selector: (entry) => entry.id, maxLength: 80 },
      ),
      timestamp,
      (entries, now) => {
        const claims = new Map<string, InvitationReplayClaim>(
          entries.map(({ id, expires }) => [
            label(id),
            {
              invitationId: `invitation:${id}`,
              offerDigest: label(id),
              expiresAtMs: expires,
              requestId: `request:${id}`,
              requestDigest: `digest:${id}`,
              accepted: false,
              acceptanceId: '',
              acceptanceDigest: '',
            },
          ]),
        );
        const keys = [...claims.keys()],
          original = [...claims];
        const expected = entries
          .filter(({ expires }) => BigInt(expires) <= BigInt(now))
          .map(({ id }) => label(id));
        const remaining = entries.filter(
          ({ expires }) => BigInt(expires) > BigInt(now),
        );
        const next = Number(
          remaining.reduce(
            (minimum, { expires }) =>
              BigInt(expires) < minimum ? BigInt(expires) : minimum,
            BigInt(Number.MAX_SAFE_INTEGER),
          ),
        );
        const first = collectExpiredInvitationClaims(keys, claims, now);
        const second = collectExpiredInvitationClaims(keys, claims, now);
        expect(first).toEqual({ expired: expected, nextExpiry: next });
        expect([...claims]).toEqual(original);
        expect(keys).toEqual(original.map(([key]) => key));
        expect(first.expired).not.toBe(second.expired);
        (first.expired as string[]).push('mutated-projection');
        keys.push('mutated-input');
        claims.clear();
        expect(second).toEqual({ expired: expected, nextExpiry: next });
        let clock = 0,
          frontier = Number.MAX_SAFE_INTEGER;
        for (const { expires } of entries) {
          const maximum =
            BigInt(clock) > BigInt(expires) ? BigInt(clock) : BigInt(expires);
          const minimum =
            BigInt(frontier) < BigInt(expires)
              ? BigInt(frontier)
              : BigInt(expires);
          clock = advanceInvitationReplayClock(clock, expires);
          frontier = nextInvitationReplayExpiry(frontier, expires);
          expect(BigInt(clock)).toBe(maximum);
          expect(BigInt(frontier)).toBe(minimum);
        }
        expect(shouldSweepInvitationReplays(frontier, now)).toBe(
          BigInt(frontier) <= BigInt(now),
        );
      },
    ),
    { seed: 2011306, numRuns: 100 },
  );
});
