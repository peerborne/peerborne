import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import { InMemoryInvitationReplayGuard } from './invitation-replay-guard.js';
import {
  digestInvitationJoinRequest,
  digestInvitationOffer,
  digestInvitationAcceptance,
  signInvitationOffer,
  signInvitationJoinRequest,
  signInvitationAcceptance,
  verifyInvitationOffer,
  verifyInvitationJoinRequest,
  verifyInvitationAcceptance,
  type InvitationAcceptanceV1,
  type InvitationJoinRequestV1,
  type InvitationOfferV1,
} from './invitation-wire.js';
import type {
  InvitationReplayClaim,
  InvitationReplayEnvelope,
} from './policy/replay-admission.js';

const NOW = 2_000_000_000_000;
const LIFETIME = 60000;
const bytes = (length: number, seed: number) =>
  new Uint8Array(length).fill(seed);

async function envelopes(
  seed: number,
  issued = NOW - 1000,
  expires = NOW + LIFETIME,
) {
  const offer: InvitationOfferV1 = {
    version: 1,
    invitationId: bytes(32, seed),
    documentId: `/invitation/property/${seed}`,
    issuer: `issuer-${seed}`,
    role: 'editor',
    issuedAtMs: issued,
    expiresAtMs: expires,
    rendezvous: [`/dns4/relay-${seed}.example/tcp/443/wss`],
    signature: bytes(96, seed + 10),
  };
  const point = bytes(65, seed + 20);
  point[0] = 4;
  const request: InvitationJoinRequestV1 = {
    version: 1,
    offerDigest: await digestInvitationOffer(offer),
    requestId: bytes(32, seed + 30),
    documentId: offer.documentId,
    role: offer.role,
    recipient: `recipient-${seed}`,
    recipientKemPublicKey: point,
    signature: bytes(96, seed + 40),
  };
  const acceptance: InvitationAcceptanceV1 = {
    version: 1,
    acceptanceId: bytes(32, seed + 50),
    offerDigest: request.offerDigest.slice(),
    requestDigest: await digestInvitationJoinRequest(request),
    documentId: offer.documentId,
    issuer: offer.issuer,
    recipient: request.recipient,
    recipientKemPublicKey: point.slice(),
    role: offer.role,
    welcomeEpochId: bytes(32, seed + 60),
    sealedWelcome: bytes(125, seed + 70),
    encryptedBootstrap: bytes(64, seed + 80),
    issuedAtMs: Math.max(NOW, issued),
    expiresAtMs: expires,
    signature: bytes(96, seed + 90),
  };
  return { offer, request, acceptance };
}

function pauseFirstDigest() {
  const native = crypto.subtle.digest.bind(crypto.subtle);
  let entered!: () => void;
  let release!: () => void;
  let held = false;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const mock = jest
    .spyOn(crypto.subtle, 'digest')
    .mockImplementation(async (...args) => {
      if (!held) {
        held = true;
        entered();
        await gate;
      }
      return native(...args);
    });
  return { started, release, restore: () => mock.mockRestore() };
}

type Envelopes = Awaited<ReturnType<typeof envelopes>>;
type Kind = 'join' | 'acceptance';
function observe(
  guard: InMemoryInvitationReplayGuard,
  value: Envelopes,
  kind: Kind,
  now?: number,
) {
  return kind === 'join'
    ? guard.observeJoin(value.offer, value.request, now)
    : guard.observeAcceptance(
        value.offer,
        value.request,
        value.acceptance,
        now,
      );
}

test('rechecks hard invitation expiry after asynchronous digest preparation', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom<Kind>('join', 'acceptance'),
      fc.integer({ min: 59999, max: 60001 }),
      async (kind, delay) => {
        const value = await envelopes(1);
        const guard = new InMemoryInvitationReplayGuard();
        let now = NOW;
        const date = jest.spyOn(Date, 'now').mockImplementation(() => now);
        const paused = pauseFirstDigest();
        try {
          const pending = observe(guard, value, kind);
          await Promise.race([
            paused.started,
            pending.then(() => {
              throw new Error('Expected digest preparation');
            }),
          ]);
          now += delay;
          paused.release();
          if (delay < LIFETIME) {
            await expect(pending).resolves.toBe('accepted');
            expect(guard.size).toBe(1);
          } else {
            await expect(pending).rejects.toMatchObject({ code: 'expired' });
            expect(guard.size).toBe(0);
          }
        } finally {
          paused.release();
          paused.restore();
          date.mockRestore();
        }
      },
    ),
    {
      seed: 2011301,
      numRuns: 12,
      examples: [
        ['join', 60000],
        ['acceptance', 60000],
        ['join', 59999],
        ['acceptance', 60001],
      ],
    },
  );
});

test('retired invitations cannot revive after clock rollback or delayed older observations', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom<Kind>('join', 'acceptance'),
      fc.boolean(),
      async (kind, overlapping) => {
        const first = await envelopes(2);
        const later = await envelopes(
          3,
          NOW + LIFETIME - 1000,
          NOW + 2 * LIFETIME,
        );
        const guard = new InMemoryInvitationReplayGuard(2);
        await observe(guard, first, kind, NOW);
        const paused = overlapping ? pauseFirstDigest() : undefined;
        let pending: Promise<unknown> | undefined;
        try {
          if (paused) {
            pending = observe(guard, first, kind, NOW);
            await Promise.race([
              paused.started,
              pending.then(() => {
                throw new Error('Expected digest preparation');
              }),
            ]);
          }
          await observe(guard, later, kind, NOW + LIFETIME);
          expect(guard.size).toBe(1);
          if (pending) {
            paused!.release();
            await expect(pending).rejects.toMatchObject({ code: 'expired' });
          }
          await expect(observe(guard, first, kind, NOW)).rejects.toMatchObject({
            code: 'expired',
          });
          expect(guard.size).toBe(1);
        } finally {
          paused?.release();
          paused?.restore();
        }
      },
    ),
    {
      seed: 2011302,
      numRuns: 12,
      examples: [
        ['join', false],
        ['acceptance', true],
      ],
    },
  );
});

test('live invitation bursts and exact replays avoid full index sweeps', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 16, max: 48 }), async (count) => {
      const values = await Promise.all(
        Array.from({ length: count }, (_, index) => envelopes(index + 10)),
      );
      const guard = new InMemoryInvitationReplayGuard(count);
      const claims = (
        guard as unknown as { _claimsByOffer: Map<string, unknown> }
      )._claimsByOffer;
      let visited = 0;
      const entries = Map.prototype.entries;
      const keys = Map.prototype.keys;
      Object.defineProperty(claims, Symbol.iterator, {
        value: function* () {
          for (const entry of entries.call(claims)) {
            visited++;
            yield entry;
          }
        },
      });
      Object.defineProperty(claims, 'keys', {
        value: function* () {
          for (const key of keys.call(claims)) {
            visited++;
            yield key;
          }
        },
      });
      for (const value of values)
        await expect(observe(guard, value, 'join', NOW)).resolves.toBe(
          'accepted',
        );
      for (const value of values)
        await expect(observe(guard, value, 'join', NOW)).resolves.toBe(
          'replay',
        );
      expect(guard.size).toBe(count);
      expect(visited).toBe(0);
    }),
    { seed: 2011303, numRuns: 4 },
  );
});

test('the configured replay capacity remains immutable across native callers', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom<unknown>(0, 65536, 'unbounded', NaN, Infinity),
      async (replacement) => {
        const guard = new InMemoryInvitationReplayGuard(1);
        expect(Reflect.set(guard, 'maxEntries', replacement)).toBe(false);
        expect(guard.maxEntries).toBe(1);
        const first = await envelopes(4),
          second = await envelopes(5);
        await observe(guard, first, 'join', NOW);
        await expect(observe(guard, second, 'join', NOW)).rejects.toMatchObject(
          { code: 'capacity-exceeded' },
        );
        await expect(observe(guard, first, 'join', NOW)).resolves.toBe(
          'replay',
        );
        expect(guard.size).toBe(1);
      },
    ),
    { seed: 2011304, numRuns: 10 },
  );
});

const hex = (value: Uint8Array) =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

interface ModelEnvelope {
  readonly value: Envelopes;
  readonly offer: string;
  readonly invitation: string;
  readonly request: string;
  readonly requestDigest: string;
  readonly acceptance: string;
  readonly acceptanceDigest: string;
}
interface ModelClaim {
  readonly envelope: ModelEnvelope;
  readonly accepted?: ModelEnvelope;
}

async function modelEnvelopes(): Promise<ModelEnvelope[]> {
  const result: ModelEnvelope[] = [];
  for (let index = 0; index < 6; index++) {
    const base = await envelopes(
      60 + index,
      NOW - 1000,
      NOW + (index + 1) * LIFETIME,
    );
    const offer = {
      ...base.offer,
      invitationId: bytes(32, index === 1 ? 1 : index + 1),
    };
    const offerDigest = await digestInvitationOffer(offer);
    for (let requestVariant = 0; requestVariant < 2; requestVariant++) {
      const request = {
        ...base.request,
        offerDigest: offerDigest.slice(),
        requestId: bytes(
          32,
          index === 2 && requestVariant === 0
            ? 10
            : index * 2 + requestVariant + 10,
        ),
        recipient: `recipient-${index}-${requestVariant}`,
        signature: bytes(96, 100 + index * 2 + requestVariant),
      };
      const requestDigest = await digestInvitationJoinRequest(request);
      for (
        let acceptanceVariant = 0;
        acceptanceVariant < 2;
        acceptanceVariant++
      ) {
        const acceptance = {
          ...base.acceptance,
          offerDigest: offerDigest.slice(),
          requestDigest: requestDigest.slice(),
          recipient: request.recipient,
          acceptanceId: bytes(
            32,
            index === 3 && acceptanceVariant === 0
              ? 20
              : 20 + index * 4 + requestVariant * 2 + acceptanceVariant,
          ),
          signature: bytes(
            96,
            140 + index * 4 + requestVariant * 2 + acceptanceVariant,
          ),
        };
        result.push({
          value: { offer, request, acceptance },
          offer: hex(offerDigest),
          invitation: hex(offer.invitationId),
          request: hex(request.requestId),
          requestDigest: hex(requestDigest),
          acceptance: hex(acceptance.acceptanceId),
          acceptanceDigest: hex(await digestInvitationAcceptance(acceptance)),
        });
      }
    }
  }
  return result;
}

test('native admission and retirement histories match an independent tuple ledger', async () => {
  const catalog = await modelEnvelopes();
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 1, max: 6 }),
      fc.array(
        fc.record({
          entry: fc.integer({ min: 0, max: 23 }),
          kind: fc.constantFrom<Kind>('join', 'acceptance'),
          time: fc.oneof(
            fc.nat(240000),
            fc.constantFrom(0, 59999, 60000, 119999, 120000, 179999, 180000),
          ),
        }),
        { maxLength: 80 },
      ),
      async (capacity, actions) => {
        const guard = new InMemoryInvitationReplayGuard(capacity);
        const state = guard as unknown as {
          _claimsByOffer: Map<string, InvitationReplayClaim>;
          _offersById: Map<string, string>;
          _requestsById: Map<string, InvitationReplayEnvelope>;
          _acceptancesById: Map<string, InvitationReplayEnvelope>;
          _observedAtMs: number;
          _nextExpiryAtMs: number;
        };
        let rows: ModelClaim[] = [],
          clock = 0;
        const prelude = [
          { entry: 0, kind: 'join' as const, time: 0 },
          { entry: 0, kind: 'acceptance' as const, time: 0 },
          { entry: 0, kind: 'acceptance' as const, time: 0 },
          { entry: 2, kind: 'join' as const, time: 0 },
          { entry: 1, kind: 'acceptance' as const, time: 0 },
          { entry: 4, kind: 'join' as const, time: 0 },
          { entry: 8, kind: 'join' as const, time: 0 },
          { entry: 12, kind: 'acceptance' as const, time: 0 },
          { entry: 20, kind: 'join' as const, time: 0 },
          { entry: 4, kind: 'join' as const, time: LIFETIME },
          { entry: 0, kind: 'acceptance' as const, time: 0 },
        ];
        for (const action of [...prelude, ...actions]) {
          const envelope = catalog[action.entry];
          clock = Math.max(clock, NOW + action.time);
          let outcome: string;
          if (envelope.value.offer.expiresAtMs <= clock) {
            outcome = 'expired';
          } else {
            rows = rows.filter(
              (row) => row.envelope.value.offer.expiresAtMs > clock,
            );
            const byInvitation = rows.find(
              (row) => row.envelope.invitation === envelope.invitation,
            );
            const byRequest = rows.find(
              (row) => row.envelope.request === envelope.request,
            );
            const existing = rows.find(
              (row) => row.envelope.offer === envelope.offer,
            );
            if (byInvitation && byInvitation.envelope.offer !== envelope.offer)
              outcome = 'invitation-id-conflict';
            else if (
              byRequest &&
              (byRequest.envelope.offer !== envelope.offer ||
                byRequest.envelope.requestDigest !== envelope.requestDigest)
            )
              outcome = 'request-id-conflict';
            else if (
              existing &&
              (existing.envelope.request !== envelope.request ||
                existing.envelope.requestDigest !== envelope.requestDigest)
            )
              outcome = 'offer-already-claimed';
            else if (!existing && rows.length >= capacity)
              outcome = 'capacity-exceeded';
            else if (action.kind === 'join') {
              outcome = existing ? 'replay' : 'accepted';
              if (!existing) rows.push({ envelope });
            } else {
              const byAcceptance = rows.find(
                (row) => row.accepted?.acceptance === envelope.acceptance,
              );
              if (
                byAcceptance &&
                (byAcceptance.envelope.offer !== envelope.offer ||
                  byAcceptance.accepted!.acceptanceDigest !==
                    envelope.acceptanceDigest)
              )
                outcome = 'acceptance-id-conflict';
              else if (existing?.accepted)
                outcome =
                  existing.accepted.acceptance === envelope.acceptance &&
                  existing.accepted.acceptanceDigest ===
                    envelope.acceptanceDigest
                    ? 'replay'
                    : 'offer-already-consumed';
              else {
                outcome = 'accepted';
                if (existing)
                  rows = rows.map((row) =>
                    row === existing ? { ...row, accepted: envelope } : row,
                  );
                else rows.push({ envelope, accepted: envelope });
              }
            }
          }
          let actual: unknown;
          try {
            actual = await observe(
              guard,
              envelope.value,
              action.kind,
              NOW + action.time,
            );
          } catch (error) {
            actual = (error as { code?: unknown }).code;
          }
          expect(actual).toBe(outcome);
          expect(guard.size).toBe(rows.length);
          expect(state._observedAtMs).toBe(clock);
          expect(state._nextExpiryAtMs).toBe(
            rows.reduce(
              (next, row) =>
                Math.min(next, row.envelope.value.offer.expiresAtMs),
              Number.MAX_SAFE_INTEGER,
            ),
          );
          expect(state._offersById.size).toBe(rows.length);
          expect(state._requestsById.size).toBe(rows.length);
          expect(state._acceptancesById.size).toBe(
            rows.filter((row) => row.accepted).length,
          );
          for (const row of rows) {
            const input = row.envelope,
              accepted = row.accepted;
            expect(state._claimsByOffer.get(input.offer)).toEqual({
              invitationId: input.invitation,
              offerDigest: input.offer,
              expiresAtMs: input.value.offer.expiresAtMs,
              requestId: input.request,
              requestDigest: input.requestDigest,
              accepted: accepted !== undefined,
              acceptanceId: accepted?.acceptance ?? '',
              acceptanceDigest: accepted?.acceptanceDigest ?? '',
            });
            expect(state._offersById.get(input.invitation)).toBe(input.offer);
            expect(state._requestsById.get(input.request)).toEqual({
              offerDigest: input.offer,
              envelopeDigest: input.requestDigest,
            });
            if (accepted)
              expect(state._acceptancesById.get(accepted.acceptance)).toEqual({
                offerDigest: input.offer,
                envelopeDigest: accepted.acceptanceDigest,
              });
          }
        }
      },
    ),
    { seed: 2011307, numRuns: 25 },
  );
});

test('malformed native clock values fail before hashing or consuming replay state', async () => {
  const value = await envelopes(7);
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom<unknown>(
        NaN,
        Infinity,
        -Infinity,
        -1,
        0.5,
        Number.MAX_SAFE_INTEGER + 1,
        'time',
        null,
        {},
        new Number(NOW),
      ),
      fc.constantFrom<Kind>('join', 'acceptance'),
      async (observed, kind) => {
        const guard = new InMemoryInvitationReplayGuard();
        const digest = jest.spyOn(crypto.subtle, 'digest');
        try {
          await expect(
            observe(guard, value, kind, observed as number),
          ).rejects.toThrow();
          expect(digest).not.toHaveBeenCalled();
          expect(guard.size).toBe(0);
        } finally {
          digest.mockRestore();
        }
        await expect(observe(guard, value, kind, NOW)).resolves.toBe(
          'accepted',
        );
        expect(guard.size).toBe(1);
      },
    ),
    { seed: 2011308, numRuns: 30 },
  );
});

test('signature-verified invitations cannot bind a second recipient after expiry retirement and rollback', async () => {
  const provider = new SubtleCrypto();
  const [issuer, recipient, attacker] = await Promise.all(
    Array.from({ length: 3 }, () =>
      crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
        'sign',
        'verify',
      ]),
    ),
  );
  const points = await Promise.all(
    Array.from({ length: 2 }, async () => {
      const key = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveKey'],
      );
      return new Uint8Array(
        await crypto.subtle.exportKey('raw', key.publicKey),
      );
    }),
  );
  const issuerName = await provider.serializePublicKey(issuer.publicKey);
  const identities = await Promise.all(
    [recipient, attacker].map((key) =>
      provider.serializePublicKey(key.publicKey),
    ),
  );
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom<Kind>('join', 'acceptance'),
      fc.integer({ min: 0, max: 30000 }),
      async (kind, gap) => {
        async function signed(
          seed: number,
          issuedAtMs: number,
          expiresAtMs: number,
          identity: number,
          reused?: InvitationOfferV1,
        ): Promise<Envelopes> {
          const offer =
            reused ??
            (await signInvitationOffer(
              {
                version: 1,
                invitationId: bytes(32, seed),
                documentId: `/signed-invitation/${seed}`,
                issuer: issuerName,
                role: 'editor',
                issuedAtMs,
                expiresAtMs,
                rendezvous: ['/dns4/relay.example/tcp/443/wss'],
              },
              issuer.privateKey,
              issuer.publicKey,
              provider,
            ));
          const keys = [recipient, attacker][identity];
          const request = await signInvitationJoinRequest(
            {
              version: 1,
              offerDigest: await digestInvitationOffer(offer),
              requestId: bytes(32, seed + 20),
              documentId: offer.documentId,
              role: offer.role,
              recipient: identities[identity],
              recipientKemPublicKey: points[identity],
            },
            keys.privateKey,
            keys.publicKey,
            provider,
          );
          const acceptance = await signInvitationAcceptance(
            {
              version: 1,
              acceptanceId: bytes(32, seed + 40),
              offerDigest: request.offerDigest,
              requestDigest: await digestInvitationJoinRequest(request),
              documentId: offer.documentId,
              issuer: offer.issuer,
              recipient: request.recipient,
              recipientKemPublicKey: request.recipientKemPublicKey,
              role: request.role,
              welcomeEpochId: bytes(32, seed + 60),
              sealedWelcome: bytes(125, seed + 80),
              encryptedBootstrap: bytes(64, seed + 100),
              issuedAtMs: Math.max(NOW, issuedAtMs),
              expiresAtMs: offer.expiresAtMs,
            },
            issuer.privateKey,
            issuer.publicKey,
            provider,
          );
          expect(
            await verifyInvitationOffer(offer, issuer.publicKey, provider),
          ).toBe(true);
          expect(
            await verifyInvitationJoinRequest(
              request,
              keys.publicKey,
              provider,
            ),
          ).toBe(true);
          expect(
            await verifyInvitationAcceptance(
              acceptance,
              issuer.publicKey,
              provider,
            ),
          ).toBe(true);
          return { offer, request, acceptance };
        }
        const first = await signed(10, NOW - 1000, NOW + LIFETIME, 0);
        const later = await signed(
          11,
          NOW + LIFETIME - 1000,
          NOW + 2 * LIFETIME + gap,
          0,
        );
        const conflicting = await signed(
          12,
          NOW - 1000,
          NOW + LIFETIME,
          1,
          first.offer,
        );
        const guard = new InMemoryInvitationReplayGuard(1);
        await expect(observe(guard, first, kind, NOW)).resolves.toBe(
          'accepted',
        );
        await expect(
          observe(guard, conflicting, kind, NOW),
        ).rejects.toMatchObject({ code: 'offer-already-claimed' });
        await expect(
          observe(guard, later, kind, NOW + LIFETIME + gap),
        ).resolves.toBe('accepted');
        await expect(
          observe(guard, conflicting, kind, NOW),
        ).rejects.toMatchObject({ code: 'expired' });
        expect(guard.size).toBe(1);
      },
    ),
    {
      seed: 2011309,
      numRuns: 6,
      examples: [
        ['join', 0],
        ['acceptance', 30000],
      ],
    },
  );
});
