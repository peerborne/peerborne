import { describe, expect, test } from '@jest/globals';

import {
  InMemoryInvitationReplayGuard,
  InvitationReplayError,
} from './invitation-replay-guard.js';
import {
  INVITATION_WIRE_VERSION,
  InvitationAcceptanceV1,
  InvitationJoinRequestV1,
  InvitationOfferV1,
  InvitationWireError,
  digestInvitationJoinRequest,
  digestInvitationOffer,
} from './invitation-wire.js';

const NOW = 2_000_000_000_000;

function bytes(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

function offer(seed: number): InvitationOfferV1 {
  return {
    version: INVITATION_WIRE_VERSION,
    invitationId: bytes(32, seed),
    documentId: `/documents/${seed}`,
    issuer: `issuer-${seed}`,
    role: 'editor',
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000,
    rendezvous: [`/dns4/relay-${seed}.peerborne.io/tcp/443/wss`],
    signature: bytes(96, seed + 10),
  };
}

async function joinRequest(
  invitation: InvitationOfferV1,
  seed: number,
  overrides: Partial<InvitationJoinRequestV1> = {},
): Promise<InvitationJoinRequestV1> {
  const kem = bytes(65, seed + 20);
  kem[0] = 4;
  return {
    version: INVITATION_WIRE_VERSION,
    offerDigest: await digestInvitationOffer(invitation),
    requestId: bytes(32, seed),
    documentId: invitation.documentId,
    role: invitation.role,
    recipient: `recipient-${seed}`,
    recipientKemPublicKey: kem,
    signature: bytes(96, seed + 30),
    ...overrides,
  };
}

async function acceptance(
  invitation: InvitationOfferV1,
  request: InvitationJoinRequestV1,
  seed: number,
  overrides: Partial<InvitationAcceptanceV1> = {},
): Promise<InvitationAcceptanceV1> {
  return {
    version: INVITATION_WIRE_VERSION,
    acceptanceId: bytes(32, seed),
    offerDigest: await digestInvitationOffer(invitation),
    requestDigest: await digestInvitationJoinRequest(request),
    documentId: invitation.documentId,
    issuer: invitation.issuer,
    recipient: request.recipient,
    recipientKemPublicKey: request.recipientKemPublicKey.slice(),
    role: request.role,
    welcomeEpochId: bytes(32, seed + 40),
    sealedWelcome: bytes(125, seed + 50),
    encryptedBootstrap: bytes(64, seed + 60),
    issuedAtMs: NOW,
    expiresAtMs: invitation.expiresAtMs,
    signature: bytes(96, seed + 70),
    ...overrides,
  };
}

async function expectReplayCode(
  action: () => Promise<unknown>,
  code: string,
): Promise<void> {
  try {
    await action();
    throw new Error('expected InvitationReplayError');
  } catch (error) {
    expect(error).toBeInstanceOf(InvitationReplayError);
    expect(error).toMatchObject({ code });
  }
}

describe('InMemoryInvitationReplayGuard', () => {
  test('treats exact join and acceptance repeats as idempotent replays', async () => {
    const invitation = offer(1);
    const request = await joinRequest(invitation, 2);
    const accepted = await acceptance(invitation, request, 3);
    const guard = new InMemoryInvitationReplayGuard();

    await expect(guard.observeJoin(invitation, request, NOW)).resolves.toBe(
      'accepted',
    );
    await expect(guard.observeJoin(invitation, request, NOW)).resolves.toBe(
      'replay',
    );
    await expect(
      guard.observeAcceptance(invitation, request, accepted, NOW),
    ).resolves.toBe('accepted');
    await expect(
      guard.observeAcceptance(invitation, request, accepted, NOW),
    ).resolves.toBe('replay');
    expect(guard.size).toBe(1);
  });

  test('serializes concurrent observations into one accept and one replay', async () => {
    const invitation = offer(4);
    const request = await joinRequest(invitation, 5);
    const guard = new InMemoryInvitationReplayGuard();

    const decisions = await Promise.all([
      guard.observeJoin(invitation, request, NOW),
      guard.observeJoin(invitation, request, NOW),
    ]);
    expect(decisions.sort()).toEqual(['accepted', 'replay']);
    expect(guard.size).toBe(1);
  });

  test('snapshots envelope identifiers before asynchronous replay checks', async () => {
    const invitation = offer(46);
    const request = await joinRequest(invitation, 47);
    const accepted = await acceptance(invitation, request, 48);
    const expectedInvitationId = hex(invitation.invitationId);
    const expectedRequestId = hex(request.requestId);
    const expectedAcceptanceId = hex(accepted.acceptanceId);
    const guard = new InMemoryInvitationReplayGuard();

    const observation = guard.observeAcceptance(
      invitation,
      request,
      accepted,
      NOW,
    );
    invitation.invitationId[0] ^= 1;
    request.requestId[0] ^= 1;
    accepted.acceptanceId[0] ^= 1;

    await expect(observation).resolves.toBe('accepted');
    expect((guard as any)._offersById.has(expectedInvitationId)).toBe(true);
    expect((guard as any)._requestsById.has(expectedRequestId)).toBe(true);
    expect((guard as any)._acceptancesById.has(expectedAcceptanceId)).toBe(
      true,
    );
    expect((guard as any)._offersById.has(hex(invitation.invitationId))).toBe(
      false,
    );
    expect((guard as any)._requestsById.has(hex(request.requestId))).toBe(
      false,
    );
    expect((guard as any)._acceptancesById.has(hex(accepted.acceptanceId))).toBe(
      false,
    );
  });

  test('rejects a second recipient or KEM binding for the same offer', async () => {
    const invitation = offer(6);
    const first = await joinRequest(invitation, 7);
    const second = await joinRequest(invitation, 8);
    const guard = new InMemoryInvitationReplayGuard();

    await guard.observeJoin(invitation, first, NOW);
    await expectReplayCode(
      () => guard.observeJoin(invitation, second, NOW),
      'offer-already-claimed',
    );
    expect(guard.size).toBe(1);
  });

  test('rejects request-ID reuse across distinct signed offers', async () => {
    const firstOffer = offer(9);
    const secondOffer = offer(10);
    const requestId = bytes(32, 11);
    const first = await joinRequest(firstOffer, 12, { requestId });
    const second = await joinRequest(secondOffer, 13, {
      requestId: requestId.slice(),
    });
    const guard = new InMemoryInvitationReplayGuard();

    await guard.observeJoin(firstOffer, first, NOW);
    await expectReplayCode(
      () => guard.observeJoin(secondOffer, second, NOW),
      'request-id-conflict',
    );
    expect(guard.size).toBe(1);
  });

  test('rejects invitation-ID reuse by a different signed offer', async () => {
    const firstOffer = offer(34);
    const secondOffer = {
      ...offer(35),
      invitationId: firstOffer.invitationId.slice(),
    };
    const first = await joinRequest(firstOffer, 36);
    const second = await joinRequest(secondOffer, 37);
    const guard = new InMemoryInvitationReplayGuard();

    await guard.observeJoin(firstOffer, first, NOW);
    await expectReplayCode(
      () => guard.observeJoin(secondOffer, second, NOW),
      'invitation-id-conflict',
    );
    expect(guard.size).toBe(1);
  });

  test('rejects a second acceptance even when only opaque bytes change', async () => {
    const invitation = offer(14);
    const request = await joinRequest(invitation, 15);
    const first = await acceptance(invitation, request, 16);
    const changedBootstrap = first.encryptedBootstrap.slice();
    changedBootstrap[0] ^= 1;
    const second = await acceptance(invitation, request, 17, {
      encryptedBootstrap: changedBootstrap,
    });
    const guard = new InMemoryInvitationReplayGuard();

    await guard.observeAcceptance(invitation, request, first, NOW);
    await expectReplayCode(
      () => guard.observeAcceptance(invitation, request, second, NOW),
      'offer-already-consumed',
    );
  });

  test('rejects acceptance-ID reuse transactionally', async () => {
    const firstOffer = offer(18);
    const secondOffer = offer(19);
    const firstRequest = await joinRequest(firstOffer, 20);
    const secondRequest = await joinRequest(secondOffer, 21);
    const acceptanceId = bytes(32, 22);
    const first = await acceptance(firstOffer, firstRequest, 23, {
      acceptanceId,
    });
    const second = await acceptance(secondOffer, secondRequest, 24, {
      acceptanceId: acceptanceId.slice(),
    });
    const guard = new InMemoryInvitationReplayGuard();

    await guard.observeAcceptance(firstOffer, firstRequest, first, NOW);
    await expectReplayCode(
      () =>
        guard.observeAcceptance(secondOffer, secondRequest, second, NOW),
      'acceptance-id-conflict',
    );
    expect(guard.size).toBe(1);
  });

  test('checks recipient and KEM binding before recording state', async () => {
    const invitation = offer(25);
    const request = await joinRequest(invitation, 26);
    const repointed = await acceptance(invitation, request, 27, {
      recipient: 'attacker',
    });
    const guard = new InMemoryInvitationReplayGuard();

    await expect(
      guard.observeAcceptance(invitation, request, repointed, NOW),
    ).rejects.toMatchObject<Partial<InvitationWireError>>({
      code: 'binding-mismatch',
    });
    expect(guard.size).toBe(0);
  });

  test('expired envelopes do not consume replay capacity', async () => {
    const invitation = offer(28);
    const request = await joinRequest(invitation, 29);
    const guard = new InMemoryInvitationReplayGuard();

    await expect(
      guard.observeJoin(invitation, request, invitation.expiresAtMs),
    ).rejects.toMatchObject<Partial<InvitationWireError>>({ code: 'expired' });
    expect(guard.size).toBe(0);
  });

  test('retires every replay index only after hard offer expiry', async () => {
    const firstOffer = offer(40);
    const firstRequest = await joinRequest(firstOffer, 41);
    const firstAcceptance = await acceptance(
      firstOffer,
      firstRequest,
      42,
    );
    const secondOffer: InvitationOfferV1 = {
      ...offer(43),
      invitationId: firstOffer.invitationId.slice(),
      issuedAtMs: firstOffer.expiresAtMs - 1_000,
      expiresAtMs: firstOffer.expiresAtMs + 60_000,
    };
    const secondRequest = await joinRequest(secondOffer, 44, {
      requestId: firstRequest.requestId.slice(),
    });
    const secondAcceptance = await acceptance(
      secondOffer,
      secondRequest,
      45,
      {
        acceptanceId: firstAcceptance.acceptanceId.slice(),
        issuedAtMs: firstOffer.expiresAtMs,
        expiresAtMs: secondOffer.expiresAtMs,
      },
    );
    const guard = new InMemoryInvitationReplayGuard(1);

    await expect(
      guard.observeAcceptance(
        firstOffer,
        firstRequest,
        firstAcceptance,
        NOW,
      ),
    ).resolves.toBe('accepted');
    await expect(
      guard.observeAcceptance(
        secondOffer,
        secondRequest,
        secondAcceptance,
        firstOffer.expiresAtMs,
      ),
    ).resolves.toBe('accepted');
    expect(guard.size).toBe(1);
    await expect(
      guard.observeAcceptance(
        firstOffer,
        firstRequest,
        firstAcceptance,
        firstOffer.expiresAtMs,
      ),
    ).rejects.toMatchObject<Partial<InvitationWireError>>({ code: 'expired' });
  });

  test('fails closed at capacity without evicting live replay history', async () => {
    const firstOffer = offer(30);
    const secondOffer = offer(31);
    const first = await joinRequest(firstOffer, 32);
    const second = await joinRequest(secondOffer, 33);
    const guard = new InMemoryInvitationReplayGuard(1);

    await guard.observeJoin(firstOffer, first, NOW);
    await expectReplayCode(
      () => guard.observeJoin(secondOffer, second, NOW),
      'capacity-exceeded',
    );
    await expect(guard.observeJoin(firstOffer, first, NOW)).resolves.toBe(
      'replay',
    );
    expect(guard.size).toBe(1);
  });

  test('rejects invalid capacities', () => {
    expect(() => new InMemoryInvitationReplayGuard(0)).toThrow(
      InvitationReplayError,
    );
    expect(() => new InMemoryInvitationReplayGuard(Number.POSITIVE_INFINITY)).toThrow(
      InvitationReplayError,
    );
  });
});
