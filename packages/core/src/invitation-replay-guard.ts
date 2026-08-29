import {
  InvitationAcceptanceV1,
  InvitationJoinRequestV1,
  InvitationOfferV1,
  assertInvitationAcceptanceMatches,
  assertInvitationAcceptanceUsable,
  assertInvitationJoinMatchesOffer,
  assertInvitationOfferUsable,
  decodeInvitationAcceptance,
  decodeInvitationJoinRequest,
  decodeInvitationOffer,
  digestInvitationAcceptance,
  digestInvitationJoinRequest,
  digestInvitationOffer,
  encodeInvitationAcceptance,
  encodeInvitationJoinRequest,
  encodeInvitationOffer,
} from './invitation-wire.js';

export const DEFAULT_INVITATION_REPLAY_GUARD_ENTRIES = 1024;
export const MAX_INVITATION_REPLAY_GUARD_ENTRIES = 65_536;

export type InvitationReplayDecision = 'accepted' | 'replay';

export type InvitationReplayErrorCode =
  | 'invalid-capacity'
  | 'capacity-exceeded'
  | 'invitation-id-conflict'
  | 'request-id-conflict'
  | 'acceptance-id-conflict'
  | 'offer-already-claimed'
  | 'offer-already-consumed';

export class InvitationReplayError extends Error {
  constructor(
    public readonly code: InvitationReplayErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'InvitationReplayError';
  }
}

interface JoinClaim {
  readonly invitationId: string;
  readonly offerDigest: string;
  readonly expiresAtMs: number;
  readonly requestId: string;
  readonly requestDigest: string;
  acceptanceId?: string;
  acceptanceDigest?: string;
}

interface IdentifierRecord {
  readonly offerDigest: string;
  readonly envelopeDigest: string;
}

/**
 * Bounded, fail-closed replay memory for one-time public invitations.
 *
 * `observeJoin` lets an inviter claim an offer for exactly one signed join
 * request. `observeAcceptance` additionally enforces every recipient,
 * KEM-key, role, document, issuer, digest, and lifetime binding before it
 * records a single acceptance. Byte-identical repeats return `replay`, so an
 * integration can return or apply its cached result without repeating ACL or
 * key mutations. Reuse of an identifier with different signed bytes, or a
 * second request/acceptance for the same offer, fails closed.
 *
 * This guard intentionally does not verify signatures. Callers MUST verify
 * the offer, join request, and acceptance with their bound public identities
 * before recording them here. The guard stores identifiers and SHA-256
 * digests only; it never retains sealed Welcomes, bootstrap ciphertext, or
 * key material.
 *
 * Live entries are never silently evicted because eviction would make an old
 * invitation replayable. Records are retired only after the signed offer's
 * hard expiry, when the envelope can no longer be accepted.
 */
export class InMemoryInvitationReplayGuard {
  private readonly _claimsByOffer = new Map<string, JoinClaim>();
  private readonly _offersById = new Map<string, string>();
  private readonly _requestsById = new Map<string, IdentifierRecord>();
  private readonly _acceptancesById = new Map<string, IdentifierRecord>();

  constructor(
    public readonly maxEntries = DEFAULT_INVITATION_REPLAY_GUARD_ENTRIES,
  ) {
    if (
      !Number.isSafeInteger(maxEntries) ||
      maxEntries < 1 ||
      maxEntries > MAX_INVITATION_REPLAY_GUARD_ENTRIES
    ) {
      throw new InvitationReplayError(
        'invalid-capacity',
        `maxEntries must be an integer from 1 to ${MAX_INVITATION_REPLAY_GUARD_ENTRIES}`,
      );
    }
  }

  /** Number of distinct one-time offers currently remembered. */
  get size(): number {
    return this._claimsByOffer.size;
  }

  /**
   * Record a recipient's signed request for a usable offer.
   *
   * A byte-identical request is idempotent and returns `replay`. A different
   * request for the same offer, including one that changes only recipient or
   * KEM key, is rejected.
   */
  async observeJoin(
    offer: InvitationOfferV1,
    request: InvitationJoinRequestV1,
    nowMs = Date.now(),
  ): Promise<InvitationReplayDecision> {
    const offerSnapshot = decodeInvitationOffer(
      encodeInvitationOffer(offer),
    );
    const requestSnapshot = decodeInvitationJoinRequest(
      encodeInvitationJoinRequest(request),
    );
    assertInvitationOfferUsable(offerSnapshot, nowMs);
    await assertInvitationJoinMatchesOffer(requestSnapshot, offerSnapshot);
    const [offerDigest, requestDigest] = await Promise.all([
      digestInvitationOffer(offerSnapshot),
      digestInvitationJoinRequest(requestSnapshot),
    ]);
    this._pruneExpired(nowMs);
    return this._recordJoin(
      toHex(offerSnapshot.invitationId),
      toHex(offerDigest),
      offerSnapshot.expiresAtMs,
      toHex(requestSnapshot.requestId),
      toHex(requestDigest),
    );
  }

  /**
   * Record an issuer acceptance after checking its complete recipient binding.
   *
   * A byte-identical acceptance is idempotent and returns `replay`. A second
   * acceptance for the offer or reuse of an acceptance ID with other bytes is
   * rejected. This method also records the matching join claim when called on
   * a fresh recipient-side guard.
   */
  async observeAcceptance(
    offer: InvitationOfferV1,
    request: InvitationJoinRequestV1,
    acceptance: InvitationAcceptanceV1,
    nowMs = Date.now(),
  ): Promise<InvitationReplayDecision> {
    const offerSnapshot = decodeInvitationOffer(
      encodeInvitationOffer(offer),
    );
    const requestSnapshot = decodeInvitationJoinRequest(
      encodeInvitationJoinRequest(request),
    );
    const acceptanceSnapshot = decodeInvitationAcceptance(
      encodeInvitationAcceptance(acceptance),
    );
    assertInvitationOfferUsable(offerSnapshot, nowMs);
    assertInvitationAcceptanceUsable(acceptanceSnapshot, nowMs);
    await assertInvitationAcceptanceMatches(
      acceptanceSnapshot,
      offerSnapshot,
      requestSnapshot,
    );

    const [offerDigestBytes, requestDigestBytes, acceptanceDigestBytes] =
      await Promise.all([
        digestInvitationOffer(offerSnapshot),
        digestInvitationJoinRequest(requestSnapshot),
        digestInvitationAcceptance(acceptanceSnapshot),
      ]);
    const offerDigest = toHex(offerDigestBytes);
    const invitationId = toHex(offerSnapshot.invitationId);
    const requestId = toHex(requestSnapshot.requestId);
    const requestDigest = toHex(requestDigestBytes);
    const acceptanceId = toHex(acceptanceSnapshot.acceptanceId);
    const acceptanceDigest = toHex(acceptanceDigestBytes);

    this._pruneExpired(nowMs);
    const joinDecision = this._checkJoin(
      invitationId,
      offerDigest,
      requestId,
      requestDigest,
    );

    const idRecord = this._acceptancesById.get(acceptanceId);
    if (
      idRecord !== undefined &&
      (idRecord.offerDigest !== offerDigest ||
        idRecord.envelopeDigest !== acceptanceDigest)
    ) {
      throw new InvitationReplayError(
        'acceptance-id-conflict',
        'acceptance ID was already used by different signed bytes',
      );
    }

    const existingClaim = this._claimsByOffer.get(offerDigest);
    if (existingClaim?.acceptanceDigest !== undefined) {
      if (
        existingClaim.acceptanceId === acceptanceId &&
        existingClaim.acceptanceDigest === acceptanceDigest
      ) {
        return 'replay';
      }
      throw new InvitationReplayError(
        'offer-already-consumed',
        'offer already has a different acceptance',
      );
    }

    if (joinDecision === 'accepted') {
      this._commitJoin(
        invitationId,
        offerDigest,
        offerSnapshot.expiresAtMs,
        requestId,
        requestDigest,
      );
    }
    const claim = this._claimsByOffer.get(offerDigest)!;
    claim.acceptanceId = acceptanceId;
    claim.acceptanceDigest = acceptanceDigest;
    this._acceptancesById.set(acceptanceId, {
      offerDigest,
      envelopeDigest: acceptanceDigest,
    });
    return 'accepted';
  }

  private _recordJoin(
    invitationId: string,
    offerDigest: string,
    expiresAtMs: number,
    requestId: string,
    requestDigest: string,
  ): InvitationReplayDecision {
    const decision = this._checkJoin(
      invitationId,
      offerDigest,
      requestId,
      requestDigest,
    );
    if (decision === 'accepted') {
      this._commitJoin(
        invitationId,
        offerDigest,
        expiresAtMs,
        requestId,
        requestDigest,
      );
    }
    return decision;
  }

  private _checkJoin(
    invitationId: string,
    offerDigest: string,
    requestId: string,
    requestDigest: string,
  ): InvitationReplayDecision {
    const existingOfferDigest = this._offersById.get(invitationId);
    if (
      existingOfferDigest !== undefined &&
      existingOfferDigest !== offerDigest
    ) {
      throw new InvitationReplayError(
        'invitation-id-conflict',
        'invitation ID was already used by a different signed offer',
      );
    }

    const idRecord = this._requestsById.get(requestId);
    if (
      idRecord !== undefined &&
      (idRecord.offerDigest !== offerDigest ||
        idRecord.envelopeDigest !== requestDigest)
    ) {
      throw new InvitationReplayError(
        'request-id-conflict',
        'request ID was already used by different signed bytes',
      );
    }

    const existing = this._claimsByOffer.get(offerDigest);
    if (existing !== undefined) {
      if (
        existing.requestId === requestId &&
        existing.requestDigest === requestDigest
      ) {
        return 'replay';
      }
      throw new InvitationReplayError(
        'offer-already-claimed',
        'offer was already claimed by a different join request',
      );
    }

    if (this._claimsByOffer.size >= this.maxEntries) {
      throw new InvitationReplayError(
        'capacity-exceeded',
        'invitation replay guard is at capacity',
      );
    }

    return 'accepted';
  }

  private _commitJoin(
    invitationId: string,
    offerDigest: string,
    expiresAtMs: number,
    requestId: string,
    requestDigest: string,
  ): void {
    this._claimsByOffer.set(offerDigest, {
      invitationId,
      offerDigest,
      expiresAtMs,
      requestId,
      requestDigest,
    });
    this._offersById.set(invitationId, offerDigest);
    this._requestsById.set(requestId, {
      offerDigest,
      envelopeDigest: requestDigest,
    });
  }

  private _pruneExpired(nowMs: number): void {
    for (const [offerDigest, claim] of this._claimsByOffer) {
      if (claim.expiresAtMs > nowMs) continue;
      this._claimsByOffer.delete(offerDigest);
      if (this._offersById.get(claim.invitationId) === offerDigest) {
        this._offersById.delete(claim.invitationId);
      }
      if (this._requestsById.get(claim.requestId)?.offerDigest === offerDigest) {
        this._requestsById.delete(claim.requestId);
      }
      if (
        claim.acceptanceId !== undefined &&
        this._acceptancesById.get(claim.acceptanceId)?.offerDigest ===
          offerDigest
      ) {
        this._acceptancesById.delete(claim.acceptanceId);
      }
    }
  }
}

function toHex(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    result += bytes[i].toString(16).padStart(2, '0');
  }
  return result;
}
