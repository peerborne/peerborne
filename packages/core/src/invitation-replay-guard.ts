import {
  decideJoinReplay,
  decideAcceptanceReplay,
  advanceInvitationReplayClock,
  nextInvitationReplayExpiry,
  shouldSweepInvitationReplays,
  collectExpiredInvitationClaims,
  recordInvitationReplayJoin,
  recordInvitationReplayAcceptance,
  retireInvitationReplayClaim,
  type InvitationReplayClaim,
  type InvitationReplayEnvelope,
} from './policy/replay-admission.js';
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
 *
 * Omit the optional time argument to sample wall time again after hashing.
 * An explicit timestamp supplies a trusted, fixed clock observation. Effective
 * time never moves backwards within this guard instance.
 */
export class InMemoryInvitationReplayGuard {
  private readonly _claimsByOffer = new Map<string, InvitationReplayClaim>();
  private readonly _offersById = new Map<string, string>();
  private readonly _requestsById = new Map<string, InvitationReplayEnvelope>();
  private readonly _acceptancesById = new Map<
    string,
    InvitationReplayEnvelope
  >();
  private _observedAtMs = 0;
  private _nextExpiryAtMs = Number.MAX_SAFE_INTEGER;

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
    Object.defineProperty(this, 'maxEntries', {
      value: maxEntries,
      enumerable: true,
      writable: false,
      configurable: false,
    });
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
    nowMs?: number,
  ): Promise<InvitationReplayDecision> {
    const offerSnapshot = decodeInvitationOffer(encodeInvitationOffer(offer));
    const requestSnapshot = decodeInvitationJoinRequest(
      encodeInvitationJoinRequest(request),
    );
    assertInvitationOfferUsable(offerSnapshot, this._observeTime(nowMs));
    await assertInvitationJoinMatchesOffer(requestSnapshot, offerSnapshot);
    const [offerDigest, requestDigest] = await Promise.all([
      digestInvitationOffer(offerSnapshot),
      digestInvitationJoinRequest(requestSnapshot),
    ]);
    const committedAt = this._observeTime(nowMs);
    assertInvitationOfferUsable(offerSnapshot, committedAt);
    this._pruneExpired(committedAt);
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
    nowMs?: number,
  ): Promise<InvitationReplayDecision> {
    const offerSnapshot = decodeInvitationOffer(encodeInvitationOffer(offer));
    const requestSnapshot = decodeInvitationJoinRequest(
      encodeInvitationJoinRequest(request),
    );
    const acceptanceSnapshot = decodeInvitationAcceptance(
      encodeInvitationAcceptance(acceptance),
    );
    const startedAt = this._observeTime(nowMs);
    assertInvitationOfferUsable(offerSnapshot, startedAt);
    assertInvitationAcceptanceUsable(acceptanceSnapshot, startedAt);
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

    const committedAt = this._observeTime(nowMs);
    assertInvitationOfferUsable(offerSnapshot, committedAt);
    assertInvitationAcceptanceUsable(acceptanceSnapshot, committedAt);
    this._pruneExpired(committedAt);
    const joinDecision = this._checkJoin(
      invitationId,
      offerDigest,
      requestId,
      requestDigest,
    );

    const idRecord = this._acceptancesById.get(acceptanceId);
    const existingClaim = this._claimsByOffer.get(offerDigest);
    const acceptanceDecision = decideAcceptanceReplay(
      {
        known: idRecord !== undefined,
        offerDigest: idRecord?.offerDigest ?? '',
        envelopeDigest: idRecord?.envelopeDigest ?? '',
      },
      offerDigest,
      acceptanceDigest,
      existingClaim?.accepted === true,
      existingClaim?.acceptanceId === acceptanceId &&
        existingClaim?.acceptanceDigest === acceptanceDigest,
    );
    if (acceptanceDecision === 'replay') return 'replay';
    if (acceptanceDecision === 'acceptance-id-conflict')
      throw new InvitationReplayError(
        'acceptance-id-conflict',
        'acceptance ID was already used by different signed bytes',
      );
    if (acceptanceDecision === 'offer-already-consumed')
      throw new InvitationReplayError(
        'offer-already-consumed',
        'offer already has a different acceptance',
      );

    if (joinDecision === 'accepted') {
      this._commitJoin(
        invitationId,
        offerDigest,
        offerSnapshot.expiresAtMs,
        requestId,
        requestDigest,
      );
    }
    recordInvitationReplayAcceptance(
      this._claimsByOffer,
      this._offersById,
      this._requestsById,
      this._acceptancesById,
      offerDigest,
      acceptanceId,
      acceptanceDigest,
    );
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
    const offer = this._offersById.get(invitationId);
    const request = this._requestsById.get(requestId);
    const claim = this._claimsByOffer.get(offerDigest);
    const decision = decideJoinReplay(
      { known: offer !== undefined, digest: offer ?? '' },
      {
        known: request !== undefined,
        offerDigest: request?.offerDigest ?? '',
        envelopeDigest: request?.envelopeDigest ?? '',
      },
      {
        known: claim !== undefined,
        requestId: claim?.requestId ?? '',
        requestDigest: claim?.requestDigest ?? '',
      },
      offerDigest,
      requestId,
      requestDigest,
      this._claimsByOffer.size,
      this.maxEntries,
    );
    if (decision === 'accepted' || decision === 'replay') return decision;
    const messages = {
      'invitation-id-conflict':
        'invitation ID was already used by a different signed offer',
      'request-id-conflict':
        'request ID was already used by different signed bytes',
      'offer-already-claimed':
        'offer was already claimed by a different join request',
      'capacity-exceeded': 'invitation replay guard is at capacity',
    };
    throw new InvitationReplayError(decision, messages[decision]);
  }

  private _commitJoin(
    invitationId: string,
    offerDigest: string,
    expiresAtMs: number,
    requestId: string,
    requestDigest: string,
  ): void {
    recordInvitationReplayJoin(
      this._claimsByOffer,
      this._offersById,
      this._requestsById,
      this._acceptancesById,
      invitationId,
      offerDigest,
      expiresAtMs,
      requestId,
      requestDigest,
    );
    this._nextExpiryAtMs = nextInvitationReplayExpiry(
      this._nextExpiryAtMs,
      expiresAtMs,
    );
  }

  private _pruneExpired(nowMs: number): void {
    if (!shouldSweepInvitationReplays(this._nextExpiryAtMs, nowMs)) return;
    const plan = collectExpiredInvitationClaims(
      [...this._claimsByOffer.keys()],
      this._claimsByOffer,
      nowMs,
    );
    for (const offerDigest of plan.expired) {
      retireInvitationReplayClaim(
        this._claimsByOffer,
        this._offersById,
        this._requestsById,
        this._acceptancesById,
        offerDigest,
      );
    }
    this._nextExpiryAtMs = plan.nextExpiry;
  }

  private _observeTime(nowMs?: number): number {
    const observed = nowMs === undefined ? Date.now() : nowMs;
    if (!Number.isSafeInteger(observed) || observed < 0)
      throw new TypeError(
        'Invitation replay clock must be a non-negative safe integer',
      );
    this._observedAtMs = advanceInvitationReplayClock(
      this._observedAtMs,
      observed,
    );
    return this._observedAtMs;
  }
}

function toHex(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    result += bytes[i].toString(16).padStart(2, '0');
  }
  return result;
}
