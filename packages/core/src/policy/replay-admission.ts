export interface ReplayOfferIdentity {
  readonly known: boolean;
  readonly digest: string;
}

export interface ReplayEnvelopeIdentity {
  readonly known: boolean;
  readonly offerDigest: string;
  readonly envelopeDigest: string;
}

export interface ReplayJoinClaim {
  readonly known: boolean;
  readonly requestId: string;
  readonly requestDigest: string;
}

export function decideJoinReplay(
  offer: ReplayOfferIdentity,
  request: ReplayEnvelopeIdentity,
  claim: ReplayJoinClaim,
  offerDigest: string,
  requestId: string,
  requestDigest: string,
  size: number,
  capacity: number,
):
  | 'invitation-id-conflict'
  | 'request-id-conflict'
  | 'offer-already-claimed'
  | 'capacity-exceeded'
  | 'accepted'
  | 'replay' {
  //@ verify
  //@ requires 0 <= size && size <= capacity && capacity <= 9007199254740991
  //@ ensures \result === "invitation-id-conflict" <==> offer.known && offer.digest !== offerDigest
  //@ ensures \result === "request-id-conflict" <==> (!offer.known || offer.digest === offerDigest) && request.known && (request.offerDigest !== offerDigest || request.envelopeDigest !== requestDigest)
  //@ ensures \result === "replay" <==> (!offer.known || offer.digest === offerDigest) && (!request.known || (request.offerDigest === offerDigest && request.envelopeDigest === requestDigest)) && claim.known && claim.requestId === requestId && claim.requestDigest === requestDigest
  //@ ensures \result === "accepted" <==> (!offer.known || offer.digest === offerDigest) && (!request.known || (request.offerDigest === offerDigest && request.envelopeDigest === requestDigest)) && !claim.known && size < capacity
  //@ ensures \result === "offer-already-claimed" <==> (!offer.known || offer.digest === offerDigest) && (!request.known || (request.offerDigest === offerDigest && request.envelopeDigest === requestDigest)) && claim.known && (claim.requestId !== requestId || claim.requestDigest !== requestDigest)
  //@ ensures \result === "capacity-exceeded" <==> (!offer.known || offer.digest === offerDigest) && (!request.known || (request.offerDigest === offerDigest && request.envelopeDigest === requestDigest)) && !claim.known && size >= capacity
  if (offer.known && offer.digest !== offerDigest)
    return 'invitation-id-conflict';
  if (
    request.known &&
    (request.offerDigest !== offerDigest ||
      request.envelopeDigest !== requestDigest)
  )
    return 'request-id-conflict';
  if (claim.known) {
    if (claim.requestId === requestId && claim.requestDigest === requestDigest)
      return 'replay';
    return 'offer-already-claimed';
  }
  if (size >= capacity) return 'capacity-exceeded';
  return 'accepted';
}

export function decideAcceptanceReplay(
  identity: ReplayEnvelopeIdentity,
  offerDigest: string,
  acceptanceDigest: string,
  alreadyAccepted: boolean,
  sameAcceptance: boolean,
): 'acceptance-id-conflict' | 'offer-already-consumed' | 'accepted' | 'replay' {
  //@ verify
  //@ ensures \result === "acceptance-id-conflict" <==> identity.known && (identity.offerDigest !== offerDigest || identity.envelopeDigest !== acceptanceDigest)
  //@ ensures \result === "replay" <==> (!identity.known || (identity.offerDigest === offerDigest && identity.envelopeDigest === acceptanceDigest)) && alreadyAccepted && sameAcceptance
  //@ ensures \result === "offer-already-consumed" <==> (!identity.known || (identity.offerDigest === offerDigest && identity.envelopeDigest === acceptanceDigest)) && alreadyAccepted && !sameAcceptance
  //@ ensures \result === "accepted" <==> (!identity.known || (identity.offerDigest === offerDigest && identity.envelopeDigest === acceptanceDigest)) && !alreadyAccepted
  if (
    identity.known &&
    (identity.offerDigest !== offerDigest ||
      identity.envelopeDigest !== acceptanceDigest)
  )
    return 'acceptance-id-conflict';
  if (alreadyAccepted)
    return sameAcceptance ? 'replay' : 'offer-already-consumed';
  return 'accepted';
}

export interface InvitationReplayClaim {
  readonly invitationId: string;
  readonly offerDigest: string;
  readonly expiresAtMs: number;
  readonly requestId: string;
  readonly requestDigest: string;
  readonly accepted: boolean;
  readonly acceptanceId: string;
  readonly acceptanceDigest: string;
}

export interface InvitationReplayEnvelope {
  readonly offerDigest: string;
  readonly envelopeDigest: string;
}

export interface InvitationReplayTables {
  readonly claims: Map<string, InvitationReplayClaim>;
  readonly offers: Map<string, string>;
  readonly requests: Map<string, InvitationReplayEnvelope>;
  readonly acceptances: Map<string, InvitationReplayEnvelope>;
}

export interface InvitationReplayExpiryPlan {
  readonly expired: readonly string[];
  readonly nextExpiry: number;
}

export function advanceInvitationReplayClock(
  previous: number,
  observed: number,
): number {
  //@ verify
  //@ requires 0 <= previous && previous <= 9007199254740991
  //@ requires 0 <= observed && observed <= 9007199254740991
  //@ ensures \result === (previous > observed ? previous : observed)
  //@ ensures previous <= \result && observed <= \result && \result <= 9007199254740991
  return previous > observed ? previous : observed;
}

export function nextInvitationReplayExpiry(
  previous: number,
  added: number,
): number {
  //@ verify
  //@ requires 0 <= previous && previous <= 9007199254740991
  //@ requires 0 <= added && added <= 9007199254740991
  //@ ensures \result === (previous < added ? previous : added)
  //@ ensures 0 <= \result && \result <= previous && \result <= added
  return previous < added ? previous : added;
}

export function shouldSweepInvitationReplays(
  earliest: number,
  now: number,
): boolean {
  //@ verify
  //@ requires 0 <= earliest && earliest <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ ensures \result <==> earliest <= now
  return now >= earliest;
}

export function collectExpiredInvitationClaims(
  keys: readonly string[],
  claims: Map<string, InvitationReplayClaim>,
  now: number,
): InvitationReplayExpiryPlan {
  //@ verify
  //@ requires 0 <= now && now <= 9007199254740991
  //@ requires keys.length === claims.size && claims.size <= 65536
  //@ requires forall(i: int, forall(j: int, 0 <= i && i < j && j < keys.length ==> keys[i] !== keys[j]))
  //@ requires forall(key: string, claims.has(key) <==> keys.includes(key))
  //@ requires forall(key: string, claims.has(key) ==> claims.get(key).expiresAtMs >= 0 && claims.get(key).expiresAtMs <= 9007199254740991)
  //@ ensures \result.expired.length <= keys.length
  //@ ensures forall(key: string, \result.expired.includes(key) <==> claims.has(key) && claims.get(key).expiresAtMs <= now)
  //@ ensures forall(i: int, forall(j: int, 0 <= i && i < j && j < \result.expired.length ==> \result.expired[i] !== \result.expired[j]))
  //@ ensures 0 <= \result.nextExpiry && \result.nextExpiry <= 9007199254740991
  //@ ensures forall(key: string, claims.has(key) && claims.get(key).expiresAtMs > now ==> claims.get(key).expiresAtMs >= \result.nextExpiry)
  //@ ensures \result.nextExpiry === 9007199254740991 || exists(key: string, claims.has(key) && claims.get(key).expiresAtMs === \result.nextExpiry && claims.get(key).expiresAtMs > now)
  const expired: string[] = [];
  let nextExpiry = 9007199254740991;
  for (let index = 0; index < keys.length; index++) {
    //@ invariant 0 <= index && index <= keys.length
    //@ invariant expired.length <= index
    //@ invariant forall(key: string, expired.includes(key) <==> claims.has(key) && claims.get(key).expiresAtMs <= now && exists(i: int, 0 <= i && i < index && keys[i] === key))
    //@ invariant forall(i: int, forall(j: int, 0 <= i && i < j && j < expired.length ==> expired[i] !== expired[j]))
    //@ invariant 0 <= nextExpiry && nextExpiry <= 9007199254740991
    //@ invariant forall(i: int, 0 <= i && i < index && claims.get(keys[i]).expiresAtMs > now ==> claims.get(keys[i]).expiresAtMs >= nextExpiry)
    //@ invariant nextExpiry === 9007199254740991 || exists(i: int, 0 <= i && i < index && claims.get(keys[i]).expiresAtMs === nextExpiry && claims.get(keys[i]).expiresAtMs > now)
    //@ decreases keys.length - index
    const key = keys[index];
    const expiry = claims.get(key)!.expiresAtMs;
    //@ assert !expired.includes(key)
    if (expiry <= now) {
      expired.push(key);
      //@ assert expired[expired.length - 1] === key
    } else {
      nextExpiry = nextInvitationReplayExpiry(nextExpiry, expiry);
    }
  }
  return { expired, nextExpiry };
}

/** @internal Mutate only the guard's owned, distinct index maps. */
export function recordInvitationReplayJoin(
  claims: Map<string, InvitationReplayClaim>,
  offers: Map<string, string>,
  requests: Map<string, InvitationReplayEnvelope>,
  acceptances: Map<string, InvitationReplayEnvelope>,
  invitationId: string,
  offerDigest: string,
  expiresAtMs: number,
  requestId: string,
  requestDigest: string,
): InvitationReplayTables {
  //@ verify
  //@ requires !claims.has(offerDigest) && !offers.has(invitationId) && !requests.has(requestId)
  //@ requires claims.size < 65536 && offers.size < 65536 && requests.size < 65536
  //@ requires 0 <= expiresAtMs && expiresAtMs <= 9007199254740991
  //@ ensures \result.claims.size === claims.size + 1 && \result.offers.size === offers.size + 1 && \result.requests.size === requests.size + 1
  //@ ensures \result.claims.has(offerDigest) && \result.claims.get(offerDigest).invitationId === invitationId && \result.claims.get(offerDigest).offerDigest === offerDigest && \result.claims.get(offerDigest).expiresAtMs === expiresAtMs
  //@ ensures \result.claims.get(offerDigest).requestId === requestId && \result.claims.get(offerDigest).requestDigest === requestDigest && !\result.claims.get(offerDigest).accepted
  //@ ensures \result.claims.get(offerDigest).acceptanceId === "" && \result.claims.get(offerDigest).acceptanceDigest === ""
  //@ ensures forall(key: string, \result.claims.has(key) <==> claims.has(key) || key === offerDigest)
  //@ ensures forall(key: string, claims.has(key) ==> \result.claims.has(key) && \result.claims.get(key) === claims.get(key))
  //@ ensures \result.offers.has(invitationId) && \result.offers.get(invitationId) === offerDigest
  //@ ensures forall(key: string, \result.offers.has(key) <==> offers.has(key) || key === invitationId)
  //@ ensures forall(key: string, offers.has(key) ==> \result.offers.has(key) && \result.offers.get(key) === offers.get(key))
  //@ ensures \result.requests.has(requestId) && \result.requests.get(requestId).offerDigest === offerDigest && \result.requests.get(requestId).envelopeDigest === requestDigest
  //@ ensures forall(key: string, \result.requests.has(key) <==> requests.has(key) || key === requestId)
  //@ ensures forall(key: string, requests.has(key) ==> \result.requests.has(key) && \result.requests.get(key) === requests.get(key))
  //@ ensures \result.acceptances === acceptances
  claims.set(offerDigest, {
    invitationId,
    offerDigest,
    expiresAtMs,
    requestId,
    requestDigest,
    accepted: false,
    acceptanceId: '',
    acceptanceDigest: '',
  });
  offers.set(invitationId, offerDigest);
  requests.set(requestId, { offerDigest, envelopeDigest: requestDigest });
  //@ assert claims.has(offerDigest) && claims.get(offerDigest).requestId === requestId
  //@ assert offers.has(invitationId) && offers.get(invitationId) === offerDigest
  //@ assert requests.has(requestId) && requests.get(requestId).envelopeDigest === requestDigest
  return { claims, offers, requests, acceptances };
}

/** @internal Complete an owned claim without changing its signed join binding. */
export function recordInvitationReplayAcceptance(
  claims: Map<string, InvitationReplayClaim>,
  offers: Map<string, string>,
  requests: Map<string, InvitationReplayEnvelope>,
  acceptances: Map<string, InvitationReplayEnvelope>,
  offerDigest: string,
  acceptanceId: string,
  acceptanceDigest: string,
): InvitationReplayTables {
  //@ verify
  //@ requires claims.has(offerDigest) && !claims.get(offerDigest).accepted && !acceptances.has(acceptanceId)
  //@ requires acceptances.size < 9007199254740991
  //@ ensures \result.claims.size === claims.size && \result.acceptances.size === acceptances.size + 1
  //@ ensures forall(key: string, \result.claims.has(key) <==> claims.has(key))
  //@ ensures forall(key: string, claims.has(key) && key !== offerDigest ==> \result.claims.has(key) && \result.claims.get(key) === claims.get(key))
  //@ ensures \result.claims.has(offerDigest) && \result.claims.get(offerDigest).accepted && \result.claims.get(offerDigest).acceptanceId === acceptanceId && \result.claims.get(offerDigest).acceptanceDigest === acceptanceDigest
  //@ ensures \result.claims.get(offerDigest).invitationId === claims.get(offerDigest).invitationId && \result.claims.get(offerDigest).offerDigest === claims.get(offerDigest).offerDigest && \result.claims.get(offerDigest).expiresAtMs === claims.get(offerDigest).expiresAtMs
  //@ ensures \result.claims.get(offerDigest).requestId === claims.get(offerDigest).requestId && \result.claims.get(offerDigest).requestDigest === claims.get(offerDigest).requestDigest
  //@ ensures \result.offers === offers && \result.requests === requests
  //@ ensures \result.acceptances.has(acceptanceId) && \result.acceptances.get(acceptanceId).offerDigest === offerDigest && \result.acceptances.get(acceptanceId).envelopeDigest === acceptanceDigest
  //@ ensures forall(key: string, \result.acceptances.has(key) <==> acceptances.has(key) || key === acceptanceId)
  //@ ensures forall(key: string, acceptances.has(key) ==> \result.acceptances.has(key) && \result.acceptances.get(key) === acceptances.get(key))
  const claim = claims.get(offerDigest)!;
  claims.set(offerDigest, {
    invitationId: claim.invitationId,
    offerDigest: claim.offerDigest,
    expiresAtMs: claim.expiresAtMs,
    requestId: claim.requestId,
    requestDigest: claim.requestDigest,
    accepted: true,
    acceptanceId,
    acceptanceDigest,
  });
  acceptances.set(acceptanceId, {
    offerDigest,
    envelopeDigest: acceptanceDigest,
  });
  //@ assert claims.has(offerDigest) && claims.get(offerDigest).acceptanceId === acceptanceId
  //@ assert acceptances.has(acceptanceId) && acceptances.get(acceptanceId).offerDigest === offerDigest
  return { claims, offers, requests, acceptances };
}

/** @internal Retire only indexes that still belong to this exact offer. */
export function retireInvitationReplayClaim(
  claims: Map<string, InvitationReplayClaim>,
  offers: Map<string, string>,
  requests: Map<string, InvitationReplayEnvelope>,
  acceptances: Map<string, InvitationReplayEnvelope>,
  offerDigest: string,
): InvitationReplayTables {
  //@ verify
  //@ ensures forall(key: string, \result.claims.has(key) <==> claims.has(key) && key !== offerDigest)
  //@ ensures forall(key: string, \result.claims.has(key) ==> claims.has(key) && \result.claims.get(key) === claims.get(key))
  //@ ensures forall(key: string, \result.offers.has(key) <==> offers.has(key) && !(claims.has(offerDigest) && claims.get(offerDigest).invitationId === key && offers.get(key) === offerDigest))
  //@ ensures forall(key: string, \result.offers.has(key) ==> offers.has(key) && \result.offers.get(key) === offers.get(key))
  //@ ensures forall(key: string, \result.requests.has(key) <==> requests.has(key) && !(claims.has(offerDigest) && claims.get(offerDigest).requestId === key && requests.get(key).offerDigest === offerDigest))
  //@ ensures forall(key: string, \result.requests.has(key) ==> requests.has(key) && \result.requests.get(key) === requests.get(key))
  //@ ensures forall(key: string, \result.acceptances.has(key) <==> acceptances.has(key) && !(claims.has(offerDigest) && claims.get(offerDigest).accepted && claims.get(offerDigest).acceptanceId === key && acceptances.get(key).offerDigest === offerDigest))
  //@ ensures forall(key: string, \result.acceptances.has(key) ==> acceptances.has(key) && \result.acceptances.get(key) === acceptances.get(key))
  //@ ensures \result.claims.size <= claims.size && \result.offers.size <= offers.size && \result.requests.size <= requests.size && \result.acceptances.size <= acceptances.size
  if (claims.has(offerDigest)) {
    const claim = claims.get(offerDigest)!;
    claims.delete(offerDigest);
    if (
      offers.has(claim.invitationId) &&
      offers.get(claim.invitationId) === offerDigest
    )
      offers.delete(claim.invitationId);
    if (
      requests.has(claim.requestId) &&
      requests.get(claim.requestId)!.offerDigest === offerDigest
    )
      requests.delete(claim.requestId);
    if (
      claim.accepted &&
      acceptances.has(claim.acceptanceId) &&
      acceptances.get(claim.acceptanceId)!.offerDigest === offerDigest
    )
      acceptances.delete(claim.acceptanceId);
  }
  return { claims, offers, requests, acceptances };
}
