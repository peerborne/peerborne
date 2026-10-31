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
