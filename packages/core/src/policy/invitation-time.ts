export function hasInvitationProcessingWindow(
  expiresAt: number,
  now: number,
  minimum: number,
): boolean {
  //@ verify
  //@ requires 0 <= expiresAt && expiresAt <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ requires 0 <= minimum && minimum <= 9007199254740991
  //@ ensures \result <==> expiresAt - now >= minimum
  //@ ensures \result && minimum > 0 ==> expiresAt > now
  return !(expiresAt - now < minimum);
}

export function isExpiredInvitation(expiresAt: number, now: number): boolean {
  //@ verify
  //@ requires 0 <= expiresAt && expiresAt <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ ensures \result <==> expiresAt <= now
  return expiresAt <= now;
}

export function invitationTimeDisposition(
  created: number,
  expires: number,
  now: number,
  skew: number,
): 'expired' | 'future' | 'usable' {
  //@ verify
  //@ requires 0 <= created && created <= 9007199254740991
  //@ requires 0 <= expires && expires <= 9007199254740991
  //@ requires created < expires
  //@ requires 0 <= now && now <= 9007199254740991
  //@ requires 0 <= skew && skew <= 9007199254740991
  //@ ensures \result === "expired" <==> expires <= now
  //@ ensures \result === "future" <==> expires > now && created > now + skew
  //@ ensures \result === "usable" <==> expires > now && created <= now + skew
  if (created - now > skew) return 'future';
  if (expires <= now) return 'expired';
  return 'usable';
}
