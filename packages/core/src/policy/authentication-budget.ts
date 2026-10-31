export interface AuthenticationReservation {
  readonly accepted: boolean;
  readonly attempts: number;
  readonly bytes: number;
}

/** Reserve both dimensions together; a refusal consumes neither. */
export function reserveAuthenticationWork(
  attempts: number,
  bytes: number,
  payloadBytes: number,
  attemptLimit: number,
  byteLimit: number,
): AuthenticationReservation {
  //@ verify
  //@ requires 0 <= attempts && attempts <= attemptLimit && attemptLimit <= 9007199254740991
  //@ requires 0 <= bytes && bytes <= byteLimit && byteLimit <= 9007199254740991
  //@ requires 0 <= payloadBytes && payloadBytes <= 9007199254740991
  //@ ensures \result.accepted <==> attempts < attemptLimit && payloadBytes <= byteLimit - bytes
  //@ ensures \result.accepted ==> \result.attempts === attempts + 1 && \result.bytes === bytes + payloadBytes
  //@ ensures !\result.accepted ==> \result.attempts === attempts && \result.bytes === bytes
  //@ ensures attempts <= \result.attempts && \result.attempts <= attemptLimit
  //@ ensures bytes <= \result.bytes && \result.bytes <= byteLimit
  if (attempts === attemptLimit || payloadBytes > byteLimit - bytes) {
    return { accepted: false, attempts, bytes };
  }
  return {
    accepted: true,
    attempts: attempts + 1,
    bytes: bytes + payloadBytes,
  };
}
