export function syncRequestTimeAllowed(issuedAt: number, now: number): boolean {
  //@ verify
  //@ requires 0 <= issuedAt && issuedAt <= 9007199254740991
  //@ requires 0 <= now && now <= 9007199254740991
  //@ ensures \result <==> now - issuedAt <= 60000 && issuedAt - now <= 30000
  return issuedAt - now >= -60000 && issuedAt - now <= 30000;
}
