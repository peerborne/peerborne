/** Exact base64 block sizing within the wire-format arithmetic domain. */
export function base64EncodedLength(rawBytes: number): number {
  //@ verify
  //@ requires 0 <= rawBytes && rawBytes <= 4294967295
  //@ ensures 0 <= \result && \result <= 5726623060
  //@ ensures \result % 4 === 0
  //@ ensures rawBytes <= (\result / 4) * 3 && (\result / 4) * 3 <= rawBytes + 2
  return 4 * Math.ceil(rawBytes / 3);
}

export function base64DecodedUpperBound(encodedLength: number): number {
  //@ verify
  //@ requires 0 <= encodedLength && encodedLength <= 4294967295
  //@ ensures 0 <= \result && \result <= 3221225472
  //@ ensures \result % 3 === 0
  //@ ensures encodedLength <= (\result / 3) * 4 && (\result / 3) * 4 <= encodedLength + 3
  return Math.ceil(encodedLength / 4) * 3;
}
