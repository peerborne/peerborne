export type DocumentCatchUpReceiptAdmission = 'keep' | 'adopt' | 'conflict';

/** A missing head is sequence zero. Matching heads preserve the local receipt. */
export function admitDocumentCatchUpReceipt(
  current: number,
  offered: number,
  hashesMatch: boolean,
  canAdopt: boolean,
): DocumentCatchUpReceiptAdmission {
  //@ verify
  //@ requires 0 <= current && current <= 9007199254740991
  //@ requires 0 <= offered && offered <= 9007199254740991
  //@ ensures \result === "keep" <==> offered === 0 || current === offered && hashesMatch
  //@ ensures \result === "adopt" <==> current === 0 && offered > 0 && canAdopt
  //@ ensures \result === "conflict" <==> offered > 0 && (current === 0 && !canAdopt || current > 0 && (current !== offered || !hashesMatch))
  if (offered === 0) return 'keep';
  if (current === 0) return canAdopt ? 'adopt' : 'conflict';
  return current === offered && hashesMatch ? 'keep' : 'conflict';
}
