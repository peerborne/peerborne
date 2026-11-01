export type ContentSequenceAdmission =
  | 'apply'
  | 'replay'
  | 'gap'
  | 'parent-mismatch';

export function admitContentSequence(
  sequence: number,
  accepted: number,
  parentMatches: boolean,
): ContentSequenceAdmission {
  //@ verify
  //@ requires 1 <= sequence && sequence <= 9007199254740991
  //@ requires 0 <= accepted && accepted <= 9007199254740991
  //@ ensures \result === "apply" <==> sequence > accepted && sequence - accepted === 1 && parentMatches
  //@ ensures \result === "replay" <==> sequence <= accepted
  //@ ensures \result === "gap" <==> sequence > accepted && sequence - accepted !== 1
  //@ ensures \result === "parent-mismatch" <==> sequence > accepted && sequence - accepted === 1 && !parentMatches
  if (sequence <= accepted) return 'replay';
  if (sequence - accepted !== 1) return 'gap';
  return parentMatches ? 'apply' : 'parent-mismatch';
}

export function nextContentSequence(accepted: number): number {
  //@ verify
  //@ requires 0 <= accepted && accepted < 9007199254740991
  //@ ensures \result === accepted + 1
  //@ ensures 1 <= \result && \result <= 9007199254740991
  return accepted + 1;
}

export function contentRolePermits(role: number, snapshot: boolean): boolean {
  //@ verify
  //@ requires 0 <= role && role <= 3
  //@ ensures \result <==> role === 3 || !snapshot && role === 2
  return role === 3 || (!snapshot && role === 2);
}
