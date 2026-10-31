export interface AnchorPosition {
  readonly revision: number;
  readonly epoch: bigint;
  readonly poisoned: boolean;
}

export function classifyAnchorAdvance(
  hasPrevious: boolean,
  previous: AnchorPosition,
  next: AnchorPosition,
  sameControlHead: boolean,
):
  | 'initialPoison'
  | 'terminalPoison'
  | 'poisonMethod'
  | 'revision'
  | 'epoch'
  | 'controlHead'
  | 'valid' {
  //@ verify
  //@ requires 0 <= previous.revision && previous.revision <= 9007199254740991
  //@ requires 0 <= next.revision && next.revision <= 9007199254740991
  //@ requires 0n <= previous.epoch && previous.epoch <= 18446744073709551615n
  //@ requires 0n <= next.epoch && next.epoch <= 18446744073709551615n
  //@ ensures \result === "valid" <==> (!hasPrevious && !next.poisoned) || (hasPrevious && !previous.poisoned && !next.poisoned && next.revision === previous.revision + 1 && previous.epoch <= next.epoch && next.epoch <= previous.epoch + 1n && (next.epoch !== previous.epoch || sameControlHead))
  //@ ensures hasPrevious && previous.poisoned ==> \result === "terminalPoison"
  //@ ensures \result === "valid" && hasPrevious ==> next.revision > previous.revision && next.epoch >= previous.epoch
  if (!hasPrevious) return next.poisoned ? 'initialPoison' : 'valid';
  if (previous.poisoned) return 'terminalPoison';
  if (next.poisoned) return 'poisonMethod';
  if (next.revision !== previous.revision + 1) return 'revision';
  if (next.epoch < previous.epoch || next.epoch > previous.epoch + 1n)
    return 'epoch';
  if (next.epoch === previous.epoch && !sameControlHead) return 'controlHead';
  return 'valid';
}
