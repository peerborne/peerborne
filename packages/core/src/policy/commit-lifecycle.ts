export type PreparedCommitPhase = 'prepared' | 'claimed' | 'committed';

export function claimPreparedCommit(
  phase: PreparedCommitPhase,
  baseCurrent: boolean,
  hydrating: boolean,
): 'claimed' | 'notPrepared' | 'stale' | 'hydrating' {
  //@ verify
  //@ ensures \result === "claimed" <==> phase === "prepared" && baseCurrent && !hydrating
  //@ ensures \result === "notPrepared" <==> phase !== "prepared"
  //@ ensures \result === "stale" <==> phase === "prepared" && !baseCurrent
  //@ ensures \result === "hydrating" <==> phase === "prepared" && baseCurrent && hydrating
  if (phase !== 'prepared') return 'notPrepared';
  if (!baseCurrent) return 'stale';
  if (hydrating) return 'hydrating';
  return 'claimed';
}

export function completePreparedCommit(
  phase: PreparedCommitPhase,
): PreparedCommitPhase {
  //@ verify
  //@ requires phase === "claimed" || phase === "committed"
  //@ ensures \result === "committed"
  return 'committed';
}

export function coordinatorAdmission(
  forked: boolean,
  poisoned: boolean,
  initialized: boolean,
): 'forked' | 'poisoned' | 'uninitialized' | 'usable' {
  //@ verify
  //@ ensures \result === "usable" <==> !forked && !poisoned && initialized
  //@ ensures \result === "forked" <==> forked
  //@ ensures \result === "poisoned" <==> !forked && poisoned
  //@ ensures \result === "uninitialized" <==> !forked && !poisoned && !initialized
  if (forked) return 'forked';
  if (poisoned) return 'poisoned';
  return initialized ? 'usable' : 'uninitialized';
}

export function failedCommitRecovery(
  ambiguousStoreFailure: boolean,
): 'propagate' | 'poison' {
  //@ verify
  //@ ensures \result === "propagate" <==> ambiguousStoreFailure
  //@ ensures \result === "poison" <==> !ambiguousStoreFailure
  return ambiguousStoreFailure ? 'propagate' : 'poison';
}
