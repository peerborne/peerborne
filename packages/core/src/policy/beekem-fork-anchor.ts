const MAX_REVISION = 9007199254740991;

export type BeeKEMForkPhase = 'available' | 'active' | 'quarantined';
export type BeeKEMForkAction = 'acquire' | 'release' | 'quarantine';

/** Validate an owned transition before submitting its exact store CAS. */
export function canAdvanceBeeKEMForkAnchor(
  phase: BeeKEMForkPhase,
  revision: number,
  action: BeeKEMForkAction,
  leaseMatches: boolean,
  stopObserved: boolean,
): boolean {
  //@ verify
  //@ requires 0 <= revision && revision <= MAX_REVISION
  //@ ensures \result <==> revision < MAX_REVISION && ((action === "acquire" && phase === "available" && !stopObserved) || (phase === "active" && leaseMatches && ((action === "release" && !stopObserved) || (action === "quarantine" && stopObserved))))
  if (revision === MAX_REVISION || phase === 'quarantined') return false;
  if (action === 'acquire') return phase === 'available' && !stopObserved;
  if (phase !== 'active' || !leaseMatches) return false;
  return action === 'quarantine' ? stopObserved : !stopObserved;
}
