export type DocumentOperationPhase =
  | 'preparing'
  | 'prepared'
  | 'committed'
  | 'cancelled';

export type DocumentOperationEvent = 'prepare' | 'commit' | 'cancel';

export type PreparedDocumentPhase =
  | 'prepared'
  | 'applying'
  | 'committed'
  | 'cancelled'
  | 'failed';
export type PreparedDocumentEvent = 'begin' | 'succeed' | 'fail' | 'cancel';

export function advancePreparedDocumentChange(
  phase: PreparedDocumentPhase,
  event: PreparedDocumentEvent,
): PreparedDocumentPhase {
  //@ verify
  //@ ensures phase === "committed" || phase === "cancelled" || phase === "failed" ==> \result === phase
  //@ ensures phase !== "committed" ==> (\result === "committed" <==> phase === "applying" && event === "succeed")
  //@ ensures phase !== "failed" ==> (\result === "failed" <==> phase === "applying" && event === "fail")
  //@ ensures phase !== "cancelled" ==> (\result === "cancelled" <==> phase === "prepared" && event === "cancel")
  //@ ensures phase !== "applying" ==> (\result === "applying" <==> phase === "prepared" && event === "begin")
  //@ ensures phase === "applying" && event === "cancel" ==> \result === "applying"
  if (phase === 'committed' || phase === 'cancelled' || phase === 'failed')
    return phase;
  if (phase === 'prepared') {
    if (event === 'begin') return 'applying';
    if (event === 'cancel') return 'cancelled';
  }
  if (phase === 'applying') {
    if (event === 'succeed') return 'committed';
    if (event === 'fail') return 'failed';
  }
  return phase;
}

export function canReserveDocumentOperation(
  count: number,
  bytes: number,
  incomingBytes: number,
  countLimit: number,
  byteLimit: number,
): boolean {
  //@ verify
  //@ requires 0 <= count && count <= countLimit && countLimit <= 9007199254740991
  //@ requires 0 <= bytes && bytes <= byteLimit && byteLimit <= 9007199254740991
  //@ requires 0 <= incomingBytes && incomingBytes <= 9007199254740991
  //@ ensures \result <==> count < countLimit && incomingBytes <= byteLimit - bytes
  //@ ensures \result ==> count + 1 <= countLimit && bytes + incomingBytes <= byteLimit
  return count < countLimit && incomingBytes <= byteLimit - bytes;
}

export function releaseDocumentOperationBytes(
  bytes: number,
  releasedBytes: number,
): number {
  //@ verify
  //@ requires 0 <= releasedBytes && releasedBytes <= bytes && bytes <= 9007199254740991
  //@ ensures \result === bytes - releasedBytes
  //@ ensures 0 <= \result && \result <= bytes
  return bytes - releasedBytes;
}

export function advanceDocumentOperation(
  phase: DocumentOperationPhase,
  event: DocumentOperationEvent,
  contextMatches: boolean,
  authorizationMatches: boolean,
): DocumentOperationPhase {
  //@ verify
  //@ ensures phase === "committed" || phase === "cancelled" ==> \result === phase
  //@ ensures phase !== "committed" ==> (\result === "committed" <==> phase === "prepared" && event === "commit" && contextMatches && authorizationMatches)
  //@ ensures phase !== "cancelled" && phase !== "committed" ==> (\result === "cancelled" <==> event === "cancel")
  //@ ensures phase === "preparing" && event === "commit" ==> \result === "preparing"
  //@ ensures phase === "preparing" && event === "prepare" ==> \result === "prepared"
  //@ ensures phase === "prepared" && event === "commit" && !contextMatches ==> \result === "prepared"
  if (phase === 'committed' || phase === 'cancelled') return phase;
  if (event === 'cancel') return 'cancelled';
  if (event === 'prepare' && phase === 'preparing') return 'prepared';
  if (event === 'commit' && phase === 'prepared')
    return contextMatches && authorizationMatches ? 'committed' : phase;
  return phase;
}
