/**
 * A claimed staged-state commit whose remaining work is infallible.
 *
 * `finalize()` MUST synchronously install the complete staged state using only
 * operations that cannot reject (normally prebuilt reference swaps). It MUST
 * NOT inspect mutable live state, allocate, invoke application callbacks or
 * unclaimed provider work, or throw. It may compose other already-claimed
 * finalizers. A repeated call must be an idempotent no-op. Abandoning a claim
 * without finalizing it must leave live state unchanged and must not prevent a
 * fresh staging attempt against that unchanged state.
 *
 * From a successful claim until it is finalized or permanently abandoned,
 * the caller MUST serialize every conflicting mutation of that provider's
 * staged revision. It MUST NOT independently compose multiple claims that
 * install competing snapshots for the same provider revision: a finalizer
 * deliberately performs no stale-state check and may otherwise overwrite an
 * intervening commit.
 */
export interface PreparedCommitClaim {
  finalize(): void;
}
