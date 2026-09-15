/**
 * A claimed staged-state commit whose remaining work is infallible.
 *
 * `finalize()` MUST synchronously install the complete staged state using only
 * operations that cannot reject (normally prebuilt reference swaps). It MUST
 * NOT inspect mutable live state, allocate, invoke application callbacks or
 * unclaimed provider work, throw, or return any value other than `undefined`.
 * Security wrappers may treat any other return, including a promise or custom
 * thenable, as a terminal contract violation. It may compose other
 * already-claimed finalizers. A repeated call must be an idempotent no-op.
 * Abandoning a claim without finalizing it must leave live state unchanged and
 * must not prevent a fresh staging attempt against that unchanged state.
 *
 * A claim covers only the provider that created it. Defining or returning a
 * claim does not make a multi-provider workflow atomic: that workflow must
 * obtain every required claim before publication and then finalize them at one
 * synchronous commit boundary. Callers must fail closed when any participating
 * provider cannot supply a claim.
 *
 * Core security wrappers accept claims only as same-realm plain records with
 * `Object.prototype` or `null` as their direct prototype. `finalize` must
 * resolve through a data-property function descriptor; accessors, thenables,
 * promises, class instances, and cross-realm records are rejected after the
 * claim method has been invoked and therefore poison the owning document.
 * Providers intended for those wrappers should return an object literal such
 * as `{ finalize() { ... } }`.
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
