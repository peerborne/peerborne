import type { PeerborneState } from './reducers.js';

/**
 * Local alias for the fully-parameterised `PeerborneState` shape used by
 * {@link defaultStateSelector}. Keeping the generic list in one place avoids
 * having to keep the return type and the internal cast in sync by hand.
 *
 * @internal
 */
type State<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> = PeerborneState<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
>;

/**
 * Default selector used when the peerborne state sits at the root of the
 * Redux store (i.e. the store IS the PeerborneState with no nesting).
 *
 * Callers whose Redux store has a nested layout must pass their own selector
 * to each *Async() action creator — this helper deliberately casts the
 * `unknown` root state as if it IS the peerborne slice. Because `state` is
 * already typed as `unknown`, a single `state as PeerborneState<...>` cast
 * is sufficient (TypeScript allows asserting `unknown` to any type directly,
 * so the `as unknown as ...` double-cast used at each former inline call site
 * collapses to a single assertion here).
 *
 * The cast cannot be made type-safe without locking the RootStateType generic
 * to PeerborneState, which would prevent callers from using nested stores.
 * Extracting it here removes the five identical inline casts from actions.ts
 * without changing any runtime behaviour.
 *
 * @internal This helper is package-internal — exported only so that
 * `actions.ts` can use it as the default selector. External consumers should
 * provide their own selector matching their store layout.
 */
export function defaultStateSelector<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
>(
  state: unknown,
): State<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
> {
  return state as State<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >;
}
