import { MAX_INVITATION_TTL_MS } from './invitation-wire.js';

/**
 * Controls which historical document-key epochs a peer supplies in load and
 * Welcome responses.
 *
 * This setting is not a historical-content confidentiality boundary. A key
 * can encrypt multiple CRDT operations, and retained sync trees or snapshots
 * can still contain earlier operations encrypted under a supplied key.
 *
 * - `current_only` (default): Supply only the current epoch key.
 * - `full_history`: Supply every retained epoch key.
 * - `since_invited`: Supply keys from the recorded invitation epoch onward.
 */
export type HistoryVisibility =
  | 'current_only'
  | 'full_history'
  | 'since_invited';

/** Reserve enough time for bounded local onboarding work and one response. */
export const MIN_INVITATION_PROCESSING_WINDOW_MS = 30_000;
/** Leave transport time before the founder-side processing window begins. */
export const MIN_INVITATION_OFFER_TTL_MS = 60_000;
export const INVITATION_STREAM_TIMEOUT_MS = 30_000;

/** @internal Validate the lifetime advertised by a newly-created offer. */
export function assertInvitationOfferLifetime(expiresInMs: number): void {
  if (
    !Number.isSafeInteger(expiresInMs) ||
    expiresInMs < MIN_INVITATION_OFFER_TTL_MS ||
    expiresInMs > MAX_INVITATION_TTL_MS
  ) {
    throw new Error(
      `Invitation expiresInMs must be an integer from ` +
        `${MIN_INVITATION_OFFER_TTL_MS} to ${MAX_INVITATION_TTL_MS}`,
    );
  }
}

function throwIfInvitationAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw signal.reason instanceof Error
    ? signal.reason
    : new Error('Invitation stream closed before onboarding started');
}

/**
 * Per-offer cache and in-flight registry for idempotent invitation responses.
 *
 * The queue covers only the one-time claim and synchronous installation of
 * the operation promise. It is released while onboarding runs so an exact
 * retry can attach immediately. Once `start` is called the operation remains
 * tracked even if its original stream is aborted, because document membership
 * work may already have begun and must be allowed to reach a consistent end.
 *
 * @internal
 */
export class InMemoryInvitationAcceptanceCoordinator<T> {
  private readonly _cached = new Map<string, T>();
  private readonly _inFlight = new Map<string, Promise<T>>();
  private _queue: Promise<void> = Promise.resolve();

  get cachedCount(): number {
    return this._cached.size;
  }

  get inFlightCount(): number {
    return this._inFlight.size;
  }

  async run(
    requestKey: string,
    offerExpiresAtMs: number,
    signal: AbortSignal | undefined,
    claim: () => Promise<void>,
    assertCanStart: () => void,
    start: () => Promise<T>,
  ): Promise<T> {
    const cached = this._cached.get(requestKey);
    if (cached !== undefined) {
      return reuseCachedInvitationAcceptanceOrAssertFresh(
        cached,
        offerExpiresAtMs,
      )!;
    }
    const inFlight = this._inFlight.get(requestKey);
    if (inFlight) return inFlight;
    reuseCachedInvitationAcceptanceOrAssertFresh(
      undefined,
      offerExpiresAtMs,
    );
    throwIfInvitationAborted(signal);

    const previous = this._queue;
    let release!: () => void;
    this._queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;

    let result: Promise<T>;
    try {
      const cachedAfterQueue = this._cached.get(requestKey);
      if (cachedAfterQueue !== undefined) {
        result = Promise.resolve(
          reuseCachedInvitationAcceptanceOrAssertFresh(
            cachedAfterQueue,
            offerExpiresAtMs,
          )!,
        );
      } else {
        const inFlightAfterQueue = this._inFlight.get(requestKey);
        if (inFlightAfterQueue) {
          result = inFlightAfterQueue;
        } else {
          // The stream may have closed while this request waited behind a
          // different claim. Do not consume replay state for abandoned work.
          throwIfInvitationAborted(signal);
          reuseCachedInvitationAcceptanceOrAssertFresh(
            undefined,
            offerExpiresAtMs,
          );
          await claim();

          assertCanStart();
          // This is the final cancellation point. Install the operation before
          // invoking `start`, whose synchronous prefix may already mutate state.
          throwIfInvitationAborted(signal);
          const operation = Promise.resolve().then(start);
          this._inFlight.set(requestKey, operation);
          void operation.then(
            (value) => {
              this._cached.set(requestKey, value);
              if (this._inFlight.get(requestKey) === operation) {
                this._inFlight.delete(requestKey);
              }
            },
            () => {
              if (this._inFlight.get(requestKey) === operation) {
                this._inFlight.delete(requestKey);
              }
            },
          );
          result = operation;
        }
      }
    } finally {
      release();
    }
    return result;
  }
}

/** @internal Race invitation stream work against a hard cleanup deadline. */
export async function withInvitationDeadline<T>(
  operation: () => Promise<T>,
  onTimeout: (error: Error) => void,
  timeoutMs: number = INVITATION_STREAM_TIMEOUT_MS,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      const error = new Error('Invitation stream deadline exceeded');
      try {
        onTimeout(error);
      } catch {
        // Cleanup is best-effort; the deadline must still reject.
      }
      reject(error);
    }, timeoutMs);
  });
  try {
    return await Promise.race([operation(), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** @internal Initial invitations intentionally disclose retained history. */
export function assertInitialInvitationHistoryVisibility(
  historyVisibility: HistoryVisibility,
): void {
  if (historyVisibility !== 'full_history') {
    throw new Error(
      'Initial-release invitations require historyVisibility "full_history" ' +
        'because current_only and since_invited filter epoch keys but do not ' +
        'safely exclude retained historical CRDT operations from the bootstrap',
    );
  }
}

/** @internal Keep an idempotent response usable for the offer's full lifetime. */
export function invitationAcceptanceExpiresAt(
  offerExpiresAtMs: number,
  nowMs: number = Date.now(),
): number {
  if (offerExpiresAtMs <= nowMs) {
    throw new Error('Invitation expired while the join was processed');
  }
  return offerExpiresAtMs;
}

/** @internal Reject near-expiry offers before any membership mutation. */
export function assertInvitationProcessingWindow(
  offerExpiresAtMs: number,
  nowMs: number = Date.now(),
): void {
  if (offerExpiresAtMs - nowMs < MIN_INVITATION_PROCESSING_WINDOW_MS) {
    throw new Error(
      `Invitation must have at least ${MIN_INVITATION_PROCESSING_WINDOW_MS}ms remaining`,
    );
  }
}

/**
 * Return an already-built exact response without requiring time for fresh
 * membership work. Callers must first verify the request and confirm that the
 * offer itself has not expired.
 */
export function reuseCachedInvitationAcceptanceOrAssertFresh<T>(
  cached: T | undefined,
  offerExpiresAtMs: number,
  nowMs: number = Date.now(),
): T | undefined {
  if (cached !== undefined) return cached;
  assertInvitationProcessingWindow(offerExpiresAtMs, nowMs);
  return undefined;
}

/** @internal Try signed offer endpoints in order until one full attempt works. */
export async function firstSuccessfulInvitationRendezvous<T>(
  addresses: readonly string[],
  attempt: (address: string) => Promise<T>,
): Promise<{ address: string; value: T }> {
  let lastError: unknown;
  for (const address of addresses) {
    try {
      return { address, value: await attempt(address) };
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(
    `Unable to accept invitation from any rendezvous address${
      lastError instanceof Error ? `: ${lastError.message}` : ''
    }`,
  );
}
