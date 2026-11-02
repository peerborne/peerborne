import {
  advanceDocumentOperation,
  canReserveDocumentOperation,
  releaseDocumentOperationBytes,
  type DocumentOperationPhase,
} from './policy/document-admission.js';
import {
  copyUnsharedUint8Array,
  unsharedUint8ArrayByteLength,
  snapshotEnumerableOwnDataObject,
} from './utils.js';
import { observeAdmissionWork } from './internal/admission-work.js';

export const DEFAULT_DOCUMENT_OPERATION_COUNT = 16;
export const DEFAULT_DOCUMENT_OPERATION_BYTES = 16 * 1024 * 1024;
export const DEFAULT_DOCUMENT_OPERATION_INPUT_BYTES = 1024 * 1024;
export const DEFAULT_DOCUMENT_OPERATION_TIMEOUT_MS = 10_000;

const MAX_DOCUMENT_OPERATION_BYTES = 128 * 1024 * 1024;
const nativeAbortAny = AbortSignal.any;
const nativeAbortedGetter = Object.getOwnPropertyDescriptor(
  AbortSignal.prototype,
  'aborted',
)!.get!;
const nativeAddListener = EventTarget.prototype.addEventListener;
const nativeRemoveListener = EventTarget.prototype.removeEventListener;

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal !== undefined && Reflect.apply(nativeAbortedGetter, signal, []);
}

export type GroupDocumentOperationFailure =
  | 'capacity-exceeded'
  | 'invalid-input'
  | 'invalid-preparation'
  | 'stale-context'
  | 'authorization-changed'
  | 'aborted'
  | 'timeout';

export class GroupDocumentOperationError extends Error {
  constructor(readonly code: GroupDocumentOperationFailure) {
    super(`Document operation rejected: ${code}`);
    this.name = 'GroupDocumentOperationError';
  }
}

/** Accounts work slots and charged bytes, not JavaScript heap allocations. */
export class GroupDocumentOperationBudget {
  private count = 0;
  private bytes = 0;

  constructor(
    readonly maxOperations: number,
    readonly maxBytes: number,
  ) {
    if (
      !Number.isSafeInteger(maxOperations) ||
      maxOperations < 1 ||
      maxOperations > 1024 ||
      !Number.isSafeInteger(maxBytes) ||
      maxBytes < 1 ||
      maxBytes > MAX_DOCUMENT_OPERATION_BYTES
    ) {
      throw new RangeError('Document operation budget is outside bounds');
    }
  }

  get usage(): Readonly<{ operations: number; bytes: number }> {
    return { operations: this.count, bytes: this.bytes };
  }

  reserve(bytes: number): () => void {
    if (
      !Number.isSafeInteger(bytes) ||
      bytes < 0 ||
      !canReserveDocumentOperation(
        this.count,
        this.bytes,
        bytes,
        this.maxOperations,
        this.maxBytes,
      )
    ) {
      throw new GroupDocumentOperationError('capacity-exceeded');
    }
    this.count += 1;
    this.bytes += bytes;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.count -= 1;
      this.bytes = releaseDocumentOperationBytes(this.bytes, bytes);
    };
  }
}

// Shared by every coordinator using this module instance, across document IDs.
const sharedBudget = new GroupDocumentOperationBudget(64, 64 * 1024 * 1024);

export interface GroupDocumentOperationOptions {
  readonly signal?: AbortSignal;
}

/** Detached staging. Both callbacks are synchronous; the guard is pure. */
export interface PreparedGroupDocumentOperation {
  readonly isAuthorizationCurrent: () => boolean;
  readonly commit: () => void;
}

/** Observe actual nested work without thenable assimilation or early credit release. */
export interface GroupDocumentPreparationWork {
  isActive(): boolean;
  observe<T>(work: unknown): Promise<{ readonly value: T }>;
}

export interface GroupDocumentOperationHooks<Context> {
  capture(signal: AbortSignal): Promise<Context>;
  prepare(
    context: Context,
    input: Uint8Array,
    signal: AbortSignal,
    work: GroupDocumentPreparationWork,
  ): Promise<PreparedGroupDocumentOperation>;
  commit(
    context: Context,
    finish: (contextMatches: boolean) => void,
    signal: AbortSignal,
  ): Promise<void>;
  poison(): void;
}

/** Internal orchestration; authentication and detached staging are trusted hooks. */
export class GroupDocumentOperationGate {
  readonly budget: GroupDocumentOperationBudget;

  constructor(
    maxOperations = DEFAULT_DOCUMENT_OPERATION_COUNT,
    maxBytes = DEFAULT_DOCUMENT_OPERATION_BYTES,
    private readonly timeoutMs = DEFAULT_DOCUMENT_OPERATION_TIMEOUT_MS,
    private readonly aggregateBudget = sharedBudget,
    private readonly inputByteLimit = DEFAULT_DOCUMENT_OPERATION_INPUT_BYTES,
  ) {
    this.budget = new GroupDocumentOperationBudget(maxOperations, maxBytes);
    if (
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > 120_000
    ) {
      throw new RangeError('Document operation timeout is outside bounds');
    }
    if (
      !Number.isSafeInteger(inputByteLimit) ||
      inputByteLimit < 1 ||
      inputByteLimit > MAX_DOCUMENT_OPERATION_BYTES
    )
      throw new RangeError('Document operation input limit is outside bounds');
  }

  run<Context>(
    input: Uint8Array,
    hooks: GroupDocumentOperationHooks<Context>,
    options: GroupDocumentOperationOptions = {},
  ): Promise<void> {
    let signal: AbortSignal | undefined;
    let releaseLocal: (() => void) | undefined;
    let releaseAggregate: (() => void) | undefined;
    let payload: Uint8Array;
    try {
      const raw =
        snapshotEnumerableOwnDataObject<GroupDocumentOperationOptions>(
          options,
          'document operation options',
          { maxProperties: 1, maxKeyBytes: 12 },
        );
      if (Object.keys(raw).some((key) => key !== 'signal'))
        throw new GroupDocumentOperationError('invalid-input');
      if (isAborted(raw.signal))
        throw new GroupDocumentOperationError('aborted');
      signal =
        raw.signal === undefined
          ? undefined
          : (Reflect.apply(nativeAbortAny, AbortSignal, [
              [raw.signal],
            ]) as AbortSignal);
      const length = unsharedUint8ArrayByteLength(
        input,
        0,
        this.inputByteLimit,
        'document operation',
      );
      releaseAggregate = this.aggregateBudget.reserve(length);
      releaseLocal = this.budget.reserve(length);
      payload = copyUnsharedUint8Array(input, 0, length, 'document operation');
    } catch (error) {
      releaseLocal?.();
      releaseAggregate?.();
      return Promise.reject(
        error instanceof GroupDocumentOperationError
          ? error
          : new GroupDocumentOperationError('invalid-input'),
      );
    }

    const controller = new AbortController();
    let phase: DocumentOperationPhase = 'preparing';
    let cancelled: GroupDocumentOperationError | undefined;
    let rejectCancellation!: (error: GroupDocumentOperationError) => void;
    const cancellation = new Promise<never>((_, reject) => {
      rejectCancellation = reject;
    });
    let rejectInvalid!: (error: GroupDocumentOperationError) => void;
    const invalid = new Promise<never>((_, reject) => {
      rejectInvalid = reject;
    });
    const unexpectedWork = new Set<Promise<unknown>>();
    let preparationActive = false;
    const retain = (pending: Promise<unknown>) => {
      unexpectedWork.add(pending);
      void pending.then(() => {
        unexpectedWork.delete(pending);
      });
    };
    const invalidPreparation = (result: unknown) => {
      const pending = observeRejectedNativePromise(result);
      if (pending !== undefined) retain(pending);
      const error = new GroupDocumentOperationError('invalid-preparation');
      if (pending !== undefined) rejectInvalid(error);
      return error;
    };
    const preparationWork: GroupDocumentPreparationWork = {
      isActive: () => preparationActive && !isAborted(controller.signal),
      observe: <T>(value: unknown) => {
        if (!preparationActive)
          return Promise.reject(
            new GroupDocumentOperationError('invalid-preparation'),
          );
        const observed = observeAdmissionWork<T>(value);
        retain(observed.settlement);
        if (!observed.observable) {
          const error = new GroupDocumentOperationError('invalid-preparation');
          rejectInvalid(error);
          return Promise.reject(error);
        }
        return observed.result;
      },
    };
    const cancel = (code: 'aborted' | 'timeout') => {
      if (phase === 'committed' || cancelled !== undefined) return;
      phase = advanceDocumentOperation(phase, 'cancel', false, false);
      cancelled = new GroupDocumentOperationError(code);
      controller.abort();
      rejectCancellation(cancelled);
    };
    const onAbort = () => cancel('aborted');
    const timer = setTimeout(() => cancel('timeout'), this.timeoutMs);
    const checkActive = () => {
      if (isAborted(signal)) cancel('aborted');
      if (cancelled !== undefined) throw cancelled;
    };
    if (signal !== undefined)
      Reflect.apply(nativeAddListener, signal, [
        'abort',
        onAbort,
        { once: true },
      ]);
    if (isAborted(signal)) onAbort();

    const work = (async () => {
      checkActive();
      const context = await hooks.capture(controller.signal);
      checkActive();
      let staged: PreparedGroupDocumentOperation;
      preparationActive = true;
      try {
        const preparation =
          observeAdmissionWork<PreparedGroupDocumentOperation>(
            hooks.prepare(context, payload, controller.signal, preparationWork),
          );
        retain(preparation.settlement);
        if (!preparation.observable) {
          const error = new GroupDocumentOperationError('invalid-preparation');
          rejectInvalid(error);
          throw error;
        }
        staged = (await preparation.result).value;
      } finally {
        preparationActive = false;
      }
      checkActive();
      if (unexpectedWork.size !== 0) {
        const error = new GroupDocumentOperationError('invalid-preparation');
        rejectInvalid(error);
        throw error;
      }
      let stagedSnapshot: PreparedGroupDocumentOperation;
      try {
        stagedSnapshot =
          snapshotEnumerableOwnDataObject<PreparedGroupDocumentOperation>(
            staged,
            'prepared document operation',
            { maxProperties: 2, maxKeyBytes: 64 },
          );
      } catch {
        throw new GroupDocumentOperationError('invalid-preparation');
      }
      const finalize = stagedSnapshot.commit;
      const authorize = stagedSnapshot.isAuthorizationCurrent;
      if (typeof finalize !== 'function' || typeof authorize !== 'function')
        throw new GroupDocumentOperationError('invalid-preparation');
      phase = advanceDocumentOperation(phase, 'prepare', true, false);
      await hooks.commit(
        context,
        (contextMatches) => {
          checkActive();
          if (phase !== 'prepared')
            throw new GroupDocumentOperationError('invalid-preparation');
          let authorized: unknown = false;
          if (contextMatches) {
            try {
              authorized = authorize();
            } catch {
              throw new GroupDocumentOperationError('authorization-changed');
            }
            if (typeof authorized !== 'boolean') {
              throw invalidPreparation(authorized);
            }
          }
          const next = advanceDocumentOperation(
            phase,
            'commit',
            contextMatches,
            authorized === true,
          );
          if (next !== 'committed')
            throw new GroupDocumentOperationError(
              contextMatches ? 'authorization-changed' : 'stale-context',
            );
          phase = next;
          try {
            const result: unknown = finalize();
            if (result !== undefined) {
              // Observe native rejected promises without invoking arbitrary then getters.
              throw invalidPreparation(result);
            }
          } catch (error) {
            hooks.poison();
            throw error;
          }
        },
        controller.signal,
      );
      if (phase !== 'committed')
        throw new GroupDocumentOperationError('invalid-preparation');
    })().finally(async () => {
      clearTimeout(timer);
      try {
        if (signal !== undefined)
          Reflect.apply(nativeRemoveListener, signal, ['abort', onAbort]);
      } finally {
        try {
          await Promise.all(unexpectedWork);
        } finally {
          releaseLocal!();
          releaseAggregate!();
        }
      }
    });

    // Cancellation stops the caller waiting, but credits stay charged until
    // uncancellable work settles and releases its retained input.
    return Promise.race([work, cancellation, invalid]);
  }
}

function observeRejectedNativePromise(
  value: unknown,
): Promise<unknown> | undefined {
  if (
    (typeof value !== 'object' || value === null) &&
    typeof value !== 'function'
  )
    return undefined;
  const work = observeAdmissionWork(value);
  if (work.observable)
    void work.result.then(
      () => {},
      () => {},
    );
  return work.settlement;
}
