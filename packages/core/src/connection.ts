import {
  MAX_CONNECTION_ATTEMPTS,
  shouldRetryConnection,
} from './policy/connection-retry.js';

export type ConnectionErrorType =
  | 'ConnectionFailedError'
  | 'ConnectionClosedError'
  | 'TimeoutError'
  | 'AbortError'
  | 'DialError'
  | 'UnexpectedPeerError'
  | 'EncryptionFailedError'
  | 'InvalidCryptoExchangeError'
  | 'OtherError';

export interface ConnectionProgress {
  readonly type: 'attempt' | 'progress' | 'retrying' | 'connected' | 'failed';
  readonly stage: 'dial' | 'transport' | 'secure-channel' | 'multiplexing';
  readonly addressIndex: number;
  readonly addressCount: number;
  readonly attempt: number;
  readonly maxAttempts: number;
  readonly elapsedMs: number;
  readonly aborted: boolean;
  readonly errorType?: ConnectionErrorType;
}

export interface ConnectOptions {
  readonly signal?: AbortSignal;
  /** One attempt by default; at most three, only for transient transport failures. */
  readonly maxAttempts?: number;
  /** Delay between attempts, from zero to 10 seconds. Defaults to 250 ms. */
  readonly retryDelayMs?: number;
  /** Receives bounded metadata without addresses, native details, or error messages. */
  readonly onProgress?: (event: ConnectionProgress) => void | Promise<void>;
}

interface CapturedConnectOptions {
  readonly signal?: AbortSignal;
  readonly maxAttempts: number;
  readonly retryDelayMs: number;
  readonly onProgress?: ConnectOptions['onProgress'];
}

export function captureConnectOptions(
  options: ConnectOptions = {},
): CapturedConnectOptions {
  const { signal, maxAttempts = 1, retryDelayMs = 250, onProgress } = options;
  if (
    !Number.isInteger(maxAttempts) ||
    maxAttempts < 1 ||
    maxAttempts > MAX_CONNECTION_ATTEMPTS
  ) {
    throw new RangeError('maxAttempts must be an integer from one to three');
  }
  if (
    !Number.isInteger(retryDelayMs) ||
    retryDelayMs < 0 ||
    retryDelayMs > 10_000
  ) {
    throw new RangeError('retryDelayMs must be an integer from zero to 10000');
  }
  if (onProgress !== undefined && typeof onProgress !== 'function') {
    throw new TypeError('onProgress must be a function');
  }
  return Object.freeze({ signal, maxAttempts, retryDelayMs, onProgress });
}

function errorType(error: unknown): ConnectionErrorType {
  let name: unknown;
  try {
    name = error instanceof Error ? error.name : undefined;
  } catch {
    return 'OtherError';
  }
  switch (name) {
    case 'ConnectionFailedError':
    case 'ConnectionClosedError':
    case 'TimeoutError':
    case 'AbortError':
    case 'DialError':
    case 'UnexpectedPeerError':
    case 'EncryptionFailedError':
    case 'InvalidCryptoExchangeError':
      return name;
    default:
      return 'OtherError';
  }
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    };
    const abort = () => {
      cleanup();
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, milliseconds);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
  });
}

/** @internal Retry transport establishment, never an application protocol operation. */
export async function connectWithRetry(
  dial: (
    attempt: number,
    onProgress: (event: { type: string }) => void,
  ) => Promise<unknown>,
  options: CapturedConnectOptions,
  addressIndex: number,
  addressCount: number,
): Promise<void> {
  const started = performance.now();
  let attempt = 0;
  let stage: ConnectionProgress['stage'] = 'dial';
  const emit = (
    type: ConnectionProgress['type'],
    failure?: ConnectionErrorType,
  ) => {
    if (!options.onProgress) return;
    const event: ConnectionProgress = Object.freeze({
      type,
      stage,
      addressIndex,
      addressCount,
      attempt,
      maxAttempts: options.maxAttempts,
      elapsedMs: Math.max(0, Math.round(performance.now() - started)),
      aborted: options.signal?.aborted === true,
      ...(failure === undefined ? {} : { errorType: failure }),
    });
    try {
      void Promise.resolve(options.onProgress(event)).catch(() => undefined);
    } catch {}
  };
  const progress = (event: { type: string }) => {
    switch (event.type) {
      case 'websockets:open-connection':
      case 'transport-manager:selected-transport':
        stage = 'transport';
        break;
      case 'upgrader:encrypt-outbound-connection':
        stage = 'secure-channel';
        break;
      case 'upgrader:multiplex-outbound-connection':
        stage = 'multiplexing';
        break;
      default:
        return;
    }
    emit('progress');
  };
  try {
    for (attempt = 1; attempt <= options.maxAttempts; attempt++) {
      stage = 'dial';
      options.signal?.throwIfAborted();
      emit('attempt');
      try {
        let active = true;
        try {
          await dial(attempt, (event) => {
            if (active) progress(event);
          });
        } finally {
          active = false;
        }
        options.signal?.throwIfAborted();
        emit('connected');
        return;
      } catch (error) {
        const type = errorType(error);
        const retryable =
          type === 'ConnectionFailedError' ||
          type === 'ConnectionClosedError' ||
          type === 'TimeoutError';
        if (
          !shouldRetryConnection(
            retryable,
            options.signal?.aborted === true,
            attempt,
            options.maxAttempts,
          )
        )
          throw error;
        emit('retrying', type);
        await delay(options.retryDelayMs, options.signal);
      }
    }
  } catch (error) {
    const failure = options.signal?.aborted ? options.signal.reason : error;
    emit('failed', errorType(failure));
    throw failure;
  }
}
