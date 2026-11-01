import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  captureConnectOptions,
  connectWithRetry,
  type ConnectionProgress,
} from './connection.js';

function failure(name: string) {
  return Object.assign(
    new Error('private-payload-marker #invite=secret-marker'),
    { name },
  );
}

describe('connection recovery and diagnostics', () => {
  test('retries transport establishment and preserves safe progress without replaying a protocol operation', async () => {
    const events: ConnectionProgress[] = [];
    const dial = jest
      .fn<Parameters<typeof connectWithRetry>[0]>()
      .mockRejectedValueOnce(failure('ConnectionFailedError'))
      .mockImplementationOnce(async (_attempt, report) => {
        report({
          type: 'websockets:open-connection',
          detail: 'secret-marker',
        } as { type: string });
        report({ type: 'upgrader:encrypt-outbound-connection' });
        return {};
      });
    await connectWithRetry(
      dial,
      captureConnectOptions({
        maxAttempts: 3,
        retryDelayMs: 0,
        onProgress: (event) => {
          events.push(event);
        },
      }),
      0,
      1,
    );
    expect(dial.mock.calls.map(([attempt]) => attempt)).toEqual([1, 2]);
    expect(events.filter((event) => event.type === 'retrying')).toMatchObject([
      { errorType: 'ConnectionFailedError', attempt: 1 },
    ]);
    expect(events.at(-1)).toMatchObject({
      type: 'connected',
      stage: 'secure-channel',
      attempt: 2,
    });
    expect(events.every(Object.isFrozen)).toBe(true);
    expect(JSON.stringify(events)).not.toMatch(
      /secret-marker|private-payload-marker|invite=/,
    );
  });

  test.each([
    'UnexpectedPeerError',
    'InvalidCryptoExchangeError',
    'DialError',
    'TypeError',
    'Error',
  ])('does not retry %s and preserves its original error', async (name) => {
    const error = failure(name);
    const dial = jest
      .fn<Parameters<typeof connectWithRetry>[0]>()
      .mockRejectedValue(error);
    await expect(
      connectWithRetry(
        dial,
        captureConnectOptions({ maxAttempts: 3, retryDelayMs: 0 }),
        0,
        1,
      ),
    ).rejects.toBe(error);
    expect(dial).toHaveBeenCalledTimes(1);
  });

  test('keeps one attempt as the default', async () => {
    const dial = jest
      .fn<Parameters<typeof connectWithRetry>[0]>()
      .mockRejectedValue(failure('ConnectionFailedError'));
    await expect(
      connectWithRetry(dial, captureConnectOptions(), 0, 1),
    ).rejects.toThrow();
    expect(dial).toHaveBeenCalledTimes(1);
  });

  test('ignores late progress from a completed attempt', async () => {
    const events: ConnectionProgress[] = [];
    let staleProgress: ((event: { type: string }) => void) | undefined;
    await connectWithRetry(
      async (attempt, report) => {
        if (attempt === 1) {
          staleProgress = report;
          throw failure('TimeoutError');
        }
        staleProgress?.({ type: 'upgrader:encrypt-outbound-connection' });
      },
      captureConnectOptions({
        maxAttempts: 2,
        retryDelayMs: 0,
        onProgress: (event) => {
          events.push(event);
        },
      }),
      0,
      1,
    );
    const count = events.length;
    staleProgress?.({ type: 'websockets:open-connection' });
    expect(events).toHaveLength(count);
    expect(events.filter((event) => event.type === 'progress')).toEqual([]);
    expect(events.at(-1)).toMatchObject({
      type: 'connected',
      attempt: 2,
      stage: 'dial',
    });
  });

  test('bounds actual asynchronous attempts for arbitrary failure schedules', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 3 }),
        fc.integer({ min: 0, max: 6 }),
        async (maximum, failures) => {
          let calls = 0;
          const operation = connectWithRetry(
            async () => {
              calls++;
              if (calls <= failures) throw failure('ConnectionClosedError');
            },
            captureConnectOptions({ maxAttempts: maximum, retryDelayMs: 0 }),
            0,
            1,
          );
          if (failures < maximum) await operation;
          else await expect(operation).rejects.toThrow();
          expect(calls).toBe(Math.min(failures + 1, maximum));
        },
      ),
      { seed: 2011112, numRuns: 40 },
    );
  });

  test('cancels during backoff without making another dial or exposing the abort reason', async () => {
    const controller = new AbortController();
    const reason = new Error('secret-marker');
    const events: ConnectionProgress[] = [];
    const dial = jest
      .fn<Parameters<typeof connectWithRetry>[0]>()
      .mockRejectedValue(failure('ConnectionFailedError'));
    await expect(
      connectWithRetry(
        dial,
        captureConnectOptions({
          signal: controller.signal,
          maxAttempts: 3,
          retryDelayMs: 10000,
          onProgress: (event) => {
            events.push(event);
            if (event.type === 'retrying') controller.abort(reason);
          },
        }),
        0,
        1,
      ),
    ).rejects.toBe(reason);
    expect(dial).toHaveBeenCalledTimes(1);
    expect(events.at(-1)?.type).toBe('failed');
    expect(events.at(-1)?.aborted).toBe(true);
    expect(JSON.stringify(events)).not.toContain('secret-marker');
  });

  test('rejects a late result when the caller already cancelled', async () => {
    const controller = new AbortController();
    const reason = new Error('cancelled');
    await expect(
      connectWithRetry(
        async () => {
          controller.abort(reason);
        },
        captureConnectOptions({ signal: controller.signal }),
        0,
        1,
      ),
    ).rejects.toBe(reason);
  });

  test('isolates throwing and rejecting diagnostic observers from the connection', async () => {
    for (const callback of [
      () => {
        throw new Error('observer failure');
      },
      async () => {
        throw new Error('observer failure');
      },
    ]) {
      const dial = jest
        .fn<Parameters<typeof connectWithRetry>[0]>()
        .mockResolvedValue({});
      await expect(
        connectWithRetry(
          dial,
          captureConnectOptions({ onProgress: callback }),
          0,
          1,
        ),
      ).resolves.toBeUndefined();
      expect(dial).toHaveBeenCalledTimes(1);
    }
  });

  test.each([0, 4, NaN, 1.5, Infinity])(
    'rejects invalid attempt bound %s before dialing',
    (maximum) => {
      expect(() => captureConnectOptions({ maxAttempts: maximum })).toThrow(
        RangeError,
      );
    },
  );

  test.each([-1, 10001, NaN, 0.5, Infinity])(
    'rejects invalid retry delay %s',
    (retryDelayMs) => {
      expect(() => captureConnectOptions({ retryDelayMs })).toThrow(RangeError);
    },
  );

  test('captures options before caller mutation', () => {
    const options = { maxAttempts: 2, retryDelayMs: 0 };
    const captured = captureConnectOptions(options);
    options.maxAttempts = 200;
    expect(captured.maxAttempts).toBe(2);
  });
});
