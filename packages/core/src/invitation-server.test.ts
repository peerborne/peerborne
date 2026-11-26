import { describe, expect, jest, test } from '@jest/globals';
import {
  assertInvitationOfferLifetime,
  INVITATION_BEFORE_ACCEPTANCE_TIMEOUT_MS,
  InMemoryInvitationAcceptanceCoordinator,
  MIN_INVITATION_OFFER_TTL_MS,
  MIN_INVITATION_PROCESSING_WINDOW_MS,
  runInvitationBeforeAcceptance,
  withInvitationDeadline,
} from './invitation-policy.js';
import { MAX_INVITATION_TTL_MS } from './invitation-wire.js';

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

const OFFER_EXPIRES_AT = 1_900_000_000_000;

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe('invitation acceptance in-flight lifecycle', () => {
  test('an abort before onboarding does not invoke the mutation', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const claim = jest.fn(async () => {});
    const start = jest.fn(async () => 'acceptance');
    const controller = new AbortController();
    controller.abort(new Error('request stream closed'));

    await expect(
      coordinator.run(
        'request-a',
        OFFER_EXPIRES_AT,
        controller.signal,
        claim,
        () => {},
        start,
      ),
    ).rejects.toThrow(/request stream closed/);
    expect(claim).not.toHaveBeenCalled();
    expect(start).not.toHaveBeenCalled();
    expect(coordinator.inFlightCount).toBe(0);
  });

  test('an abort after the claim but before start does not invoke the mutation', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const controller = new AbortController();
    const claim = jest.fn(async () => {
      controller.abort(new Error('stream closed during claim'));
    });
    const start = jest.fn(async () => 'acceptance');

    await expect(
      coordinator.run(
        'request-a',
        OFFER_EXPIRES_AT,
        controller.signal,
        claim,
        () => {},
        start,
      ),
    ).rejects.toThrow(/stream closed during claim/);
    expect(claim).toHaveBeenCalledTimes(1);
    expect(start).not.toHaveBeenCalled();
    expect(coordinator.inFlightCount).toBe(0);
  });

  test('an abort while waiting for the claim queue does not consume the claim', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const claimGate = deferred<void>();
    const claimStarted = deferred<void>();
    const first = coordinator.run(
      'request-a',
      OFFER_EXPIRES_AT,
      undefined,
      async () => {
        claimStarted.resolve();
        await claimGate.promise;
      },
      () => {},
      async () => 'acceptance-a',
    );
    await claimStarted.promise;

    const controller = new AbortController();
    const secondClaim = jest.fn(async () => {});
    const second = coordinator.run(
      'request-b',
      OFFER_EXPIRES_AT,
      controller.signal,
      secondClaim,
      () => {},
      async () => 'acceptance-b',
    );
    controller.abort(new Error('request closed while queued'));
    claimGate.resolve();

    await expect(first).resolves.toBe('acceptance-a');
    await expect(second).rejects.toThrow(/closed while queued/);
    expect(secondClaim).not.toHaveBeenCalled();
  });

  test('availability is rechecked after the claim and before mutation', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    let available = true;
    const claim = jest.fn(async () => {
      available = false;
    });
    const assertCanStart = jest.fn(() => {
      if (!available) throw new Error('invitation offer is unavailable');
    });
    const start = jest.fn(async () => 'acceptance');

    await expect(
      coordinator.run(
        'request-a',
        OFFER_EXPIRES_AT,
        undefined,
        claim,
        assertCanStart,
        start,
      ),
    ).rejects.toThrow(/offer is unavailable/);
    expect(claim).toHaveBeenCalledTimes(1);
    expect(assertCanStart).toHaveBeenCalledTimes(1);
    expect(start).not.toHaveBeenCalled();
    expect(coordinator.inFlightCount).toBe(0);
  });

  test('a timed-out stream can retry the exact request without repeating onboarding', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const pending = deferred<string>();
    const started = deferred<void>();
    const claim = jest.fn(async () => {});
    const start = jest.fn(() => {
      started.resolve();
      return pending.promise;
    });
    const controller = new AbortController();
    const first = coordinator.run(
      'request-a',
      OFFER_EXPIRES_AT,
      controller.signal,
      claim,
      () => {},
      start,
    );
    await started.promise;

    await expect(
      withInvitationDeadline(
        () => first,
        (error) => controller.abort(error),
        1,
      ),
    ).rejects.toThrow(/deadline exceeded/);

    const retry = coordinator.run(
      'request-a',
      OFFER_EXPIRES_AT,
      undefined,
      claim,
      () => {},
      start,
    );
    expect(claim).toHaveBeenCalledTimes(1);
    expect(start).toHaveBeenCalledTimes(1);
    expect(coordinator.inFlightCount).toBe(1);

    pending.resolve('exact-acceptance');
    await expect(Promise.all([first, retry])).resolves.toEqual([
      'exact-acceptance',
      'exact-acceptance',
    ]);
    await Promise.resolve();
    expect(coordinator.inFlightCount).toBe(0);
    expect(coordinator.cachedCount).toBe(1);

    await expect(
      coordinator.run(
        'request-a',
        OFFER_EXPIRES_AT,
        undefined,
        claim,
        () => {},
        start,
      ),
    ).resolves.toBe('exact-acceptance');
    expect(claim).toHaveBeenCalledTimes(1);
    expect(start).toHaveBeenCalledTimes(1);
  });

  test('records a synchronously throwing start before an exact retry can run', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const claim = jest.fn(async () => {});
    let inFlightAtStart = 0;
    const start = jest.fn((): Promise<string> => {
      inFlightAtStart = coordinator.inFlightCount;
      throw new Error('synchronous onboarding failure');
    });

    const first = coordinator.run(
      'request-a',
      OFFER_EXPIRES_AT,
      undefined,
      claim,
      () => {},
      start,
    );
    const exactRetry = coordinator.run(
      'request-a',
      OFFER_EXPIRES_AT,
      undefined,
      claim,
      () => {},
      start,
    );

    const results = await Promise.allSettled([first, exactRetry]);
    expect(results).toEqual([
      expect.objectContaining({
        status: 'rejected',
        reason: expect.objectContaining({
          message: 'synchronous onboarding failure',
        }),
      }),
      expect.objectContaining({
        status: 'rejected',
        reason: expect.objectContaining({
          message: 'synchronous onboarding failure',
        }),
      }),
    ]);
    expect(inFlightAtStart).toBe(1);
    expect(claim).toHaveBeenCalledTimes(1);
    expect(start).toHaveBeenCalledTimes(1);
    expect(coordinator.inFlightCount).toBe(0);
    expect(coordinator.cachedCount).toBe(0);
  });

  test('a different request is rejected while the claimed request is in flight', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const pending = deferred<string>();
    const started = deferred<void>();
    let claimedRequest: string | undefined;
    const claimFor = (requestKey: string) => async () => {
      if (claimedRequest !== undefined && claimedRequest !== requestKey) {
        throw new Error('offer already claimed by another request');
      }
      claimedRequest = requestKey;
    };
    const start = jest.fn(() => {
      started.resolve();
      return pending.promise;
    });
    const first = coordinator.run(
      'request-a',
      OFFER_EXPIRES_AT,
      undefined,
      claimFor('request-a'),
      () => {},
      start,
    );
    await started.promise;

    await expect(
      coordinator.run(
        'request-b',
        OFFER_EXPIRES_AT,
        undefined,
        claimFor('request-b'),
        () => {},
        start,
      ),
    ).rejects.toThrow(/offer already claimed/);
    expect(start).toHaveBeenCalledTimes(1);

    pending.resolve('acceptance-a');
    await first;
  });

  test('a failed operation is removed so the exact request can retry', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const claim = jest.fn(async () => {});
    let attempts = 0;
    const start = jest.fn(async () => {
      attempts += 1;
      if (attempts === 1) throw new Error('bootstrap failed');
      return 'recovered-acceptance';
    });

    await expect(
      coordinator.run(
        'request-a',
        OFFER_EXPIRES_AT,
        undefined,
        claim,
        () => {},
        start,
      ),
    ).rejects.toThrow(/bootstrap failed/);
    await Promise.resolve();
    expect(coordinator.inFlightCount).toBe(0);
    expect(coordinator.cachedCount).toBe(0);

    await expect(
      coordinator.run(
        'request-a',
        OFFER_EXPIRES_AT,
        undefined,
        claim,
        () => {},
        start,
      ),
    ).resolves.toBe('recovered-acceptance');
    expect(claim).toHaveBeenCalledTimes(2);
    expect(start).toHaveBeenCalledTimes(2);
    await Promise.resolve();
    expect(coordinator.inFlightCount).toBe(0);
    expect(coordinator.cachedCount).toBe(1);
  });
});

describe('invitation retries near expiry', () => {
  test('a request that already started can retry inside the processing window', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const start = jest
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error('storage unavailable'))
      .mockResolvedValueOnce('acceptance');
    await expect(
      coordinator.run(
        'request-a',
        Date.now() + MIN_INVITATION_OFFER_TTL_MS,
        undefined,
        async () => {},
        () => {},
        start,
      ),
    ).rejects.toThrow(/storage unavailable/);

    const lateExpiry = Date.now() + MIN_INVITATION_PROCESSING_WINDOW_MS - 1;
    await expect(
      coordinator.run(
        'request-b',
        lateExpiry,
        undefined,
        async () => {},
        () => {},
        start,
      ),
    ).rejects.toThrow(/at least 30000ms remaining/);
    await expect(
      coordinator.run(
        'request-a',
        lateExpiry,
        undefined,
        async () => {},
        () => {},
        start,
      ),
    ).resolves.toBe('acceptance');
    expect(start).toHaveBeenCalledTimes(2);
  });

  test('a started request cannot retry after its offer expires', async () => {
    const coordinator = new InMemoryInvitationAcceptanceCoordinator<string>();
    const start = jest
      .fn<() => Promise<string>>()
      .mockRejectedValue(new Error('storage unavailable'));
    await expect(
      coordinator.run(
        'request-a',
        Date.now() + MIN_INVITATION_OFFER_TTL_MS,
        undefined,
        async () => {},
        () => {},
        start,
      ),
    ).rejects.toThrow(/storage unavailable/);
    await expect(
      coordinator.run(
        'request-a',
        Date.now() - 1,
        undefined,
        async () => {},
        () => {},
        start,
      ),
    ).rejects.toThrow(/expired before the retry started/);
    expect(start).toHaveBeenCalledTimes(1);
  });
});

describe('invitation beforeAcceptance bound', () => {
  test('passes through a settled hook and its rejection', async () => {
    const expiresAt = Date.now() + MIN_INVITATION_OFFER_TTL_MS;
    await expect(
      runInvitationBeforeAcceptance(async () => {}, expiresAt),
    ).resolves.toBeUndefined();
    await expect(
      runInvitationBeforeAcceptance(async () => {
        throw new Error('storage unavailable');
      }, expiresAt),
    ).rejects.toThrow(/storage unavailable/);
  });

  test('times out at the fixed bound or the offer expiry, whichever is first', async () => {
    jest.useFakeTimers({ now: 1_000_000 });
    try {
      const pending = () => new Promise<void>(() => {});
      const bounded = runInvitationBeforeAcceptance(
        pending,
        Date.now() + MIN_INVITATION_OFFER_TTL_MS,
      );
      const boundedResult = expect(bounded).rejects.toThrow(/timed out/);
      await jest.advanceTimersByTimeAsync(
        INVITATION_BEFORE_ACCEPTANCE_TIMEOUT_MS,
      );
      await boundedResult;

      const nearExpiry = runInvitationBeforeAcceptance(
        pending,
        Date.now() + 1_000,
      );
      const nearExpiryResult = expect(nearExpiry).rejects.toThrow(/timed out/);
      await jest.advanceTimersByTimeAsync(1_000);
      await nearExpiryResult;

      await expect(
        runInvitationBeforeAcceptance(pending, Date.now()),
      ).rejects.toThrow(/expired before beforeAcceptance ran/);
    } finally {
      jest.useRealTimers();
    }
  });
});

describe('invitation offer lifetime', () => {
  test('keeps transport time ahead of the founder processing window', () => {
    expect(() =>
      assertInvitationOfferLifetime(MIN_INVITATION_OFFER_TTL_MS - 1),
    ).toThrow(/60000/);
    expect(() =>
      assertInvitationOfferLifetime(MIN_INVITATION_OFFER_TTL_MS),
    ).not.toThrow();
    expect(() =>
      assertInvitationOfferLifetime(MAX_INVITATION_TTL_MS),
    ).not.toThrow();
    expect(() =>
      assertInvitationOfferLifetime(MAX_INVITATION_TTL_MS + 1),
    ).toThrow(/604800000/);
  });
});
