import { NoteSharingError } from './sharing-error.js';

test('keeps the original failure available without including it in serializable diagnostics', () => {
  const cause = new Error(
    'secret-marker #invite=private-link private document body',
  );
  const error = new NoteSharingError(
    'relay-connection',
    cause,
    'ConnectionFailedError',
    3,
    1234,
  );
  expect(error.cause).toBe(cause);
  expect(error.diagnostic).toEqual({
    stage: 'relay-connection',
    errorType: 'ConnectionFailedError',
    attempts: 3,
    elapsedMs: 1234,
  });
  expect(Object.isFrozen(error.diagnostic)).toBe(true);
  expect(JSON.stringify(error)).not.toMatch(
    /secret-marker|invite=|private document/,
  );
  expect(error.message).toMatch(/relay/);
});

test('distinguishes relay reservation from invitation creation failures', () => {
  expect(
    new NoteSharingError(
      'relay-reservation',
      undefined,
      'TimeoutError',
      1,
      45000,
    ).message,
  ).toMatch(/did not become ready/);
  expect(
    new NoteSharingError('invitation', undefined, 'OtherError', 1, 100)
      .diagnostic.stage,
  ).toBe('invitation');
});
