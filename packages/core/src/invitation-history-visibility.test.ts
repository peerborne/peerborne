import { describe, expect, test } from '@jest/globals';
import {
  assertInvitationProcessingWindow,
  assertInitialInvitationHistoryVisibility,
  invitationAcceptanceExpiresAt,
  firstSuccessfulInvitationRendezvous,
  MIN_INVITATION_PROCESSING_WINDOW_MS,
  reuseCachedInvitationAcceptanceOrAssertFresh,
  withInvitationDeadline,
} from './invitation-policy.js';

describe('initial invitation history visibility', () => {
  test('allows an explicit full-history disclosure', () => {
    expect(() =>
      assertInitialInvitationHistoryVisibility('full_history'),
    ).not.toThrow();
  });

  test.each(['current_only', 'since_invited'] as const)(
    'rejects %s because key filtering does not redact retained operations',
    (visibility) => {
      expect(() =>
        assertInitialInvitationHistoryVisibility(visibility),
      ).toThrow(/require historyVisibility "full_history"/);
    },
  );
});

describe('invitation stream deadline', () => {
  test('returns completed work and cancels its timer', async () => {
    await expect(
      withInvitationDeadline(async () => 'accepted', () => {}, 10),
    ).resolves.toBe('accepted');
  });

  test('runs cleanup and rejects even when cleanup itself throws', async () => {
    let cleanupCalled = false;
    await expect(
      withInvitationDeadline(
        () => new Promise<never>(() => {}),
        () => {
          cleanupCalled = true;
          throw new Error('already closed');
        },
        1,
      ),
    ).rejects.toThrow(/deadline exceeded/);
    expect(cleanupCalled).toBe(true);
  });

  test('fails over when post-response verification exceeds the address deadline', async () => {
    const attempted: string[] = [];
    const result = await firstSuccessfulInvitationRendezvous(
      ['stalled-verifier', 'healthy-founder'],
      (address) =>
        withInvitationDeadline(
          async () => {
            attempted.push(address);
            if (address === 'stalled-verifier') {
              await new Promise<never>(() => {});
            }
            return 'verified-acceptance';
          },
          () => {},
          1,
        ),
    );

    expect(attempted).toEqual(['stalled-verifier', 'healthy-founder']);
    expect(result).toEqual({
      address: 'healthy-founder',
      value: 'verified-acceptance',
    });
  });
});

describe('invitation acceptance retry lifetime', () => {
  test('keeps a cached response valid after five minutes and through offer expiry', () => {
    const issuedAtMs = 1_700_000_000_000;
    const offerExpiresAtMs = issuedAtMs + 15 * 60 * 1000;

    expect(
      invitationAcceptanceExpiresAt(
        offerExpiresAtMs,
        issuedAtMs + 6 * 60 * 1000,
      ),
    ).toBe(offerExpiresAtMs);
  });

  test('rejects a response completed after its offer expired', () => {
    expect(() => invitationAcceptanceExpiresAt(100, 100)).toThrow(
      /Invitation expired/,
    );
  });

  test('rejects near-expiry offers before onboarding starts', () => {
    expect(() =>
      assertInvitationProcessingWindow(
        1_000 + MIN_INVITATION_PROCESSING_WINDOW_MS - 1,
        1_000,
      ),
    ).toThrow(/at least/);
    expect(() =>
      assertInvitationProcessingWindow(
        1_000 + MIN_INVITATION_PROCESSING_WINDOW_MS,
        1_000,
      ),
    ).not.toThrow();
  });

  test('returns an exact cached response near expiry but rejects fresh work', () => {
    const now = 10_000;
    const expiresAt = now + 1;
    const cached = { acceptanceId: 'exact-response' };

    expect(
      reuseCachedInvitationAcceptanceOrAssertFresh(cached, expiresAt, now),
    ).toBe(cached);
    expect(() =>
      reuseCachedInvitationAcceptanceOrAssertFresh(undefined, expiresAt, now),
    ).toThrow(/at least/);
  });
});
