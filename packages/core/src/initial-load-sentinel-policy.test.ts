import { describe, expect, test } from '@jest/globals';
import {
  allowsUnauthenticatedUnknownDocumentSentinel,
  isUnknownDocumentAdvertisement,
  unknownDocumentAdvertisement,
} from './initial-load-sentinel-policy.js';

describe('initial-load unknown-document sentinel policy', () => {
  test.each([
    [false, false, true],
    [true, false, false],
    [false, true, false],
    [true, true, false],
  ])(
    'securityAware=%s authenticatedInitial=%s => allowed=%s',
    (securityAware, requireAuthenticatedInitialLoad, expected) => {
      const policy = { securityAware, requireAuthenticatedInitialLoad };
      expect(allowsUnauthenticatedUnknownDocumentSentinel(policy)).toBe(expected);
      expect(unknownDocumentAdvertisement(policy)).toEqual(
        expected ? [new Uint8Array([0xff])] : [],
      );
      expect(
        isUnknownDocumentAdvertisement(new Uint8Array([0xff]), policy),
      ).toBe(expected);
    },
  );

  test('does not mistake other payloads for the sentinel', () => {
    const policy = {
      securityAware: false,
      requireAuthenticatedInitialLoad: false,
    };
    expect(isUnknownDocumentAdvertisement(new Uint8Array(), policy)).toBe(false);
    expect(
      isUnknownDocumentAdvertisement(new Uint8Array([0xff, 0xff]), policy),
    ).toBe(false);
  });
});
