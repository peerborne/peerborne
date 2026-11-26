import { describe, expect, test } from '@jest/globals';
import {
  assertSharedProtocolRequestSize,
  MAX_SHARED_PROTOCOL_REQUEST_BYTES,
} from './shared-protocol-request.js';

describe('shared protocol request size', () => {
  test('accepts the exact cap and rejects the next byte', () => {
    expect(() =>
      assertSharedProtocolRequestSize(MAX_SHARED_PROTOCOL_REQUEST_BYTES),
    ).not.toThrow();
    expect(() =>
      assertSharedProtocolRequestSize(MAX_SHARED_PROTOCOL_REQUEST_BYTES + 1),
    ).toThrow(/exceeds/);
  });

  test.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    'rejects invalid byte length %p',
    (byteLength) => {
      expect(() => assertSharedProtocolRequestSize(byteLength)).toThrow(
        /invalid byte length/,
      );
    },
  );
});
