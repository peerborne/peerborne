import { describe, expect, jest, test } from '@jest/globals';

describe('@peerborne/core import safety', () => {
  test('does not require text codecs or WebCrypto during module evaluation', () => {
    const textEncoderDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'TextEncoder',
    );
    const textDecoderDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'TextDecoder',
    );
    const cryptoDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'crypto',
    );

    try {
      Object.defineProperty(globalThis, 'TextEncoder', {
        configurable: true,
        value: undefined,
      });
      Object.defineProperty(globalThis, 'TextDecoder', {
        configurable: true,
        value: undefined,
      });
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: undefined,
      });

      jest.isolateModules(() => {
        expect(() => require('@peerborne/core')).not.toThrow();
      });
    } finally {
      if (textEncoderDescriptor === undefined) {
        Reflect.deleteProperty(globalThis, 'TextEncoder');
      } else {
        Object.defineProperty(
          globalThis,
          'TextEncoder',
          textEncoderDescriptor,
        );
      }
      if (textDecoderDescriptor === undefined) {
        Reflect.deleteProperty(globalThis, 'TextDecoder');
      } else {
        Object.defineProperty(
          globalThis,
          'TextDecoder',
          textDecoderDescriptor,
        );
      }
      if (cryptoDescriptor === undefined) {
        Reflect.deleteProperty(globalThis, 'crypto');
      } else {
        Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
      }
    }
  });
});
