import { describe, expect, test, jest } from '@jest/globals';
import {
  AuthProvider,
  requireDeserializePublicKey,
  requireSerializePublicKey,
} from './auth-provider';

function makeProvider(): AuthProvider<string, string> {
  return {
    sign: async () => new Uint8Array(),
    verify: async () => true,
    encrypt: async () => ({ data: new Uint8Array() }),
    decrypt: async () => new Uint8Array(),
    nonceBytes: 12,
    serializePublicKey: async (key) => key,
    deserializePublicKey: async (serialized) => serialized,
  };
}

describe('requireSerializePublicKey', () => {
  test('returns a bound function', async () => {
    const provider = makeProvider();
    provider.serializePublicKey = jest.fn(async function (
      this: unknown,
      key: string,
    ) {
      expect(this).toBe(provider);
      return `serialized:${key}`;
    });
    await expect(
      requireSerializePublicKey(provider, 'test-feature')('key'),
    ).resolves.toBe('serialized:key');
    expect(provider.serializePublicKey).toHaveBeenCalledWith('key');
  });

  test('rejects a missing method at the JavaScript boundary', () => {
    const provider = makeProvider();
    Reflect.deleteProperty(provider, 'serializePublicKey');
    expect(() => requireSerializePublicKey(provider, 'BeeKEM Welcome')).toThrow(
      /BeeKEM Welcome requires AuthProvider.serializePublicKey/,
    );
  });

  test('includes the feature name in a malformed-provider error', () => {
    const provider = makeProvider();
    Reflect.set(provider, 'serializePublicKey', { callable: true });
    expect(() => requireSerializePublicKey(provider, 'MyFeature')).toThrow(
      /MyFeature requires AuthProvider.serializePublicKey/,
    );
  });
});

describe('requireDeserializePublicKey', () => {
  test('returns a bound function', async () => {
    const provider = makeProvider();
    provider.deserializePublicKey = jest.fn(async function (
      this: unknown,
      serialized: string,
    ) {
      expect(this).toBe(provider);
      return `key:${serialized}`;
    });
    await expect(
      requireDeserializePublicKey(provider, 'Invitations')('abc'),
    ).resolves.toBe('key:abc');
    expect(provider.deserializePublicKey).toHaveBeenCalledWith('abc');
  });

  test.each([undefined, { callable: true }])(
    'rejects a missing or malformed method: %p',
    (value) => {
      const provider = makeProvider();
      Reflect.set(provider, 'deserializePublicKey', value);
      expect(() =>
        requireDeserializePublicKey(provider, 'Invitations'),
      ).toThrow(/Invitations requires AuthProvider.deserializePublicKey/);
    },
  );
});
