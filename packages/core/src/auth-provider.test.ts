import { describe, expect, test, jest } from '@jest/globals';
import {
  AuthProvider,
  requireDeserializePublicKey,
  requireSerializePublicKey,
} from './auth-provider';

function createProvider(
  overrides: Partial<Record<keyof AuthProvider<string, string>, unknown>> = {},
): AuthProvider<string, string> {
  return {
    sign: async () => new Uint8Array(),
    verify: async () => true,
    encrypt: async () => ({ data: new Uint8Array() }),
    decrypt: async () => new Uint8Array(),
    nonceBytes: 12,
    serializePublicKey: async (key: string) => key,
    deserializePublicKey: async (serialized: string) => serialized,
    ...overrides,
  } as AuthProvider<string, string>;
}

describe('requireSerializePublicKey', () => {
  test('returns a bound function when serializePublicKey is implemented', () => {
    const serializeFn = jest.fn(async (_key: string) => 'serialized-key');
    const provider = createProvider({ serializePublicKey: serializeFn });
    const fn = requireSerializePublicKey(provider, 'test-feature');
    expect(typeof fn).toBe('function');
    void fn('my-key');
    expect(serializeFn).toHaveBeenCalledWith('my-key');
  });

  test('rejects a runtime provider without serializePublicKey', () => {
    const provider = createProvider({ serializePublicKey: undefined });
    expect(() => requireSerializePublicKey(provider, 'BeeKEM Welcome')).toThrow(
      /BeeKEM Welcome requires AuthProvider.serializePublicKey/,
    );
  });

  test('rejects a non-function serializePublicKey', () => {
    const provider = createProvider({ serializePublicKey: 'serialize' });
    expect(() => requireSerializePublicKey(provider, 'MyFeature')).toThrow(
      new TypeError(
        'MyFeature requires AuthProvider.serializePublicKey to be a function',
      ),
    );
  });
});

describe('requireDeserializePublicKey', () => {
  test('returns a bound function when implemented', async () => {
    const deserializeFn = jest.fn(
      async (serialized: string) => `key:${serialized}`,
    );
    const provider = createProvider({ deserializePublicKey: deserializeFn });

    await expect(
      requireDeserializePublicKey(provider, 'Invitations')('abc'),
    ).resolves.toBe('key:abc');
    expect(deserializeFn).toHaveBeenCalledWith('abc');
  });

  test('rejects a runtime provider without deserializePublicKey', () => {
    const provider = createProvider({ deserializePublicKey: undefined });

    expect(() => requireDeserializePublicKey(provider, 'Invitations')).toThrow(
      /Invitations requires AuthProvider.deserializePublicKey/,
    );
  });

  test('rejects a non-function deserializePublicKey', () => {
    const provider = createProvider({ deserializePublicKey: {} });

    expect(() => requireDeserializePublicKey(provider, 'Invitations')).toThrow(
      new TypeError(
        'Invitations requires AuthProvider.deserializePublicKey to be a function',
      ),
    );
  });
});
