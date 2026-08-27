import { describe, expect, test, jest } from '@jest/globals';
import {
  AuthProvider,
  requireDeserializePublicKey,
  requireSerializePublicKey,
} from './auth-provider';

describe('requireSerializePublicKey', () => {
  test('returns a bound function when serializePublicKey is implemented', () => {
    const serializeFn = jest.fn(async (_key: string) => 'serialized-key');
    const provider: AuthProvider<string, string> = {
      sign: async () => new Uint8Array(),
      verify: async () => true,
      encrypt: async () => ({ data: new Uint8Array() }),
      decrypt: async () => new Uint8Array(),
      nonceBits: 96,
      serializePublicKey: serializeFn as any,
    };
    const fn = requireSerializePublicKey(provider, 'test-feature');
    expect(typeof fn).toBe('function');
    void fn('my-key');
    expect(serializeFn).toHaveBeenCalledWith('my-key');
  });

  test('throws when serializePublicKey is not implemented', () => {
    const provider: AuthProvider<string, string> = {
      sign: async () => new Uint8Array(),
      verify: async () => true,
      encrypt: async () => ({ data: new Uint8Array() }),
      decrypt: async () => new Uint8Array(),
      nonceBits: 96,
    };
    expect(() => requireSerializePublicKey(provider, 'BeeKEM Welcome')).toThrow(
      /BeeKEM Welcome requires AuthProvider.serializePublicKey/,
    );
  });

  test('error message includes the feature name', () => {
    const provider: AuthProvider<string, string> = {
      sign: async () => new Uint8Array(),
      verify: async () => true,
      encrypt: async () => ({ data: new Uint8Array() }),
      decrypt: async () => new Uint8Array(),
      nonceBits: 96,
    };
    expect(() => requireSerializePublicKey(provider, 'MyFeature')).toThrow(
      /MyFeature requires AuthProvider.serializePublicKey/,
    );
  });
});

describe('requireDeserializePublicKey', () => {
  test('returns a bound function when implemented', async () => {
    const deserializeFn = jest.fn(async (serialized: string) => `key:${serialized}`);
    const provider: AuthProvider<string, string> = {
      sign: async () => new Uint8Array(),
      verify: async () => true,
      encrypt: async () => ({ data: new Uint8Array() }),
      decrypt: async () => new Uint8Array(),
      nonceBits: 96,
      deserializePublicKey: deserializeFn,
    };

    await expect(
      requireDeserializePublicKey(provider, 'Invitations')('abc'),
    ).resolves.toBe('key:abc');
    expect(deserializeFn).toHaveBeenCalledWith('abc');
  });

  test('throws when not implemented', () => {
    const provider: AuthProvider<string, string> = {
      sign: async () => new Uint8Array(),
      verify: async () => true,
      encrypt: async () => ({ data: new Uint8Array() }),
      decrypt: async () => new Uint8Array(),
      nonceBits: 96,
    };

    expect(() => requireDeserializePublicKey(provider, 'Invitations')).toThrow(
      /Invitations requires AuthProvider.deserializePublicKey/,
    );
  });
});
