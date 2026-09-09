import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  WEBCRYPTO_GROUP_STATE_NONCE_LENGTH,
  WebCryptoGroupStateProtector,
} from './webcrypto-group-state-protector.js';

describe('WebCryptoGroupStateProtector', () => {
  test('uses fresh AES-GCM nonces and authenticates associated data', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('key-1');
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const associatedData = new Uint8Array([5, 6, 7]);
    const first = await protector.seal(plaintext, associatedData);
    const second = await protector.seal(plaintext, associatedData);

    expect(first.nonce).toHaveLength(WEBCRYPTO_GROUP_STATE_NONCE_LENGTH);
    expect(first.nonce).not.toEqual(second.nonce);
    await expect(protector.open(first, associatedData)).resolves.toEqual(
      plaintext,
    );
    await expect(
      protector.open(first, new Uint8Array([5, 6, 8])),
    ).rejects.toBeDefined();
  });

  test('rejects ciphertext and nonce tampering', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('key-1');
    const sealed = await protector.seal(
      new Uint8Array([1]),
      new Uint8Array([2]),
    );
    sealed.ciphertext[0] ^= 1;
    await expect(
      protector.open(sealed, new Uint8Array([2])),
    ).rejects.toBeDefined();
    await expect(
      protector.open(
        { ...sealed, nonce: new Uint8Array(11) },
        new Uint8Array([2]),
      ),
    ).rejects.toThrow(/nonce.*invalid length/);
  });

  test('snapshots seal inputs before asynchronous encryption', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const delayedCrypto = {
      getRandomValues: crypto.getRandomValues.bind(crypto),
      subtle: {
        encrypt: async (
          algorithm: AlgorithmIdentifier,
          cryptoKey: CryptoKey,
          data: BufferSource,
        ) => {
          await gate;
          return crypto.subtle.encrypt(algorithm, cryptoKey, data);
        },
        decrypt: crypto.subtle.decrypt.bind(crypto.subtle),
      },
    } as unknown as Crypto;
    const protector = new WebCryptoGroupStateProtector(
      'key-1',
      key,
      delayedCrypto,
    );
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const associatedData = new Uint8Array([5, 6, 7]);
    const expectedPlaintext = new Uint8Array(plaintext);
    const expectedAssociatedData = new Uint8Array(associatedData);

    const pending = protector.seal(plaintext, associatedData);
    plaintext.fill(0xee);
    associatedData.fill(0xdd);
    release();

    const sealed = await pending;
    const verifier = new WebCryptoGroupStateProtector('key-1', key);
    await expect(
      verifier.open(sealed, expectedAssociatedData),
    ).resolves.toEqual(expectedPlaintext);
  });

  test('snapshots open inputs before asynchronous decryption', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const protector = new WebCryptoGroupStateProtector('key-1', key);
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const associatedData = new Uint8Array([5, 6, 7]);
    const sealed = await protector.seal(plaintext, associatedData);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const delayedCrypto = {
      getRandomValues: crypto.getRandomValues.bind(crypto),
      subtle: {
        encrypt: crypto.subtle.encrypt.bind(crypto.subtle),
        decrypt: async (
          algorithm: AlgorithmIdentifier,
          cryptoKey: CryptoKey,
          data: BufferSource,
        ) => {
          await gate;
          return crypto.subtle.decrypt(algorithm, cryptoKey, data);
        },
      },
    } as unknown as Crypto;
    const delayedProtector = new WebCryptoGroupStateProtector(
      'key-1',
      key,
      delayedCrypto,
    );

    const pending = delayedProtector.open(sealed, associatedData);
    sealed.nonce.fill(0xee);
    sealed.ciphertext.fill(0xdd);
    associatedData.fill(0xcc);
    release();

    await expect(pending).resolves.toEqual(plaintext);
  });

  test('accepts cross-realm byte inputs', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('key-1');
    const crossRealm = (bytes: Uint8Array): Uint8Array =>
      runInNewContext(
        `new Uint8Array([${Array.from(bytes).join(',')}])`,
      ) as Uint8Array;
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const associatedData = new Uint8Array([5, 6, 7]);
    const sealed = await protector.seal(
      crossRealm(plaintext),
      crossRealm(associatedData),
    );

    await expect(
      protector.open(
        {
          nonce: crossRealm(sealed.nonce),
          ciphertext: crossRealm(sealed.ciphertext),
        },
        crossRealm(associatedData),
      ),
    ).resolves.toEqual(plaintext);
  });

  test('rejects SharedArrayBuffer-backed byte inputs', async () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    const protector = await WebCryptoGroupStateProtector.generate('key-1');
    const shared = (length: number) =>
      new Uint8Array(new SharedArrayBuffer(length));
    const plaintext = new Uint8Array([1]);
    const associatedData = new Uint8Array([2]);
    const sealed = await protector.seal(plaintext, associatedData);

    await expect(protector.seal(shared(1), associatedData)).rejects.toThrow(
      /plaintext.*backing buffer/,
    );
    await expect(protector.seal(plaintext, shared(1))).rejects.toThrow(
      /associatedData.*backing buffer/,
    );
    await expect(
      protector.open(
        { ...sealed, nonce: shared(WEBCRYPTO_GROUP_STATE_NONCE_LENGTH) },
        associatedData,
      ),
    ).rejects.toThrow(/nonce.*backing buffer/);
    await expect(
      protector.open(
        { ...sealed, ciphertext: shared(sealed.ciphertext.byteLength) },
        associatedData,
      ),
    ).rejects.toThrow(/ciphertext.*backing buffer/);
    await expect(protector.open(sealed, shared(1))).rejects.toThrow(
      /associatedData.*backing buffer/,
    );
  });

  test('reports unavailable Web Crypto from generate', async () => {
    await expect(
      WebCryptoGroupStateProtector.generate(
        'key-1',
        null as unknown as Crypto,
      ),
    ).rejects.toThrow('Web Crypto is unavailable');
    await expect(
      WebCryptoGroupStateProtector.generate(
        'key-1',
        {} as unknown as Crypto,
      ),
    ).rejects.toThrow('Web Crypto is unavailable');

    for (const generateKey of [undefined, 1]) {
      await expect(
        WebCryptoGroupStateProtector.generate('key-1', {
          subtle: { generateKey },
        } as unknown as Crypto),
      ).rejects.toThrow(/^Web Crypto is unavailable$/);
    }

    let generateKeyReads = 0;
    const subtle = Object.defineProperty({}, 'generateKey', {
      get() {
        generateKeyReads++;
        throw new TypeError('hostile generateKey getter detail');
      },
    });
    await expect(
      WebCryptoGroupStateProtector.generate('key-1', {
        subtle,
      } as unknown as Crypto),
    ).rejects.toThrow(/^Web Crypto is unavailable$/);
    expect(generateKeyReads).toBe(1);
  });

  test('reports unavailable Web Crypto from seal capability boundaries', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    for (const getRandomValues of [undefined, 1]) {
      let encryptReads = 0;
      const subtle = Object.defineProperty({}, 'encrypt', {
        get() {
          encryptReads++;
          return crypto.subtle.encrypt;
        },
      });
      expect(
        () =>
          new WebCryptoGroupStateProtector('key-1', key, {
            getRandomValues,
            subtle,
          } as unknown as Crypto),
      ).toThrow(/^Web Crypto is unavailable$/);
      expect(encryptReads).toBe(0);
    }

    for (const encrypt of [undefined, 1]) {
      let randomCalls = 0;
      expect(
        () =>
          new WebCryptoGroupStateProtector('key-1', key, {
            getRandomValues() {
              randomCalls++;
              return new Uint8Array(WEBCRYPTO_GROUP_STATE_NONCE_LENGTH);
            },
            subtle: { encrypt },
          } as unknown as Crypto),
      ).toThrow(/^Web Crypto is unavailable$/);
      expect(randomCalls).toBe(0);
    }

    let encryptReads = 0;
    const subtle = Object.defineProperty({}, 'encrypt', {
      get() {
        encryptReads++;
        throw new TypeError('hostile encrypt getter detail');
      },
    });
    expect(
      () =>
        new WebCryptoGroupStateProtector('key-1', key, {
          getRandomValues: crypto.getRandomValues.bind(crypto),
          subtle,
        } as unknown as Crypto),
    ).toThrow(/^Web Crypto is unavailable$/);
    expect(encryptReads).toBe(1);
  });

  test('reports unavailable Web Crypto from open capability boundaries', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );

    for (const decrypt of [undefined, 1]) {
      expect(
        () =>
          new WebCryptoGroupStateProtector('key-1', key, {
            getRandomValues: crypto.getRandomValues.bind(crypto),
            subtle: {
              encrypt: crypto.subtle.encrypt.bind(crypto.subtle),
              decrypt,
            },
          } as unknown as Crypto),
      ).toThrow(/^Web Crypto is unavailable$/);
    }

    let decryptReads = 0;
    const subtle = Object.defineProperty(
      { encrypt: crypto.subtle.encrypt.bind(crypto.subtle) },
      'decrypt',
      {
        get() {
          decryptReads++;
          throw new TypeError('hostile decrypt getter detail');
        },
      },
    );
    expect(
      () =>
        new WebCryptoGroupStateProtector('key-1', key, {
          getRandomValues: crypto.getRandomValues.bind(crypto),
          subtle,
        } as unknown as Crypto),
    ).toThrow(/^Web Crypto is unavailable$/);
    expect(decryptReads).toBe(1);
  });

  test('snapshots subtle once across generate and construction', async () => {
    let subtleReads = 0;
    let randomReceiver = false;
    const cryptoProvider = {
      get subtle() {
        subtleReads++;
        if (subtleReads > 1) {
          throw new TypeError('stateful subtle getter was read again');
        }
        return crypto.subtle;
      },
      getRandomValues(this: unknown, ...args: unknown[]) {
        randomReceiver = this === cryptoProvider;
        return Reflect.apply(crypto.getRandomValues, crypto, args);
      },
    } as unknown as Crypto;

    const protector = await WebCryptoGroupStateProtector.generate(
      'key-1',
      cryptoProvider,
    );
    const associatedData = new Uint8Array([2]);
    const sealed = await protector.seal(new Uint8Array([1]), associatedData);
    await expect(protector.open(sealed, associatedData)).resolves.toEqual(
      new Uint8Array([1]),
    );
    expect(subtleReads).toBe(1);
    expect(randomReceiver).toBe(true);
  });

  test('invokes injected Web Crypto methods with their owning receivers', async () => {
    let generateReceiver = false;
    let randomReceiver = false;
    let encryptReceiver = false;
    let decryptReceiver = false;
    const subtle = {
      generateKey(this: unknown, ...args: unknown[]) {
        generateReceiver = this === subtle;
        return Reflect.apply(crypto.subtle.generateKey, crypto.subtle, args);
      },
      encrypt(this: unknown, ...args: unknown[]) {
        encryptReceiver = this === subtle;
        return Reflect.apply(crypto.subtle.encrypt, crypto.subtle, args);
      },
      decrypt(this: unknown, ...args: unknown[]) {
        decryptReceiver = this === subtle;
        return Reflect.apply(crypto.subtle.decrypt, crypto.subtle, args);
      },
    };
    const cryptoProvider = {
      subtle,
      getRandomValues(this: unknown, ...args: unknown[]) {
        randomReceiver = this === cryptoProvider;
        return Reflect.apply(crypto.getRandomValues, crypto, args);
      },
    } as unknown as Crypto;

    const protector = await WebCryptoGroupStateProtector.generate(
      'key-1',
      cryptoProvider,
    );
    const associatedData = new Uint8Array([2]);
    const sealed = await protector.seal(new Uint8Array([1]), associatedData);
    await expect(protector.open(sealed, associatedData)).resolves.toEqual(
      new Uint8Array([1]),
    );
    expect({
      generateReceiver,
      randomReceiver,
      encryptReceiver,
      decryptReceiver,
    }).toEqual({
      generateReceiver: true,
      randomReceiver: true,
      encryptReceiver: true,
      decryptReceiver: true,
    });
  });

  test('retains method snapshots after provider properties are replaced', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    let replacementCalls = 0;
    const subtle = {
      encrypt(this: unknown, ...args: unknown[]) {
        return Reflect.apply(crypto.subtle.encrypt, crypto.subtle, args);
      },
      decrypt(this: unknown, ...args: unknown[]) {
        return Reflect.apply(crypto.subtle.decrypt, crypto.subtle, args);
      },
    };
    const cryptoProvider = {
      subtle,
      getRandomValues(this: unknown, ...args: unknown[]) {
        return Reflect.apply(crypto.getRandomValues, crypto, args);
      },
    };
    const protector = new WebCryptoGroupStateProtector(
      'key-1',
      key,
      cryptoProvider as unknown as Crypto,
    );
    cryptoProvider.getRandomValues = () => {
      replacementCalls++;
      throw new Error('replacement RNG must not run');
    };
    subtle.encrypt = () => {
      replacementCalls++;
      throw new Error('replacement encrypt must not run');
    };
    subtle.decrypt = () => {
      replacementCalls++;
      throw new Error('replacement decrypt must not run');
    };

    const associatedData = new Uint8Array([2]);
    const sealed = await protector.seal(new Uint8Array([1]), associatedData);
    await expect(protector.open(sealed, associatedData)).resolves.toEqual(
      new Uint8Array([1]),
    );
    expect(replacementCalls).toBe(0);
  });

  test('captures all operation methods before awaiting generateKey', async () => {
    let replacementCalls = 0;
    const subtle = {
      async generateKey(this: unknown, ...args: unknown[]) {
        const key = await Reflect.apply(
          crypto.subtle.generateKey,
          crypto.subtle,
          args,
        );
        cryptoProvider.getRandomValues = () => {
          replacementCalls++;
          throw new Error('replacement RNG must not run');
        };
        subtle.encrypt = () => {
          replacementCalls++;
          throw new Error('replacement encrypt must not run');
        };
        subtle.decrypt = () => {
          replacementCalls++;
          throw new Error('replacement decrypt must not run');
        };
        return key;
      },
      encrypt(this: unknown, ...args: unknown[]) {
        return Reflect.apply(crypto.subtle.encrypt, crypto.subtle, args);
      },
      decrypt(this: unknown, ...args: unknown[]) {
        return Reflect.apply(crypto.subtle.decrypt, crypto.subtle, args);
      },
    };
    const cryptoProvider = {
      subtle,
      getRandomValues(this: unknown, ...args: unknown[]) {
        return Reflect.apply(crypto.getRandomValues, crypto, args);
      },
    };

    const protector = await WebCryptoGroupStateProtector.generate(
      'key-1',
      cryptoProvider as unknown as Crypto,
    );
    const associatedData = new Uint8Array([2]);
    const sealed = await protector.seal(new Uint8Array([1]), associatedData);
    await expect(protector.open(sealed, associatedData)).resolves.toEqual(
      new Uint8Array([1]),
    );
    expect(replacementCalls).toBe(0);
  });

  test('rejects an invalid key id before reading the provider', async () => {
    let providerReads = 0;
    const cryptoProvider = Object.defineProperty({}, 'subtle', {
      get() {
        providerReads++;
        throw new Error('provider must not be read');
      },
    });

    await expect(
      WebCryptoGroupStateProtector.generate(
        'bad key id',
        cryptoProvider as unknown as Crypto,
      ),
    ).rejects.toThrow(/^invalid group-state protector keyId$/);
    expect(providerReads).toBe(0);
  });

  test('rejects extractable and lookalike provider-produced keys', async () => {
    const extractableKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const cryptoProvider = {
      subtle: {
        generateKey: async () => extractableKey,
        encrypt: crypto.subtle.encrypt.bind(crypto.subtle),
        decrypt: crypto.subtle.decrypt.bind(crypto.subtle),
      },
      getRandomValues: crypto.getRandomValues.bind(crypto),
    } as unknown as Crypto;
    await expect(
      WebCryptoGroupStateProtector.generate('key-1', cryptoProvider),
    ).rejects.toThrow(
      /^group-state protector requires a non-extractable 256-bit AES-GCM key with exactly encrypt\/decrypt usages$/,
    );

    let algorithmReads = 0;
    const hostileKey = Object.defineProperties(
      {},
      {
        type: { value: 'secret' },
        extractable: { value: false },
        algorithm: {
          get() {
            algorithmReads++;
            throw new Error('provider-controlled key detail');
          },
        },
        usages: { value: ['encrypt', 'decrypt'] },
      },
    );
    await expect(
      WebCryptoGroupStateProtector.generate('key-1', {
        subtle: {
          generateKey: async () => hostileKey,
          encrypt: crypto.subtle.encrypt.bind(crypto.subtle),
          decrypt: crypto.subtle.decrypt.bind(crypto.subtle),
        },
        getRandomValues: crypto.getRandomValues.bind(crypto),
      } as unknown as Crypto),
    ).rejects.toThrow(
      /^group-state protector requires a non-extractable 256-bit AES-GCM key with exactly encrypt\/decrypt usages$/,
    );
    expect(algorithmReads).toBe(0);
  });

  test('validates native key slots instead of shadowable metadata', async () => {
    const extractableKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    let extractableReads = 0;
    Object.defineProperty(extractableKey, 'extractable', {
      configurable: true,
      get() {
        extractableReads++;
        return false;
      },
    });
    expect(
      () => new WebCryptoGroupStateProtector('key-1', extractableKey),
    ).toThrow(
      /^group-state protector requires a non-extractable 256-bit AES-GCM key with exactly encrypt\/decrypt usages$/,
    );
    expect(extractableReads).toBe(0);
    Reflect.deleteProperty(extractableKey, 'extractable');
    expect(
      (await crypto.subtle.exportKey('raw', extractableKey)).byteLength,
    ).toBe(32);

    const shortKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 128 },
      false,
      ['encrypt', 'decrypt'],
    );
    Object.defineProperty(shortKey, 'algorithm', {
      configurable: true,
      value: { name: 'AES-GCM', length: 256 },
    });
    expect(
      () => new WebCryptoGroupStateProtector('key-1', shortKey),
    ).toThrow(
      /^group-state protector requires a non-extractable 256-bit AES-GCM key with exactly encrypt\/decrypt usages$/,
    );

    const overprivilegedKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    );
    Object.defineProperty(overprivilegedKey, 'usages', {
      configurable: true,
      value: ['encrypt', 'decrypt'],
    });
    expect(
      () => new WebCryptoGroupStateProtector('key-1', overprivilegedKey),
    ).toThrow(
      /^group-state protector requires a non-extractable 256-bit AES-GCM key with exactly encrypt\/decrypt usages$/,
    );
  });

  test('stores a detached key clone and accepts keys across a realm boundary', async () => {
    const key = await runInNewContext(
      `crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      )`,
      { crypto },
    );
    const observedKeys: CryptoKey[] = [];
    const subtle = {
      encrypt(
        this: unknown,
        algorithm: AlgorithmIdentifier,
        operationKey: CryptoKey,
        data: BufferSource,
      ) {
        expect(this).toBe(subtle);
        observedKeys.push(operationKey);
        return crypto.subtle.encrypt(algorithm, operationKey, data);
      },
      decrypt(
        this: unknown,
        algorithm: AlgorithmIdentifier,
        operationKey: CryptoKey,
        data: BufferSource,
      ) {
        expect(this).toBe(subtle);
        observedKeys.push(operationKey);
        return crypto.subtle.decrypt(algorithm, operationKey, data);
      },
    };
    const protector = new WebCryptoGroupStateProtector(
      'key-1',
      key as CryptoKey,
      {
        getRandomValues: crypto.getRandomValues.bind(crypto),
        subtle,
      } as unknown as Crypto,
    );

    Object.defineProperties(key, {
      algorithm: {
        configurable: true,
        value: { name: 'AES-GCM', length: 128 },
      },
      usages: { configurable: true, value: [] },
    });

    const associatedData = new Uint8Array([2]);
    const sealed = await protector.seal(new Uint8Array([1]), associatedData);
    await expect(protector.open(sealed, associatedData)).resolves.toEqual(
      new Uint8Array([1]),
    );
    expect(observedKeys).toHaveLength(2);
    expect(observedKeys[0]).not.toBe(key);
    expect(observedKeys[1]).toBe(observedKeys[0]);
  });

  test('detaches provider-owned encryption and decryption outputs', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    let retainedCiphertext: ArrayBuffer | undefined;
    let retainedPlaintext: ArrayBuffer | undefined;
    const protector = new WebCryptoGroupStateProtector('key-1', key, {
      getRandomValues: crypto.getRandomValues.bind(crypto),
      subtle: {
        encrypt: async () => {
          retainedCiphertext = new ArrayBuffer(17);
          return retainedCiphertext;
        },
        decrypt: async () => {
          retainedPlaintext = new ArrayBuffer(1);
          new Uint8Array(retainedPlaintext)[0] = 7;
          return retainedPlaintext;
        },
      },
    } as unknown as Crypto);

    const sealed = await protector.seal(
      new Uint8Array([1]),
      new Uint8Array([2]),
    );
    new Uint8Array(retainedCiphertext!).fill(0xff);
    expect(sealed.ciphertext).toEqual(new Uint8Array(17));

    const plaintext = await protector.open(
      { nonce: new Uint8Array(12), ciphertext: new Uint8Array(17) },
      new Uint8Array([2]),
    );
    new Uint8Array(retainedPlaintext!).fill(0xff);
    expect(plaintext).toEqual(new Uint8Array([7]));
  });

  test('rejects detached and safely snapshots resizable Web Crypto outputs', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const detached = (length: number): ArrayBuffer => {
      const buffer = new ArrayBuffer(length);
      structuredClone(buffer, { transfer: [buffer] });
      return buffer;
    };
    const detachedOutputs = new WebCryptoGroupStateProtector('key-1', key, {
      getRandomValues: crypto.getRandomValues.bind(crypto),
      subtle: {
        encrypt: async () => detached(17),
        decrypt: async () => detached(1),
      },
    } as unknown as Crypto);
    await expect(
      detachedOutputs.seal(new Uint8Array([1]), new Uint8Array([2])),
    ).rejects.toThrow(/^Web Crypto returned invalid AES-GCM ciphertext$/);
    await expect(
      detachedOutputs.open(
        { nonce: new Uint8Array(12), ciphertext: new Uint8Array(17) },
        new Uint8Array([2]),
      ),
    ).rejects.toThrow(/^Web Crypto returned invalid AES-GCM plaintext$/);

    if (typeof ArrayBuffer.prototype.resize !== 'function') return;
    let retainedCiphertext: ArrayBuffer | undefined;
    let retainedPlaintext: ArrayBuffer | undefined;
    const resizableOutputs = new WebCryptoGroupStateProtector('key-1', key, {
      getRandomValues: crypto.getRandomValues.bind(crypto),
      subtle: {
        encrypt: async () => {
          retainedCiphertext = new ArrayBuffer(17, { maxByteLength: 34 });
          new Uint8Array(retainedCiphertext).fill(3);
          return retainedCiphertext;
        },
        decrypt: async () => {
          retainedPlaintext = new ArrayBuffer(1, { maxByteLength: 2 });
          new Uint8Array(retainedPlaintext)[0] = 7;
          return retainedPlaintext;
        },
      },
    } as unknown as Crypto);
    const sealed = await resizableOutputs.seal(
      new Uint8Array([1]),
      new Uint8Array([2]),
    );
    retainedCiphertext!.resize(1);
    expect(sealed.ciphertext).toEqual(new Uint8Array(17).fill(3));

    const plaintext = await resizableOutputs.open(
      { nonce: new Uint8Array(12), ciphertext: new Uint8Array(17) },
      new Uint8Array([2]),
    );
    retainedPlaintext!.resize(0);
    expect(plaintext).toEqual(new Uint8Array([7]));
  });

  test('rejects shared, malformed, and proxy Web Crypto outputs', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const provider = (
      encrypt: () => Promise<ArrayBuffer>,
      decrypt: () => Promise<ArrayBuffer>,
    ) =>
      ({
        getRandomValues: crypto.getRandomValues.bind(crypto),
        subtle: { encrypt, decrypt },
      }) as unknown as Crypto;
    const malformed = new WebCryptoGroupStateProtector(
      'key-1',
      key,
      provider(
        async () => new ArrayBuffer(16),
        async () => new ArrayBuffer(2),
      ),
    );
    await expect(
      malformed.seal(new Uint8Array([1]), new Uint8Array([2])),
    ).rejects.toThrow(/^Web Crypto returned invalid AES-GCM ciphertext$/);
    await expect(
      malformed.open(
        { nonce: new Uint8Array(12), ciphertext: new Uint8Array(17) },
        new Uint8Array([2]),
      ),
    ).rejects.toThrow(/^Web Crypto returned invalid AES-GCM plaintext$/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new WebCryptoGroupStateProtector(
        'key-1',
        key,
        provider(
          async () => new SharedArrayBuffer(17) as unknown as ArrayBuffer,
          async () => new SharedArrayBuffer(1) as unknown as ArrayBuffer,
        ),
      );
      await expect(
        shared.seal(new Uint8Array([1]), new Uint8Array([2])),
      ).rejects.toThrow(/^Web Crypto returned invalid AES-GCM ciphertext$/);
      await expect(
        shared.open(
          { nonce: new Uint8Array(12), ciphertext: new Uint8Array(17) },
          new Uint8Array([2]),
        ),
      ).rejects.toThrow(/^Web Crypto returned invalid AES-GCM plaintext$/);
    }

    let propertyReads = 0;
    let prototypeReads = 0;
    const proxiedOutput = new Proxy(new ArrayBuffer(17), {
      get(_target, property) {
        if (property === 'then') return undefined;
        propertyReads++;
        throw new Error('output property must not be read');
      },
      getPrototypeOf() {
        prototypeReads++;
        throw new Error('output prototype must not be read');
      },
    });
    const proxied = new WebCryptoGroupStateProtector(
      'key-1',
      key,
      provider(
        async () => proxiedOutput,
        async () => new ArrayBuffer(1),
      ),
    );
    await expect(
      proxied.seal(new Uint8Array([1]), new Uint8Array([2])),
    ).rejects.toThrow(/^Web Crypto returned invalid AES-GCM ciphertext$/);
    expect({ propertyReads, prototypeReads }).toEqual({
      propertyReads: 0,
      prototypeReads: 0,
    });
  });

  test('accepts cross-realm ArrayBuffer outputs from Web Crypto', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const protector = new WebCryptoGroupStateProtector('key-1', key, {
      getRandomValues: crypto.getRandomValues.bind(crypto),
      subtle: {
        encrypt: async () =>
          runInNewContext('new ArrayBuffer(17)') as ArrayBuffer,
        decrypt: async () =>
          runInNewContext('new ArrayBuffer(1)') as ArrayBuffer,
      },
    } as unknown as Crypto);

    await expect(
      protector.seal(new Uint8Array([1]), new Uint8Array([2])),
    ).resolves.toEqual({
      nonce: expect.any(Uint8Array),
      ciphertext: new Uint8Array(17),
    });
    await expect(
      protector.open(
        { nonce: new Uint8Array(12), ciphertext: new Uint8Array(17) },
        new Uint8Array([2]),
      ),
    ).resolves.toEqual(new Uint8Array(1));
  });

  test('rejects an incompatible key and invalid key id', async () => {
    const wrongKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 128 },
      false,
      ['encrypt', 'decrypt'],
    );
    expect(
      () => new WebCryptoGroupStateProtector('key', wrongKey),
    ).toThrow(/256-bit AES-GCM/);
    await expect(
      WebCryptoGroupStateProtector.generate('bad key id'),
    ).rejects.toThrow(/keyId/);
  });
});
