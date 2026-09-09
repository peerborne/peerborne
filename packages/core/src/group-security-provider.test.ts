import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  AppliedGroupMembershipDelta,
  EncryptedKeyPackageState,
  EncryptedGroupState,
  GroupKeyPackage,
  GroupSecurityPublicState,
  GroupStateProtector,
  appliedGroupMembershipDeltaHash,
  canonicalAppliedGroupMembershipDelta,
  isEncryptedKeyPackageState,
  isEncryptedGroupState,
} from './group-security-provider.js';
import { WebCryptoGroupStateProtector } from './webcrypto-group-state-protector.js';

const state: GroupSecurityPublicState = {
  protocol: { id: 'contract.test', version: 7 },
  groupId: new Uint8Array([1, 2, 3, 4]),
  epoch: 42n,
  confirmedTranscriptHash: new Uint8Array(32).fill(0x11),
  treeHash: new Uint8Array(32).fill(0x22),
};

const keyPackage: GroupKeyPackage = {
  protocol: { ...state.protocol },
  groupId: new Uint8Array(state.groupId),
  reference: new Uint8Array([0xa1, 0xa2, 0xa3]),
  payload: new Uint8Array([0xb1, 0xb2, 0xb3, 0xb4]),
};

describe('EncryptedKeyPackageState', () => {
  test('round-trips one-time private state and defensively clones public fields', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('kp-key');
    const privateState = new TextEncoder().encode('one-time HPKE private key');
    const envelope = await EncryptedKeyPackageState.seal(
      keyPackage,
      privateState,
      protector,
    );

    expect(isEncryptedKeyPackageState(envelope)).toBe(true);
    expect(new TextDecoder().decode(envelope.serialize())).not.toContain(
      'one-time HPKE private key',
    );
    const restored = EncryptedKeyPackageState.deserialize(envelope.serialize());
    await expect(restored.open(protector)).resolves.toEqual(privateState);
    const exposed = restored.keyPackage;
    exposed.reference[0] ^= 0xff;
    exposed.payload[0] ^= 0xff;
    expect(restored.keyPackage).toEqual(keyPackage);
    const exposedGroupId = restored.groupId;
    exposedGroupId[0] ^= 0xff;
    expect(restored.groupId).toEqual(state.groupId);
  });

  test('authenticates the complete public KeyPackage and rejects malformed envelopes', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('kp-key');
    const envelope = await EncryptedKeyPackageState.seal(
      keyPackage,
      new Uint8Array([9, 8, 7]),
      protector,
    );
    const bytes = envelope.serialize();
    const payloadOffset = findSubarray(bytes, keyPackage.payload);
    bytes[payloadOffset] ^= 0x80;
    await expect(
      EncryptedKeyPackageState.deserialize(bytes).open(protector),
    ).rejects.toBeDefined();

    const relabeled = envelope.serialize();
    const groupOffset = findSubarray(relabeled, state.groupId);
    relabeled[groupOffset] ^= 0x40;
    await expect(
      EncryptedKeyPackageState.deserialize(relabeled).open(protector),
    ).rejects.toBeDefined();

    const canonical = envelope.serialize();
    expect(() =>
      EncryptedKeyPackageState.deserialize(
        canonical.subarray(0, canonical.byteLength - 1),
      ),
    ).toThrow(/truncated/);
    const trailing = new Uint8Array(canonical.byteLength + 1);
    trailing.set(canonical);
    expect(() => EncryptedKeyPackageState.deserialize(trailing)).toThrow(
      /trailing/,
    );
    expect(
      EncryptedKeyPackageState.deserialize(
        crossRealmBytes(canonical),
      ).serialize(),
    ).toEqual(canonical);
    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(
        new SharedArrayBuffer(canonical.byteLength),
      );
      shared.set(canonical);
      expect(() => EncryptedKeyPackageState.deserialize(shared)).toThrow(
        /backing buffer/,
      );
    }
    expect(
      isEncryptedKeyPackageState({
        keyPackage,
        nonce: new Uint8Array([1]),
        ciphertext: new Uint8Array([2]),
      }),
    ).toBe(false);
  });

  test('snapshots mutable protector identity before asynchronous sealing', async () => {
    const delegate = await WebCryptoGroupStateProtector.generate('stable-key');
    let algorithmReads = 0;
    let keyIdReads = 0;
    const mutableProtector: GroupStateProtector = {
      get algorithm() {
        algorithmReads += 1;
        return algorithmReads === 1 ? delegate.algorithm : 'changed-algorithm';
      },
      get keyId() {
        keyIdReads += 1;
        return keyIdReads === 1 ? delegate.keyId : 'changed-key';
      },
      seal: (plaintext, associatedData) =>
        delegate.seal(plaintext, associatedData),
      open: (sealed, associatedData) => delegate.open(sealed, associatedData),
    };

    const envelope = await EncryptedKeyPackageState.seal(
      keyPackage,
      new Uint8Array([1, 2, 3]),
      mutableProtector,
    );
    expect(envelope.algorithm).toBe(delegate.algorithm);
    expect(envelope.keyId).toBe(delegate.keyId);
    await expect(envelope.open(delegate)).resolves.toEqual(
      new Uint8Array([1, 2, 3]),
    );
  });

  test('brands genuine envelopes and rejects forged or overridden instances', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('brand-key');
    const envelope = await EncryptedKeyPackageState.seal(
      keyPackage,
      new Uint8Array([1]),
      protector,
    );
    expect(
      isEncryptedKeyPackageState(
        Object.create(EncryptedKeyPackageState.prototype),
      ),
    ).toBe(false);
    Object.defineProperty(envelope, 'serialize', {
      value: () => new Uint8Array([1]),
    });
    expect(isEncryptedKeyPackageState(envelope)).toBe(false);
  });

  test('freezes the envelope constructor and security-relevant prototype', () => {
    expect(Object.isFrozen(EncryptedKeyPackageState)).toBe(true);
    expect(Object.isFrozen(EncryptedKeyPackageState.prototype)).toBe(true);
    expect(() =>
      Object.defineProperty(EncryptedKeyPackageState.prototype, 'keyPackage', {
        get: () => keyPackage,
      }),
    ).toThrow();
  });
});

describe('EncryptedGroupState', () => {
  test('round-trips authenticated private state without exposing plaintext', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('test-key');
    const privateState = new TextEncoder().encode('private ratchet material');
    const envelope = await EncryptedGroupState.seal(
      state,
      privateState,
      protector,
    );

    expect(isEncryptedGroupState(envelope)).toBe(true);
    expect(new TextDecoder().decode(envelope.serialize())).not.toContain(
      'private ratchet material',
    );
    const restored = EncryptedGroupState.deserialize(envelope.serialize());
    await expect(restored.open(protector)).resolves.toEqual(privateState);
    expect(restored.state).toEqual(state);
  });

  test('binds ciphertext to public metadata and rejects tampering', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('test-key');
    const envelope = await EncryptedGroupState.seal(
      state,
      new Uint8Array([9, 8, 7]),
      protector,
    );
    const bytes = envelope.serialize();
    const offset = findSubarray(bytes, state.groupId);
    bytes[offset] ^= 0x80;

    await expect(
      EncryptedGroupState.deserialize(bytes).open(protector),
    ).rejects.toBeDefined();
  });

  test('strictly rejects truncation, trailing bytes, and oversized lengths', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('test-key');
    const bytes = (
      await EncryptedGroupState.seal(state, new Uint8Array([1]), protector)
    ).serialize();

    expect(() =>
      EncryptedGroupState.deserialize(bytes.subarray(0, bytes.length - 1)),
    ).toThrow(/truncated/);
    const trailing = new Uint8Array(bytes.length + 1);
    trailing.set(bytes);
    expect(() => EncryptedGroupState.deserialize(trailing)).toThrow(/trailing/);
    const unknown = new Uint8Array(bytes);
    unknown[9] = 2;
    expect(() => EncryptedGroupState.deserialize(unknown)).toThrow(
      /unsupported.*version/,
    );
    const oversized = new Uint8Array(bytes);
    const cipherLength = envelopeCipherLengthOffset(bytes);
    new DataView(oversized.buffer).setUint32(cipherLength, 0xffffffff, false);
    expect(() => EncryptedGroupState.deserialize(oversized)).toThrow(
      /invalid length/,
    );
    expect(
      EncryptedGroupState.deserialize(crossRealmBytes(bytes)).serialize(),
    ).toEqual(bytes);
    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(new SharedArrayBuffer(bytes.byteLength));
      shared.set(bytes);
      expect(() => EncryptedGroupState.deserialize(shared)).toThrow(
        /backing buffer/,
      );
    }
  });

  test('defensively clones public state and supports the complete u64 epoch', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('test-key');
    const maximum = (1n << 64n) - 1n;
    const envelope = await EncryptedGroupState.seal(
      { ...state, epoch: maximum },
      new Uint8Array([1]),
      protector,
    );
    const first = envelope.state;
    first.groupId[0] = 0xff;

    expect(envelope.state.groupId).toEqual(state.groupId);
    expect(EncryptedGroupState.deserialize(envelope.serialize()).state.epoch).toBe(
      maximum,
    );
    await expect(
      EncryptedGroupState.seal(
        { ...state, epoch: maximum + 1n },
        new Uint8Array([1]),
        protector,
      ),
    ).rejects.toThrow(/unsigned 64-bit bigint/);
  });

  test('rejects accessor, proxy, and shared public-state storage without invoking it', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('test-key');
    const accessorState = { ...state };
    let treeHashReads = 0;
    Object.defineProperty(accessorState, 'treeHash', {
      configurable: true,
      enumerable: true,
      get() {
        treeHashReads += 1;
        return state.treeHash;
      },
    });
    await expect(
      EncryptedGroupState.seal(
        accessorState,
        new Uint8Array([1]),
        protector,
      ),
    ).rejects.toThrow(/own data properties/);
    expect(treeHashReads).toBe(0);

    let iteratorReads = 0;
    const proxiedTreeHash = new Proxy(new Uint8Array(state.treeHash), {
      get(target, property) {
        if (property === Symbol.iterator) {
          iteratorReads += 1;
          return function* () {
            while (true) yield 0;
          };
        }
        return Reflect.get(target, property, target) as unknown;
      },
    });
    await expect(
      EncryptedGroupState.seal(
        { ...state, treeHash: proxiedTreeHash },
        new Uint8Array([1]),
        protector,
      ),
    ).rejects.toThrow(/genuine Uint8Array/);
    expect(iteratorReads).toBe(0);

    if (typeof SharedArrayBuffer !== 'undefined') {
      await expect(
        EncryptedGroupState.seal(
          {
            ...state,
            confirmedTranscriptHash: new Uint8Array(
              new SharedArrayBuffer(32),
            ),
          },
          new Uint8Array([1]),
          protector,
        ),
      ).rejects.toThrow(/backing buffer/);
    }
  });

  test('does not accept structural plaintext lookalikes as encrypted state', () => {
    expect(
      isEncryptedGroupState({
        state,
        algorithm: 'AES-256-GCM',
        keyId: 'key',
        nonce: new Uint8Array(12),
        ciphertext: new Uint8Array(17),
      }),
    ).toBe(false);
  });

  test('rejects prototype-forged and method-overridden instances', async () => {
    const protector = await WebCryptoGroupStateProtector.generate('brand-key');
    const envelope = await EncryptedGroupState.seal(
      state,
      new Uint8Array([1]),
      protector,
    );
    expect(
      isEncryptedGroupState(Object.create(EncryptedGroupState.prototype)),
    ).toBe(false);
    Object.defineProperty(envelope, 'serialize', {
      value: () => new Uint8Array([1]),
    });
    expect(isEncryptedGroupState(envelope)).toBe(false);
  });

  test('freezes the envelope constructor and security-relevant prototype', () => {
    expect(Object.isFrozen(EncryptedGroupState)).toBe(true);
    expect(Object.isFrozen(EncryptedGroupState.prototype)).toBe(true);
    expect(() =>
      Object.defineProperty(EncryptedGroupState.prototype, 'state', {
        get: () => state,
      }),
    ).toThrow();
  });
});

describe('applied membership delta commitment', () => {
  test('is domain-separated, deterministic, mutation-safe, and strictly bounded', async () => {
    const delta: AppliedGroupMembershipDelta = {
      changes: [
        {
          kind: 'add',
          memberId: new Uint8Array([1, 2]),
          keyPackageRef: new Uint8Array([3, 4]),
        },
      ],
    };
    const canonical = canonicalAppliedGroupMembershipDelta(delta);
    const firstHash = await appliedGroupMembershipDeltaHash(delta);
    canonical.fill(0xff);

    expect(await appliedGroupMembershipDeltaHash(delta)).toEqual(firstHash);
    expect(new TextDecoder().decode(
      canonicalAppliedGroupMembershipDelta(delta),
    )).toContain('group-security-applied-membership-delta/v1');
    expect(() =>
      canonicalAppliedGroupMembershipDelta({ changes: [] }),
    ).toThrow(/change count/);
    expect(() =>
      canonicalAppliedGroupMembershipDelta({
        changes: [
          {
            kind: 'remove',
            memberId: new Uint8Array(513),
          },
        ],
      }),
    ).toThrow(/invalid length/);
    expect(() =>
      canonicalAppliedGroupMembershipDelta({
        changes: [
          {
            kind: 'remove',
            memberId: new Uint8Array([1]),
            ignored: true,
          },
        ],
      } as unknown as AppliedGroupMembershipDelta),
    ).toThrow(/unexpected or missing fields/);
    expect(() =>
      canonicalAppliedGroupMembershipDelta({
        changes: [
          { kind: 'remove', memberId: new Uint8Array([1]) },
          {
            kind: 'update',
            memberId: new Uint8Array([1]),
            keyPackageRef: new Uint8Array([2]),
          },
        ],
      }),
    ).toThrow(/duplicates a memberId/);
  });

  test('snapshots bounded own entries without invoking iterator overrides', () => {
    let iteratorCalls = 0;
    const memberId = new Uint8Array([1]);
    Object.defineProperty(memberId, Symbol.iterator, {
      value: () => {
        iteratorCalls += 1;
        throw new Error('member iterator must not run');
      },
    });
    expect(() =>
      canonicalAppliedGroupMembershipDelta({
        changes: [{ kind: 'remove', memberId }],
      }),
    ).not.toThrow();
    expect(iteratorCalls).toBe(0);

    const changes: AppliedGroupMembershipDelta['changes'] = [
      { kind: 'remove', memberId: new Uint8Array([2]) },
    ];
    Object.defineProperty(changes, 'entries', {
      value: () => {
        iteratorCalls += 1;
        throw new Error('array entries override must not run');
      },
    });
    expect(() =>
      canonicalAppliedGroupMembershipDelta({ changes }),
    ).toThrow(/extra properties/);
    expect(iteratorCalls).toBe(0);
  });

  test('rejects accessor-backed changes and shared byte storage', () => {
    let getterCalls = 0;
    const change = {
      memberId: new Uint8Array([1]),
    } as { kind: 'remove'; memberId: Uint8Array };
    Object.defineProperty(change, 'kind', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return 'remove';
      },
    });
    expect(() =>
      canonicalAppliedGroupMembershipDelta({ changes: [change] }),
    ).toThrow(/enumerable data properties/);
    expect(getterCalls).toBe(0);

    if (typeof SharedArrayBuffer !== 'undefined') {
      expect(() =>
        canonicalAppliedGroupMembershipDelta({
          changes: [
            {
              kind: 'remove',
              memberId: new Uint8Array(new SharedArrayBuffer(1)),
            },
          ],
        }),
      ).toThrow(/backing buffer/);
    }
  });
});

function findSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let start = 0; start <= haystack.length - needle.length; start++) {
    for (let index = 0; index < needle.length; index++) {
      if (haystack[start + index] !== needle[index]) continue outer;
    }
    return start;
  }
  return -1;
}

function envelopeCipherLengthOffset(bytes: Uint8Array): number {
  const restored = EncryptedGroupState.deserialize(bytes);
  return bytes.length - restored.ciphertext.length - 4;
}

function crossRealmBytes(bytes: Uint8Array): Uint8Array {
  return runInNewContext(
    `new Uint8Array([${Array.from(bytes).join(',')}])`,
  ) as Uint8Array;
}
