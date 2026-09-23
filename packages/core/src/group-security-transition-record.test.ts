import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  MEMBERSHIP_CONTROL_VERSION,
  MembershipControlSigner,
  canonicalMembershipControlPayload,
  signMembershipControlRecord,
} from './membership-control-record.js';
import {
  GROUP_SECURITY_TRANSITION_RECORD_VERSION,
  MAX_GROUP_SECURITY_TRANSITION_DELIVERY_BYTES,
  deserializeGroupSecurityTransitionRecord,
  serializeGroupSecurityTransitionRecord,
} from './group-security-transition-record.js';

const protocol = { id: 'transition.test', version: 1 };

async function fixture(deliveryPayload = new Uint8Array([9, 8, 7])) {
  const key = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sign: MembershipControlSigner = async (payload) =>
    new Uint8Array(
      await crypto.subtle.sign('HMAC', key, payload as BufferSource),
    );
  const controlRecord = await signMembershipControlRecord(
    {
      version: MEMBERSHIP_CONTROL_VERSION,
      protocol,
      groupId: new Uint8Array([1, 2, 3]),
      epoch: 4n,
      parentRecordId: new Uint8Array(32).fill(1),
      operationId: new Uint8Array(32).fill(2),
      action: 'remove',
      actorId: new Uint8Array([3]),
      subjectId: new Uint8Array([4]),
      controlPayload: new Uint8Array([5, 6]),
    },
    sign,
  );
  return {
    version: GROUP_SECURITY_TRANSITION_RECORD_VERSION,
    deliveryCodec: { id: 'transition.test-codec', version: 1 },
    controlRecord,
    deliveryPayload,
  } as const;
}

describe('group-security transition records', () => {
  test('round-trips an empty delivery while rejecting inconsistent lengths', async () => {
    const record = await fixture(new Uint8Array());
    const serialized = serializeGroupSecurityTransitionRecord(record);
    const decoded = deserializeGroupSecurityTransitionRecord(serialized);
    expect(decoded.deliveryPayload).toEqual(new Uint8Array());
    expect(serializeGroupSecurityTransitionRecord(decoded)).toEqual(serialized);
    expect(() =>
      deserializeGroupSecurityTransitionRecord(serialized.subarray(0, -1)),
    ).toThrow();
    const trailing = new Uint8Array(serialized.length + 1);
    trailing.set(serialized);
    expect(() => deserializeGroupSecurityTransitionRecord(trailing)).toThrow(
      /delivery length/,
    );
    const truncatedDelivery = new Uint8Array(serialized);
    new DataView(truncatedDelivery.buffer).setUint32(serialized.length - 4, 1);
    expect(() =>
      deserializeGroupSecurityTransitionRecord(truncatedDelivery),
    ).toThrow(/delivery length/);
  });

  test('strictly round-trips and detaches complete transition bytes', async () => {
    const record = await fixture();
    const serialized = serializeGroupSecurityTransitionRecord(record);
    const decoded = deserializeGroupSecurityTransitionRecord(serialized);
    const expected = serializeGroupSecurityTransitionRecord(decoded);

    record.controlRecord.groupId.fill(0xee);
    record.deliveryPayload.fill(0xee);
    serialized.fill(0xee);

    expect(serializeGroupSecurityTransitionRecord(decoded)).toEqual(expected);
    expect(decoded.deliveryPayload).toEqual(new Uint8Array([9, 8, 7]));
    expect(decoded.deliveryCodec).toEqual(record.deliveryCodec);
    expect(Object.isFrozen(decoded.deliveryCodec)).toBe(true);
  });

  test('accepts genuine unshared cross-realm Uint8Arrays', async () => {
    const serialized = serializeGroupSecurityTransitionRecord(await fixture());
    const crossRealm = runInNewContext(
      'new Uint8Array(input)',
      { input: Array.from(serialized) },
    ) as Uint8Array;

    expect(
      serializeGroupSecurityTransitionRecord(
        deserializeGroupSecurityTransitionRecord(crossRealm),
      ),
    ).toEqual(serialized);
  });

  test('uses captured intrinsics after hostile runtime mutation', async () => {
    const record = await fixture();
    const serialized = serializeGroupSecurityTransitionRecord(record);
    const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
    const original = {
      reflectApply: Reflect.apply,
      reflectOwnKeys: Reflect.ownKeys,
      objectFreeze: Object.freeze,
      objectIs: Object.is,
      objectGetPrototypeOf: Object.getPrototypeOf,
      objectGetOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
      objectGetOwnPropertyDescriptors: Object.getOwnPropertyDescriptors,
      objectDefineProperty: Object.defineProperty,
      numberIsInteger: Number.isInteger,
      numberIsSafeInteger: Number.isSafeInteger,
      stringCharCodeAt: String.prototype.charCodeAt,
      stringFromCharCode: String.fromCharCode,
      uint8ArrayConstructor: Uint8Array,
      dataViewConstructor: DataView,
      textEncoderConstructor: TextEncoder,
      textDecoderConstructor: TextDecoder,
      regExpTest: RegExp.prototype.test,
      uint8ArraySet: Uint8Array.prototype.set,
      uint8ArraySlice: Uint8Array.prototype.slice,
      uint8ArraySubarray: Uint8Array.prototype.subarray,
      dataViewGetBigUint64: DataView.prototype.getBigUint64,
      dataViewGetUint16: DataView.prototype.getUint16,
      dataViewGetUint32: DataView.prototype.getUint32,
      dataViewSetBigUint64: DataView.prototype.setBigUint64,
      dataViewSetUint16: DataView.prototype.setUint16,
      dataViewSetUint32: DataView.prototype.setUint32,
      textEncoderEncode: TextEncoder.prototype.encode,
      textDecoderDecode: TextDecoder.prototype.decode,
      typedArrayByteLength: Object.getOwnPropertyDescriptor(
        typedArrayPrototype,
        'byteLength',
      )!,
      typedArrayByteOffset: Object.getOwnPropertyDescriptor(
        typedArrayPrototype,
        'byteOffset',
      )!,
      typedArrayBuffer: Object.getOwnPropertyDescriptor(
        typedArrayPrototype,
        'buffer',
      )!,
      typedArrayTag: Object.getOwnPropertyDescriptor(
        typedArrayPrototype,
        Symbol.toStringTag,
      )!,
    };
    const poisoned = () => {
      throw new Error('poisoned runtime intrinsic');
    };
    let encodedWhilePoisoned: Uint8Array | undefined;
    let decodedWhilePoisoned:
      | ReturnType<typeof deserializeGroupSecurityTransitionRecord>
      | undefined;
    try {
      Reflect.apply = poisoned as typeof Reflect.apply;
      Reflect.ownKeys = poisoned as typeof Reflect.ownKeys;
      Object.freeze = poisoned as typeof Object.freeze;
      Object.is = poisoned as typeof Object.is;
      Object.getPrototypeOf = poisoned as typeof Object.getPrototypeOf;
      Object.getOwnPropertyDescriptor =
        poisoned as typeof Object.getOwnPropertyDescriptor;
      Object.getOwnPropertyDescriptors =
        poisoned as typeof Object.getOwnPropertyDescriptors;
      Number.isInteger = poisoned as typeof Number.isInteger;
      Number.isSafeInteger = poisoned as typeof Number.isSafeInteger;
      String.prototype.charCodeAt = poisoned;
      String.fromCharCode = poisoned as typeof String.fromCharCode;
      RegExp.prototype.test = poisoned;
      Uint8Array.prototype.set = poisoned;
      Uint8Array.prototype.slice = poisoned;
      Uint8Array.prototype.subarray = poisoned;
      DataView.prototype.getBigUint64 = poisoned;
      DataView.prototype.getUint16 = poisoned;
      DataView.prototype.getUint32 = poisoned;
      DataView.prototype.setBigUint64 = poisoned;
      DataView.prototype.setUint16 = poisoned;
      DataView.prototype.setUint32 = poisoned;
      TextEncoder.prototype.encode = poisoned;
      TextDecoder.prototype.decode = poisoned;
      original.objectDefineProperty(typedArrayPrototype, 'byteLength', {
        configurable: true,
        get: poisoned,
      });
      original.objectDefineProperty(typedArrayPrototype, 'byteOffset', {
        configurable: true,
        get: poisoned,
      });
      original.objectDefineProperty(typedArrayPrototype, 'buffer', {
        configurable: true,
        get: poisoned,
      });
      original.objectDefineProperty(
        typedArrayPrototype,
        Symbol.toStringTag,
        { configurable: true, get: poisoned },
      );
      globalThis.Uint8Array = poisoned as unknown as typeof Uint8Array;
      globalThis.DataView = poisoned as unknown as typeof DataView;
      globalThis.TextEncoder = poisoned as unknown as typeof TextEncoder;
      globalThis.TextDecoder = poisoned as unknown as typeof TextDecoder;

      encodedWhilePoisoned = serializeGroupSecurityTransitionRecord(record);
      decodedWhilePoisoned = deserializeGroupSecurityTransitionRecord(
        serialized,
      );
    } finally {
      globalThis.Uint8Array = original.uint8ArrayConstructor;
      globalThis.DataView = original.dataViewConstructor;
      globalThis.TextEncoder = original.textEncoderConstructor;
      globalThis.TextDecoder = original.textDecoderConstructor;
      original.objectDefineProperty(
        typedArrayPrototype,
        'byteLength',
        original.typedArrayByteLength,
      );
      original.objectDefineProperty(
        typedArrayPrototype,
        'byteOffset',
        original.typedArrayByteOffset,
      );
      original.objectDefineProperty(
        typedArrayPrototype,
        'buffer',
        original.typedArrayBuffer,
      );
      original.objectDefineProperty(
        typedArrayPrototype,
        Symbol.toStringTag,
        original.typedArrayTag,
      );
      Reflect.apply = original.reflectApply;
      Reflect.ownKeys = original.reflectOwnKeys;
      Object.freeze = original.objectFreeze;
      Object.is = original.objectIs;
      Object.getPrototypeOf = original.objectGetPrototypeOf;
      Object.getOwnPropertyDescriptor =
        original.objectGetOwnPropertyDescriptor;
      Object.getOwnPropertyDescriptors =
        original.objectGetOwnPropertyDescriptors;
      Number.isInteger = original.numberIsInteger;
      Number.isSafeInteger = original.numberIsSafeInteger;
      String.prototype.charCodeAt = original.stringCharCodeAt;
      String.fromCharCode = original.stringFromCharCode;
      RegExp.prototype.test = original.regExpTest;
      Uint8Array.prototype.set = original.uint8ArraySet;
      Uint8Array.prototype.slice = original.uint8ArraySlice;
      Uint8Array.prototype.subarray = original.uint8ArraySubarray;
      DataView.prototype.getBigUint64 = original.dataViewGetBigUint64;
      DataView.prototype.getUint16 = original.dataViewGetUint16;
      DataView.prototype.getUint32 = original.dataViewGetUint32;
      DataView.prototype.setBigUint64 = original.dataViewSetBigUint64;
      DataView.prototype.setUint16 = original.dataViewSetUint16;
      DataView.prototype.setUint32 = original.dataViewSetUint32;
      TextEncoder.prototype.encode = original.textEncoderEncode;
      TextDecoder.prototype.decode = original.textDecoderDecode;
    }

    expect(encodedWhilePoisoned).toEqual(serialized);
    expect(decodedWhilePoisoned?.deliveryPayload).toEqual(
      record.deliveryPayload,
    );
    expect(decodedWhilePoisoned?.deliveryCodec).toEqual(record.deliveryCodec);
    expect(Object.isFrozen(decodedWhilePoisoned)).toBe(true);
  });

  test('rejects truncation, trailing bytes, bad magic, and unknown versions', async () => {
    const serialized = serializeGroupSecurityTransitionRecord(await fixture());
    expect(() =>
      deserializeGroupSecurityTransitionRecord(
        serialized.subarray(0, serialized.length - 1),
      ),
    ).toThrow(/delivery length/);

    const trailing = new Uint8Array(serialized.length + 1);
    trailing.set(serialized);
    expect(() => deserializeGroupSecurityTransitionRecord(trailing)).toThrow(
      /delivery length/,
    );

    const badMagic = new Uint8Array(serialized);
    badMagic[0] ^= 0xff;
    expect(() => deserializeGroupSecurityTransitionRecord(badMagic)).toThrow(
      /magic/,
    );

    const unknownVersion = new Uint8Array(serialized);
    unknownVersion[9] = 2;
    expect(() =>
      deserializeGroupSecurityTransitionRecord(unknownVersion),
    ).toThrow(/unsupported.*version/);
  });

  test('rejects zero, oversized, and inconsistent frame lengths', async () => {
    const serialized = serializeGroupSecurityTransitionRecord(await fixture());
    const codecLengthOffset = 10;
    const codecLength = new DataView(serialized.buffer).getUint16(
      codecLengthOffset,
    );
    const controlLengthOffset = codecLengthOffset + 2 + codecLength + 2;
    const controlLength = new DataView(serialized.buffer).getUint32(
      controlLengthOffset,
    );
    const deliveryLengthOffset = controlLengthOffset + 4 + controlLength;

    const zeroControl = new Uint8Array(serialized);
    new DataView(zeroControl.buffer).setUint32(controlLengthOffset, 0);
    expect(() => deserializeGroupSecurityTransitionRecord(zeroControl)).toThrow(
      /control length/,
    );

    const oversizedControl = new Uint8Array(serialized);
    new DataView(oversizedControl.buffer).setUint32(
      controlLengthOffset,
      4 * 1024 * 1024 + 1,
    );
    expect(() =>
      deserializeGroupSecurityTransitionRecord(oversizedControl),
    ).toThrow(/control length/);

    const zeroDelivery = new Uint8Array(serialized);
    new DataView(zeroDelivery.buffer).setUint32(deliveryLengthOffset, 0);
    expect(() =>
      deserializeGroupSecurityTransitionRecord(zeroDelivery),
    ).toThrow(/delivery length/);

    const oversizedDelivery = new Uint8Array(serialized);
    new DataView(oversizedDelivery.buffer).setUint32(
      deliveryLengthOffset,
      MAX_GROUP_SECURITY_TRANSITION_DELIVERY_BYTES + 1,
    );
    expect(() =>
      deserializeGroupSecurityTransitionRecord(oversizedDelivery),
    ).toThrow(/delivery length/);
  });

  test('rejects accessor-backed and extended transition objects', async () => {
    const record = await fixture();
    const accessor = {
      version: record.version,
      deliveryCodec: record.deliveryCodec,
      controlRecord: record.controlRecord,
      get deliveryPayload() {
        return record.deliveryPayload;
      },
    };
    expect(() =>
      serializeGroupSecurityTransitionRecord(accessor),
    ).toThrow(/data properties/);
    expect(() =>
      serializeGroupSecurityTransitionRecord({ ...record, extra: true }),
    ).toThrow(/unexpected properties/);
  });

  test('does not invoke input property access or version coercion hooks', async () => {
    const record = await fixture();
    const proxied = new Proxy(record, {
      get() {
        throw new Error('property access is forbidden');
      },
    });
    expect(serializeGroupSecurityTransitionRecord(proxied)).toEqual(
      serializeGroupSecurityTransitionRecord(record),
    );

    let coercions = 0;
    expect(() =>
      serializeGroupSecurityTransitionRecord({
        ...record,
        version: {
          [Symbol.toPrimitive]() {
            coercions++;
            return 2;
          },
        } as unknown as number,
      }),
    ).toThrow(/unsupported.*version/);
    expect(coercions).toBe(0);
  });

  test('ignores inherited accessors while snapshotting transition fields', async () => {
    const record = await fixture();
    const alternate = await fixture(new Uint8Array([0xaa]));
    const expected = serializeGroupSecurityTransitionRecord(record);
    const controlDescriptor = Object.getOwnPropertyDescriptor(
      Object.prototype,
      'controlRecord',
    );
    const idDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'id');
    try {
      Object.defineProperty(Object.prototype, 'controlRecord', {
        configurable: true,
        get: () => alternate.controlRecord,
        set: () => undefined,
      });
      Object.defineProperty(Object.prototype, 'id', {
        configurable: true,
        get: () => 'attacker.selected-codec',
        set: () => undefined,
      });

      expect(serializeGroupSecurityTransitionRecord(record)).toEqual(expected);
    } finally {
      if (controlDescriptor === undefined) {
        Reflect.deleteProperty(Object.prototype, 'controlRecord');
      } else {
        Object.defineProperty(
          Object.prototype,
          'controlRecord',
          controlDescriptor,
        );
      }
      if (idDescriptor === undefined) {
        Reflect.deleteProperty(Object.prototype, 'id');
      } else {
        Object.defineProperty(Object.prototype, 'id', idDescriptor);
      }
    }
  });

  test('preserves signed actions after Array iterator mutation', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    );
    const unsigned = {
      version: MEMBERSHIP_CONTROL_VERSION,
      protocol,
      groupId: new Uint8Array([1, 2, 3]),
      epoch: 4n,
      parentRecordId: new Uint8Array(32).fill(1),
      operationId: new Uint8Array(32).fill(2),
      action: 'remove' as const,
      actorId: new Uint8Array([3]),
      subjectId: new Uint8Array([4]),
      controlPayload: new Uint8Array([5, 6]),
    };
    const deliveryPayload = new Uint8Array([9, 8, 7]);
    const iteratorDescriptor = Object.getOwnPropertyDescriptor(
      Array.prototype,
      Symbol.iterator,
    )!;
    const poisonedIterator = function (this: unknown[]) {
      let index = 0;
      const source = this;
      return {
        next() {
          if (index >= source.length) return { done: true, value: undefined };
          const value = source[index++];
          return {
            done: false,
            value: source.length === 1 && value === 2 ? 1 : value,
          };
        },
        [Symbol.iterator]() {
          return this;
        },
      };
    };
    let signed: Awaited<ReturnType<typeof signMembershipControlRecord>>;
    let serialized: Uint8Array;
    try {
      Object.defineProperty(Array.prototype, Symbol.iterator, {
        ...iteratorDescriptor,
        value: poisonedIterator,
      });
      signed = await signMembershipControlRecord(unsigned, async (payload) =>
        new Uint8Array(
          await crypto.subtle.sign('HMAC', key, payload as BufferSource),
        ),
      );
      serialized = serializeGroupSecurityTransitionRecord({
        version: GROUP_SECURITY_TRANSITION_RECORD_VERSION,
        deliveryCodec: { id: 'transition.test-codec', version: 1 },
        controlRecord: signed,
        deliveryPayload,
      });
    } finally {
      Object.defineProperty(
        Array.prototype,
        Symbol.iterator,
        iteratorDescriptor,
      );
    }

    const decoded = deserializeGroupSecurityTransitionRecord(serialized!);
    expect(signed!.action).toBe('remove');
    expect(decoded.controlRecord.action).toBe('remove');
    await expect(
      crypto.subtle.verify(
        'HMAC',
        key,
        decoded.controlRecord.signature as BufferSource,
        canonicalMembershipControlPayload(
          decoded.controlRecord,
        ) as BufferSource,
      ),
    ).resolves.toBe(true);
  });

  test('strictly validates the delivery codec compatibility boundary', async () => {
    const record = await fixture();
    expect(() =>
      serializeGroupSecurityTransitionRecord({
        ...record,
        deliveryCodec: { id: '', version: 1 },
      }),
    ).toThrow(/codec id.*length/);
    expect(() =>
      serializeGroupSecurityTransitionRecord({
        ...record,
        deliveryCodec: { id: '.invalid', version: 1 },
      }),
    ).toThrow(/codec id.*canonical ASCII/);
    expect(() =>
      serializeGroupSecurityTransitionRecord({
        ...record,
        deliveryCodec: { id: 'a'.repeat(128), version: 1 },
      }),
    ).not.toThrow();
    expect(() =>
      serializeGroupSecurityTransitionRecord({
        ...record,
        deliveryCodec: { id: 'a'.repeat(129), version: 1 },
      }),
    ).toThrow(/codec id.*length/);
    expect(() =>
      serializeGroupSecurityTransitionRecord({
        ...record,
        deliveryCodec: { id: 'valid.codec', version: 0x1_0000 },
      }),
    ).toThrow(/codec version.*unsigned 16-bit/);
    expect(() =>
      serializeGroupSecurityTransitionRecord({
        ...record,
        deliveryCodec: { id: 'valid.codec', version: 1, extra: true },
      } as unknown as typeof record),
    ).toThrow(/codec.*unexpected properties/);

    const serialized = serializeGroupSecurityTransitionRecord(record);
    const codecLengthOffset = 10;
    const codecLength = new DataView(serialized.buffer).getUint16(
      codecLengthOffset,
    );
    const codecOffset = codecLengthOffset + 2;
    const badCodecId = new Uint8Array(serialized);
    badCodecId[codecOffset] = 0x2e;
    expect(() =>
      deserializeGroupSecurityTransitionRecord(badCodecId),
    ).toThrow(/codec id.*canonical ASCII/);

    const zeroCodecLength = new Uint8Array(serialized);
    new DataView(zeroCodecLength.buffer).setUint16(codecLengthOffset, 0);
    expect(() =>
      deserializeGroupSecurityTransitionRecord(zeroCodecLength),
    ).toThrow(/codec length/);

    const oversizedCodecLength = new Uint8Array(serialized);
    new DataView(oversizedCodecLength.buffer).setUint16(
      codecLengthOffset,
      129,
    );
    expect(() =>
      deserializeGroupSecurityTransitionRecord(oversizedCodecLength),
    ).toThrow(/codec length/);
    expect(codecLength).toBe(record.deliveryCodec.id.length);
  });

  test('rejects SharedArrayBuffer-backed and typed-array-lookalike payloads', async () => {
    const record = await fixture();
    if (typeof SharedArrayBuffer !== 'undefined') {
      expect(() =>
        serializeGroupSecurityTransitionRecord({
          ...record,
          deliveryPayload: new Uint8Array(new SharedArrayBuffer(1)),
        }),
      ).toThrow(/backing buffer/);

      const serialized = serializeGroupSecurityTransitionRecord(record);
      const sharedInput = new Uint8Array(
        new SharedArrayBuffer(serialized.byteLength),
      );
      sharedInput.set(serialized);
      expect(() =>
        deserializeGroupSecurityTransitionRecord(sharedInput),
      ).toThrow(/backing buffer/);
    }
    expect(() =>
      serializeGroupSecurityTransitionRecord({
        ...record,
        deliveryPayload: {
          0: 1,
          length: 1,
          byteLength: 1,
          [Symbol.toStringTag]: 'Uint8Array',
        } as unknown as Uint8Array,
      }),
    ).toThrow(/genuine Uint8Array/);
    expect(() =>
      deserializeGroupSecurityTransitionRecord({
        length: 20,
        byteLength: 20,
        [Symbol.toStringTag]: 'Uint8Array',
      } as unknown as Uint8Array),
    ).toThrow(/genuine Uint8Array/);
  });

  test('ignores shadowed byte-view instance properties', async () => {
    const serialized = serializeGroupSecurityTransitionRecord(await fixture());
    const expected = new Uint8Array(serialized);
    Object.defineProperties(serialized, {
      buffer: { value: new ArrayBuffer(1) },
      byteLength: { value: 1 },
      byteOffset: { value: 999 },
      length: { value: 1 },
      slice: { value: () => new Uint8Array([0xff]) },
      set: { value: () => undefined },
      [Symbol.toStringTag]: { value: 'NotBytes' },
    });

    expect(
      serializeGroupSecurityTransitionRecord(
        deserializeGroupSecurityTransitionRecord(serialized),
      ),
    ).toEqual(expected);
  });

  test('enforces the delivery payload bound at serialization', async () => {
    const maximum = await fixture(
      new Uint8Array(MAX_GROUP_SECURITY_TRANSITION_DELIVERY_BYTES),
    );
    expect(() => serializeGroupSecurityTransitionRecord(maximum)).not.toThrow();
    const oversized = await fixture(
      new Uint8Array(MAX_GROUP_SECURITY_TRANSITION_DELIVERY_BYTES + 1),
    );
    expect(() =>
      serializeGroupSecurityTransitionRecord(oversized),
    ).toThrow(/invalid length/);
  });
});
