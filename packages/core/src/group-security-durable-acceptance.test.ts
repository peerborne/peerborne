import { describe, expect, test } from '@jest/globals';

import type { GroupWelcome } from './group-security-provider.js';
import {
  MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES,
  MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS,
  type GroupSecurityAcceptanceDelivery,
  cloneGroupSecurityDurableAcceptance,
  createGroupSecurityDurableAcceptance,
  validateGroupSecurityDurableAcceptance,
} from './group-security-durable-acceptance.js';
import {
  MEMBERSHIP_CONTROL_VERSION,
  type MembershipControlRecord,
  membershipControlRecordId,
} from './membership-control-record.js';

const protocol = { id: 'durable-acceptance.test', version: 1 };
const groupId = new Uint8Array([1, 2, 3]);

function bytes(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function controlRecord(operation = 1): MembershipControlRecord {
  return {
    version: MEMBERSHIP_CONTROL_VERSION,
    protocol,
    groupId: new Uint8Array(groupId),
    epoch: 1n,
    parentRecordId: bytes(32, 9),
    operationId: bytes(32, operation),
    action: 'add',
    actorId: new Uint8Array([4]),
    subjectId: new Uint8Array([5]),
    controlPayload: new Uint8Array([6]),
    signature: new Uint8Array([7]),
  };
}

function welcome(reference: Uint8Array): GroupWelcome {
  return {
    protocol,
    groupId: new Uint8Array(groupId),
    epoch: 1n,
    recipientKeyPackageRef: reference,
    payload: new Uint8Array([8]),
  };
}

function delivery(
  references: ReadonlyArray<Uint8Array>,
): GroupSecurityAcceptanceDelivery {
  return {
    controlRecord: controlRecord(),
    welcomes: references.map(welcome),
  };
}

describe('group-security durable acceptance', () => {
  test('constructs a canonical exact-set acceptance with defensive copies', async () => {
    const value = delivery([
      new Uint8Array([3]),
      new Uint8Array([1]),
      new Uint8Array([2]),
    ]);
    const expectedRecordId = await membershipControlRecordId(
      value.controlRecord,
    );
    const pending = createGroupSecurityDurableAcceptance(value);

    value.controlRecord.operationId.fill(0xff);
    value.welcomes[0].recipientKeyPackageRef.fill(0xee);

    const acceptance = await pending;
    expect(acceptance).toEqual({
      controlRecordId: expectedRecordId,
      recipientKeyPackageRefs: [
        new Uint8Array([1]),
        new Uint8Array([2]),
        new Uint8Array([3]),
      ],
    });

    value.welcomes[1].recipientKeyPackageRef[0] = 0xdd;
    expect(acceptance.recipientKeyPackageRefs[0]).toEqual(
      new Uint8Array([1]),
    );
  });

  test('accepts either reference order and returns a canonical clone', async () => {
    const value = delivery([
      new Uint8Array([1, 2]),
      new Uint8Array([1]),
      new Uint8Array([2]),
    ]);
    const recordId = await membershipControlRecordId(value.controlRecord);
    const candidate = {
      controlRecordId: new Uint8Array(recordId),
      recipientKeyPackageRefs: [
        new Uint8Array([2]),
        new Uint8Array([1, 2]),
        new Uint8Array([1]),
      ],
    };

    await expect(
      validateGroupSecurityDurableAcceptance(candidate, value),
    ).resolves.toEqual({
      controlRecordId: recordId,
      recipientKeyPackageRefs: [
        new Uint8Array([1]),
        new Uint8Array([1, 2]),
        new Uint8Array([2]),
      ],
    });
  });

  test('snapshots both arguments across the asynchronous record digest', async () => {
    const value = delivery([new Uint8Array([1]), new Uint8Array([2])]);
    const acceptance = await createGroupSecurityDurableAcceptance(value);
    const expected = cloneGroupSecurityDurableAcceptance(acceptance);
    const pending = validateGroupSecurityDurableAcceptance(acceptance, value);

    acceptance.controlRecordId.fill(0xff);
    acceptance.recipientKeyPackageRefs[0].fill(0xff);
    value.controlRecord.controlPayload.fill(0xff);
    value.welcomes[0].recipientKeyPackageRef.fill(0xff);

    const validated = await pending;
    expect(validated).toEqual(expected);
    expect(validated.controlRecordId).not.toBe(acceptance.controlRecordId);
    expect(validated.recipientKeyPackageRefs[0]).not.toBe(
      acceptance.recipientKeyPackageRefs[0],
    );
  });

  test('rejects a mismatched control record identity', async () => {
    const value = delivery([new Uint8Array([1])]);
    const acceptance = await createGroupSecurityDurableAcceptance(value);
    acceptance.controlRecordId[0] ^= 0xff;

    await expect(
      validateGroupSecurityDurableAcceptance(acceptance, value),
    ).rejects.toThrow(/controlRecordId.*does not match/);
  });

  test('rejects missing, extra, and duplicate recipient references', async () => {
    const value = delivery([new Uint8Array([1]), new Uint8Array([2])]);
    const recordId = await membershipControlRecordId(value.controlRecord);

    await expect(
      validateGroupSecurityDurableAcceptance(
        {
          controlRecordId: recordId,
          recipientKeyPackageRefs: [new Uint8Array([1])],
        },
        value,
      ),
    ).rejects.toThrow(/do not exactly match/);
    await expect(
      validateGroupSecurityDurableAcceptance(
        {
          controlRecordId: recordId,
          recipientKeyPackageRefs: [
            new Uint8Array([1]),
            new Uint8Array([2]),
            new Uint8Array([3]),
          ],
        },
        value,
      ),
    ).rejects.toThrow(/do not exactly match/);
    await expect(
      validateGroupSecurityDurableAcceptance(
        {
          controlRecordId: recordId,
          recipientKeyPackageRefs: [
            new Uint8Array([1]),
            new Uint8Array([1]),
          ],
        },
        value,
      ),
    ).rejects.toThrow(/duplicate/);
  });

  test('rejects a same-cardinality recipient substitution', async () => {
    const value = delivery([new Uint8Array([1]), new Uint8Array([2])]);
    const recordId = await membershipControlRecordId(value.controlRecord);

    await expect(
      validateGroupSecurityDurableAcceptance(
        {
          controlRecordId: recordId,
          recipientKeyPackageRefs: [
            new Uint8Array([1]),
            new Uint8Array([3]),
          ],
        },
        value,
      ),
    ).rejects.toThrow(/do not exactly match/);
  });

  test('rejects duplicate references in the delivery instead of deduplicating', async () => {
    const value = delivery([new Uint8Array([1]), new Uint8Array([1])]);
    await expect(createGroupSecurityDurableAcceptance(value)).rejects.toThrow(
      /duplicate/,
    );
  });

  test('strictly rejects undefined and structurally ambiguous acceptances', () => {
    expect(() => cloneGroupSecurityDurableAcceptance(undefined)).toThrow(
      /must be an object/,
    );
    expect(() =>
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: bytes(32, 1),
      }),
    ).toThrow(/must contain exactly/);
    expect(() =>
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: bytes(32, 1),
        recipientKeyPackageRefs: [],
        accepted: true,
      }),
    ).toThrow(/must contain exactly/);

    const inherited = Object.create({
      controlRecordId: bytes(32, 1),
      recipientKeyPackageRefs: [],
    });
    expect(() => cloneGroupSecurityDurableAcceptance(inherited)).toThrow(
      /plain object/,
    );

    const accessor = Object.defineProperties(
      {},
      {
        controlRecordId: { get: () => bytes(32, 1), enumerable: true },
        recipientKeyPackageRefs: { value: [], enumerable: true },
      },
    );
    expect(() => cloneGroupSecurityDurableAcceptance(accessor)).toThrow(
      /own data property/,
    );

    const sparse = new Array<Uint8Array>(1);
    expect(() =>
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: bytes(32, 1),
        recipientKeyPackageRefs: sparse,
      }),
    ).toThrow(/sparse/);
  });

  test('rejects wrong-sized IDs, references, and recipient lists', () => {
    for (const length of [31, 33]) {
      expect(() =>
        cloneGroupSecurityDurableAcceptance({
          controlRecordId: bytes(length, 1),
          recipientKeyPackageRefs: [],
        }),
      ).toThrow(/controlRecordId.*invalid length/);
    }
    for (const length of [
      0,
      MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES + 1,
    ]) {
      expect(() =>
        cloneGroupSecurityDurableAcceptance({
          controlRecordId: bytes(32, 1),
          recipientKeyPackageRefs: [bytes(length, 2)],
        }),
      ).toThrow(/invalid length/);
    }
    expect(() =>
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: bytes(32, 1),
        recipientKeyPackageRefs: Array.from(
          {
            length:
              MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS + 1,
          },
          (_, index) =>
            new Uint8Array([
              (index >>> 8) & 0xff,
              index & 0xff,
            ]),
        ),
      }),
    ).toThrow(/bounded plain array/);
  });

  test('rejects oversized recipient arrays before requesting their keys', () => {
    let ownKeysCalls = 0;
    const references = new Proxy(
      new Array(
        MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS + 1,
      ),
      {
        ownKeys() {
          ownKeysCalls += 1;
          throw new Error('oversized array keys must not be enumerated');
        },
      },
    );
    expect(() =>
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: bytes(32, 1),
        recipientKeyPackageRefs: references,
      }),
    ).toThrow(/bounded plain array/);
    expect(ownKeysCalls).toBe(0);
  });

  test('rejects shared backing buffers that can change during validation', () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    expect(() =>
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: new Uint8Array(new SharedArrayBuffer(32)),
        recipientKeyPackageRefs: [],
      }),
    ).toThrow(/backing buffer/);
    expect(() =>
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: bytes(32, 1),
        recipientKeyPackageRefs: [
          new Uint8Array(new SharedArrayBuffer(1)),
        ],
      }),
    ).toThrow(/backing buffer/);
  });

  test('uses intrinsic typed-array length and buffer brands', () => {
    const controlRecordId = bytes(32, 1);
    Object.defineProperties(controlRecordId, {
      byteLength: { value: 1 },
      buffer: {
        value:
          typeof SharedArrayBuffer === 'undefined'
            ? new ArrayBuffer(1)
            : new SharedArrayBuffer(1),
      },
    });
    expect(
      cloneGroupSecurityDurableAcceptance({
        controlRecordId,
        recipientKeyPackageRefs: [],
      }).controlRecordId,
    ).toEqual(bytes(32, 1));

    const shortId = bytes(31, 2);
    Object.defineProperty(shortId, 'byteLength', { value: 32 });
    expect(() =>
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: shortId,
        recipientKeyPackageRefs: [],
      }),
    ).toThrow(/controlRecordId.*invalid length/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(new SharedArrayBuffer(32));
      Object.defineProperty(shared, 'buffer', {
        value: new ArrayBuffer(32),
      });
      expect(() =>
        cloneGroupSecurityDurableAcceptance({
          controlRecordId: shared,
          recipientKeyPackageRefs: [],
        }),
      ).toThrow(/backing buffer/);
    }
  });

  test('snapshots a proxied array count exactly once', () => {
    let lengthSnapshots = 0;
    const references = new Proxy([new Uint8Array([1])], {
      get(target, property, receiver) {
        if (property === 'length') {
          throw new Error('array length was read through a Proxy get trap');
        }
        return Reflect.get(target, property, receiver);
      },
      getOwnPropertyDescriptor(target, property) {
        if (property === 'length') lengthSnapshots += 1;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });

    expect(
      cloneGroupSecurityDurableAcceptance({
        controlRecordId: bytes(32, 1),
        recipientKeyPackageRefs: references,
      }).recipientKeyPackageRefs,
    ).toEqual([new Uint8Array([1])]);
    expect(lengthSnapshots).toBe(1);
  });

  test('rejects malformed, accessor-backed, and oversized delivery fields', async () => {
    const extraDelivery = { ...delivery([]), ignored: true };
    await expect(
      createGroupSecurityDurableAcceptance(
        extraDelivery as unknown as GroupSecurityAcceptanceDelivery,
      ),
    ).rejects.toThrow(/unexpected or missing fields/);

    const accessorRecord = { ...controlRecord() } as Record<string, unknown>;
    Object.defineProperty(accessorRecord, 'operationId', {
      enumerable: true,
      get: () => bytes(32, 1),
    });
    await expect(
      createGroupSecurityDurableAcceptance({
        controlRecord:
          accessorRecord as unknown as MembershipControlRecord,
        welcomes: [],
      }),
    ).rejects.toThrow(/own data property/);

    const accessorWelcome = { ...welcome(new Uint8Array([1])) };
    Object.defineProperty(accessorWelcome, 'recipientKeyPackageRef', {
      enumerable: true,
      get: () => new Uint8Array([1]),
    });
    await expect(
      createGroupSecurityDurableAcceptance({
        controlRecord: controlRecord(),
        welcomes: [accessorWelcome],
      }),
    ).rejects.toThrow(/own data property/);

    await expect(
      createGroupSecurityDurableAcceptance(
        delivery([
          bytes(
            MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES + 1,
            3,
          ),
        ]),
      ),
    ).rejects.toThrow(/recipientKeyPackageRef.*invalid length/);

    const oversizedPayload = {
      ...welcome(new Uint8Array([1])),
      payload: bytes(1024 * 1024 + 1, 4),
    };
    await expect(
      createGroupSecurityDurableAcceptance({
        controlRecord: controlRecord(),
        welcomes: [oversizedPayload],
      }),
    ).rejects.toThrow(/payload.*invalid length/);

    const tooManyWelcomes = Array.from(
      { length: MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS + 1 },
      () => welcome(new Uint8Array([1])),
    );
    await expect(
      createGroupSecurityDurableAcceptance({
        controlRecord: controlRecord(),
        welcomes: tooManyWelcomes,
      }),
    ).rejects.toThrow(/bounded plain array/);
  });

  test('rejects shared delivery bytes and Welcome metadata substitutions', async () => {
    const wrongGroup = {
      ...welcome(new Uint8Array([1])),
      groupId: new Uint8Array([9]),
    };
    await expect(
      createGroupSecurityDurableAcceptance({
        controlRecord: controlRecord(),
        welcomes: [wrongGroup],
      }),
    ).rejects.toThrow(/metadata does not match/);

    const wrongEpoch = {
      ...welcome(new Uint8Array([1])),
      epoch: 2n,
    };
    await expect(
      createGroupSecurityDurableAcceptance({
        controlRecord: controlRecord(),
        welcomes: [wrongEpoch],
      }),
    ).rejects.toThrow(/metadata does not match/);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedReference = welcome(
        new Uint8Array(new SharedArrayBuffer(1)),
      );
      await expect(
        createGroupSecurityDurableAcceptance({
          controlRecord: controlRecord(),
          welcomes: [sharedReference],
        }),
      ).rejects.toThrow(/backing buffer/);

      const sharedRecord = {
        ...controlRecord(),
        controlPayload: new Uint8Array(new SharedArrayBuffer(1)),
      };
      await expect(
        createGroupSecurityDurableAcceptance({
          controlRecord: sharedRecord,
          welcomes: [],
        }),
      ).rejects.toThrow(/backing buffer/);
    }
  });

  test('supports a delivery with no Welcomes', async () => {
    const value = delivery([]);
    const acceptance = await createGroupSecurityDurableAcceptance(value);
    await expect(
      validateGroupSecurityDurableAcceptance(acceptance, value),
    ).resolves.toEqual(acceptance);
  });

  test('accepts the coordinator delivery shape with an own-data commit', async () => {
    const value = {
      ...delivery([new Uint8Array([1])]),
      commit: {
        protocol,
        groupId: new Uint8Array(groupId),
        priorEpoch: 0n,
        epoch: 1n,
        payload: new Uint8Array([9]),
      },
    };
    await expect(
      createGroupSecurityDurableAcceptance(value),
    ).resolves.toEqual({
      controlRecordId: await membershipControlRecordId(value.controlRecord),
      recipientKeyPackageRefs: [new Uint8Array([1])],
    });

    const accessorCommit = delivery([]) as unknown as Record<
      PropertyKey,
      unknown
    >;
    Object.defineProperty(accessorCommit, 'commit', {
      enumerable: true,
      get: () => ({ ignored: true }),
    });
    await expect(
      createGroupSecurityDurableAcceptance(
        accessorCommit as unknown as GroupSecurityAcceptanceDelivery,
      ),
    ).rejects.toThrow(/own data property/);
  });
});
