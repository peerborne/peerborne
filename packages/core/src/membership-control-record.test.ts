import { describe, expect, test } from '@jest/globals';
import { runInNewContext } from 'node:vm';

import {
  MEMBERSHIP_CONTROL_ID_LENGTH,
  MEMBERSHIP_CONTROL_VERSION,
  MembershipControlChain,
  MembershipControlRecord,
  MembershipControlSignatureVerifier,
  MembershipControlSigner,
  UnsignedMembershipControlRecord,
  canonicalMembershipControlPayload,
  deserializeMembershipControlRecord,
  membershipControlRecordId,
  serializeMembershipControlRecord,
  signMembershipControlRecord,
} from './membership-control-record.js';

const protocol = { id: 'control.test', version: 1 };
const groupId = new Uint8Array([1, 2, 3]);
const actorId = new Uint8Array([7, 8, 9]);

function id(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

class HmacIdentity {
  private constructor(private readonly key: CryptoKey) {}

  static async create(): Promise<HmacIdentity> {
    return new HmacIdentity(
      await crypto.subtle.generateKey(
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify'],
      ),
    );
  }

  readonly sign: MembershipControlSigner = async (payload) =>
    new Uint8Array(
      await crypto.subtle.sign('HMAC', this.key, payload as BufferSource),
    );

  readonly verify: MembershipControlSignatureVerifier = async (
    payload,
    signature,
  ) =>
    crypto.subtle.verify(
      'HMAC',
      this.key,
      signature as BufferSource,
      payload as BufferSource,
    );
}

function unsigned(
  epoch: bigint,
  operation: number,
  parentRecordId?: Uint8Array,
): UnsignedMembershipControlRecord {
  return {
    version: MEMBERSHIP_CONTROL_VERSION,
    protocol,
    groupId,
    epoch,
    parentRecordId,
    operationId: id(operation),
    action: epoch === 0n ? 'create' : 'update',
    actorId,
    subjectId: new Uint8Array([4, 5, 6]),
    controlPayload: new Uint8Array([0xa0, operation]),
  };
}

describe('membership control records', () => {
  test('strictly round-trips canonical records across the u64 epoch range', async () => {
    const identity = await HmacIdentity.create();
    const maximum = (1n << 64n) - 1n;
    const record = await signMembershipControlRecord(
      { ...unsigned(maximum, 1, id(9)), action: 'remove' },
      identity.sign,
    );
    const serialized = serializeMembershipControlRecord(record);

    expect(deserializeMembershipControlRecord(serialized)).toEqual(record);
    expect(
      canonicalMembershipControlPayload(
        deserializeMembershipControlRecord(serialized),
      ),
    ).toEqual(canonicalMembershipControlPayload(record));
  });

  test('rejects truncation, trailing bytes, unknown versions, and oversized fields', async () => {
    const identity = await HmacIdentity.create();
    const serialized = serializeMembershipControlRecord(
      await signMembershipControlRecord(unsigned(0n, 1), identity.sign),
    );

    expect(() =>
      deserializeMembershipControlRecord(
        serialized.subarray(0, serialized.length - 1),
      ),
    ).toThrow(/truncated/);
    const trailing = new Uint8Array(serialized.length + 1);
    trailing.set(serialized);
    expect(() => deserializeMembershipControlRecord(trailing)).toThrow(
      /trailing/,
    );
    const unknown = new Uint8Array(serialized);
    unknown[9] = 2;
    expect(() => deserializeMembershipControlRecord(unknown)).toThrow(
      /unsupported.*version/,
    );
    expect(() =>
      deserializeMembershipControlRecord(new Uint8Array(4 * 1024 * 1024 + 1)),
    ).toThrow(/invalid length/);
  });

  test('record identity covers canonical content but not signature bytes', async () => {
    const identity = await HmacIdentity.create();
    const record = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const changedSignature: MembershipControlRecord = {
      ...record,
      signature: new Uint8Array(record.signature).fill(0x55),
    };

    await expect(membershipControlRecordId(changedSignature)).resolves.toEqual(
      await membershipControlRecordId(record),
    );
  });

  test('snapshots unsigned buffers before awaiting the signer', async () => {
    const identity = await HmacIdentity.create();
    const input: UnsignedMembershipControlRecord = {
      ...unsigned(0n, 1),
      groupId: new Uint8Array(groupId),
      actorId: new Uint8Array(actorId),
      subjectId: new Uint8Array([4, 5, 6]),
      controlPayload: new Uint8Array([0xa0, 1]),
    };
    const expected = canonicalMembershipControlPayload(input);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = signMembershipControlRecord(input, async (payload, signer) => {
      await gate;
      return identity.sign(payload, signer);
    });

    input.groupId.fill(0xee);
    input.operationId.fill(0xee);
    input.actorId.fill(0xee);
    input.subjectId.fill(0xee);
    input.controlPayload.fill(0xee);
    release();

    const signed = await pending;
    expect(canonicalMembershipControlPayload(signed)).toEqual(expected);
    await expect(
      identity.verify(
        canonicalMembershipControlPayload(signed),
        signed.signature,
        signed.actorId,
      ),
    ).resolves.toBe(true);
  });

  test('snapshots every serialized field once through own data descriptors', async () => {
    const identity = await HmacIdentity.create();
    const record = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const descriptorReads = new Map<PropertyKey, number>();
    const wrapped = new Proxy(record, {
      getPrototypeOf: () => Object.prototype,
      getOwnPropertyDescriptor: (target, property) => {
        descriptorReads.set(property, (descriptorReads.get(property) ?? 0) + 1);
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });

    expect(serializeMembershipControlRecord(wrapped)).toEqual(
      serializeMembershipControlRecord(record),
    );
    for (const field of [
      'version',
      'protocol',
      'groupId',
      'epoch',
      'parentRecordId',
      'operationId',
      'action',
      'actorId',
      'subjectId',
      'controlPayload',
      'signature',
    ]) {
      expect(descriptorReads.get(field)).toBe(1);
    }
  });

  test('rejects accessor-backed records without invoking their getters', async () => {
    const identity = await HmacIdentity.create();
    const record = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    let getterCalls = 0;
    const accessorBacked = { ...record };
    Object.defineProperty(accessorBacked, 'groupId', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return groupId;
      },
    });

    expect(() => serializeMembershipControlRecord(accessorBacked)).toThrow(
      /groupId.*own data property/,
    );
    expect(() => canonicalMembershipControlPayload(accessorBacked)).toThrow(
      /groupId.*own data property/,
    );
    await expect(membershipControlRecordId(accessorBacked)).rejects.toThrow(
      /groupId.*own data property/,
    );
    expect(getterCalls).toBe(0);
  });

  test('rejects shared byte storage at canonical input boundaries', () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    const sharedOperationId = new Uint8Array(
      new SharedArrayBuffer(MEMBERSHIP_CONTROL_ID_LENGTH),
    );
    expect(() =>
      canonicalMembershipControlPayload({
        ...unsigned(0n, 1),
        operationId: sharedOperationId,
      }),
    ).toThrow(/operationId.*backing buffer/);
  });

  test('accepts genuine Uint8Array subclasses and snapshots their bytes', () => {
    class DerivedBytes extends Uint8Array {}
    const derivedOperationId = new DerivedBytes(id(1));
    expect(
      canonicalMembershipControlPayload({
        ...unsigned(0n, 1),
        operationId: derivedOperationId,
      }),
    ).toEqual(canonicalMembershipControlPayload(unsigned(0n, 1)));
  });

  test('snapshots cross-realm chain group IDs and rejects shared backing', async () => {
    const identity = await HmacIdentity.create();
    const configuredGroupId = crossRealmBytes(groupId);
    const chain = new MembershipControlChain({
      protocol,
      groupId: configuredGroupId,
      verifySignature: identity.verify,
      authorize: async () => true,
    });
    configuredGroupId.fill(0xee);
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );

    await expect(chain.ingest(genesis)).resolves.toMatchObject({
      status: 'accepted',
    });

    if (typeof SharedArrayBuffer !== 'undefined') {
      expect(
        () =>
          new MembershipControlChain({
            protocol,
            groupId: new Uint8Array(
              new SharedArrayBuffer(groupId.byteLength),
            ),
            verifySignature: identity.verify,
            authorize: async () => true,
          }),
      ).toThrow(/groupId.*backing buffer/);
    }
  });

  test('accepts a signed hash-linked chain and makes exact replay idempotent', async () => {
    const identity = await HmacIdentity.create();
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => true,
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const genesisId = await membershipControlRecordId(genesis);
    const next = await signMembershipControlRecord(
      unsigned(1n, 2, genesisId),
      identity.sign,
    );

    await expect(chain.ingest(genesis)).resolves.toMatchObject({
      status: 'accepted',
    });
    await expect(chain.ingest(next)).resolves.toMatchObject({
      status: 'accepted',
    });
    await expect(chain.ingest(next)).resolves.toMatchObject({
      status: 'duplicate',
    });
    expect(chain.length).toBe(2);
    expect(chain.headRecordId).toEqual(await membershipControlRecordId(next));
  });

  test('rejects truthy non-boolean verifier and authorizer results', async () => {
    const identity = await HmacIdentity.create();
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const malformedVerifier = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: (async () =>
        'false') as unknown as MembershipControlSignatureVerifier,
      authorize: async () => true,
    });
    await expect(malformedVerifier.ingest(genesis)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'bad-signature',
    });

    const malformedAuthorizer = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: (async () => ({})) as never,
    });
    await expect(malformedAuthorizer.ingest(genesis)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'unauthorized-actor',
    });
  });

  test('does not expose verifier or authorizer exception messages', async () => {
    const identity = await HmacIdentity.create();
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const verifierFailure = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: async () => {
        throw new Error('secret verifier detail');
      },
      authorize: async () => true,
    });

    await expect(verifierFailure.ingest(genesis)).resolves.toEqual({
      status: 'rejected',
      reason: 'bad-signature',
      message: 'control signature verification failed',
    });

    const authorizerFailure = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => {
        throw new Error('secret authorizer detail');
      },
    });
    await expect(authorizerFailure.ingest(genesis)).resolves.toEqual({
      status: 'rejected',
      reason: 'unauthorized-actor',
      message: 'control authorization failed',
    });

    let authorizationCalls = 0;
    const forkAuthorizerFailure = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => {
        authorizationCalls += 1;
        if (authorizationCalls === 3) {
          throw new Error('secret fork authorizer detail');
        }
        return true;
      },
    });
    const genesisId = await membershipControlRecordId(genesis);
    const first = await signMembershipControlRecord(
      unsigned(1n, 2, genesisId),
      identity.sign,
    );
    const sibling = await signMembershipControlRecord(
      unsigned(1n, 3, genesisId),
      identity.sign,
    );
    await expect(forkAuthorizerFailure.ingest(genesis)).resolves.toMatchObject({
      status: 'accepted',
    });
    await expect(forkAuthorizerFailure.ingest(first)).resolves.toMatchObject({
      status: 'accepted',
    });
    await expect(forkAuthorizerFailure.ingest(sibling)).resolves.toEqual({
      status: 'rejected',
      reason: 'unauthorized-actor',
      message: 'control authorization failed',
    });
    expect(forkAuthorizerFailure.length).toBe(2);
  });

  test('snapshots records before they wait behind another ingestion', async () => {
    const identity = await HmacIdentity.create();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let authorizationCalls = 0;
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => {
        authorizationCalls += 1;
        if (authorizationCalls === 1) await gate;
        return true;
      },
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const next = await signMembershipControlRecord(
      unsigned(1n, 2, await membershipControlRecordId(genesis)),
      identity.sign,
    );
    const expectedNext = serializeMembershipControlRecord(next);

    const first = chain.ingest(genesis);
    const second = chain.ingest(next);
    next.groupId.fill(0xdd);
    next.operationId.fill(0xdd);
    next.controlPayload.fill(0xdd);
    next.signature.fill(0xdd);
    release();

    await expect(first).resolves.toMatchObject({ status: 'accepted' });
    await expect(second).resolves.toMatchObject({ status: 'accepted' });
    expect(serializeMembershipControlRecord(chain.records()[1])).toEqual(
      expectedNext,
    );
  });

  test('fails closed after two authorized records share one parent', async () => {
    const identity = await HmacIdentity.create();
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => true,
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const genesisId = await membershipControlRecordId(genesis);
    const first = await signMembershipControlRecord(
      unsigned(1n, 2, genesisId),
      identity.sign,
    );
    const sibling = await signMembershipControlRecord(
      unsigned(1n, 3, genesisId),
      identity.sign,
    );
    await chain.ingest(genesis);
    await chain.ingest(first);

    await expect(chain.ingest(sibling)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'fork-detected',
    });
    await expect(chain.ingest(first)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'fork-detected',
    });
    expect(chain.length).toBe(2);
  });

  test('detects an authorized sibling for a retained historical slot', async () => {
    const identity = await HmacIdentity.create();
    const observedParents: Array<{
      previousRecord?: MembershipControlRecord;
      previousRecordId?: Uint8Array;
    }> = [];
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async (context) => {
        observedParents.push({
          previousRecord: context.previousRecord,
          previousRecordId: context.previousRecordId,
        });
        return true;
      },
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const genesisId = await membershipControlRecordId(genesis);
    const first = await signMembershipControlRecord(
      unsigned(1n, 2, genesisId),
      identity.sign,
    );
    const firstId = await membershipControlRecordId(first);
    const second = await signMembershipControlRecord(
      unsigned(2n, 3, firstId),
      identity.sign,
    );
    const secondId = await membershipControlRecordId(second);
    const historicalSibling = await signMembershipControlRecord(
      unsigned(1n, 3, genesisId),
      identity.sign,
    );
    const next = await signMembershipControlRecord(
      unsigned(3n, 4, secondId),
      identity.sign,
    );

    await expect(chain.ingest(genesis)).resolves.toMatchObject({
      status: 'accepted',
    });
    await expect(chain.ingest(first)).resolves.toMatchObject({
      status: 'accepted',
    });
    await expect(chain.ingest(second)).resolves.toMatchObject({
      status: 'accepted',
    });
    await expect(chain.ingest(historicalSibling)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'fork-detected',
    });
    expect(observedParents.at(-1)?.previousRecord).toEqual(genesis);
    expect(observedParents.at(-1)?.previousRecordId).toEqual(genesisId);
    await expect(chain.ingest(next)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'fork-detected',
    });
    await expect(chain.ingest(second)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'fork-detected',
    });
    expect(chain.length).toBe(3);
  });

  test('rejects create in a retained non-genesis slot without poisoning', async () => {
    const identity = await HmacIdentity.create();
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => true,
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const genesisId = await membershipControlRecordId(genesis);
    const first = await signMembershipControlRecord(
      unsigned(1n, 2, genesisId),
      identity.sign,
    );
    const firstId = await membershipControlRecordId(first);
    const second = await signMembershipControlRecord(
      unsigned(2n, 3, firstId),
      identity.sign,
    );
    const secondId = await membershipControlRecordId(second);
    const invalidCreate = await signMembershipControlRecord(
      { ...unsigned(1n, 4, genesisId), action: 'create' },
      identity.sign,
    );
    const next = await signMembershipControlRecord(
      unsigned(3n, 5, secondId),
      identity.sign,
    );

    await chain.ingest(genesis);
    await chain.ingest(first);
    await chain.ingest(second);
    await expect(chain.ingest(invalidCreate)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'epoch-out-of-order',
    });
    await expect(chain.ingest(next)).resolves.toMatchObject({
      status: 'accepted',
    });
    expect(chain.length).toBe(4);
  });

  test('rejects a non-create competing genesis without poisoning', async () => {
    const identity = await HmacIdentity.create();
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => true,
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const genesisId = await membershipControlRecordId(genesis);
    const invalidGenesis = await signMembershipControlRecord(
      { ...unsigned(0n, 2), action: 'update' },
      identity.sign,
    );
    const next = await signMembershipControlRecord(
      unsigned(1n, 3, genesisId),
      identity.sign,
    );

    await chain.ingest(genesis);
    await expect(chain.ingest(invalidGenesis)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'epoch-out-of-order',
    });
    await expect(chain.ingest(next)).resolves.toMatchObject({
      status: 'accepted',
    });
    expect(chain.length).toBe(2);
  });

  test('does not let an unauthorized historical sibling poison the chain', async () => {
    const identity = await HmacIdentity.create();
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async ({ record }) => record.operationId[0] !== 4,
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const genesisId = await membershipControlRecordId(genesis);
    const first = await signMembershipControlRecord(
      unsigned(1n, 2, genesisId),
      identity.sign,
    );
    const firstId = await membershipControlRecordId(first);
    const second = await signMembershipControlRecord(
      unsigned(2n, 3, firstId),
      identity.sign,
    );
    const secondId = await membershipControlRecordId(second);
    const unauthorizedSibling = await signMembershipControlRecord(
      unsigned(1n, 4, genesisId),
      identity.sign,
    );
    const differentEpochSameParent = await signMembershipControlRecord(
      unsigned(2n, 6, genesisId),
      identity.sign,
    );
    const next = await signMembershipControlRecord(
      unsigned(3n, 5, secondId),
      identity.sign,
    );

    await chain.ingest(genesis);
    await chain.ingest(first);
    await chain.ingest(second);
    await expect(
      chain.ingest(differentEpochSameParent),
    ).resolves.toMatchObject({
      status: 'rejected',
      reason: 'epoch-out-of-order',
    });
    await expect(chain.ingest(unauthorizedSibling)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'unauthorized-actor',
    });
    await expect(chain.ingest(next)).resolves.toMatchObject({
      status: 'accepted',
    });
    expect(chain.length).toBe(4);
  });

  test('detects a late competing genesis without a parent context', async () => {
    const identity = await HmacIdentity.create();
    const observedParents: Array<{
      previousRecord?: MembershipControlRecord;
      previousRecordId?: Uint8Array;
    }> = [];
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async (context) => {
        observedParents.push({
          previousRecord: context.previousRecord,
          previousRecordId: context.previousRecordId,
        });
        return true;
      },
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    const next = await signMembershipControlRecord(
      unsigned(1n, 2, await membershipControlRecordId(genesis)),
      identity.sign,
    );
    const competingGenesis = await signMembershipControlRecord(
      unsigned(0n, 3),
      identity.sign,
    );

    await chain.ingest(genesis);
    await chain.ingest(next);
    await expect(chain.ingest(competingGenesis)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'fork-detected',
    });
    expect(observedParents.at(-1)).toEqual({
      previousRecord: undefined,
      previousRecordId: undefined,
    });
    expect(chain.length).toBe(2);
  });

  test('rejects bad signatures, broken parents, and operation-id conflicts', async () => {
    const identity = await HmacIdentity.create();
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => true,
    });
    const genesis = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );
    await chain.ingest(genesis);

    const broken = await signMembershipControlRecord(
      unsigned(1n, 2, id(0xff)),
      identity.sign,
    );
    await expect(chain.ingest(broken)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'parent-mismatch',
    });

    const badSignature = {
      ...broken,
      signature: new Uint8Array(broken.signature).fill(0),
    };
    await expect(chain.ingest(badSignature)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'bad-signature',
    });

    const conflict = await signMembershipControlRecord(
      {
        ...unsigned(1n, 1, await membershipControlRecordId(genesis)),
        subjectId: new Uint8Array([9]),
      },
      identity.sign,
    );
    await expect(chain.ingest(conflict)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'operation-id-conflict',
    });
  });

  test('fails closed when authorization rejects without mutating the chain', async () => {
    const identity = await HmacIdentity.create();
    const chain = new MembershipControlChain({
      protocol,
      groupId,
      verifySignature: identity.verify,
      authorize: async () => false,
    });
    const record = await signMembershipControlRecord(
      unsigned(0n, 1),
      identity.sign,
    );

    await expect(chain.ingest(record)).resolves.toMatchObject({
      status: 'rejected',
      reason: 'unauthorized-actor',
    });
    expect(chain.length).toBe(0);
  });
});

function crossRealmBytes(bytes: Uint8Array): Uint8Array {
  return runInNewContext(
    `new Uint8Array([${Array.from(bytes).join(',')}])`,
  ) as Uint8Array;
}
