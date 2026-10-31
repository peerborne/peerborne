import { beforeAll, describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  MEMBERSHIP_CONTROL_VERSION,
  MembershipControlChain,
  type MembershipControlRecord,
  type UnsignedMembershipControlRecord,
  canonicalMembershipControlPayload,
  membershipControlRecordId,
  signMembershipControlRecord,
} from './membership-control-record.js';

const maximumEpoch = (1n << 64n) - 1n;
const epoch = fc.oneof(
  fc.bigInt({ min: 0n, max: maximumEpoch }),
  fc.constantFrom(0n, maximumEpoch - 2n, maximumEpoch - 1n, maximumEpoch),
);
const protocol = { id: 'property.control', version: 1 };
const groupId = new Uint8Array([1, 2, 3]);
let keys: CryptoKeyPair[];

function operationId(value: number): Uint8Array {
  const result = new Uint8Array(32);
  new DataView(result.buffer).setUint32(0, value);
  return result;
}

function unsigned(
  initial: bigint,
  operation: number,
  previous?: MembershipControlRecord,
  parentRecordId?: Uint8Array,
): UnsignedMembershipControlRecord {
  return {
    version: MEMBERSHIP_CONTROL_VERSION,
    protocol,
    groupId,
    epoch:
      previous === undefined
        ? initial
        : previous.epoch === maximumEpoch
          ? 0n
          : previous.epoch + 1n,
    parentRecordId,
    operationId: operationId(operation),
    action: previous === undefined ? 'create' : 'update',
    actorId: new Uint8Array([0]),
    subjectId: new Uint8Array([1]),
    controlPayload: new Uint8Array([operation % 256]),
  };
}

async function sign(
  value: UnsignedMembershipControlRecord,
): Promise<MembershipControlRecord> {
  return signMembershipControlRecord(
    value,
    async (payload, actor) =>
      new Uint8Array(
        await crypto.subtle.sign(
          'Ed25519',
          keys[actor[0]].privateKey,
          payload as BufferSource,
        ),
      ),
  );
}

describe('generated signed membership-control histories', () => {
  beforeAll(async () => {
    keys = await Promise.all(
      [0, 1].map(
        () =>
          crypto.subtle.generateKey('Ed25519', false, [
            'sign',
            'verify',
          ]) as Promise<CryptoKeyPair>,
      ),
    );
  });

  test('rejects hostile appends without moving the authenticated head or poisoning a valid continuation', async () => {
    await fc.assert(
      fc.asyncProperty(
        epoch,
        fc.array(
          fc.constantFrom(
            'append',
            'duplicate',
            'reader',
            'reader-fork',
            'parent',
            'epoch',
            'create',
            'operation',
            'signature',
            'group',
            'protocol',
            'verify-throw',
            'authorize-throw',
          ),
          { maxLength: 45 },
        ),
        async (initial, actions) => {
          let fault = '';
          const observedParents: Array<{
            id: Uint8Array | undefined;
            payload: Uint8Array | undefined;
          }> = [];
          const chain = new MembershipControlChain({
            protocol,
            groupId,
            initialEpoch: initial,
            verifySignature: async (payload, signature, actor) => {
              if (fault === 'verify-throw')
                throw new Error('synthetic verifier failure');
              const valid = await crypto.subtle.verify(
                'Ed25519',
                keys[actor[0]].publicKey,
                signature as BufferSource,
                payload as BufferSource,
              );
              payload.fill(0xff);
              signature.fill(0xff);
              actor.fill(0xff);
              return valid;
            },
            authorize: async ({
              record,
              recordId,
              previousRecord,
              previousRecordId,
            }) => {
              if (fault === 'authorize-throw')
                throw new Error('synthetic authorizer failure');
              observedParents.push({
                id:
                  previousRecordId === undefined
                    ? undefined
                    : new Uint8Array(previousRecordId),
                payload:
                  previousRecord === undefined
                    ? undefined
                    : canonicalMembershipControlPayload(previousRecord),
              });
              const allowed = record.actorId[0] === 0;
              record.controlPayload.fill(0xee);
              recordId.fill(0xee);
              previousRecord?.controlPayload.fill(0xee);
              previousRecordId?.fill(0xee);
              return allowed;
            },
          });
          const records = [await sign(unsigned(initial, 1))];
          const ids = [await membershipControlRecordId(records[0])];
          expect((await chain.ingest(records[0])).status).toBe('accepted');
          for (let index = 0; index < actions.length; index++) {
            const action = actions[index];
            const previous = records[records.length - 1];
            const head = ids[ids.length - 1];
            const authorizationsBefore = observedParents.length;
            let value = unsigned(initial, index + 2, previous, head);
            let reason: string | undefined;
            if (action === 'reader-fork') {
              const { signature: _signature, ...genesis } = records[0];
              value = {
                ...genesis,
                operationId: operationId(index + 2),
                actorId: new Uint8Array([1]),
              };
              reason = 'unauthorized-actor';
            } else if (action === 'reader') {
              value = { ...value, actorId: new Uint8Array([1]) };
              reason =
                previous.epoch === maximumEpoch
                  ? 'epoch-out-of-order'
                  : 'unauthorized-actor';
            } else if (action === 'parent') {
              value = {
                ...value,
                parentRecordId: new Uint8Array(32).fill(0xff),
              };
              reason =
                previous.epoch === maximumEpoch
                  ? 'epoch-out-of-order'
                  : 'parent-mismatch';
            } else if (action === 'epoch') {
              value = { ...value, epoch: previous.epoch };
              reason = 'epoch-out-of-order';
            } else if (action === 'create') {
              value = { ...value, action: 'create' };
              reason = 'epoch-out-of-order';
            } else if (action === 'operation') {
              value = { ...value, operationId: records[0].operationId };
              reason = 'operation-id-conflict';
            } else if (action === 'group') {
              value = { ...value, groupId: new Uint8Array([9]) };
              reason = 'group-mismatch';
            } else if (action === 'protocol') {
              value = { ...value, protocol: { ...protocol, version: 2 } };
              reason = 'protocol-mismatch';
            } else if (action === 'signature' || action === 'verify-throw') {
              reason = 'bad-signature';
            } else if (action === 'authorize-throw') {
              reason =
                previous.epoch === maximumEpoch
                  ? 'epoch-out-of-order'
                  : 'unauthorized-actor';
            } else if (action === 'append' && previous.epoch === maximumEpoch) {
              reason = 'epoch-out-of-order';
            }
            const record =
              action === 'duplicate'
                ? records[index % records.length]
                : await sign(value);
            if (action === 'signature') record.signature[0] ^= 1;
            fault = action;
            const result = await chain.ingest(record);
            fault = '';
            const expectedAuthorization =
              action === 'reader-fork' ||
              ((action === 'append' || action === 'reader') &&
                previous.epoch !== maximumEpoch);
            expect(observedParents.length - authorizationsBefore).toBe(
              expectedAuthorization ? 1 : 0,
            );
            if (expectedAuthorization) {
              expect(observedParents[observedParents.length - 1]).toEqual(
                action === 'reader-fork'
                  ? { id: undefined, payload: undefined }
                  : {
                      id: head,
                      payload: canonicalMembershipControlPayload(previous),
                    },
              );
            }
            if (reason !== undefined) {
              expect(result).toMatchObject({ status: 'rejected', reason });
            } else if (action === 'duplicate') {
              expect(result).toMatchObject({ status: 'duplicate' });
            } else {
              expect(result).toMatchObject({ status: 'accepted' });
              records.push(record);
              ids.push(await membershipControlRecordId(record));
            }
            expect(chain.length).toBe(records.length);
            expect(chain.headRecordId).toEqual(ids[ids.length - 1]);
            expect(chain.records()).toEqual(records);
            const exposed = chain.records();
            exposed[0].controlPayload.fill(0xaa);
            chain.headRecordId!.fill(0xaa);
            expect(chain.records()).toEqual(records);
          }
        },
      ),
      { seed: 9703, numRuns: 120 },
    );
  });

  test('serializes concurrent duplicates and authenticated forks while capturing input before queueing', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.boolean(),
        fc.shuffledSubarray([2, 3, 4, 5, 6], { minLength: 2 }),
        async (duplicates, order) => {
          const authorizedParents: Array<Uint8Array | undefined> = [];
          const chain = new MembershipControlChain({
            protocol,
            groupId,
            verifySignature: async (payload, signature, actor) =>
              crypto.subtle.verify(
                'Ed25519',
                keys[actor[0]].publicKey,
                signature as BufferSource,
                payload as BufferSource,
              ),
            authorize: async ({ previousRecordId }) => {
              authorizedParents.push(previousRecordId);
              await Promise.resolve();
              return true;
            },
          });
          const genesis = await sign(unsigned(0n, 1));
          await chain.ingest(genesis);
          const genesisId = await membershipControlRecordId(genesis);
          const records = await Promise.all(
            order.map((op) =>
              sign(unsigned(0n, duplicates ? 2 : op, genesis, genesisId)),
            ),
          );
          const originals = records.map((record) =>
            canonicalMembershipControlPayload(record),
          );
          const jobs = records.map((record) => {
            const job = chain.ingest(record);
            record.controlPayload.fill(0xff);
            record.signature.fill(0xff);
            return job;
          });
          const results = await Promise.all(jobs);
          expect(results[0].status).toBe('accepted');
          results
            .slice(1)
            .forEach((result) =>
              expect(result).toMatchObject(
                duplicates
                  ? { status: 'duplicate' }
                  : { status: 'rejected', reason: 'fork-detected' },
              ),
            );
          expect(chain.length).toBe(2);
          expect(canonicalMembershipControlPayload(chain.records()[1])).toEqual(
            originals[0],
          );
          expect(authorizedParents).toEqual(
            duplicates
              ? [undefined, genesisId]
              : [undefined, genesisId, genesisId],
          );
          if (!duplicates) {
            expect(await chain.ingest(genesis)).toMatchObject({
              status: 'rejected',
              reason: 'fork-detected',
            });
          }
        },
      ),
      { seed: 9704, numRuns: 60 },
    );
  });
});
