import type { GroupWelcome } from './group-security-provider.js';
import {
  compareBytes,
  copyUnsharedUint8Array,
  equalBytes,
  unsharedUint8ArrayByteLength,
} from './internal/bytes.js';
import {
  MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES,
  MEMBERSHIP_CONTROL_VERSION,
  MEMBERSHIP_CONTROL_ID_LENGTH,
  type MembershipControlRecord,
  deserializeMembershipControlRecord,
  membershipControlRecordId,
  serializeMembershipControlRecord,
} from './membership-control-record.js';
import { requireU64 } from './internal/big-endian.js';
import {
  optionalOwnDataProperty,
  ownDataProperty,
} from './internal/data-property.js';
import {
  snapshotPlainDataArray,
  snapshotPlainDataObject,
} from './internal/plain-data.js';
import { snapshotCanonicalProtocol } from './internal/protocol-identifier.js';

export const MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS = 4096;
export const MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES = 512;

const MAX_GROUP_ID_BYTES = 1024;
const MAX_IDENTITY_BYTES = 512;
const MAX_CONTROL_PAYLOAD_BYTES = 2 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 4096;
const MAX_WELCOME_PAYLOAD_BYTES = 1024 * 1024;
const MAX_CANONICAL_WELCOME_SET_BYTES = 1024 * 1024;
const CANONICAL_WELCOME_SET_DOMAIN_BYTES =
  'peerborne/group-security-welcome-set/v1\0'.length;

/**
 * A receiver's explicit durable acceptance of one group-security delivery.
 *
 * A network delivery callback may return this value only after the receiver
 * has authenticated and authorized the control record, validated the group
 * transition, and durably persisted both the accepted state and the metadata
 * needed for replay/idempotency checks. Transport delivery alone is not
 * durable acceptance.
 */
export interface GroupSecurityDurableAcceptance {
  readonly controlRecordId: Uint8Array;
  readonly recipientKeyPackageRefs: ReadonlyArray<Uint8Array>;
}

/** The portion of a group-security delivery covered by durable acceptance. */
export interface GroupSecurityAcceptanceDelivery {
  readonly controlRecord: MembershipControlRecord;
  readonly welcomes: ReadonlyArray<GroupWelcome>;
}

/**
 * Constructs the canonical acceptance value for a delivery.
 *
 * This function only constructs the bound value; it does not authenticate or
 * persist the delivery. Callers must satisfy the durable-acceptance contract
 * above before returning the result from a network delivery callback.
 */
export async function createGroupSecurityDurableAcceptance(
  delivery: GroupSecurityAcceptanceDelivery,
): Promise<GroupSecurityDurableAcceptance> {
  const snapshot = snapshotDelivery(delivery);
  const controlRecordId = await membershipControlRecordId(
    snapshot.controlRecord,
  );
  return makeAcceptance(controlRecordId, snapshot.recipientKeyPackageRefs);
}

/** Strictly validates, canonicalizes, and defensively clones an acceptance. */
export function cloneGroupSecurityDurableAcceptance(
  value: unknown,
): GroupSecurityDurableAcceptance {
  const object = exactPlainObject(value, [
    'controlRecordId',
    'recipientKeyPackageRefs',
  ]);
  const controlRecordId = copyUnsharedUint8Array(
    ownDataProperty(object, 'controlRecordId'),
    MEMBERSHIP_CONTROL_ID_LENGTH,
    MEMBERSHIP_CONTROL_ID_LENGTH,
    'durable acceptance controlRecordId',
  );
  const recipientKeyPackageRefs = cloneCanonicalReferences(
    ownDataProperty(object, 'recipientKeyPackageRefs'),
    'durable acceptance recipientKeyPackageRefs',
  );
  return makeAcceptance(controlRecordId, recipientKeyPackageRefs);
}

/**
 * Verifies that an acceptance binds the exact control-record identity and the
 * complete unique set of Welcome recipient KeyPackage references.
 *
 * Both arguments are synchronously snapshotted before hashing so mutations
 * made while the digest is pending cannot change what is validated.
 */
export async function validateGroupSecurityDurableAcceptance(
  value: unknown,
  delivery: GroupSecurityAcceptanceDelivery,
): Promise<GroupSecurityDurableAcceptance> {
  const acceptance = cloneGroupSecurityDurableAcceptance(value);
  const deliverySnapshot = snapshotDelivery(delivery);
  const expectedRecordId = await membershipControlRecordId(
    deliverySnapshot.controlRecord,
  );
  if (!equalBytes(acceptance.controlRecordId, expectedRecordId)) {
    throw new Error(
      'durable acceptance controlRecordId does not match the delivery',
    );
  }
  if (
    !equalReferenceSets(
      acceptance.recipientKeyPackageRefs,
      deliverySnapshot.recipientKeyPackageRefs,
    )
  ) {
    throw new Error(
      'durable acceptance recipient KeyPackage references do not exactly match the delivery Welcomes',
    );
  }
  return makeAcceptance(
    acceptance.controlRecordId,
    acceptance.recipientKeyPackageRefs,
  );
}

interface DeliverySnapshot {
  readonly controlRecord: MembershipControlRecord;
  readonly recipientKeyPackageRefs: ReadonlyArray<Uint8Array>;
}

function snapshotDelivery(
  delivery: GroupSecurityAcceptanceDelivery,
): DeliverySnapshot {
  const object = snapshotPlainDataObject(
    delivery,
    ['controlRecord', 'welcomes', 'commit'],
    'group-security acceptance delivery',
    ['controlRecord', 'welcomes'],
  );
  const controlRecordValue = ownDataProperty(object, 'controlRecord');
  const welcomesValue = ownDataProperty(object, 'welcomes');
  const controlRecordSnapshot = snapshotControlRecord(controlRecordValue);
  const serializedControlRecord = serializeMembershipControlRecord(
    controlRecordSnapshot,
  );
  const controlRecord = deserializeMembershipControlRecord(
    copyUnsharedUint8Array(
      serializedControlRecord,
      1,
      MAX_MEMBERSHIP_CONTROL_SERIALIZED_BYTES,
      'serialized membership control record',
    ),
  );
  const recipientKeyPackageRefs = cloneWelcomeReferences(
    welcomesValue,
    controlRecord,
  );
  return { controlRecord, recipientKeyPackageRefs };
}

function cloneWelcomeReferences(
  value: unknown,
  controlRecord: MembershipControlRecord,
): ReadonlyArray<Uint8Array> {
  const welcomes = snapshotPlainDataArray(
    value,
    'group-security delivery Welcomes',
    MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS,
  );
  let canonicalBytes = CANONICAL_WELCOME_SET_DOMAIN_BYTES + 2;
  const references = welcomes.map((welcomeValue, index) => {
    const welcome = snapshotPlainDataObject(
      welcomeValue,
      [
        'protocol',
        'groupId',
        'epoch',
        'recipientKeyPackageRef',
        'payload',
      ],
      `group-security delivery Welcome ${index}`,
    );
    const protocol = snapshotCanonicalProtocol(
      ownDataProperty(welcome, 'protocol'),
      `group-security delivery Welcome ${index} protocol`,
    );
    const groupId = copyUnsharedUint8Array(
      ownDataProperty(welcome, 'groupId'),
      1,
      MAX_GROUP_ID_BYTES,
      `group-security delivery Welcome ${index} groupId`,
    );
    const epoch = requireU64(
      ownDataProperty(welcome, 'epoch'),
      `group-security delivery Welcome ${index} epoch`,
    );
    const reference = copyUnsharedUint8Array(
      ownDataProperty(welcome, 'recipientKeyPackageRef'),
      1,
      MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES,
      `group-security delivery Welcome ${index} recipientKeyPackageRef`,
    );
    const payloadLength = unsharedUint8ArrayByteLength(
      ownDataProperty(welcome, 'payload'),
      1,
      MAX_WELCOME_PAYLOAD_BYTES,
      `group-security delivery Welcome ${index} payload`,
    );
    if (
      protocol.id !== controlRecord.protocol.id ||
      protocol.version !== controlRecord.protocol.version ||
      !equalBytes(groupId, controlRecord.groupId) ||
      epoch !== controlRecord.epoch
    ) {
      throw new Error(
        `group-security delivery Welcome ${index} metadata does not match the control record`,
      );
    }
    canonicalBytes = claimBoundedTotal(
      canonicalBytes,
      2 +
        protocol.id.length +
        2 +
        2 +
        groupId.byteLength +
        8 +
        2 +
        reference.byteLength +
        4 +
        payloadLength,
      MAX_CANONICAL_WELCOME_SET_BYTES,
      'group-security delivery Welcome set',
    );
    return reference;
  });
  return canonicalizeUniqueReferences(
    references,
    'group-security delivery Welcomes',
  );
}

function cloneCanonicalReferences(
  value: unknown,
  field: string,
): ReadonlyArray<Uint8Array> {
  const values = snapshotPlainDataArray(
    value,
    field,
    MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_RECIPIENTS,
  );
  const references = values.map((reference, index) =>
    copyUnsharedUint8Array(
      reference,
      1,
      MAX_GROUP_SECURITY_DURABLE_ACCEPTANCE_KEY_PACKAGE_REF_BYTES,
      `${field}[${index}]`,
    ),
  );
  return canonicalizeUniqueReferences(references, field);
}

function canonicalizeUniqueReferences(
  references: Uint8Array[],
  field: string,
): ReadonlyArray<Uint8Array> {
  references.sort(compareBytes);
  for (let index = 1; index < references.length; index++) {
    if (equalBytes(references[index - 1], references[index])) {
      throw new Error(`${field} contains a duplicate KeyPackage reference`);
    }
  }
  return references;
}

function makeAcceptance(
  controlRecordId: Uint8Array,
  recipientKeyPackageRefs: ReadonlyArray<Uint8Array>,
): GroupSecurityDurableAcceptance {
  return {
    controlRecordId: new Uint8Array(controlRecordId),
    recipientKeyPackageRefs: recipientKeyPackageRefs.map(
      (reference) => new Uint8Array(reference),
    ),
  };
}

function exactPlainObject(
  value: unknown,
  expectedKeys: ReadonlyArray<string>,
): Record<PropertyKey, unknown> {
  try {
    return snapshotPlainDataObject(value, expectedKeys, 'durable acceptance');
  } catch (error) {
    if (
      error instanceof Error &&
      /unexpected or missing fields/.test(error.message)
    ) {
      throw new Error(
        'durable acceptance must contain exactly controlRecordId and recipientKeyPackageRefs',
      );
    }
    throw error;
  }
}

function snapshotControlRecord(value: unknown): MembershipControlRecord {
  const record = snapshotPlainDataObject(
    value,
    [
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
    ],
    'group-security delivery controlRecord',
    [
      'version',
      'protocol',
      'groupId',
      'epoch',
      'operationId',
      'action',
      'actorId',
      'subjectId',
      'controlPayload',
      'signature',
    ],
  );
  const version = ownDataProperty(record, 'version');
  if (version !== MEMBERSHIP_CONTROL_VERSION) {
    throw new Error('group-security delivery controlRecord version is invalid');
  }
  const action = ownDataProperty(record, 'action');
  if (
    action !== 'create' &&
    action !== 'add' &&
    action !== 'remove' &&
    action !== 'update'
  ) {
    throw new Error('group-security delivery controlRecord action is invalid');
  }
  const parentRecordId = optionalOwnDataProperty(record, 'parentRecordId');
  return {
    version,
    protocol: snapshotCanonicalProtocol(
      ownDataProperty(record, 'protocol'),
      'group-security delivery controlRecord protocol',
    ),
    groupId: copyUnsharedUint8Array(
      ownDataProperty(record, 'groupId'),
      1,
      MAX_GROUP_ID_BYTES,
      'group-security delivery controlRecord groupId',
    ),
    epoch: requireU64(
      ownDataProperty(record, 'epoch'),
      'group-security delivery controlRecord epoch',
    ),
    parentRecordId:
      parentRecordId === undefined
        ? undefined
        : copyUnsharedUint8Array(
            parentRecordId,
            MEMBERSHIP_CONTROL_ID_LENGTH,
            MEMBERSHIP_CONTROL_ID_LENGTH,
            'group-security delivery controlRecord parentRecordId',
          ),
    operationId: copyUnsharedUint8Array(
      ownDataProperty(record, 'operationId'),
      MEMBERSHIP_CONTROL_ID_LENGTH,
      MEMBERSHIP_CONTROL_ID_LENGTH,
      'group-security delivery controlRecord operationId',
    ),
    action,
    actorId: copyUnsharedUint8Array(
      ownDataProperty(record, 'actorId'),
      1,
      MAX_IDENTITY_BYTES,
      'group-security delivery controlRecord actorId',
    ),
    subjectId: copyUnsharedUint8Array(
      ownDataProperty(record, 'subjectId'),
      1,
      MAX_IDENTITY_BYTES,
      'group-security delivery controlRecord subjectId',
    ),
    controlPayload: copyUnsharedUint8Array(
      ownDataProperty(record, 'controlPayload'),
      1,
      MAX_CONTROL_PAYLOAD_BYTES,
      'group-security delivery controlRecord controlPayload',
    ),
    signature: copyUnsharedUint8Array(
      ownDataProperty(record, 'signature'),
      1,
      MAX_SIGNATURE_BYTES,
      'group-security delivery controlRecord signature',
    ),
  };
}

function claimBoundedTotal(
  total: number,
  additional: number,
  maximum: number,
  field: string,
): number {
  if (
    !Number.isSafeInteger(additional) ||
    additional < 0 ||
    additional > maximum - total
  ) {
    throw new Error(`${field} exceeds its byte bound`);
  }
  return total + additional;
}

function equalReferenceSets(
  left: ReadonlyArray<Uint8Array>,
  right: ReadonlyArray<Uint8Array>,
): boolean {
  return (
    left.length === right.length &&
    left.every((reference, index) => equalBytes(reference, right[index]))
  );
}
