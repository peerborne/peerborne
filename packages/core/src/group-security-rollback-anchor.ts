import type { GroupSecurityProtocol } from './group-security-provider.js';
import type { GroupStateStoreKey } from './group-state-store.js';

const MAX_U64 = (1n << 64n) - 1n;
const CONTROL_HEAD_LENGTH = 32;
const STORE_COMMITMENT_LENGTH = 32;
const FORK_EVIDENCE_HASH_LENGTH = 32;

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayByteLengthGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'byteLength',
)?.get;
const typedArrayBufferGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'buffer',
)?.get;
const typedArrayTagGetterValue = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
)?.get;
const uint8ArraySet = Uint8Array.prototype.set;
const sharedArrayBufferByteLengthGetter =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : Object.getOwnPropertyDescriptor(
        SharedArrayBuffer.prototype,
        'byteLength',
      )?.get;

if (
  typedArrayByteLengthGetterValue === undefined ||
  typedArrayBufferGetterValue === undefined ||
  typedArrayTagGetterValue === undefined
) {
  throw new Error('Uint8Array intrinsic accessors are unavailable');
}
const typedArrayByteLengthGetter = typedArrayByteLengthGetterValue;
const typedArrayBufferGetter = typedArrayBufferGetterValue;
const typedArrayTagGetter = typedArrayTagGetterValue;

/**
 * Monotonic state kept outside the rollbackable group-state database.
 *
 * `revision` binds every durable metadata transaction, `epoch` and
 * `controlHead` make the security-relevant position explicit, and
 * `storeCommitment` binds every byte in the matching store snapshot.
 * Production implementations must protect this value with storage that cannot
 * be rolled back together with the corresponding `DurableGroupStateStore`.
 */
export interface GroupSecurityRollbackAnchorValue {
  readonly revision: number;
  readonly epoch: bigint;
  readonly controlHead: Uint8Array;
  readonly storeCommitment: Uint8Array;
  readonly forkPoison: GroupSecurityRollbackForkPoison | undefined;
}

/** Irreversible terminal authenticated-fork commitment. */
export interface GroupSecurityRollbackAuthenticatedForkPoison {
  readonly epoch: bigint;
  readonly parentRecordId: Uint8Array;
  readonly firstRecordId: Uint8Array;
  readonly secondRecordId: Uint8Array;
  readonly evidenceHash: Uint8Array;
}

/**
 * Terminal ambiguity marker used when an authenticated/authorized candidate
 * cannot be reconciled with durable state after a write conflict.
 */
export interface GroupSecurityRollbackAmbiguityPoison {
  readonly reason: 'unreconciled-authenticated-candidate';
  readonly epoch: bigint;
  readonly baseRevision: number;
  readonly baseControlHead: Uint8Array;
  readonly baseStoreCommitment: Uint8Array;
  readonly candidateParentRecordId: Uint8Array;
  readonly candidateRecordId: Uint8Array;
  readonly observationHash: Uint8Array;
}

/**
 * Terminal marker for an authenticated first-anchor candidate whose durable
 * winner could not be read back. The candidate anchor is supplied as the
 * atomic poison initialization value, so a transient reconciliation failure
 * cannot leave an observed bootstrap/join fork unrecorded globally.
 */
export interface GroupSecurityRollbackFirstAnchorAmbiguityPoison {
  readonly reason: 'unreconciled-first-anchor-candidate';
  readonly epoch: bigint;
  readonly candidateRevision: number;
  readonly candidateControlHead: Uint8Array;
  readonly candidateStoreCommitment: Uint8Array;
  readonly observationHash: Uint8Array;
}

export type GroupSecurityRollbackForkPoison =
  | GroupSecurityRollbackAuthenticatedForkPoison
  | GroupSecurityRollbackAmbiguityPoison
  | GroupSecurityRollbackFirstAnchorAmbiguityPoison;

/**
 * Separately protected compare-and-set boundary for rollback detection.
 *
 * `advance` must be durable before it resolves and must return `false` without
 * changing state when `expected` does not equal the current value. Advancing
 * an anchor and committing its matching group-state snapshot should be treated
 * as one security transaction. A crash between the two may require explicit
 * recovery, but must never silently accept the older side.
 */
export interface DurableGroupSecurityRollbackAnchor {
  load(
    key: GroupStateStoreKey,
  ): Promise<GroupSecurityRollbackAnchorValue | undefined>;
  advance(
    key: GroupStateStoreKey,
    expected: GroupSecurityRollbackAnchorValue | undefined,
    next: GroupSecurityRollbackAnchorValue,
  ): Promise<boolean>;
  /** Atomically and irreversibly poison whichever active value is current. */
  poison(
    key: GroupStateStoreKey,
    forkPoison: GroupSecurityRollbackForkPoison,
    initial?: GroupSecurityRollbackAnchorValue,
  ): Promise<GroupSecurityRollbackAnchorValue>;
}

/**
 * Reference implementation for tests and same-process development only.
 * Keeping this object beside an in-memory store is not rollback-resistant.
 */
export class InMemoryGroupSecurityRollbackAnchor
  implements DurableGroupSecurityRollbackAnchor
{
  private readonly values = new Map<
    string,
    GroupSecurityRollbackAnchorValue
  >();
  private readonly tails = new Map<string, Promise<void>>();

  async load(
    keyValue: GroupStateStoreKey,
  ): Promise<GroupSecurityRollbackAnchorValue | undefined> {
    const key = cloneAndValidateKey(keyValue);
    const encodedKey = encodeKey(key);
    await (this.tails.get(encodedKey) ?? Promise.resolve());
    const current = this.values.get(encodedKey);
    return current === undefined ? undefined : cloneAnchor(current);
  }

  async advance(
    keyValue: GroupStateStoreKey,
    expectedValue: GroupSecurityRollbackAnchorValue | undefined,
    nextValue: GroupSecurityRollbackAnchorValue,
  ): Promise<boolean> {
    const key = cloneAndValidateKey(keyValue);
    const expected =
      expectedValue === undefined
        ? undefined
        : cloneAndValidateAnchor(expectedValue);
    const next = cloneAndValidateAnchor(nextValue);
    validateAdvance(expected, next);
    const encodedKey = encodeKey(key);
    const prior = this.tails.get(encodedKey) ?? Promise.resolve();
    const run = prior.then(() => {
      const current = this.values.get(encodedKey);
      if (!optionalAnchorEqual(current, expected)) return false;
      this.values.set(encodedKey, cloneAnchor(next));
      return true;
    });
    return trackQueuedOperation(this.tails, encodedKey, run);
  }

  async poison(
    keyValue: GroupStateStoreKey,
    forkPoisonValue: GroupSecurityRollbackForkPoison,
    initialValue?: GroupSecurityRollbackAnchorValue,
  ): Promise<GroupSecurityRollbackAnchorValue> {
    const key = cloneAndValidateKey(keyValue);
    const forkPoison = cloneForkPoison(forkPoisonValue);
    const initial =
      initialValue === undefined
        ? undefined
        : cloneAndValidateAnchor(initialValue);
    if (initial?.forkPoison !== undefined) {
      throw new Error('rollback anchor poison initialization must be active');
    }
    const encodedKey = encodeKey(key);
    const prior = this.tails.get(encodedKey) ?? Promise.resolve();
    const run = prior.then(() => {
      const current = this.values.get(encodedKey);
      if (current === undefined) {
        if (initial === undefined) {
          throw new Error(
            'rollback anchor poison requires an initialization value',
          );
        }
        const poisoned = cloneAnchor({ ...initial, forkPoison });
        this.values.set(encodedKey, poisoned);
        return cloneAnchor(poisoned);
      }
      if (current.forkPoison !== undefined) return cloneAnchor(current);
      const poisoned = cloneAnchor({ ...current, forkPoison });
      this.values.set(encodedKey, poisoned);
      return cloneAnchor(poisoned);
    });
    return trackQueuedOperation(this.tails, encodedKey, run);
  }
}

function trackQueuedOperation<T>(
  tails: Map<string, Promise<void>>,
  encodedKey: string,
  run: Promise<T>,
): Promise<T> {
  let settledTail!: Promise<void>;
  const result = run.then(
    (value) => {
      if (tails.get(encodedKey) === settledTail) tails.delete(encodedKey);
      return value;
    },
    (error: unknown) => {
      if (tails.get(encodedKey) === settledTail) tails.delete(encodedKey);
      throw error;
    },
  );
  settledTail = result.then(
    () => undefined,
    () => undefined,
  );
  tails.set(encodedKey, settledTail);
  return result;
}

export function cloneGroupSecurityRollbackAnchor(
  value: GroupSecurityRollbackAnchorValue,
): GroupSecurityRollbackAnchorValue {
  return cloneAndValidateAnchor(value);
}

export function groupSecurityRollbackAnchorsEqual(
  left: GroupSecurityRollbackAnchorValue | undefined,
  right: GroupSecurityRollbackAnchorValue | undefined,
): boolean {
  const leftSnapshot =
    left === undefined ? undefined : cloneAndValidateAnchor(left);
  const rightSnapshot =
    right === undefined ? undefined : cloneAndValidateAnchor(right);
  return optionalAnchorEqual(leftSnapshot, rightSnapshot);
}

function validateAdvance(
  expected: GroupSecurityRollbackAnchorValue | undefined,
  next: GroupSecurityRollbackAnchorValue,
): void {
  if (expected === undefined) {
    if (next.forkPoison !== undefined) {
      throw new Error('rollback anchor cannot begin poisoned');
    }
    return;
  }
  if (expected.forkPoison !== undefined) {
    throw new Error('poisoned rollback anchor is terminal');
  }
  if (next.forkPoison !== undefined) {
    throw new Error('rollback anchor poisoning requires the atomic poison method');
  }
  if (next.revision !== expected.revision + 1) {
    throw new Error(
      'rollback anchor revision must advance by exactly one',
    );
  }
  if (next.epoch < expected.epoch || next.epoch > expected.epoch + 1n) {
    throw new Error(
      'rollback anchor epoch must stay constant or advance by exactly one',
    );
  }
  if (
    next.epoch === expected.epoch &&
    !equalBytes(next.controlHead, expected.controlHead)
  ) {
    throw new Error(
      'rollback anchor control head cannot change without an epoch advance',
    );
  }
}

function cloneAndValidateAnchor(
  value: GroupSecurityRollbackAnchorValue,
): GroupSecurityRollbackAnchorValue {
  const object = exactPlainObject(value, [
    'revision',
    'epoch',
    'controlHead',
    'storeCommitment',
    'forkPoison',
  ], 'rollback anchor');
  const revision = dataProperty(object, 'revision');
  const epoch = dataProperty(object, 'epoch');
  const controlHead = dataProperty(object, 'controlHead');
  const storeCommitment = dataProperty(object, 'storeCommitment');
  const forkPoison = dataProperty(object, 'forkPoison');
  if (!Number.isSafeInteger(revision) || (revision as number) < 1) {
    throw new Error('rollback anchor revision must be a positive safe integer');
  }
  if (typeof epoch !== 'bigint' || epoch < 0n || epoch > MAX_U64) {
    throw new Error('rollback anchor epoch must be an unsigned 64-bit bigint');
  }
  return {
    revision: revision as number,
    epoch,
    controlHead: cloneExactBytes(
      controlHead,
      'rollback anchor control head',
      CONTROL_HEAD_LENGTH,
    ),
    storeCommitment: cloneExactBytes(
      storeCommitment,
      'rollback anchor store commitment',
      STORE_COMMITMENT_LENGTH,
    ),
    forkPoison:
      forkPoison === undefined ? undefined : cloneForkPoison(forkPoison),
  };
}

function cloneAnchor(
  value: GroupSecurityRollbackAnchorValue,
): GroupSecurityRollbackAnchorValue {
  return cloneAndValidateAnchor(value);
}

function optionalAnchorEqual(
  left: GroupSecurityRollbackAnchorValue | undefined,
  right: GroupSecurityRollbackAnchorValue | undefined,
): boolean {
  if (left === undefined || right === undefined) return left === right;
  return (
    left.revision === right.revision &&
    left.epoch === right.epoch &&
    equalBytes(left.controlHead, right.controlHead) &&
    equalBytes(left.storeCommitment, right.storeCommitment) &&
    optionalForkPoisonEqual(left.forkPoison, right.forkPoison)
  );
}

function cloneForkPoison(
  value: unknown,
): GroupSecurityRollbackForkPoison {
  const snapshot = snapshotPlainObject(
    value,
    'rollback anchor fork poison',
  );
  if (Object.prototype.hasOwnProperty.call(snapshot, 'reason')) {
    const reason = dataProperty(snapshot, 'reason');
    if (reason === 'unreconciled-first-anchor-candidate') {
      requireExactKeys(
        snapshot,
        [
          'reason',
          'epoch',
          'candidateRevision',
          'candidateControlHead',
          'candidateStoreCommitment',
          'observationHash',
        ],
        'rollback anchor first-anchor ambiguity poison',
      );
      const epoch = dataProperty(snapshot, 'epoch');
      if (typeof epoch !== 'bigint' || epoch < 0n || epoch > MAX_U64) {
        throw new Error(
          'rollback anchor first-anchor ambiguity epoch must be unsigned 64-bit',
        );
      }
      const candidateRevision = dataProperty(snapshot, 'candidateRevision');
      if (
        !Number.isSafeInteger(candidateRevision) ||
        (candidateRevision as number) < 1
      ) {
        throw new Error(
          'rollback anchor first-anchor ambiguity candidate revision is invalid',
        );
      }
      return {
        reason,
        epoch,
        candidateRevision: candidateRevision as number,
        candidateControlHead: cloneExactBytes(
          dataProperty(snapshot, 'candidateControlHead'),
          'rollback anchor first-anchor ambiguity candidate control head',
          CONTROL_HEAD_LENGTH,
        ),
        candidateStoreCommitment: cloneExactBytes(
          dataProperty(snapshot, 'candidateStoreCommitment'),
          'rollback anchor first-anchor ambiguity candidate store commitment',
          STORE_COMMITMENT_LENGTH,
        ),
        observationHash: cloneExactBytes(
          dataProperty(snapshot, 'observationHash'),
          'rollback anchor first-anchor ambiguity observation hash',
          FORK_EVIDENCE_HASH_LENGTH,
        ),
      };
    }
    requireExactKeys(
      snapshot,
      [
        'reason',
        'epoch',
        'baseRevision',
        'baseControlHead',
        'baseStoreCommitment',
        'candidateParentRecordId',
        'candidateRecordId',
        'observationHash',
      ],
      'rollback anchor ambiguity poison',
    );
    if (reason !== 'unreconciled-authenticated-candidate') {
      throw new Error('rollback anchor ambiguity poison reason is invalid');
    }
    const epoch = dataProperty(snapshot, 'epoch');
    if (typeof epoch !== 'bigint' || epoch < 0n || epoch > MAX_U64) {
      throw new Error('rollback anchor ambiguity epoch must be unsigned 64-bit');
    }
    const baseRevision = dataProperty(snapshot, 'baseRevision');
    if (!Number.isSafeInteger(baseRevision) || (baseRevision as number) < 1) {
      throw new Error('rollback anchor ambiguity base revision is invalid');
    }
    return {
      reason,
      epoch,
      baseRevision: baseRevision as number,
      baseControlHead: cloneExactBytes(
        dataProperty(snapshot, 'baseControlHead'),
        'rollback anchor ambiguity base control head',
        CONTROL_HEAD_LENGTH,
      ),
      baseStoreCommitment: cloneExactBytes(
        dataProperty(snapshot, 'baseStoreCommitment'),
        'rollback anchor ambiguity base store commitment',
        STORE_COMMITMENT_LENGTH,
      ),
      candidateParentRecordId: cloneExactBytes(
        dataProperty(snapshot, 'candidateParentRecordId'),
        'rollback anchor ambiguity candidate parent recordId',
        CONTROL_HEAD_LENGTH,
      ),
      candidateRecordId: cloneExactBytes(
        dataProperty(snapshot, 'candidateRecordId'),
        'rollback anchor ambiguity candidate recordId',
        CONTROL_HEAD_LENGTH,
      ),
      observationHash: cloneExactBytes(
        dataProperty(snapshot, 'observationHash'),
        'rollback anchor ambiguity observation hash',
        FORK_EVIDENCE_HASH_LENGTH,
      ),
    };
  }
  requireExactKeys(
    snapshot,
    [
      'epoch',
      'parentRecordId',
      'firstRecordId',
      'secondRecordId',
      'evidenceHash',
    ],
    'rollback anchor fork poison',
  );
  const epoch = dataProperty(snapshot, 'epoch');
  if (typeof epoch !== 'bigint' || epoch < 0n || epoch > MAX_U64) {
    throw new Error('rollback anchor fork epoch must be unsigned 64-bit');
  }
  return {
    epoch,
    parentRecordId: cloneExactBytes(
      dataProperty(snapshot, 'parentRecordId'),
      'rollback anchor fork parentRecordId',
      CONTROL_HEAD_LENGTH,
    ),
    firstRecordId: cloneExactBytes(
      dataProperty(snapshot, 'firstRecordId'),
      'rollback anchor fork firstRecordId',
      CONTROL_HEAD_LENGTH,
    ),
    secondRecordId: cloneExactBytes(
      dataProperty(snapshot, 'secondRecordId'),
      'rollback anchor fork secondRecordId',
      CONTROL_HEAD_LENGTH,
    ),
    evidenceHash: cloneExactBytes(
      dataProperty(snapshot, 'evidenceHash'),
      'rollback anchor fork evidenceHash',
      FORK_EVIDENCE_HASH_LENGTH,
    ),
  };
}

function optionalForkPoisonEqual(
  left: GroupSecurityRollbackForkPoison | undefined,
  right: GroupSecurityRollbackForkPoison | undefined,
): boolean {
  if (left === undefined || right === undefined) return left === right;
  if ('reason' in left || 'reason' in right) {
    if (!('reason' in left) || !('reason' in right)) return false;
    if (left.reason !== right.reason) return false;
    if (left.reason === 'unreconciled-first-anchor-candidate') {
      if (right.reason !== 'unreconciled-first-anchor-candidate') return false;
      return (
        left.epoch === right.epoch &&
        left.candidateRevision === right.candidateRevision &&
        equalBytes(left.candidateControlHead, right.candidateControlHead) &&
        equalBytes(
          left.candidateStoreCommitment,
          right.candidateStoreCommitment,
        ) &&
        equalBytes(left.observationHash, right.observationHash)
      );
    }
    if (right.reason !== 'unreconciled-authenticated-candidate') return false;
    return (
      left.epoch === right.epoch &&
      left.baseRevision === right.baseRevision &&
      equalBytes(left.baseControlHead, right.baseControlHead) &&
      equalBytes(left.baseStoreCommitment, right.baseStoreCommitment) &&
      equalBytes(
        left.candidateParentRecordId,
        right.candidateParentRecordId,
      ) &&
      equalBytes(left.candidateRecordId, right.candidateRecordId) &&
      equalBytes(left.observationHash, right.observationHash)
    );
  }
  return (
    left.epoch === right.epoch &&
    equalBytes(left.parentRecordId, right.parentRecordId) &&
    equalBytes(left.firstRecordId, right.firstRecordId) &&
    equalBytes(left.secondRecordId, right.secondRecordId) &&
    equalBytes(left.evidenceHash, right.evidenceHash)
  );
}

function exactPlainObject(
  value: unknown,
  expectedKeys: ReadonlyArray<string>,
  field: string,
): Record<PropertyKey, unknown> {
  const object = snapshotPlainObject(value, field);
  requireExactKeys(object, expectedKeys, field);
  return object;
}

function snapshotPlainObject(
  value: unknown,
  field: string,
): Record<PropertyKey, unknown> {
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype =
      value !== null && typeof value === 'object'
        ? Object.getPrototypeOf(value)
        : null;
    keys =
      value !== null && typeof value === 'object' ? Reflect.ownKeys(value) : [];
  } catch {
    throw new Error(`${field} must be a plain data object`);
  }
  if (
    value === null ||
    typeof value !== 'object' ||
    (prototype !== Object.prototype && prototype !== null)
  ) {
    throw new Error(`${field} must be a plain object`);
  }
  const snapshot = Object.create(null) as Record<PropertyKey, unknown>;
  for (const key of keys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      throw new Error(`${field} must contain only own data properties`);
    }
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${String(key)} must be an enumerable own data property`);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function requireExactKeys(
  object: Record<PropertyKey, unknown>,
  expectedKeys: ReadonlyArray<string>,
  field: string,
): void {
  const keys = Reflect.ownKeys(object);
  if (
    keys.length !== expectedKeys.length ||
    keys.some(
      (key) => typeof key !== 'string' || !expectedKeys.includes(key),
    )
  ) {
    throw new Error(`${field} has unexpected or missing fields`);
  }
}

function dataProperty(
  object: Record<PropertyKey, unknown>,
  key: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !('value' in descriptor)
  ) {
    throw new Error(`${key} must be an enumerable own data property`);
  }
  return descriptor.value;
}

function cloneBytes(
  value: unknown,
  field: string,
  minimumLength: number,
  maximumLength: number,
): Uint8Array {
  let length: number;
  let buffer: ArrayBufferLike;
  let tag: unknown;
  try {
    length = Reflect.apply(typedArrayByteLengthGetter, value, []) as number;
    buffer = Reflect.apply(typedArrayBufferGetter, value, []) as ArrayBufferLike;
    tag = Reflect.apply(typedArrayTagGetter, value, []);
  } catch {
    throw new Error(`${field} must be a genuine Uint8Array`);
  }
  if (
    tag !== 'Uint8Array' ||
    !Number.isSafeInteger(length) ||
    length < minimumLength ||
    length > maximumLength ||
    isSharedBuffer(buffer)
  ) {
    throw new Error(`${field} has an invalid length or backing buffer`);
  }
  const output = new Uint8Array(length);
  try {
    Reflect.apply(uint8ArraySet, output, [value]);
  } catch {
    throw new Error(`${field} could not be copied safely`);
  }
  return output;
}

function cloneExactBytes(
  value: unknown,
  field: string,
  expectedLength: number,
): Uint8Array {
  try {
    return cloneBytes(value, field, expectedLength, expectedLength);
  } catch (error) {
    throw new Error(
      `${field} must contain ${expectedLength} unshared bytes`,
      { cause: error },
    );
  }
}

function cloneBoundedBytes(
  value: unknown,
  field: string,
  minimumLength: number,
  maximumLength: number,
): Uint8Array {
  return cloneBytes(value, field, minimumLength, maximumLength);
}

function cloneAndValidateKey(key: GroupStateStoreKey): GroupStateStoreKey {
  const keySnapshot = exactPlainObject(
    key,
    ['protocol', 'groupId'],
    'rollback anchor key',
  );
  const protocol = cloneAndValidateProtocol(
    dataProperty(keySnapshot, 'protocol'),
  );
  const groupId = cloneBoundedBytes(
    dataProperty(keySnapshot, 'groupId'),
    'rollback anchor groupId',
    1,
    1024,
  );
  return { protocol, groupId };
}

function cloneAndValidateProtocol(value: unknown): GroupSecurityProtocol {
  const protocol = exactPlainObject(
    value,
    ['id', 'version'],
    'rollback anchor protocol',
  );
  const id = dataProperty(protocol, 'id');
  const version = dataProperty(protocol, 'version');
  if (
    typeof id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(id) ||
    !Number.isInteger(version) ||
    (version as number) < 0 ||
    (version as number) > 0xffff
  ) {
    throw new Error('invalid canonical rollback anchor protocol identifier');
  }
  return { id, version: version as number };
}

function isSharedBuffer(buffer: unknown): boolean {
  if (sharedArrayBufferByteLengthGetter === undefined) return false;
  try {
    Reflect.apply(sharedArrayBufferByteLengthGetter, buffer, []);
    return true;
  } catch {
    return false;
  }
}

function encodeKey(key: GroupStateStoreKey): string {
  return `${key.protocol.id}:${key.protocol.version}:${toHex(key.groupId)}`;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let different = 0;
  for (let index = 0; index < left.byteLength; index++) {
    different |= left[index] ^ right[index];
  }
  return different === 0;
}

function toHex(value: Uint8Array): string {
  let result = '';
  for (const byte of value) result += byte.toString(16).padStart(2, '0');
  return result;
}
