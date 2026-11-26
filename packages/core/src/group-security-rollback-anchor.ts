import {
  classifyAnchorAdvance,
  isRemovalAnchorTransitionAllowed,
} from './policy/anchor-advance.js';
import { trackQueuedOperation } from './queued-operation.js';
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
    : Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, 'byteLength')
        ?.get;

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
  readonly removal: GroupSecurityRollbackRemoval | undefined;
}

/** Terminal marker written only after authenticating a local-member removal. */
export interface GroupSecurityRollbackRemoval {
  readonly epoch: bigint;
  readonly parentRecordId: Uint8Array;
  readonly recordId: Uint8Array;
  readonly memberId: Uint8Array;
}

/** Irreversible terminal authenticated-fork commitment. */
export interface GroupSecurityRollbackForkPoison {
  readonly epoch: bigint;
  readonly parentRecordId: Uint8Array;
  readonly firstRecordId: Uint8Array;
  readonly secondRecordId: Uint8Array;
  readonly evidenceHash: Uint8Array;
}

/**
 * Write-ahead record of the exact store snapshot that a commit is about to
 * produce, kept beside the current anchor value.
 *
 * `baseRevision` and `baseStoreCommitment` name the snapshot the commit starts
 * from. For an active anchor they equal its revision and store commitment. For
 * a first anchor they name the pre-group snapshot, with revision 0 and no
 * commitment when the store is empty. `next` is the exact active value to
 * install once the store holds `next.storeCommitment`.
 */
export interface GroupSecurityRollbackIntent {
  readonly baseRevision: number;
  readonly baseStoreCommitment: Uint8Array | undefined;
  readonly next: GroupSecurityRollbackAnchorValue;
}

/**
 * Separately protected compare-and-set boundary for rollback detection.
 *
 * Every store commit is bracketed by two anchor writes. `prepare` records the
 * exact next value as an intent before the store commits, and `advance`
 * installs a value after it commits. If the second write never happens,
 * restore completes the intent when the store holds exactly the intended
 * snapshot and discards it when the store still holds the base snapshot. Any
 * other store state fails closed. Every mutating method must be durable before
 * it resolves and must leave state unchanged when it returns `false`.
 */
export interface DurableGroupSecurityRollbackAnchor {
  load(
    key: GroupStateStoreKey,
  ): Promise<GroupSecurityRollbackAnchorValue | undefined>;
  /** Return the intent recorded beside the current value, if any. */
  loadIntent(
    key: GroupStateStoreKey,
  ): Promise<GroupSecurityRollbackIntent | undefined>;
  /**
   * Record `intent` while `expected` is current (`undefined` before the first
   * anchor), replacing any earlier intent. The intent must extend `expected`.
   * Return false when `expected` is not current.
   */
  prepare(
    key: GroupStateStoreKey,
    expected: GroupSecurityRollbackAnchorValue | undefined,
    intent: GroupSecurityRollbackIntent,
  ): Promise<boolean>;
  /** Install `next` while `expected` is current and clear any intent. */
  advance(
    key: GroupStateStoreKey,
    expected: GroupSecurityRollbackAnchorValue | undefined,
    next: GroupSecurityRollbackAnchorValue,
  ): Promise<boolean>;
  /**
   * Remove exactly `intent` while `expected` is current. Return true when it
   * was removed or no intent remains, and false when `expected` is not current
   * or a different intent is recorded.
   */
  discard(
    key: GroupStateStoreKey,
    expected: GroupSecurityRollbackAnchorValue | undefined,
    intent: GroupSecurityRollbackIntent,
  ): Promise<boolean>;
  /**
   * Atomically and irreversibly poison whichever active value is current and
   * clear any intent.
   */
  poison(
    key: GroupStateStoreKey,
    forkPoison: GroupSecurityRollbackForkPoison,
    initial?: GroupSecurityRollbackAnchorValue,
  ): Promise<GroupSecurityRollbackAnchorValue>;
  /**
   * Durably and atomically retire the exact active position after a verified removal.
   * The caller authenticates the control and protocol Commit first. Retrying
   * the identical expected position and marker is idempotent. A different
   * current position returns false without changing state. Once written, the
   * marker prevents every later active advance, including after store rollback,
   * and any intent is cleared.
   * Return true only after the exact terminal marker is durably retained.
   */
  retire(
    key: GroupStateStoreKey,
    expected: GroupSecurityRollbackAnchorValue,
    removal: GroupSecurityRollbackRemoval,
  ): Promise<boolean>;
}

/**
 * Reference implementation for tests and same-process development only.
 * Keeping this object beside an in-memory store is not rollback-resistant.
 */
export class InMemoryGroupSecurityRollbackAnchor
  implements DurableGroupSecurityRollbackAnchor
{
  private readonly values = new Map<string, GroupSecurityRollbackAnchorValue>();
  private readonly intents = new Map<string, GroupSecurityRollbackIntent>();
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

  async loadIntent(
    keyValue: GroupStateStoreKey,
  ): Promise<GroupSecurityRollbackIntent | undefined> {
    const key = cloneAndValidateKey(keyValue);
    const encodedKey = encodeKey(key);
    await (this.tails.get(encodedKey) ?? Promise.resolve());
    const intent = this.intents.get(encodedKey);
    return intent === undefined ? undefined : cloneAndValidateIntent(intent);
  }

  async prepare(
    keyValue: GroupStateStoreKey,
    expectedValue: GroupSecurityRollbackAnchorValue | undefined,
    intentValue: GroupSecurityRollbackIntent,
  ): Promise<boolean> {
    const key = cloneAndValidateKey(keyValue);
    const expected =
      expectedValue === undefined
        ? undefined
        : cloneAndValidateAnchor(expectedValue);
    const intent = cloneAndValidateIntent(intentValue);
    validateIntentBase(expected, intent);
    const encodedKey = encodeKey(key);
    const prior = this.tails.get(encodedKey) ?? Promise.resolve();
    const run = prior.then(() => {
      if (!optionalAnchorEqual(this.values.get(encodedKey), expected)) {
        return false;
      }
      this.intents.set(encodedKey, cloneAndValidateIntent(intent));
      return true;
    });
    return trackQueuedOperation(this.tails, encodedKey, run);
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
      this.intents.delete(encodedKey);
      return true;
    });
    return trackQueuedOperation(this.tails, encodedKey, run);
  }

  async discard(
    keyValue: GroupStateStoreKey,
    expectedValue: GroupSecurityRollbackAnchorValue | undefined,
    intentValue: GroupSecurityRollbackIntent,
  ): Promise<boolean> {
    const key = cloneAndValidateKey(keyValue);
    const expected =
      expectedValue === undefined
        ? undefined
        : cloneAndValidateAnchor(expectedValue);
    const intent = cloneAndValidateIntent(intentValue);
    const encodedKey = encodeKey(key);
    const prior = this.tails.get(encodedKey) ?? Promise.resolve();
    const run = prior.then(() => {
      if (!optionalAnchorEqual(this.values.get(encodedKey), expected)) {
        return false;
      }
      const current = this.intents.get(encodedKey);
      if (current === undefined) return true;
      if (!intentEqual(current, intent)) return false;
      this.intents.delete(encodedKey);
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
    if (initial?.forkPoison !== undefined || initial?.removal !== undefined) {
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
        this.intents.delete(encodedKey);
        return cloneAnchor(poisoned);
      }
      if (current.forkPoison !== undefined || current.removal !== undefined) {
        return cloneAnchor(current);
      }
      const poisoned = cloneAnchor({ ...current, forkPoison });
      this.values.set(encodedKey, poisoned);
      this.intents.delete(encodedKey);
      return cloneAnchor(poisoned);
    });
    return trackQueuedOperation(this.tails, encodedKey, run);
  }

  async retire(
    keyValue: GroupStateStoreKey,
    expectedValue: GroupSecurityRollbackAnchorValue,
    removalValue: GroupSecurityRollbackRemoval,
  ): Promise<boolean> {
    const key = cloneAndValidateKey(keyValue);
    const expected = cloneAndValidateAnchor(expectedValue);
    const removal = cloneRemoval(removalValue);
    if (
      !isRemovalAnchorTransitionAllowed(
        expected.forkPoison === undefined && expected.removal === undefined,
        equalBytes(removal.parentRecordId, expected.controlHead),
        !equalBytes(removal.recordId, expected.controlHead),
        expected.epoch,
        removal.epoch,
      )
    ) {
      throw new Error(
        'removal must terminate the exact next child of an active anchor',
      );
    }
    const retired = cloneAnchor({ ...expected, removal });
    const encodedKey = encodeKey(key);
    const prior = this.tails.get(encodedKey) ?? Promise.resolve();
    const run = prior.then(() => {
      const current = this.values.get(encodedKey);
      if (optionalAnchorEqual(current, retired)) return true;
      if (!optionalAnchorEqual(current, expected)) return false;
      this.values.set(encodedKey, retired);
      this.intents.delete(encodedKey);
      return true;
    });
    return trackQueuedOperation(this.tails, encodedKey, run);
  }
}

export function cloneGroupSecurityRollbackAnchor(
  value: GroupSecurityRollbackAnchorValue,
): GroupSecurityRollbackAnchorValue {
  return cloneAndValidateAnchor(value);
}

export function cloneGroupSecurityRollbackIntent(
  value: GroupSecurityRollbackIntent,
): GroupSecurityRollbackIntent {
  return cloneAndValidateIntent(value);
}

/** Whether `intent` names a valid one-step successor of `expected`. */
export function groupSecurityRollbackIntentExtends(
  expected: GroupSecurityRollbackAnchorValue | undefined,
  intent: GroupSecurityRollbackIntent,
): boolean {
  try {
    validateIntentBase(
      expected === undefined ? undefined : cloneAndValidateAnchor(expected),
      cloneAndValidateIntent(intent),
    );
    return true;
  } catch {
    return false;
  }
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
  const previous = expected ?? next;
  const disposition = classifyAnchorAdvance(
    expected !== undefined,
    {
      revision: previous.revision,
      epoch: previous.epoch,
      poisoned:
        previous.forkPoison !== undefined || previous.removal !== undefined,
    },
    {
      revision: next.revision,
      epoch: next.epoch,
      poisoned: next.forkPoison !== undefined || next.removal !== undefined,
    },
    expected === undefined ||
      equalBytes(next.controlHead, expected.controlHead),
  );
  if (disposition === 'valid') return;
  const messages = {
    initialPoison: 'rollback anchor cannot begin poisoned',
    terminalPoison: 'poisoned rollback anchor is terminal',
    poisonMethod: 'rollback anchor poisoning requires the atomic poison method',
    revision: 'rollback anchor revision must advance by exactly one',
    epoch: 'rollback anchor epoch must stay constant or advance by exactly one',
    controlHead:
      'rollback anchor control head cannot change without an epoch advance',
  };
  throw new Error(messages[disposition]);
}

function validateIntentBase(
  expected: GroupSecurityRollbackAnchorValue | undefined,
  intent: GroupSecurityRollbackIntent,
): void {
  if (
    expected !== undefined &&
    (intent.baseRevision !== expected.revision ||
      intent.baseStoreCommitment === undefined ||
      !equalBytes(intent.baseStoreCommitment, expected.storeCommitment))
  ) {
    throw new Error('rollback anchor intent must extend the expected value');
  }
  validateAdvance(expected, intent.next);
}

function cloneAndValidateIntent(value: unknown): GroupSecurityRollbackIntent {
  const object = exactPlainObject(
    value,
    ['baseRevision', 'baseStoreCommitment', 'next'],
    'rollback anchor intent',
  );
  const baseRevision = dataProperty(object, 'baseRevision');
  const baseStoreCommitment = dataProperty(object, 'baseStoreCommitment');
  if (!Number.isSafeInteger(baseRevision) || (baseRevision as number) < 0) {
    throw new Error(
      'rollback anchor intent base revision must be a non-negative safe integer',
    );
  }
  if ((baseRevision === 0) !== (baseStoreCommitment === undefined)) {
    throw new Error(
      'rollback anchor intent base commitment must be present exactly when a base snapshot exists',
    );
  }
  const next = cloneAndValidateAnchor(
    dataProperty(object, 'next') as GroupSecurityRollbackAnchorValue,
  );
  if (next.forkPoison !== undefined || next.removal !== undefined) {
    throw new Error('rollback anchor intent must name an active value');
  }
  if (next.revision !== (baseRevision as number) + 1) {
    throw new Error('rollback anchor intent must name the next revision');
  }
  return {
    baseRevision: baseRevision as number,
    baseStoreCommitment:
      baseStoreCommitment === undefined
        ? undefined
        : cloneExactBytes(
            baseStoreCommitment,
            'rollback anchor intent base store commitment',
            STORE_COMMITMENT_LENGTH,
          ),
    next,
  };
}

function intentEqual(
  left: GroupSecurityRollbackIntent,
  right: GroupSecurityRollbackIntent,
): boolean {
  return (
    left.baseRevision === right.baseRevision &&
    (left.baseStoreCommitment === undefined
      ? right.baseStoreCommitment === undefined
      : right.baseStoreCommitment !== undefined &&
        equalBytes(left.baseStoreCommitment, right.baseStoreCommitment)) &&
    optionalAnchorEqual(left.next, right.next)
  );
}

function cloneAndValidateAnchor(
  value: GroupSecurityRollbackAnchorValue,
): GroupSecurityRollbackAnchorValue {
  const object = exactPlainObject(
    value,
    [
      'revision',
      'epoch',
      'controlHead',
      'storeCommitment',
      'forkPoison',
      'removal',
    ],
    'rollback anchor',
  );
  const revision = dataProperty(object, 'revision');
  const epoch = dataProperty(object, 'epoch');
  const controlHead = dataProperty(object, 'controlHead');
  const storeCommitment = dataProperty(object, 'storeCommitment');
  const forkPoison = dataProperty(object, 'forkPoison');
  const removal = dataProperty(object, 'removal');
  if (!Number.isSafeInteger(revision) || (revision as number) < 1) {
    throw new Error('rollback anchor revision must be a positive safe integer');
  }
  if (typeof epoch !== 'bigint' || epoch < 0n || epoch > MAX_U64) {
    throw new Error('rollback anchor epoch must be an unsigned 64-bit bigint');
  }
  if (forkPoison !== undefined && removal !== undefined) {
    throw new Error('rollback anchor cannot have two terminal markers');
  }
  const snapshot: GroupSecurityRollbackAnchorValue = {
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
    removal: removal === undefined ? undefined : cloneRemoval(removal),
  };
  if (
    snapshot.removal !== undefined &&
    !isRemovalAnchorTransitionAllowed(
      snapshot.forkPoison === undefined,
      equalBytes(snapshot.removal.parentRecordId, snapshot.controlHead),
      !equalBytes(snapshot.removal.recordId, snapshot.controlHead),
      snapshot.epoch,
      snapshot.removal.epoch,
    )
  ) {
    throw new Error(
      'rollback anchor removal does not bind its active position',
    );
  }
  return snapshot;
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
    optionalForkPoisonEqual(left.forkPoison, right.forkPoison) &&
    optionalRemovalEqual(left.removal, right.removal)
  );
}

function cloneRemoval(value: unknown): GroupSecurityRollbackRemoval {
  const object = exactPlainObject(
    value,
    ['epoch', 'parentRecordId', 'recordId', 'memberId'],
    'rollback anchor removal',
  );
  const epoch = dataProperty(object, 'epoch');
  if (typeof epoch !== 'bigint' || epoch < 1n || epoch > MAX_U64) {
    throw new Error('removal epoch must be a positive unsigned 64-bit bigint');
  }
  return {
    epoch,
    parentRecordId: cloneExactBytes(
      dataProperty(object, 'parentRecordId'),
      'removal parent',
      CONTROL_HEAD_LENGTH,
    ),
    recordId: cloneExactBytes(
      dataProperty(object, 'recordId'),
      'removal record',
      CONTROL_HEAD_LENGTH,
    ),
    memberId: cloneBoundedBytes(
      dataProperty(object, 'memberId'),
      'removed member',
      1,
      512,
    ),
  };
}

function optionalRemovalEqual(
  left: GroupSecurityRollbackRemoval | undefined,
  right: GroupSecurityRollbackRemoval | undefined,
): boolean {
  if (left === undefined || right === undefined) return left === right;
  return (
    left.epoch === right.epoch &&
    equalBytes(left.parentRecordId, right.parentRecordId) &&
    equalBytes(left.recordId, right.recordId) &&
    equalBytes(left.memberId, right.memberId)
  );
}

function cloneForkPoison(value: unknown): GroupSecurityRollbackForkPoison {
  const snapshot = exactPlainObject(
    value,
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
  const forkPoison = {
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
  if (equalBytes(forkPoison.firstRecordId, forkPoison.secondRecordId)) {
    throw new Error('rollback anchor fork record IDs must be distinct');
  }
  return forkPoison;
}

function optionalForkPoisonEqual(
  left: GroupSecurityRollbackForkPoison | undefined,
  right: GroupSecurityRollbackForkPoison | undefined,
): boolean {
  if (left === undefined || right === undefined) return left === right;
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
    keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
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
    buffer = Reflect.apply(
      typedArrayBufferGetter,
      value,
      [],
    ) as ArrayBufferLike;
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
    throw new Error(`${field} must contain ${expectedLength} unshared bytes`, {
      cause: error,
    });
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
  const length = Reflect.apply(typedArrayByteLengthGetter, value, []) as number;
  for (let index = 0; index < length; index++) {
    result += value[index].toString(16).padStart(2, '0');
  }
  return result;
}
