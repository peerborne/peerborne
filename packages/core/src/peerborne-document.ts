import { assertWellFormedUtf16 } from './internal/utf16.js';
import { assertPositiveSafeByteLimit } from './internal/byte-limits.js';
import { snapshotInvitationBootstrapBundle } from './internal/invitation-bootstrap.js';
import { constantTimeEqual } from './internal/constant-time-equal.js';
/**
 * Document  is just for opening documents right now
 * @remarks
 *   A document is part of a Swarm.
 *   Document keys are attached to a single document.
 */

import { pipe } from 'it-pipe';
import { Libp2p } from 'libp2p';
import { Peerborne, MAX_DOCUMENT_PATH_LENGTH } from './peerborne.js';
import type { CreateInvitationOptions } from './peerborne.js';
import {
  assertSharedProtocolRequestSize,
  concatUint8Arrays,
  copyUnsharedUint8Array,
  firstTrue,
  MAX_SHARED_PROTOCOL_REQUEST_BYTES,
  readUint8Iterable,
  shuffleArray,
  snapshotDeepEnumerableData,
  snapshotEnumerableOwnDataObject,
} from './utils.js';
import type { Stream } from '@libp2p/interface';
import { writeStream, type ProtocolWriteStream } from './stream-write.js';
import { CRDTProvider } from './crdt-provider.js';
import {
  AuthProvider,
  requireDeserializePublicKey,
  requireSerializePublicKey,
} from './auth-provider.js';
import {
  CRDTChangeNode,
  crdtChangeNodeDeferred,
  CRDTChangeNodeKind,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import {
  snapshotBoundedChangeTree,
  type BoundedChangeTreeEntry,
} from './change-tree-walk.js';
import {
  collectReferencedAncestors,
  computeServedFrontier,
  stripInlineChanges,
  MAX_CROSS_LINKS,
  MAX_RECENT_TIPS,
  mergeRemoteSyncTree,
  RecentTip,
  selectCrossLinks,
  trackTipInList,
  treeContainsCid,
  validateRemoteSyncTreeAliases,
} from './merkle-cross-links.js';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import { ChangesSerializer } from './changes-serializer.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import {
  snapshotSyncMessageForContext,
  syncMessageMatchesSnapshot,
  type SyncMessageContext,
} from './sync-message-context.js';
import { evaluateBeeKEMWelcome } from './beekem-welcome-handler.js';
import {
  PendingWelcomeBuffer,
  PendingWelcomeBodyLimitError,
  PENDING_WELCOME_MAX_BODY_BYTES,
  PENDING_WELCOMES_TTL_MS,
} from './pending-welcome-buffer.js';
import {
  snapshotKemKeyPair,
  validateAndExportKemKeyPair,
} from './kem-key-pair.js';
import {
  eciesSeal,
  eciesOpen,
  importEciesPublicKey,
  ECIES_P256_PUBLIC_KEY_LENGTH,
} from './ecies.js';
import {
  beekemPathUpdateV2,
  beekemWelcomeV2,
  documentLoadV3,
  snapshotLoadV3,
  tipAdvertiseV1,
} from './wire-protocols.js';
import { BeeKEM } from './beekem/beekem.js';
import { BeeKEMWelcomeV2, PathUpdateV2 } from './beekem/types.js';
import {
  deserializePathUpdateV2FromWire,
  serializePathUpdateV2ForWire,
} from './path-update-wire.js';
import {
  decodeWelcomeSealedPayloadV2,
  encodeWelcomeSealedPayloadV2,
  welcomeKeychainEnvelopeBytes,
} from './welcome-sealed-payload.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import { EPOCH_ID_LENGTH } from './epoch.js';
import { tipsHash, tipsHashToHex, TIPS_HASH_LENGTH } from './tips-hash.js';
import {
  constantTimeHexEquals,
  dedupePeersByPeerId,
  LOAD_QUORUM_TIMEOUT_MS_MAX,
  LoadQuorumFailedError,
} from './load-quorum.js';
import { runLoadQuorum } from './load-quorum-orchestrator.js';
import { CRDTSnapshotNode } from './snapshot-node.js';
import type { CompactionConfig } from './compaction-config.js';
import { mergeCompactionConfig } from './compaction-config.js';
import {
  filterDeletableCIDs,
  loadChangeBlock as lazyLoadChangeBlock,
} from './blockstore-gc.js';
import { documentTopic } from './document-topic.js';
import { ACLProvider } from './acl-provider.js';
import {
  ACLOperationInProgressError,
  retryACLConflict,
} from './acl.js';
import { KeychainProvider } from './keychain-provider.js';
import {
  keychainHistorySinceOrReject,
  MAX_KEYCHAIN_EPOCHS,
  type Keychain,
} from './keychain.js';
import { LoadMessageSerializer } from './load-request-serializer.js';
import { CRDTLoadRequest } from './crdt-load-request.js';
import { Base64 } from 'js-base64';
import { Uint8ArrayList } from 'uint8arraylist';
import { CID } from 'multiformats';
import { UnixFS, unixfs } from '@helia/unixfs';
// libp2p v3 moved the `PubSubBaseProtocol` shim out of `@libp2p/pubsub` (the
// package has been removed). Use the concrete `GossipSub` service interface
// from `@libp2p/gossipsub` instead -- it is what `helia` actually wires up via
// `services.pubsub` and exposes the same publish/subscribe/event surface we
// rely on. `Message` (the pubsub message shape) likewise moved here.
import { TopicValidatorResult } from '@libp2p/gossipsub';
import type {
  GossipSub,
  Message,
  TopicValidatorFn,
} from '@libp2p/gossipsub';
import { EventHandler, PeerId } from '@libp2p/interface';
import { multiaddr } from '@multiformats/multiaddr';
import {
  collectInvitationCidsToInstall,
  syncInvitationMessageCompletely,
  withIssuerPinnedInvitationStream,
} from './invitation-catch-up.js';
import {
  MAX_INVITATION_MESSAGE_BYTES,
  assertInvitationBootstrapEpochBinding,
  type InvitationOfferV1,
} from './invitation-wire.js';
import {
  assertInitialInvitationBeeKEMCapacity,
  assertInitialInvitationBeeKEMWelcomeShape,
  assertInitialInvitationCapacityProfile,
  assertInvitationOpaquePayloadCapacity,
  assertProjectedInitialInvitationBootstrapCapacity,
  assertProjectedInitialInvitationWelcomeCapacity,
  INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES,
  INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SIGNATURE_BYTES,
  projectInitialInvitationBootstrapCapacity,
} from './invitation-capacity.js';
import {
  assertInitialInvitationHistoryVisibility,
  INVITATION_STREAM_TIMEOUT_MS,
  type HistoryVisibility,
} from './invitation-policy.js';
import {
  assertAcceptedInvitationMembershipTopology,
  createInvitationMutationAdmission,
  InvitationMembershipQueue,
  prepareInitialInvitationMembership,
  type InitialInvitationMembershipState,
} from './invitation-membership.js';
import {
  isSharedProtocolHandlerActive,
  runSharedProtocolMutation,
  type SharedProtocolHandlerAdmission,
} from './shared-protocol-admission.js';
export type { HistoryVisibility } from './invitation-policy.js';



function throwIfLoadAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw signal.reason instanceof Error
    ? signal.reason
    : new Error('Document load was aborted');
}

async function awaitLoadWork<T>(
  work: T | PromiseLike<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (!signal) return await work;
  let onAbort!: () => void;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => {
      try {
        throwIfLoadAborted(signal);
      } catch (error) {
        reject(error);
      }
    };
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    return await Promise.race([work, aborted]);
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

async function retryLoadACLConflict<T>(
  operation: () => T | PromiseLike<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (!signal) return retryACLConflict(operation);
  for (;;) {
    throwIfLoadAborted(signal);
    try {
      return await awaitLoadWork(operation(), signal);
    } catch (error) {
      throwIfLoadAborted(signal);
      if (!(error instanceof ACLOperationInProgressError)) throw error;
      await awaitLoadWork(error.waitForSettlement(), signal);
    }
  }
}

const MAX_BOUNDED_BLOCK_CHUNKS = 65_536;

class _LoadFetchLimitExceededError extends RangeError {}

interface DocumentChangeFetchBudget {
  readonly maxBytes: number;
  consumedBytes: number;
}

function consumeDocumentChangeFetchBytes(
  budget: DocumentChangeFetchBudget,
  byteLength: number,
): void {
  const nextTotal = budget.consumedBytes + byteLength;
  if (!Number.isSafeInteger(nextTotal) || nextTotal > budget.maxBytes) {
    throw new _LoadFetchLimitExceededError(
      'Missing change block byte budget exceeded',
    );
  }
  budget.consumedBytes = nextTotal;
}

/** Opaque, recipient-bound material returned by the invitation join handler. */
export interface InvitationBootstrapBundle {
  welcomeEpochId: Uint8Array;
  sealedWelcome: Uint8Array;
  encryptedBootstrap: Uint8Array;
}

const reflectOwnKeys = Reflect.ownKeys;
const documentReflectApply = Reflect.apply;
const documentGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const documentGetPrototypeOf = Object.getPrototypeOf;
const documentObjectConstructor = Object;
const documentObjectPrototype = Object.prototype;
const documentFunctionPrototype = Function.prototype;
const emptyCommitArguments: never[] = [];
const documentPromiseConstructor = Promise;
const documentPromisePrototype = Promise.prototype;
const documentPromiseThen = Promise.prototype.then;
const documentPromiseSpeciesDescriptor = documentGetOwnPropertyDescriptor(
  documentPromiseConstructor,
  Symbol.species,
);
const ignoreDocumentPromiseSettlement = (_value: unknown): undefined =>
  undefined;
const ignoredDocumentPromiseSettlementArguments = [
  ignoreDocumentPromiseSettlement,
  ignoreDocumentPromiseSettlement,
];
// Bound hostile prototype traversal well above normal provider inheritance.
// Custom providers must expose prepared methods within this depth.
const MAX_PREPARED_PROPERTY_PROTOTYPE_DEPTH = 32;

interface CapturedDataMethod {
  readonly receiver: object;
  readonly method: (...args: unknown[]) => unknown;
}

interface CapturedCommitFinalizer {
  readonly receiver: object;
  readonly finalize: (...args: unknown[]) => unknown;
}

interface CapturedPreparedKeychainMerge {
  readonly keyIds: readonly Uint8Array[];
  readonly currentKeyId: Uint8Array;
  readonly hydrateKeys: CapturedDataMethod;
  readonly getKey: CapturedDataMethod;
  readonly claimCommit: CapturedDataMethod;
}

type BeeKEMWelcomeApplicationOutcome = 'applied' | 'terminal' | 'retry';

function preparedDataProperty(
  value: unknown,
  property: PropertyKey,
  label: string,
): { readonly found: boolean; readonly value?: unknown } {
  if (
    (typeof value !== 'object' || value === null) &&
    typeof value !== 'function'
  ) {
    throw new TypeError(`${label} must be provided by an object`);
  }

  let owner: object | null = value as object;
  const visited = new Set<object>();
  let depth = 0;
  while (owner !== null) {
    if (
      visited.has(owner) ||
      depth++ >= MAX_PREPARED_PROPERTY_PROTOTYPE_DEPTH
    ) {
      throw new TypeError(`${label} has an invalid prototype chain`);
    }
    visited.add(owner);
    const descriptor = documentReflectApply(
      documentGetOwnPropertyDescriptor,
      Object,
      [owner, property],
    ) as PropertyDescriptor | undefined;
    if (descriptor !== undefined) {
      if (!('value' in descriptor)) {
        throw new TypeError(`${label} must be a data property`);
      }
      return { found: true, value: descriptor.value };
    }
    owner = documentReflectApply(documentGetPrototypeOf, Object, [owner]) as
      | object
      | null;
  }
  return { found: false };
}

function capturePreparedDataMethod(
  value: unknown,
  property: PropertyKey,
  label: string,
): CapturedDataMethod {
  const captured = preparedDataProperty(value, property, label);
  if (!captured.found || typeof captured.value !== 'function') {
    throw new TypeError(`${label} must be a function`);
  }
  return {
    receiver: value as object,
    method: captured.value as (...args: unknown[]) => unknown,
  };
}

function boundedPreparedArrayLength(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  label: string,
): number {
  if (!Array.isArray(value)) {
    throw new TypeError(`${label} must be an array`);
  }
  const lengthDescriptor = documentReflectApply(
    documentGetOwnPropertyDescriptor,
    documentObjectConstructor,
    [value, 'length'],
  ) as PropertyDescriptor | undefined;
  if (
    lengthDescriptor === undefined ||
    !('value' in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < minimumLength ||
    lengthDescriptor.value > maximumLength
  ) {
    throw new TypeError(`${label} has an invalid length`);
  }
  return lengthDescriptor.value as number;
}

function preparedArrayDataEntry(
  value: readonly unknown[],
  index: number,
  label: string,
): unknown {
  const descriptor = documentReflectApply(
    documentGetOwnPropertyDescriptor,
    documentObjectConstructor,
    [value, String(index)],
  ) as PropertyDescriptor | undefined;
  if (descriptor === undefined || !('value' in descriptor)) {
    throw new TypeError(`${label} must be a data property`);
  }
  return descriptor.value;
}

function capturePreparedKeychainMerge(
  prepared: unknown,
): CapturedPreparedKeychainMerge {
  const hydrateKeys = capturePreparedDataMethod(
    prepared,
    'hydrateKeys',
    'Prepared Welcome keychain hydrateKeys',
  );
  const getKey = capturePreparedDataMethod(
    prepared,
    'getKey',
    'Prepared Welcome keychain getKey',
  );
  const claimCommit = capturePreparedDataMethod(
    prepared,
    'claimCommit',
    'Prepared Welcome keychain claimCommit',
  );
  const currentKeyIdProperty = preparedDataProperty(
    prepared,
    'currentKeyId',
    'Prepared Welcome keychain currentKeyId',
  );
  if (!currentKeyIdProperty.found) {
    throw new TypeError(
      'Prepared Welcome keychain must provide currentKeyId',
    );
  }
  const currentKeyId = copyUnsharedUint8Array(
    currentKeyIdProperty.value,
    EPOCH_ID_LENGTH,
    EPOCH_ID_LENGTH,
    'Prepared Welcome keychain currentKeyId',
  );
  const keyIdsProperty = preparedDataProperty(
    prepared,
    'keyIds',
    'Prepared Welcome keychain keyIds',
  );
  if (!keyIdsProperty.found) {
    throw new TypeError('Prepared Welcome keychain must provide keyIds');
  }
  const keyCount = boundedPreparedArrayLength(
    keyIdsProperty.value,
    1,
    MAX_KEYCHAIN_EPOCHS,
    'Prepared Welcome keychain keyIds',
  );
  const rawKeyIds = keyIdsProperty.value as readonly unknown[];
  const keyIds: Uint8Array[] = [];
  const seenKeyIds = new Set<string>();
  for (let index = 0; index < keyCount; index++) {
    const keyId = copyUnsharedUint8Array(
      preparedArrayDataEntry(
        rawKeyIds,
        index,
        `Prepared Welcome keychain keyIds[${index}]`,
      ),
      EPOCH_ID_LENGTH,
      EPOCH_ID_LENGTH,
      `Prepared Welcome keychain keyIds[${index}]`,
    );
    let encodedKeyId = '';
    for (let offset = 0; offset < keyId.byteLength; offset++) {
      encodedKeyId += keyId[offset].toString(16).padStart(2, '0');
    }
    if (seenKeyIds.has(encodedKeyId)) {
      throw new TypeError('Prepared Welcome keychain has duplicate key IDs');
    }
    seenKeyIds.add(encodedKeyId);
    keyIds.push(keyId);
  }
  if (!constantTimeEqual(currentKeyId, keyIds[keyIds.length - 1])) {
    throw new TypeError(
      'Prepared Welcome keychain currentKeyId must be its final key ID',
    );
  }
  return { keyIds, currentKeyId, hydrateKeys, getKey, claimCommit };
}

function hasCompleteHydratedKeychain(
  hydrated: unknown,
  keyIds: readonly Uint8Array[],
): boolean {
  const entryCount = boundedPreparedArrayLength(
    hydrated,
    1,
    MAX_KEYCHAIN_EPOCHS,
    'Prepared Welcome hydrated keys',
  );
  if (entryCount !== keyIds.length) return false;
  const entries = hydrated as readonly unknown[];
  for (let index = 0; index < entryCount; index++) {
    const entry = preparedArrayDataEntry(
      entries,
      index,
      `Prepared Welcome hydrated keys[${index}]`,
    );
    boundedPreparedArrayLength(
      entry,
      2,
      2,
      `Prepared Welcome hydrated keys[${index}]`,
    );
    const hydratedKeyId = copyUnsharedUint8Array(
      preparedArrayDataEntry(
        entry as readonly unknown[],
        0,
        `Prepared Welcome hydrated keys[${index}][0]`,
      ),
      EPOCH_ID_LENGTH,
      EPOCH_ID_LENGTH,
      `Prepared Welcome hydrated keys[${index}][0]`,
    );
    const key = preparedArrayDataEntry(
      entry as readonly unknown[],
      1,
      `Prepared Welcome hydrated keys[${index}][1]`,
    );
    if (
      key === undefined ||
      !constantTimeEqual(hydratedKeyId, keyIds[index])
    ) {
      return false;
    }
  }
  return true;
}

function snapshotPathUpdateMessage<ChangesType, PublicKey>(
  value: unknown,
): CRDTSyncMessage<ChangesType, PublicKey> {
  return snapshotDeepEnumerableData(
    snapshotEnumerableOwnDataObject<CRDTSyncMessage<ChangesType, PublicKey>>(
      value,
      'BeeKEM PathUpdateV2 message',
    ),
    'BeeKEM PathUpdateV2 message',
    {
      maxDepth: 32,
      maxObjects: 32_768,
      maxProperties: 131_072,
      maxArrayLength: 65_536,
      maxValueBytes: MAX_SHARED_PROTOCOL_REQUEST_BYTES,
    },
  );
}

function canSafelyObservePreparedNativePromise(
  target: object,
  label: string,
): boolean {
  const constructorProperty = preparedDataProperty(
    target,
    'constructor',
    `${label} constructor`,
  );
  if (
    !constructorProperty.found ||
    constructorProperty.value === undefined
  ) {
    return true;
  }
  const constructor = constructorProperty.value;
  if (
    (typeof constructor !== 'object' || constructor === null) &&
    typeof constructor !== 'function'
  ) {
    return false;
  }
  if (constructor === documentPromiseConstructor) {
    const currentSpeciesDescriptor = documentReflectApply(
      documentGetOwnPropertyDescriptor,
      Object,
      [documentPromiseConstructor, Symbol.species],
    ) as PropertyDescriptor | undefined;
    if (
      currentSpeciesDescriptor !== undefined &&
      !('value' in currentSpeciesDescriptor)
    ) {
      return (
        documentPromiseSpeciesDescriptor !== undefined &&
        !('value' in documentPromiseSpeciesDescriptor) &&
        currentSpeciesDescriptor.get ===
          documentPromiseSpeciesDescriptor.get &&
        currentSpeciesDescriptor.set ===
          documentPromiseSpeciesDescriptor.set
      );
    }
    const species = currentSpeciesDescriptor?.value;
    return (
      currentSpeciesDescriptor !== undefined &&
      (species === undefined ||
        species === null ||
        species === documentPromiseConstructor)
    );
  }
  // An arbitrary constructor can be a Proxy whose descriptor trap reports a
  // harmless species while its ordinary `get` trap throws or mutates state
  // when Promise.prototype.then performs species lookup. Only trust the
  // captured intrinsic Object constructor and its pristine prototype chain.
  if (constructor !== documentObjectConstructor) return false;
  if (
    documentReflectApply(documentGetPrototypeOf, documentObjectConstructor, [
      documentObjectConstructor,
    ]) !== documentFunctionPrototype ||
    documentReflectApply(documentGetPrototypeOf, documentObjectConstructor, [
      documentFunctionPrototype,
    ]) !== documentObjectPrototype ||
    documentReflectApply(documentGetPrototypeOf, documentObjectConstructor, [
      documentObjectPrototype,
    ]) !== null
  ) {
    return false;
  }
  for (const owner of [
    documentObjectConstructor,
    documentFunctionPrototype,
    documentObjectPrototype,
  ]) {
    const descriptor = documentReflectApply(
      documentGetOwnPropertyDescriptor,
      documentObjectConstructor,
      [owner, Symbol.species],
    ) as PropertyDescriptor | undefined;
    if (descriptor === undefined) continue;
    if (!('value' in descriptor)) return false;
    return (
      descriptor.value === undefined ||
      descriptor.value === null ||
      descriptor.value === documentPromiseConstructor
    );
  }
  return true;
}

function observePreparedNativePromiseSettlement(value: object): boolean {
  try {
    void documentReflectApply(
      documentPromiseThen,
      value,
      ignoredDocumentPromiseSettlementArguments,
    );
    return true;
  } catch {
    return false;
  }
}

function observeInvalidPreparedNativePromiseReturn(
  value: object,
  label: string,
): void {
  try {
    if (canSafelyObservePreparedNativePromise(value, label)) {
      observePreparedNativePromiseSettlement(value);
    }
  } catch {
    // The caller rejects the result regardless; do not invoke unsafe species
    // hooks merely to suppress a malicious provider's rejection.
  }
}

function invokePreparedCommitClaim(
  claimCommit: CapturedDataMethod,
  label: string,
): CapturedCommitFinalizer {
  const claim = documentReflectApply(
    claimCommit.method,
    claimCommit.receiver,
    emptyCommitArguments,
  );
  if (
    (typeof claim !== 'object' || claim === null) &&
    typeof claim !== 'function'
  ) {
    throw new TypeError(`${label} returned an invalid claim record`);
  }
  let claimPrototype: object | null;
  try {
    claimPrototype = documentReflectApply(
      documentGetPrototypeOf,
      documentObjectConstructor,
      [claim],
    ) as object | null;
  } catch {
    throw new TypeError(`${label} returned an invalid claim record`);
  }
  if (
    claimPrototype !== null &&
    claimPrototype !== documentObjectPrototype &&
    claimPrototype !== documentPromisePrototype
  ) {
    throw new TypeError(
      `${label} returned an invalid asynchronous result: expected a plain claim record`,
    );
  }
  let thenProperty: { readonly found: boolean; readonly value?: unknown };
  try {
    thenProperty = preparedDataProperty(
      claim,
      'then',
      `${label} result then`,
    );
  } catch {
    observeInvalidPreparedNativePromiseReturn(
      claim,
      `${label} result`,
    );
    throw new TypeError(`${label} returned an invalid asynchronous result`);
  }
  let observationIsSafe = false;
  try {
    observationIsSafe = canSafelyObservePreparedNativePromise(
      claim as object,
      `${label} result`,
    );
  } catch {
    observeInvalidPreparedNativePromiseReturn(
      claim,
      `${label} result`,
    );
    throw new TypeError(`${label} returned an invalid asynchronous result`);
  }
  if (!thenProperty.found && !observationIsSafe) {
    observeInvalidPreparedNativePromiseReturn(claim, `${label} result`);
    throw new TypeError(`${label} returned an invalid asynchronous result`);
  }
  const isNativePromise = observationIsSafe
    ? observePreparedNativePromiseSettlement(claim)
    : false;
  if (thenProperty.found || isNativePromise) {
    throw new TypeError(`${label} must complete synchronously`);
  }
  if (claimPrototype === documentPromisePrototype) {
    throw new TypeError(
      `${label} returned an invalid asynchronous result: expected a plain claim record`,
    );
  }
  const capturedFinalize = preparedDataProperty(
    claim,
    'finalize',
    `${label} finalizer`,
  );
  if (
    !capturedFinalize.found ||
    typeof capturedFinalize.value !== 'function'
  ) {
    throw new TypeError(`${label} returned an invalid finalizer`);
  }
  return {
    receiver: claim,
    finalize: capturedFinalize.value as (...args: unknown[]) => unknown,
  };
}

function finalizePreparedCommitClaim(
  claim: CapturedCommitFinalizer,
  label: string,
): void {
  const result = documentReflectApply(
    claim.finalize,
    claim.receiver,
    emptyCommitArguments,
  );
  if (result !== undefined) {
    if (
      (typeof result === 'object' && result !== null) ||
      typeof result === 'function'
    ) {
      observeInvalidPreparedNativePromiseReturn(
        result,
        `${label} finalizer result`,
      );
    }
    throw new TypeError(`${label} finalizer must return undefined`);
  }
}


interface InvitationBootstrapCapacityPlan<ChangesType, PublicKey> {
  readonly keychainChanges: ChangesType;
  readonly snapshot?: CRDTSnapshotNode<ChangesType, PublicKey>;
  readonly serializedBootstrapBaselineBytes: number;
  readonly welcomeWithoutBeeKEMBytes: number;
}

interface PostPublishCommit {
  /** User-facing operation name used when reporting a handler failure. */
  readonly operation: string;
  /** Synchronous commit for state whose change was just published. */
  readonly commit: () => void;
}

interface CapturedPreparedReaderChange<ChangesType> {
  readonly changes: ChangesType;
  readonly claimCommit: CapturedDataMethod;
}

interface CapturedPreparedWriterChange<ChangesType> {
  readonly changes: ChangesType;
  readonly commit: CapturedDataMethod;
}

interface PreparedBeeKEMReaderRegistration {
  readonly welcome: BeeKEMWelcomeV2;
  readonly install?: () => void;
}

function copyBeeKEMWelcome(welcome: BeeKEMWelcomeV2): BeeKEMWelcomeV2 {
  const copy: BeeKEMWelcomeV2 = {
    version: 2,
    generation: welcome.generation,
    numLeaves: welcome.numLeaves,
    leafIndex: welcome.leafIndex,
    pathKeys: welcome.pathKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: new Uint8Array(node.publicKey),
      encryptedPrivateKey: new Uint8Array(node.encryptedPrivateKey),
    })),
    treeNodePublicKeys: welcome.treeNodePublicKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey:
        node.publicKey === null ? null : new Uint8Array(node.publicKey),
    })),
    treeHash: new Uint8Array(welcome.treeHash),
  };
  return copy;
}

/**
 * Handler type for local-change (changes made on the current computer) and remote-change (changes made by a remote peer) events.
 *
 * Subscribe functions that match this type signature to track local-change/remote-change events.
 */
export type PeerborneDocumentChangeHandler<DocType, PublicKey> = (
  current: DocType,
  readers: PublicKey[],
  writers: PublicKey[],
  hashes: string[],
) => void;

interface RemoteUpdateNotification<DocType, PublicKey> {
  readonly handlers: PeerborneDocumentChangeHandler<DocType, PublicKey>[];
  readonly document: DocType;
  readonly readers: PublicKey[];
  readonly writers: PublicKey[];
  readonly hashes: string[];
}

interface MissingBlockFetchOptions {
  readonly signal?: AbortSignal;
  readonly maxBlockBytes?: number;
  readonly consumeBytes?: (byteLength: number) => void;
}

interface DocumentChangeFetchOptions<DocumentKey> {
  readonly signal?: AbortSignal;
  readonly maxBlockBytes?: number;
  readonly maxAggregateBlockBytes?: number;
  readonly aggregateBudget?: DocumentChangeFetchBudget;
  readonly prefetchedBlocks?: ReadonlyMap<string, Uint8Array>;
  readonly getKey?: (keyID: Uint8Array) => DocumentKey | undefined;
  readonly assertStillActive?: () => void;
}

/**
 * A peerborne "document" represents a single CRDT document.
 *
 * A new peerborne document undergoes the following process when it is first opened:
 * - Connect to the document pubsub topic
 * - Send a load-document request to any peer (and keep trying with different peers if one fails) (`.load()`)
 * - Use load-document response from peer (if any) to update existing document with any new hashes (`.sync()`)
 *
 * A new local change (made on the current computer) causes the following:
 * - The delta between the current document and the new document is calculated
 * - A sync message is constructed and sent to all peers on the document pubsub topic (`.change(...)`)
 *
 * A new remote change (made on a peer's computer) causes the following:
 * - New change hashes are used to update exising document with any new changes (`.sync()`)
 *
 * Any edits made to the document should go through its corresponding PeerborneDocument's
 * `.change(...)` method:
 *
 * @example Automerge usage
 * ```ts
 * // Open a document (Automerge-based peerborne instance).
 * const doc1 = peerborne.doc("/my-doc1-path");
 * await doc1.open();
 *
 * await doc1.change(doc => {
 *   doc.field1 = "new-value";
 * });
 * ```
 *
 * @example Yjs usage
 * ```ts
 * // Open a document (Yjs-based peerborne instance).
 * const doc2 = peerborneYjs.doc("/my-doc2-path");
 * await doc2.open();
 *
 * await doc2.change(doc => {
 *   doc.getMap('data').set('field1', 'new-value');
 * });
 * ```
 * @typeParam DocType The CRDT document type
 * @typeParam ChangesType A block of CRDT change(s)
 * @typeParam ChangeFnType A function for applying changes to a document
 * @typeParam PrivateKey The type of secret key used to identify a user (for writing)
 * @typeParam PublicKey The type of key used to identify a user publicly
 * @typeParam DocumentKey The type of key used to encrypt/decrypt document changes
 */

/**
 * Maximum size (in bytes) of a `tipAdvertiseV1` probe response read. A
 * legitimate response is a single encrypted `CRDTSyncMessage` carrying
 * the `documentId` (pre-encryption path of up to `MAX_DOCUMENT_PATH_LENGTH`
 * bytes; this is BIGGER than the tipsHash + signature payload combined),
 * a 32-byte `tipsHash`, and an optional writer signature.
 *
 * Bound derivation:
 *   - documentId: up to `MAX_DOCUMENT_PATH_LENGTH` bytes UTF-8.
 *   - JSON framing + Base64 expansion of the encrypted body: ~256 bytes.
 *   - Writer signature: ECDSA P-384 ≈ 96 raw bytes, Base64 ≈ 128 bytes,
 *     plus the field's JSON key/quotes — round to 256 bytes.
 *   - tipsHash: 32 raw bytes → Base64 ≈ 44 bytes.
 *   - AES-GCM nonce: 12 raw bytes → Base64 ≈ 16 bytes.
 *   - AES-GCM auth tag: 16 bytes.
 *   - Plus slack for the encrypted-payload header (keyID prefix) and any
 *     additional JSON overhead.
 *
 * The previous 2 KiB cap was tighter than `MAX_DOCUMENT_PATH_LENGTH`
 * alone, so a document opened at a maximal path would always blow the cap
 * and be recorded as a non-vote — quorum would never pass for such
 * documents. 6 KiB comfortably covers a maximum-length path plus all of
 * the overheads above while still bounding what a malicious peer can
 * force the loader to buffer before being rejected as a non-vote.
 */
const MAX_TIP_ADVERTISE_RESPONSE_SIZE = 6 * 1024;

/** Bound ordinary encrypted snapshot/document responses before decoding. */
export const MAX_DOCUMENT_LOAD_RESPONSE_SIZE = 10 * 1024 * 1024;

function assertCanonicalACLIdentity(
  value: unknown,
): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(
      'AuthProvider.serializePublicKey must return a non-empty string',
    );
  }
  assertWellFormedUtf16(value, 'AuthProvider.serializePublicKey return value');
}

/** Match the default per-peer load-quorum probe budget. */
const DEFAULT_DOCUMENT_LOAD_RESPONSE_TIMEOUT_MS = 5000;

function documentLoadResponseTimeoutMs(configured: unknown): number {
  return typeof configured === 'number' &&
    Number.isSafeInteger(configured) &&
    configured >= 1 &&
    configured <= LOAD_QUORUM_TIMEOUT_MS_MAX
    ? configured
    : DEFAULT_DOCUMENT_LOAD_RESPONSE_TIMEOUT_MS;
}

/**
 * Bound on the number of parallel Helia `blockstore.get(cid)` fetches
 * issued by the quorum-bound load pre-fetch (`_sendLoadRequestAndSync`).
 *
 * A bound is needed because the served `changes` tree can be large
 * under an adversary-shaped response (the agreeing peer voted for the
 * expected frontier but stuffed the tree with many additional CIDs that
 * must still be retrieved to satisfy the post-sync coverage check).
 * Without a cap, the prefetch would issue every fetch in parallel and
 * each fetch holds a libp2p bitswap stream + buffers the retrieved
 * payload via `readUint8Iterable`; for very large responses this can
 * exhaust per-connection stream quotas and pressure memory. The cap is
 * chosen large enough to overlap WAN-latency-bound bitswap fetches and
 * keep the load fast (8 inflight is comfortably more than typical mesh
 * peer counts) but small enough to bound peak resource use on the
 * loader.
 */
const LOAD_PREFETCH_MAX_CONCURRENCY = 8;

/**
 * Module-private sentinel thrown by `_sendLoadRequestAndSync` when the
 * quorum frontier binding check fails on a single peer's load response
 * (either the responder omitted `tips` or the served `tips` hashed to a
 * value other than the agreed `winningHashHex`). Caught by the `load()`
 * loop, which records the failure against the responsible peer and
 * proceeds to the NEXT peer in the agreeing cohort.
 *
 * Previously `_sendLoadRequestAndSync` threw `LoadQuorumFailedError` on bind
 * mismatch and `load()` re-raised it, aborting the entire load. A
 * single malicious peer in the agreeing cohort could vote for the
 * majority hash (passing quorum) and then serve a mismatched full load
 * (failing the bind check), unilaterally preventing the loader from
 * trying any other honest agreeing peer.
 *
 * Public callers never see this type; `load()` catches it internally
 * and only escalates to `LoadQuorumFailedError(reason:
 * 'bind-check-failed-all-agreeing-peers')` once EVERY peer in the
 * narrowed cohort has bind-failed.
 *
 * The `advertisedHex` field carries the hash the responder's served
 * `tips` actually hashed to (or the sentinel `'(missing tips)'` when the
 * response omitted the `tips` field entirely) so the outer loop can
 * thread it into the final error's `agreeingPeerBindFailures` map.
 */
class _QuorumBindCheckFailedError extends Error {
  public readonly advertisedHex: string;
  constructor(advertisedHex: string, message: string) {
    super(message);
    this.name = '_QuorumBindCheckFailedError';
    this.advertisedHex = advertisedHex;
  }
}

const invitationBootstrapContinuationBrand = Symbol(
  'invitation-bootstrap-continuation-brand',
);

interface InvitationBootstrapContinuation {
  readonly [invitationBootstrapContinuationBrand]: true;
}

function createInvitationBootstrapContinuation(): InvitationBootstrapContinuation {
  return Object.freeze({
    [invitationBootstrapContinuationBrand]: true as const,
  });
}

class _LoadWriterVersionConflictError extends Error {
  constructor() {
    super('Writer authorization changed before load application');
    this.name = '_LoadWriterVersionConflictError';
  }
}

export class PeerborneDocument<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> {
  /**
   * CORE STATE ===============================================================
   */

  // Only store/cache the full automerge document.
  private _document: DocType;
  get document(): DocType {
    this._assertNoIncompleteBootstrapLoad();
    return this._document;
  }

  // Document readers ACL.
  private _readers;

  // Document writers ACL.
  private _writers;

  // Cached snapshot of `_writers.users()` for hot-path signature verification.
  // Document-scoped (not per-DAG-node): every signature check needs the current
  // trusted writer set, so a single lazy cache is sufficient. Invalidated by
  // bumping `_writerKeysVersion` whenever `_writers` is mutated via
  // `_mergeWriters` / `_publishPreparedWriterChange`. All ACL mutations must
  // go through those helpers. The version counter is what makes invalidation
  // race-safe: `_getWriterKeys` captures the version before awaiting and only
  // commits the result if the version is still current, so an in-flight fetch
  // that races with an invalidation cannot overwrite the new null state with
  // a stale list (which could otherwise admit signatures from a revoked writer).
  // Typed `ReadonlyArray` so an accidental mutation by an internal caller is
  // a type error rather than a silent cache corruption that would affect
  // later signature verification.
  private _cachedWriterKeys: ReadonlyArray<PublicKey> | null = null;
  private _writerKeysVersion = 0;
  // Counter of in-flight `_writers` mutations. Staged local publications keep
  // it nonzero from before publication through commit and handler delivery;
  // remote merges bracket their synchronous mutation with the same guard.
  // `_getWriterKeys` bypasses the cache throughout either window, so a
  // signature check cannot observe a cached pre-mutation list.
  private _writerMutationsInFlight = 0;
  // A staged writer delta has been prepared and is awaiting its publication
  // commit point. Normal inbound sync is serialized behind this interval by
  // `_mutationQueue`; `_mergeWriters` also rejects any accidental out-of-queue
  // interleaving so a published delta cannot fail its local stale-base commit.
  private _writerPublicationsInFlight = 0;
  // Reader removals use the same publish-before-commit boundary. Supported
  // inbound ACL merges own `_mutationQueue`; reject an accidental direct merge
  // while a detached reader delta is awaiting publication.
  private _readerPublicationsInFlight = 0;

  // List of document encryption keys. Lower index numbers mean more recent.
  // Since the document is created from change history, all keys are needed.
  private _keychain;

  // Controls which document-key epochs peers supply during onboarding/load.
  private _historyVisibility: HistoryVisibility = 'current_only';

  // Tracks the epoch at which this node was invited to the document.
  // Used by `since_invited` history visibility (`_keychainChangesForVisibility`)
  // to filter keychain history. Set by `handleBeeKEMWelcomeRequestData` when
  // this node receives a Welcome message from an inviting writer; remains
  // `undefined` for the founding member of a document (who has no
  // invitation epoch).
  private _invitationEpoch: Uint8Array | undefined;

  // Pending BeeKEM Welcomes parked while the recipient is not yet a reader.
  //
  // KNOWN RACE: the inviter publishes
  // the readers-ACL update over pubsub and sends the Welcome over a
  // direct libp2p stream. The Welcome can arrive before the ACL update
  // has been applied on the recipient; without buffering, the
  // `not-in-readers-acl` gate in `evaluateBeeKEMWelcome` would drop the
  // Welcome permanently because `_sendBeeKEMWelcome` is fire-and-forget
  // (no retry / no ack). Buffering closes the race: when a Welcome is
  // dropped solely because the local user is not yet a reader, we park
  // it here keyed by hex(welcomeEpochId), and re-evaluate buffered
  // Welcomes after every readers-ACL `merge` (`_drainPendingWelcomesUnlocked`).
  //
  // Bounding:
  //  - each canonical serialized body is capped at 1 MiB and the buffer
  //    retains at most 4 MiB total, so the 10 MiB shared-protocol request
  //    ceiling cannot be multiplied by the entry count;
  //  - `PENDING_WELCOMES_MAX_ENTRIES` (16) separately bounds bookkeeping;
  //    older entries are evicted in insertion order when either bound is
  //    reached;
  //  - `PENDING_WELCOMES_TTL_MS` (5 min): caps how long any Welcome
  //    sits unresolved. Entries past their TTL are discarded on the
  //    next drain attempt. Five minutes is well above the worst-case
  //    GossipSub mesh propagation we observe in `e2e/integration/`
  //    (~10s through a relay) while remaining short enough that stale
  //    Welcomes don't linger indefinitely after a legitimate
  //    re-invite.
  //
  // The key is the lower-case hex encoding of `welcomeEpochId` (a
  // `Uint8Array`), chosen so the buffer's identity matches the
  // canonical epoch identifier used elsewhere in the receive path and
  // so duplicate Welcomes (same epoch) coalesce automatically.
  private _pendingWelcomes = new PendingWelcomeBuffer();

  // Recipient-side ECIES (P-256 ECDH) key pair for opening BeeKEM Welcome
  // sealed payloads. The inviter sends `eciesSealed` -- the keychain delta
  // encrypted to this public key (see `_sendBeeKEMWelcome`); the recipient
  // opens it with the matching private key (see
  // `_evaluateAndApplyBeeKEMWelcome`). When `undefined`, sealed Welcomes
  // addressed to us cannot be opened and are dropped (the recipient needs a
  // fresh Welcome after installing its KEM key pair). The application is
  // responsible for plumbing in a stable KEM key pair via
  // `setKemKeyPair` and sharing the matching raw public key with inviters
  // out-of-band so they can pass it to `addReader`.
  private _kemKeyPair: CryptoKeyPair | undefined;

  // Cached raw SEC1-uncompressed bytes for `_kemKeyPair.publicKey`,
  // populated eagerly inside `setKemKeyPair` so the receive path
  // (`_evaluateAndApplyBeeKEMWelcome`) never has to await an `exportKey`
  // call -- and so a non-exportable public key surfaces as a clear
  // error at installation time rather than as a generic WebCrypto
  // exception inside the Welcome handler.
  private _kemPublicKeyRaw: Uint8Array | undefined;

  /**
   * Install the recipient-side ECDH (P-256) key pair used to open
   * incoming BeeKEM Welcome sealed payloads. The application is
   * responsible for persisting and re-supplying this key pair across
   * sessions; the matching raw public key (see
   * `getKemPublicKeyRaw`) must be communicated out-of-band to any
   * writer who will invite this user, so they can pass it to
   * `addReader(reader, readerKemPublicKey)`.
   *
   * Idempotent: calling with the same key pair more than once is
   * fine. Pass `undefined` to clear (subsequent Welcomes will be
   * dropped).
   *
   * Validation: the key pair MUST be an ECDH P-256 pair, and the
   * private key MUST have `'deriveBits'` in its key usages so
   * `eciesOpen` can perform the ECDH step. The public key MUST be
   * raw-exportable (the inviter-side flow ships those bytes as the
   * `welcomeRecipientKemPublicKey` field). Mismatches are rejected
   * here with a descriptive error rather than silently accepted and
   * surfaced as a generic WebCrypto failure later in the Welcome
   * receive path.
   *
   * Async because it eagerly exports the public key to raw bytes via
   * `crypto.subtle.exportKey` and caches them for the receive path.
   */
  public async setKemKeyPair(
    keyPair: CryptoKeyPair | undefined,
  ): Promise<void> {
    // Snapshot synchronously before queueing. A caller-owned CryptoKeyPair is
    // an ordinary mutable record even though its CryptoKey handles are not.
    const snapshot = keyPair && snapshotKemKeyPair(keyPair);
    return this._runStateMutation(() => this._setKemKeyPairUnlocked(snapshot));
  }

  private async _setKemKeyPairUnlocked(
    keyPair: CryptoKeyPair | undefined,
  ): Promise<void> {
    if (keyPair === undefined) {
      this._kemKeyPair = undefined;
      this._kemPublicKeyRaw = undefined;
      return;
    }

    // Algorithm/curve/usages validation + eager raw-export, kept in
    // a standalone helper so the validation surface can be unit-tested
    // without standing up the full document dependency graph.
    // Throws a clear, install-time error on misconfiguration.
    const rawPublic = await validateAndExportKemKeyPair(keyPair);

    this._kemKeyPair = keyPair;
    // Defensive copy: ensure the cached bytes are isolated from the
    // buffer returned by the helper so callers (and the helper's own
    // internal state) cannot mutate `_kemPublicKeyRaw` after the fact.
    this._kemPublicKeyRaw = new Uint8Array(rawPublic);
  }

  /**
   * Returns the raw SEC1-uncompressed bytes (65 bytes) of the
   * installed ECDH public key, or `undefined` if no key pair has been
   * set via `setKemKeyPair`. The bytes are what inviters pass to
   * `addReader(reader, readerKemPublicKey)`.
   *
   * The raw bytes are cached on `setKemKeyPair`, so this is a
   * synchronous lookup. A defensive copy of the cached `Uint8Array` is
   * returned so callers cannot accidentally mutate the document's
   * internal state (e.g. `raw[0] = ...`), which would otherwise cause
   * hard-to-debug Welcome drops/mismatches on the receive path.
   */
  public getKemPublicKeyRaw(): Uint8Array | undefined {
    return this._kemPublicKeyRaw && new Uint8Array(this._kemPublicKeyRaw);
  }

  /**
   * Create a signed public offer for an online, distinct-identity join.
   * The offer contains only public metadata and is safe to encode in a URL
   * fragment. The inviter must remain online until the recipient accepts it.
   */
  public async createInvitation(
    options: CreateInvitationOptions,
  ): Promise<InvitationOfferV1> {
    this._assertNoIncompleteBootstrapLoad();
    return this.swarm.createInvitationForDocument(this, options);
  }

  /** @internal Validate the deliberately narrow initial membership topology. */
  public async assertCanCreateInitialInvitation(): Promise<void> {
    this._assertNoIncompleteBootstrapLoad();
    this._assertInitialInvitationCapacityProfile();
    await this._ensureCurrentUserCanWrite();
    if (!this._createdLocally) {
      throw new Error(
        `Invitation creation for ${this.documentPath} is limited to the ` +
          'founder process that created the document',
      );
    }
    const [readers, writers] = await Promise.all([
      retryACLConflict(() => this._readers.users()),
      retryACLConflict(() => this._writers.users()),
    ]);
    if (writers.length !== 1) {
      throw new Error(
        `Invitation creation for ${this.documentPath} requires exactly one ` +
          'founder writer before onboarding',
      );
    }
    if (readers.length > 0) {
      throw new Error(
        `Invitation creation for ${this.documentPath} requires an empty ` +
          'reader slot; the initial release supports one active collaborator',
      );
    }
    assertInitialInvitationBeeKEMCapacity(
      this._beekem?.memberCount,
      false,
      this.documentPath,
    );
  }

  private _assertInitialInvitationCapacityProfile(): void {
    assertInitialInvitationCapacityProfile({
      crdtProvider: this._crdtProvider,
      aclProvider: this._aclProvider,
      keychainProvider: this._keychainProvider,
      changesSerializer: this._changesSerializer,
      syncMessageSerializer: this._syncMessageSerializer,
      authProvider: this._authProvider,
      privateKey: this._userKey,
      publicKey: this._userPublicKey,
    });
  }

  // BeeKEM ratchet-tree state for cryptographic reader revocation.
  //
  // `removeReader` blanks the removed reader's BeeKEM leaf, re-keys the
  // path, and broadcasts a `PathUpdateV2` over `beekemPathUpdateV2`.
  // Surviving readers feed the update into `processPathUpdate` and
  // re-derive the document encryption key from the fresh root secret
  // (see `derive-doc-key.ts`). The removed reader's leaf is blanked,
  // so they cannot recompute the root secret -- this closes the
  // revocation-latency gap of the previous "encrypt the new key under
  // the old key" rotation scheme.
  //
  // The tree is initialized in one of two ways:
  //
  //  1. **Founder**: the first `addReader` call prepares a detached tree
  //     seeded at leaf 0 with the local key pair from `setKemKeyPair`, then
  //     installs it at the staged reader-ACL publication boundary.
  //
  //  2. **Joiner**: a peer that receives an `eciesSealed` BeeKEM
  //     Welcome from an inviting writer calls `processWelcome` on a
  //     fresh `BeeKEM` instance, populating their leaf and the path
  //     keys from the inviter's tree state.
  //
  // The PathUpdateV2 receive handler MUST NOT initialize a fresh founder
  // tree on a peer that has not gone through either path: a
  // freshly-initialized tree would produce a different root secret
  // than the writer's, and the epoch-ID mismatch gate would drop the
  // PathUpdateV2 anyway. Surface that as a clean drop-with-warning; recovery
  // requires a valid Welcome or another explicit key-recovery path.
  private _beekem: BeeKEM | null = null;
  // Local membership changes, ACL-bearing remote sync, and invitation
  // bootstrap construction/application share one queue. This keeps the ACL
  // topology, BeeKEM tree, keychain, and signed bootstrap attestation coherent.
  // One FIFO freezes every state writer while an invitation sizes and builds
  // its bootstrap. Internal helpers called from an admitted operation remain
  // unlocked to avoid reentrant waits on the same queue.
  private _mutationQueue = new InvitationMembershipQueue();
  // `true` iff `_beekem` was installed by founder onboarding or a verified
  // `processWelcome`. Distinguishes a legitimate local BeeKEM state
  // from "we have never received a Welcome and we are not the
  // founder", which is the gate `handleBeeKEMPathUpdateRequestData`
  // uses to drop PathUpdates that arrive before bootstrap.
  private _beekemInitialized = false;

  // pubkey (serialized) -> BeeKEM leaf index, populated by `addReader`
  // (writer side) so `removeReader` can look up the leaf to blank.
  // **Fast-path cache only**: `removeReader` falls back to a BeeKEM
  // tree scan (`BeeKEM.findLeafByPublicKey`) on cache miss, so a cache
  // wipe (in-process restart, different replica) does not block
  // revocation as long as the BeeKEM tree itself is initialized and
  // the reader's KEM public key is still known (see
  // `_readerKemPublicKeys`).
  // Joiner-side population requires Welcome plumbing that is out of
  // scope here and tracked alongside the BeeKEM Welcome work.
  private _readerLeafIndices = new Map<string, number>();

  // pubkey (serialized identity) -> raw SEC1-uncompressed P-256 ECDH
  // public key bytes (the reader's KEM public key as passed to
  // `addReader`). Used by `removeReader` as the lookup key when the
  // `_readerLeafIndices` fast-path cache misses: we know the
  // identity but need the KEM key to query the BeeKEM tree via
  // `BeeKEM.findLeafByPublicKey`. Persistence is not implemented, so
  // on restart this map is empty and `removeReader`
  // surfaces the gap with a clear error.
  private _readerKemPublicKeys = new Map<string, Uint8Array>();

  // BeeKEM leaf node index -> the `BeeKEMWelcomeV2` produced when that
  // leaf was first registered via `_prepareBeeKEMReaderRegistration`. Used by
  // `addReader` to re-emit a Welcome when a previous invitation was
  // dropped: re-invoking `addReader(reader, kemPub)` for an existing
  // reader is now a re-send, not a silent no-op.
  //
  // Cleared when the leaf is blanked via `removeReader`, so a
  // recipient that was revoked cannot later re-derive the original
  // Welcome (which would re-deliver the keychain delta at the leaf's
  // original epoch).
  //
  // In-memory only; on writer restart this map is empty and a
  // re-emit attempt will see the cache miss and the no-op early-out
  // in `_prepareBeeKEMReaderRegistration`. Recipients in that state need a new
  // recipient-bound Welcome or another explicit recovery path; a normal load
  // response cannot bootstrap a peer that lacks the current document key.
  private _beekemWelcomeByLeaf = new Map<number, BeeKEMWelcomeV2>();

  /**
   * Set the history visibility for this document.
   * This filters distributed epoch keys; it does not redact retained CRDT
   * operations or provide a historical-content confidentiality boundary.
   */
  public set historyVisibility(value: HistoryVisibility) {
    this._historyVisibility = value;
  }

  public get historyVisibility(): HistoryVisibility {
    return this._historyVisibility;
  }

  /**
   * /CORE STATE ==============================================================
   */

  // Last sync message (for populating load requests).
  private _lastSyncMessage?: CRDTSyncMessage<ChangesType, PublicKey>;

  // Set of already-merged change blocks.
  private _hashes = new Set<string>();

  // Fail-closed bootstrap admission state. A bootstrap load can mutate
  // ACL/keychain state before a later CRDT/provider operation throws, without
  // necessarily reaching `_hashes`, `_lastSyncMessage`, or `_latestSnapshot`.
  // `pending` is deliberately durable after any failed application attempt;
  // `complete` is set only after the entire response passes its post-sync
  // checks. `poisoned` is a separate terminal state for failures, such as an
  // opaque ACL commit exception, whose partial effects cannot be ruled out;
  // bootstrap finalization must never clear it. These states prevent a partial
  // ACL mutation from manufacturing authority for a retry or from being
  // consumed by any other public state transition. There is no safe in-place
  // recovery because the pre-failure state is not retained.
  private _bootstrapLoadApplicationState:
    | 'pristine'
    | 'pending'
    | 'complete'
    | 'poisoned' = 'pristine';

  // Monotonic generation for bootstrap state transitions. Response handlers
  // capture this before assembling a payload and require it to remain stable
  // before sending, so a pending -> complete transition cannot masquerade as
  // the same healthy state they admitted against.
  private _bootstrapLoadApplicationRevision = 0;

  // Automatic compaction is unsafe while a bootstrap response is only
  // partially applied. Remember the request and run it during successful
  // bootstrap finalization instead.
  private _bootstrapCompactionDeferred = false;

  // Set of CIDs that have been seen as a `children` key in any sync tree we
  // have processed (locally created or remotely received) -- i.e. every CID
  // some node references as a parent / cross-link target. These are
  // *referenced ancestors*: by definition they are NOT heads of the local
  // DAG, because at least one node points to them as a predecessor.
  //
  // `_currentFrontier()` returns `_hashes \ _referencedAncestors` -- the set
  // of CIDs that no node we've ever seen has referenced. That is the actual
  // "frontier" / "heads" of the merged-changes DAG, which is what the
  // initial-load quorum tip-set advertisement is supposed to attest to.
  //
  // Critically, this set converges across honest peers: two peers with the
  // same logical state but different sync histories (e.g. one loaded from a
  // snapshot, the other has been merging changes since founding) will have
  // *different* `_hashes` cardinality but the same head set, hence the same
  // `_hashes \ _referencedAncestors`. Drawing the quorum probe from
  // `_hashes` alone (the prior buggy implementation) would have made the
  // probe pessimistically diverge on irrelevant sync history.
  //
  // Populated in:
  //   - `_makeChange()`: every newly-attached `changeNode.children` key
  //     is recorded -- the new change references those parents.
  //   - `_syncDocumentChanges()`: every received sync tree is walked once
  //     and its `children` keys are recorded -- the receiver now knows the
  //     same parent relationships the sender did.
  //
  // Snapshot boundaries: when a snapshot is applied, `lastChangeNodeCID` is
  // added to `_hashes` as a sentinel for dedup, but its ancestor chain is
  // pruned -- those ancestors are not added to `_referencedAncestors`,
  // which is correct: the snapshot boundary IS the local "oldest" head
  // from the loader's view of the DAG.
  private _referencedAncestors = new Set<string>();

  // Bounded list of recently-known change CIDs paired with their node kind.
  // Used by `_makeChange()` to attach Merkle-CRDT cross-links (paper §VI.B.e)
  // in addition to the primary parent link. Cross-links improve consistency
  // and availability when peers have partial views of the DAG: a peer that
  // missed an earlier message can still discover and fetch the corresponding
  // block via a later change that references it.
  //
  // Populated by both local changes (in `_makeChange`) and remote-applied
  // changes (in `_syncDocumentChanges`), since cross-linking to a freshly-
  // received remote tip helps third peers that haven't yet received it.
  //
  // Kept small (`MAX_RECENT_TIPS`) to bound per-message overhead. Insertion-
  // ordered so the oldest entry is at index 0 and the newest at the end;
  // eviction uses `Array.prototype.shift()` (O(n) on n=`MAX_RECENT_TIPS`,
  // which is a small constant -- effectively O(1) in practice).
  private _recentTips: RecentTip[] = [];

  // Compaction state.
  private _compactionConfig: CompactionConfig;
  private _latestSnapshot?: CRDTSnapshotNode<ChangesType, PublicKey>;
  private _changesSinceSnapshot = 0;
  private _compactionInProgress = false;
  private _snapshotUnsupported = false;
  // Counts only document-kind changes (excludes ACL reader/writer changes).
  // Used by _maybeCompact() for the minChangesBeforeSnapshot threshold.
  // Incremented for both local changes (in _makeChange) and remote changes
  // (in _syncDocumentChanges). Compaction triggers from both paths, so relay-only
  // nodes that never make local changes will still compact via remote change processing.
  private _documentChangeCount = 0;

  // Handler for listening for sync messages on the document topic. Is `undefined` until
  // the document is `.open()`-ed.
  private _pubsubHandler: EventHandler<CustomEvent<Message>> | undefined;

  // Whether this instance has successfully subscribed to the pubsub topic.
  // Used in close() to avoid unsubscribing when open() failed before subscribing,
  // which would break other instances listening on the same topic.
  private _subscribed = false;

  // Exact validator installed by this instance. Cleanup compares by identity
  // so a stale/failed document cannot delete another instance's validator.
  private _topicValidator: TopicValidatorFn | undefined;

  // Set only after a signed invitation bootstrap has been fully verified and
  // applied. The following open() activates handlers without falling through
  // the ambiguous network-load/new-document branch.
  private _invitationBootstrapReady = false;

  // Per-acceptance capability for the only internal path allowed to continue
  // while bootstrap state is pending. Exact identity and prompt clearing keep
  // it from becoming a reusable bypass of the public fail-closed boundary.
  private _activeInvitationBootstrapContinuation:
    | InvitationBootstrapContinuation
    | undefined;

  // Explicit creation provenance for BeeKEM founder initialization. Change
  // count is not a valid proxy because open() replicates the founder-writer
  // ACL before the first invitation is created.
  private _createdLocally = false;

  // Cached pubsub topic string. Initialized in constructor via _computeTopic()
  // so that callers that invoke _makeChange() before open() (e.g. via load())
  // publish to a valid topic. open() recomputes this with the configured prefix.
  private _topic: string;

  // Transaction state for batching multiple changes atomically.
  private _pendingChangeFns: ChangeFnType[] = [];
  private _inTransaction = false;
  private _committing = false;

  // Handlers registered by users of `PeerborneDocument` that fire on remote changes.
  private _remoteHandlers: {
    [id: string]: PeerborneDocumentChangeHandler<DocType, PublicKey>;
  } = {};

  // Remote state is committed before its observer audience is resolved. Keep
  // conflicted notifications on a separate FIFO so waiting for an ACL
  // operation never retains the document mutation queue or prevents frontier
  // refresh. Later notifications join the same FIFO to preserve event order.
  private _remoteUpdateNotificationTail?: Promise<void>;

  // A bootstrap response can apply several remote changes before its
  // completeness checks finish. Keep those notifications private until the
  // response is known to be complete so application callbacks can never
  // observe partially-applied bootstrap state.
  private _pendingBootstrapRemoteUpdateHashes = new Set<string>();

  // Handlers registered by users of `PeerborneDocument` that fire on local changes.
  private _localHandlers: {
    [id: string]: PeerborneDocumentChangeHandler<DocType, PublicKey>;
  } = {};

  public get libp2p(): Libp2p {
    return this.swarm.heliaNode.libp2p;
  }

  private heliaFs: UnixFS;

  constructor(
    /**
     * Peerborne swarm that this document belongs to.
     */
    public readonly swarm: Peerborne<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,

    /**
     * Path of the document.
     */
    public readonly documentPath: string,

    /**
     * Private key identifying the current user.
     */
    private readonly _userKey: PrivateKey,

    /**
     * Private key identifying the current user.
     */
    private readonly _userPublicKey: PublicKey,

    /**
     * CRDTProvider handles reading/writing CRDT document data and metadata.
     */
    private readonly _crdtProvider: CRDTProvider<
      DocType,
      ChangesType,
      ChangeFnType
    >,

    /**
     * AuthProvider handles signing/verification and encryption/decryption.
     */
    private readonly _authProvider: AuthProvider<
      PrivateKey,
      PublicKey,
      DocumentKey
    >,

    /**
     * ACLProvider handles read/write ACL operations.
     */
    private readonly _aclProvider: ACLProvider<ChangesType, PublicKey>,

    /**
     * KeychainProvider handles read/write ACL operations.
     */
    private readonly _keychainProvider: KeychainProvider<
      ChangesType,
      DocumentKey
    >,

    /**
     * ChangesSerializer is responsible for serializing/deserializing CRDTChangeBlocks.
     */
    private readonly _changesSerializer: ChangesSerializer<ChangesType>,

    /**
     * SyncMessageSerializer is responsible for serializing/deserializing CRDTSyncMessages.
     */
    private readonly _syncMessageSerializer: SyncMessageSerializer<ChangesType, PublicKey>,

    /**
     * LoadMessageSerializer is responsible for serializing/deserializing CRDTLoadMessages.
     */
    private readonly _loadMessageSerializer: LoadMessageSerializer,
  ) {
    this.heliaFs = unixfs(this.swarm.heliaNode);

    this._document = this._crdtProvider.newDocument();
    this._readers = this._aclProvider.initialize();
    this._writers = this._aclProvider.initialize();
    this._keychain = this._keychainProvider.initialize();
    this._compactionConfig = mergeCompactionConfig(
      this.swarm.config?.compaction,
    );

    // Provide a valid default topic so that _makeChange() works even before
    // open() is called (e.g. when load() triggers a change). open() will
    // recompute this with the configured prefix.
    this._topic = this._computeTopic();
  }

  // Helpers ------------------------------------------------------------------

  /**
   * Computes the pubsub topic for this document by applying the configured
   * prefix to the document path. Called once in open() to populate the
   * cached _topic field.
   */
  private _computeTopic(): string {
    const prefix = this.swarm.config?.pubsubDocumentPrefix;
    return prefix !== undefined
      ? documentTopic(this.documentPath, prefix)
      : documentTopic(this.documentPath);
  }

  private async _shuffledPeers() {
    const peers = this.swarm.heliaNode.libp2p
      .getConnections()
      ?.map((x) => x.remoteAddr);
    if (peers.length === 0) {
      return peers;
    }

    // Shuffle peer array.
    const shuffledPeers = [...peers];
    shuffleArray(shuffledPeers);
    return shuffledPeers;
  }

  private _assertDocumentStateNotPoisoned(): void {
    if (this._bootstrapLoadApplicationState === 'poisoned') {
      throw new Error(
        `Document ${this.documentPath} has indeterminate authorization state; ` +
          `discard this document instance before continuing`,
      );
    }
  }

  private _assertNoIncompleteBootstrapLoad(): void {
    this._assertDocumentStateNotPoisoned();
    if (this._activeInvitationBootstrapContinuation !== undefined) {
      throw new Error(
        `Invitation bootstrap validation for ${this.documentPath} is in progress`,
      );
    }
    if (this._bootstrapLoadApplicationState === 'pending') {
      throw new Error(
        `Document load for ${this.documentPath} failed after state application began; ` +
          `discard this document instance before continuing`,
      );
    }
  }

  private _markBootstrapStateApplicationPending(): void {
    if (this._bootstrapLoadApplicationState === 'poisoned') return;
    this._bootstrapLoadApplicationState = 'pending';
    this._bootstrapLoadApplicationRevision++;
  }

  private _markDocumentStatePoisoned(): void {
    if (this._bootstrapLoadApplicationState === 'poisoned') return;
    this._bootstrapLoadApplicationState = 'poisoned';
    this._bootstrapLoadApplicationRevision++;
  }

  private _isStateApplicationBlocked(): boolean {
    return (
      this._bootstrapLoadApplicationState === 'pending' ||
      this._bootstrapLoadApplicationState === 'poisoned'
    );
  }

  private _markBootstrapStateApplicationComplete(): void {
    if (this._bootstrapLoadApplicationState !== 'pending') {
      throw new Error(
        `Bootstrap completion for ${this.documentPath} requires pending state`,
      );
    }
    this._bootstrapLoadApplicationState = 'complete';
    this._bootstrapLoadApplicationRevision++;
  }

  private _captureBootstrapResponseRevision(): number {
    this._assertNoIncompleteBootstrapLoad();
    return this._bootstrapLoadApplicationRevision;
  }

  private _assertBootstrapResponseRevision(revision: number): void {
    this._assertNoIncompleteBootstrapLoad();
    if (revision !== this._bootstrapLoadApplicationRevision) {
      throw new Error(
        `Document state changed while constructing a response for ${this.documentPath}`,
      );
    }
  }

  private _isActiveInvitationBootstrapContinuation(
    continuation?: InvitationBootstrapContinuation,
  ): boolean {
    return (
      continuation !== undefined &&
      continuation === this._activeInvitationBootstrapContinuation
    );
  }

  /** Serialize a public state transition and recheck bootstrap integrity. */
  private _runStateMutation<T>(operation: () => Promise<T>): Promise<T> {
    return this._mutationQueue.run(() => {
      this._assertNoIncompleteBootstrapLoad();
      return operation();
    });
  }

  private _runInvitationBootstrapStateApplication<T>(
    operation: (
      beginStateApplication: () => void,
      continuation: InvitationBootstrapContinuation,
    ) => Promise<T>,
    assertCanApply?: () => void,
  ): Promise<T> {
    return this._mutationQueue.run(async () => {
      if (
        this._bootstrapLoadApplicationState !== 'pristine' ||
        this._hashes.size > 0 ||
        this._lastSyncMessage !== undefined ||
        this._latestSnapshot !== undefined ||
        this._subscribed ||
        this._createdLocally
      ) {
        throw new Error(
          `Invitation bootstrap for ${this.documentPath} requires a pristine document instance`,
        );
      }
      assertCanApply?.();
      const invitationKeychain = this._keychain;
      const existingKeys = await invitationKeychain.keys();
      assertCanApply?.();
      if (
        this._keychain !== invitationKeychain ||
        !Array.isArray(existingKeys) ||
        existingKeys.length !== 0
      ) {
        throw new Error(
          'Invitation bootstrap requires a pristine, empty keychain',
        );
      }
      let stateApplicationStarted = false;
      const beginStateApplication = (): void => {
        if (stateApplicationStarted) return;
        stateApplicationStarted = true;
        // Reserve the instance immediately before the first live write. Any
        // later failure may have partially changed state and therefore
        // remains fail-closed, while purely detached validation can reject a
        // malformed invitation without poisoning this fresh instance.
        this._markBootstrapStateApplicationPending();
      };
      const continuation = createInvitationBootstrapContinuation();
      this._activeInvitationBootstrapContinuation = continuation;
      try {
        return await operation(beginStateApplication, continuation);
      } finally {
        if (this._activeInvitationBootstrapContinuation === continuation) {
          this._activeInvitationBootstrapContinuation = undefined;
        }
      }
    });
  }

  /** Finalize a verified bootstrap while holding `_mutationQueue`. */
  private async _completeBootstrapStateApplicationUnlocked(
    beforeComplete?: () => Promise<void>,
    assertStillActive?: () => void,
  ): Promise<void> {
    if (this._bootstrapLoadApplicationState !== 'pending') {
      throw new Error(
        `Bootstrap finalization for ${this.documentPath} requires pending state`,
      );
    }
    if (this._pendingWelcomes.size > 0) {
      await this._drainPendingWelcomesUnlocked(true);
    }
    if (this._bootstrapCompactionDeferred) {
      this._bootstrapCompactionDeferred = false;
      await this._maybeCompact();
    }
    await beforeComplete?.();
    const deferredNotification =
      await this._prepareDeferredBootstrapRemoteUpdateNotification();
    // Preparing the notification can await ACL providers. Recheck the caller's
    // deadline immediately before publishing completion; after this point the
    // notification dispatch is deliberately synchronous and cannot escape as
    // late background work after a timed-out invitation has been rejected.
    assertStillActive?.();
    this._markBootstrapStateApplicationComplete();
    if (deferredNotification) {
      this._pendingBootstrapRemoteUpdateHashes.clear();
      this._dispatchRemoteUpdateHandlers(deferredNotification);
    }
  }

  private async _decryptBlock(
    blockKeyID: Uint8Array,
    nonce: Uint8Array,
    data: Uint8Array,
    getKey: (keyID: Uint8Array) => DocumentKey | undefined = (keyID) =>
      this._keychain.getKey(keyID),
  ) {
    try {
      const key = getKey(blockKeyID);
      if (key) {
        return this._authProvider.decrypt(data, key, nonce);
      } else {
        console.warn('Unable to find a document key for encrypted data');
      }
    } catch {
      console.warn('Failed to decrypt encrypted document data');
    }
  }

  private async _readBlock(
    hash: CID,
    options?: MissingBlockFetchOptions,
  ): Promise<Uint8Array> {
    // Helia v6 / interface-blockstore v6 changed `Blockstore#get(cid)` to
    // return an `AwaitGenerator<Uint8Array>` (a generator of byte chunks)
    // rather than a single `Uint8Array`. Consume the generator into a
    // contiguous buffer here before slicing the encryption header off.
    throwIfLoadAborted(options?.signal);
    const signal = options?.signal;
    const maxBlockBytes = options?.maxBlockBytes;
    const consumeBytes = options?.consumeBytes;
    const rawBlock = this.swarm.heliaNode.blockstore.get(
      hash,
      signal ? { signal } : undefined,
    );
    const boundedBlock =
      maxBlockBytes !== undefined || consumeBytes !== undefined
        ? (async function* () {
            let byteLength = 0;
            let chunkCount = 0;
            for await (const chunk of rawBlock) {
              throwIfLoadAborted(signal);
              chunkCount += 1;
              if (chunkCount > MAX_BOUNDED_BLOCK_CHUNKS) {
                throw new _LoadFetchLimitExceededError(
                  'Block stream chunk budget exceeded',
                );
              }
              const nextByteLength = byteLength + chunk.byteLength;
              if (
                !Number.isSafeInteger(nextByteLength) ||
                (maxBlockBytes !== undefined && nextByteLength > maxBlockBytes)
              ) {
                throw new _LoadFetchLimitExceededError(
                  'Block stream byte budget exceeded',
                );
              }
              consumeBytes?.(chunk.byteLength);
              byteLength = nextByteLength;
              yield chunk;
            }
          })()
        : rawBlock;
    const block = await awaitLoadWork(readUint8Iterable(boundedBlock), signal);
    throwIfLoadAborted(options?.signal);
    return block;
  }

  private async _decodeBlock(
    hash: CID,
    block: Uint8Array,
    signal?: AbortSignal,
    getKey?: (keyID: Uint8Array) => DocumentKey | undefined,
  ): Promise<ChangesType> {
    const blockKeyID = block.slice(0, this._keychainProvider.keyIDLength);
    const blockNonce = block.slice(
      this._keychainProvider.keyIDLength,
      this._keychainProvider.keyIDLength + this._authProvider.nonceBytes,
    );
    const blockData = block.slice(
      this._keychainProvider.keyIDLength + this._authProvider.nonceBytes,
    );
    const content = await awaitLoadWork(
      this._decryptBlock(blockKeyID, blockNonce, blockData, getKey),
      signal,
    );
    throwIfLoadAborted(signal);
    if (!content) {
      throw new Error(`Failed to decrypt block (CID: ${hash})`);
    }
    const changes = this._changesSerializer.deserializeChanges(content);
    throwIfLoadAborted(signal);
    return changes;
  }

  private async _getBlock(
    hash: CID,
    options?: MissingBlockFetchOptions,
    getKey?: (keyID: Uint8Array) => DocumentKey | undefined,
  ): Promise<ChangesType> {
    return this._decodeBlock(
      hash,
      await this._readBlock(hash, options),
      options?.signal,
      getKey,
    );
  }

  private async _putBlock(block: ChangesType): Promise<string> {
    const [documentKeyID, documentKey] = await this._keychain.current();
    if (!documentKey) {
      throw new Error(`Document ${this.documentPath} has an empty keychain!`);
    }
    const content = this._changesSerializer.serializeChanges(block);
    const { nonce, data } = await this._authProvider.encrypt(
      content,
      documentKey,
    );
    if (!nonce) {
      throw new Error(`Failed to encrypt change block! Nonce cannot be empty`);
    }
    const blockData = concatUint8Arrays(documentKeyID, nonce, data);
    const newFileResult = await this.heliaFs.addBytes(blockData);
    return newFileResult.toString();
  }

  /**
   * Walk the remote sync tree and return entries that are new relative to
   * `localHashes` / `localRootId`. Delegates to the pure `mergeRemoteSyncTree`
   * helper, which also performs per-message dedup so a cross-link CID that
   * coincides with an inline ancestor in the same sync tree is not applied
   * (or fetched + applied) twice -- see paper §VI.B.e.
   */
  private async _mergeSyncTree(
    remoteRootId: string | undefined,
    remoteRoot: CRDTChangeNode<ChangesType>,

    localRootId: string | undefined,
    localHashes: Set<string>,
  ): Promise<[string, CRDTChangeNodeKind, ChangesType | undefined][]> {
    return mergeRemoteSyncTree<ChangesType>(
      remoteRootId,
      remoteRoot,
      localRootId,
      localHashes,
    );
  }

  private _dispatchRemoteUpdateHandlers(
    notification: RemoteUpdateNotification<DocType, PublicKey>,
  ): void {
    for (const handler of notification.handlers) {
      try {
        void Promise.resolve(
          handler(
            notification.document,
            [...notification.readers],
            [...notification.writers],
            [...notification.hashes],
          ) as void | Promise<void>,
        ).catch(() => {
          console.error(
            `Remote update handler failed for ${this.documentPath}`,
          );
        });
      } catch {
        console.error(`Remote update handler failed for ${this.documentPath}`);
      }
    }
  }

  private async _prepareRemoteUpdateNotification(
    hashes: string[],
    handlers = Object.values(this._remoteHandlers),
  ): Promise<RemoteUpdateNotification<DocType, PublicKey>> {
    if (handlers.length === 0) {
      return {
        handlers,
        document: this._document,
        readers: [],
        writers: [],
        hashes,
      };
    }
    const [readers, writers] = await Promise.all([
      this._readers.users(),
      this._writers.users(),
    ]);
    // ACL implementations may reject overlapping operations, so keep at most
    // one read against the reader ACL in flight.
    const filteredWriters: PublicKey[] = [];
    for (const writer of writers) {
      if ((await this._readers.check(writer)) !== true) {
        filteredWriters.push(writer);
      }
    }
    return {
      handlers,
      document: this._document,
      readers: [...readers, ...filteredWriters],
      writers: [...writers],
      hashes: [...hashes],
    };
  }

  private _appendRemoteUpdateNotificationTask(
    task: () => void | Promise<void>,
  ): void {
    const previous = this._remoteUpdateNotificationTail ?? Promise.resolve();
    let queued!: Promise<void>;
    queued = previous
      .then(task)
      .catch(() => {
        console.error(
          `Failed to prepare remote update notification for ${this.documentPath}`,
        );
      })
      .finally(() => {
        if (this._remoteUpdateNotificationTail === queued) {
          this._remoteUpdateNotificationTail = undefined;
        }
      });
    this._remoteUpdateNotificationTail = queued;
  }

  private _enqueueRemoteUpdateNotification(
    hashes: string[],
    handlers: PeerborneDocumentChangeHandler<DocType, PublicKey>[],
    initialConflict?: ACLOperationInProgressError,
  ): void {
    const capturedHashes = [...hashes];
    const capturedHandlers = [...handlers];
    this._appendRemoteUpdateNotificationTask(async () => {
      let conflict = initialConflict;
      for (;;) {
        if (conflict) {
          await conflict.waitForSettlement();
          conflict = undefined;
        }
        try {
          await this._mutationQueue.run(async () => {
            this._assertNoIncompleteBootstrapLoad();
            const notification = await this._prepareRemoteUpdateNotification(
              capturedHashes,
              capturedHandlers,
            );
            this._dispatchRemoteUpdateHandlers(notification);
          });
          return;
        } catch (error) {
          if (!(error instanceof ACLOperationInProgressError)) throw error;
          conflict = error;
        }
      }
    });
  }

  private async _fireRemoteUpdateHandlers(hashes: string[]): Promise<void> {
    const handlers = Object.values(this._remoteHandlers);
    if (handlers.length === 0) return;
    if (this._remoteUpdateNotificationTail) {
      this._enqueueRemoteUpdateNotification(hashes, handlers);
      return;
    }
    try {
      const notification = await this._prepareRemoteUpdateNotification(
        hashes,
        handlers,
      );
      this._dispatchRemoteUpdateHandlers(notification);
    } catch (error) {
      if (error instanceof ACLOperationInProgressError) {
        this._enqueueRemoteUpdateNotification(hashes, handlers, error);
        return;
      }
      console.error(
        `Failed to prepare remote update notification for ${this.documentPath}`,
      );
    }
  }

  private async _fireOrDeferRemoteUpdateHandlers(hashes: string[]) {
    if (this._bootstrapLoadApplicationState === 'poisoned') {
      this._pendingBootstrapRemoteUpdateHashes.clear();
      return;
    }
    if (this._bootstrapLoadApplicationState === 'pending') {
      for (const hash of hashes) {
        this._pendingBootstrapRemoteUpdateHashes.add(hash);
      }
      return;
    }
    await this._fireRemoteUpdateHandlers(hashes);
  }

  private async _prepareDeferredBootstrapRemoteUpdateNotification(): Promise<
    RemoteUpdateNotification<DocType, PublicKey> | undefined
  > {
    if (this._pendingBootstrapRemoteUpdateHashes.size === 0) return undefined;
    return this._prepareRemoteUpdateNotification([
      ...this._pendingBootstrapRemoteUpdateHashes,
    ]);
  }

  private async _fireLocalUpdateHandlers(
    hashes: string[],
    postPublishOperation?: string,
  ) {
    for (const handler of Object.values(this._localHandlers)) {
      const result = (handler as (
        current: DocType,
        readers: PublicKey[],
        writers: PublicKey[],
        hashes: string[],
      ) => unknown)(
        this._document,
        await this.getReaders(),
        await this.getWriters(),
        hashes,
      );
      if (result !== undefined) {
        void Promise.resolve(result).catch(() => {
          this._reportLocalUpdateHandlerFailure(
            postPublishOperation,
            true,
          );
        });
      }
    }
  }

  private _reportLocalUpdateHandlerFailure(
    postPublishOperation?: string,
    asynchronous = false,
  ): void {
    if (postPublishOperation) {
      console.error(
        `[${this.documentPath}] ${postPublishOperation}: a local update ` +
          `handler failed after the ACL change was published and committed. ` +
          `The handler failure is not a retryable ACL publication failure.`,
      );
      return;
    }
    if (asynchronous) {
      console.error(
        `[${this.documentPath}] an asynchronous local update handler failed ` +
          'after the change was published.',
      );
    }
  }

  private _createSyncMessage(context: SyncMessageContext): CRDTSyncMessage<ChangesType, PublicKey> {
    const message: CRDTSyncMessage<ChangesType, PublicKey> = {
      ...(this._lastSyncMessage || {
        documentId: this.documentPath,
      }),
      signatureContext: context,
    };
    return message;
  }

  /**
   * Returns this peer's structural local-DAG frontier as a plain
   * string[] of CIDs -- the heads of EVERYTHING this peer has seen.
   *
   * NOTE: this is NOT the value advertised in a `tipAdvertiseV1` probe
   * and NOT the value the responder commits to on a v3 load response.
   * Both of those use `_servedFrontier()` instead -- the heads of the
   * change tree this peer can actually ship in a single load round.
   * See `_servedFrontier()`'s docstring for why the two differ (short
   * version: a load response only carries the tree rooted at
   * `_lastSyncMessage.changeId`, so concurrent local heads that aren't
   * cross-linked into that tree don't appear in what's served).
   *
   * `_currentFrontier()` is retained for callers that need the
   * structural truth of "what heads do I have locally?" rather than
   * "what would I advertise / serve?":
   *
   *   - `_makeChange()` cross-link selection (so a new local change
   *     can reference concurrent remote heads that landed since the
   *     last cached sync message).
   *   - Diagnostics / introspection paths.
   *
   * The frontier is the set of heads of the local merged-changes DAG:
   * CIDs that this peer has seen but that no other change references
   * as a parent or cross-link target. Computed as `_hashes \
   * _referencedAncestors`. See the `_referencedAncestors` field
   * docstring for why this matters: it is the part of the local DAG
   * that converges across honest peers regardless of differing sync
   * histories or pruning levels.
   *
   * Edge cases:
   *   - Empty DAG (founding member, brand-new document): `_hashes` is
   *     empty, the returned frontier is `[]`.
   *   - Just-loaded from snapshot: `_hashes` holds the snapshot
   *     boundary CID (and any post-snapshot changes). The boundary CID
   *     is NOT in `_referencedAncestors`, so it correctly appears as a
   *     head.
   *   - Pruned ancestors: irrelevant. Pruning removes CIDs from the
   *     in-memory change tree but leaves them in `_hashes` for dedup;
   *     they were already in `_referencedAncestors`, so they remain
   *     marked as non-heads.
   *
   * Returns a fresh array so callers can't mutate internal state;
   * `tipsHash` sorts independently, so we don't sort here.
   *
   * @internal
   */
  private _currentFrontier(): string[] {
    const out: string[] = [];
    for (const cid of this._hashes) {
      if (!this._referencedAncestors.has(cid)) {
        out.push(cid);
      }
    }
    return out;
  }

  /**
   * Returns the frontier this peer would *advertise as part of a load
   * response* -- the heads of the change tree this peer can actually ship
   * in a single `documentLoadV3` / `snapshotLoadV3` round.
   *
   * # Why this is NOT the same as `_currentFrontier()`
   *
   * `_currentFrontier()` returns the heads of the local DAG (`_hashes \
   * _referencedAncestors`) -- the structural truth of EVERYTHING this peer
   * has seen. That set is the right answer for "what is the logical state
   * of my local document?", but it is the WRONG answer for "what hash
   * should I advertise in a `tipAdvertiseV1` probe?".
   *
   * A load response only carries ONE change tree (rooted at
   * `_lastSyncMessage.changeId`), plus optionally `_latestSnapshot`.
   * `_lastSyncMessage` is refreshed by `_makeChange()` (its tree is
   * rooted at *this peer's* last locally-produced change) AND by
   * `_syncDocumentChanges()` (when an incoming remote tree subsumes the
   * cached root, including on relay peers that never make local changes;
   * see `_refreshLastSyncMessageFromSync()`). When the
   * incoming root is concurrent with the cached root, the cache is left
   * alone so served-frontier coverage cannot shrink; the next local
   * change re-bundles concurrent heads via cross-links from
   * `_recentTips` (`selectCrossLinks`).
   *
   * So when a peer has multiple concurrent heads (e.g. its own last local
   * change H1 plus remotely-applied changes H2, H3 that aren't yet
   * cross-linked from any local change), `_currentFrontier()` returns
   * `{H1, H2, H3}` but the load response only contains H1's subtree.
   * That creates an inconsistency: the tip-advertise probe would hash
   * `{H1, H2, H3}` and win the quorum vote, but the served payload's
   * structural frontier (`computeServedFrontier(...)` on the loader side)
   * hashes only `{H1}`, causing the loader's bind check to reject the
   * honest peer.
   *
   * # What this returns
   *
   * The heads of the served payload, computed via `computeServedFrontier`
   * over EXACTLY the same inputs the load response will carry:
   *   - `_lastSyncMessage?.changeId` -- root CID of the served tree (if any);
   *   - `_lastSyncMessage?.changes` -- the served tree itself (if any);
   *   - `_latestSnapshot?.lastChangeNodeCID` -- snapshot boundary CID (if any).
   *
   * This mirrors the loader's `_sendLoadRequestAndSync` binding check:
   * both sides hash the structurally-derived served frontier, so an
   * honest responder advertises a hash the loader can reproduce from the
   * payload it received. Two honest peers in the same logical state with
   * the same `_lastSyncMessage` / `_latestSnapshot` advertise the same
   * hash regardless of any unrelated concurrent heads they happen to be
   * holding in `_currentFrontier()`.
   *
   * # Trade-off (acknowledged)
   *
   * The quorum no longer verifies that a responder has all of its
   * logical heads -- only the ones it would actually serve. A peer with
   * un-served concurrent heads can pass quorum on the subset it ships
   * via load. This matches the existing load semantics (the load only
   * ever ships what `_lastSyncMessage` covers anyway) and is reconciled
   * by post-load GossipSub sync; the alternative (Option B in the design
   * notes) would require the load response itself to carry every head's
   * subtree, a larger protocol change.
   *
   * @internal
   */
  private _servedFrontier(): string[] {
    return computeServedFrontier(
      this._lastSyncMessage?.changeId,
      this._lastSyncMessage?.changes,
      this._latestSnapshot?.lastChangeNodeCID,
    );
  }

  /**
   * Record a CID as a recently-known tip for Merkle-CRDT cross-linking
   * (paper §VI.B.e). Called for both locally-generated and remote-applied
   * change nodes -- a peer A that just received B's change can cross-link
   * to it on A's next outgoing change, helping a third peer C that missed
   * B's broadcast discover the missing block. Cross-links to deferred CIDs
   * are emitted as leaf nodes with only `kind` set; the receiver fetches
   * the block from Helia when needed (see `_syncDocumentChanges`).
   *
   * Bounded to `MAX_RECENT_TIPS` entries (oldest evicted). If the CID is
   * already tracked, move it to the back so it remains a high-priority
   * cross-link candidate.
   */
  private _trackTip(cid: string, kind: CRDTChangeNodeKind): void {
    trackTipInList(this._recentTips, { cid, kind }, MAX_RECENT_TIPS);
  }

  private async _syncDocumentChanges(
    changeId: string | undefined,
    changes: CRDTChangeNode<ChangesType>,
    fetchOptions: DocumentChangeFetchOptions<DocumentKey> = {},
  ) {
    const signal = fetchOptions.signal;
    const assertStillActive = (): void => {
      throwIfLoadAborted(signal);
      this._assertDocumentStateNotPoisoned();
      fetchOptions.assertStillActive?.();
    };
    const maxBlockBytes = fetchOptions.maxBlockBytes;
    const maxAggregateBlockBytes = fetchOptions.maxAggregateBlockBytes;
    if (maxBlockBytes !== undefined) {
      assertPositiveSafeByteLimit(maxBlockBytes, 'Missing block byte limit');
    }
    if (maxAggregateBlockBytes !== undefined) {
      assertPositiveSafeByteLimit(
        maxAggregateBlockBytes,
        'Missing block aggregate byte limit',
      );
    }
    const aggregateBudget =
      fetchOptions.aggregateBudget ??
      (maxAggregateBlockBytes === undefined
        ? undefined
        : { maxBytes: maxAggregateBlockBytes, consumedBytes: 0 });
    if (aggregateBudget !== undefined) {
      assertPositiveSafeByteLimit(
        aggregateBudget.maxBytes,
        'Missing block aggregate byte limit',
      );
      if (
        !Number.isSafeInteger(aggregateBudget.consumedBytes) ||
        aggregateBudget.consumedBytes < 0 ||
        aggregateBudget.consumedBytes > aggregateBudget.maxBytes
      ) {
        throw new RangeError(
          'Missing block aggregate byte consumption must be in range',
        );
      }
    }
    const consumeBytes =
      aggregateBudget === undefined
        ? undefined
        : (byteLength: number): void => {
            assertStillActive();
            consumeDocumentChangeFetchBytes(aggregateBudget, byteLength);
          };
    assertStillActive();
    // Walk the incoming sync tree once and record every CID that appears
    // as a `children` key. Those CIDs are referenced ancestors -- by
    // definition no longer heads of the local DAG. Doing this BEFORE the
    // merge keeps `_currentFrontier()` correct regardless of whether the
    // referenced parent ends up applied inline or fetched lazily from the
    // blockstore: either way, the receiver now knows the parent relationship
    // the sender had.
    //
    // Idempotent and inexpensive: the helper walks at most the size of the
    // delivered tree (bounded by the sender's compaction config); duplicates
    // are no-ops in a Set.
    collectReferencedAncestors(changeId, changes, this._referencedAncestors);

    // Only process hashes that we haven't seen yet.
    const newChangeEntries = await awaitLoadWork(
      this._mergeSyncTree(
        changeId,
        changes,
        this._lastSyncMessage && this._lastSyncMessage.changeId,
        this._hashes,
      ),
      signal,
    );
    assertStillActive();

    // First apply changes that were sent directly.
    let newDocument = this._document;
    const newDocumentHashes: string[] = [];
    const newDocumentTips: Array<[string, CRDTChangeNodeKind]> = [];
    const missingDocumentHashes: [string, CRDTChangeNodeKind][] = [];
    for (const [sentHash, sentChangeKind, sentChanges] of newChangeEntries) {
      assertStillActive();
      if (sentChanges) {
        switch (sentChangeKind) {
          case crdtDocumentChangeNode: {
            // Apply the changes that were sent directly.
            newDocument = this._crdtProvider.remoteChange(
              newDocument,
              sentChanges,
            );
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            this._documentChangeCount++;
            this._changesSinceSnapshot++;
            break;
          }
          case crdtReaderChangeNode: {
            // Apply the changes that were sent directly. Use the
            // `_mergeReaders` wrapper so pending BeeKEM Welcomes are
            // drained immediately after the ACL update lands.
            await this._mergeReaders(sentChanges, assertStillActive, signal);
            assertStillActive();
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            break;
          }
          case crdtWriterChangeNode: {
            // Apply the changes that were sent directly.
            await this._mergeWriters(sentChanges, assertStillActive, signal);
            assertStillActive();
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            break;
          }
        }
      } else {
        missingDocumentHashes.push([sentHash, sentChangeKind]);
      }
    }
    if (newDocumentHashes.length) {
      assertStillActive();
      this._document = newDocument;
      for (const newHash of newDocumentHashes) {
        this._hashes.add(newHash);
      }
      // Track applied tips for Merkle-CRDT cross-linking (paper §VI.B.e)
      // *before* firing remote update handlers. Recording remote-applied
      // CIDs lets this peer cross-link to them on its next outgoing change,
      // helping other peers that may have missed the original broadcast.
      // The ordering matters: if a handler synchronously triggers a local
      // `change()`, `_makeChange()` must see the just-received remote tips
      // in `_recentTips` to cross-link to them. This matches the ordering
      // used in the missing-block fetch path below.
      //
      // `newDocumentTips` is populated in `mergeRemoteSyncTree`'s traversal
      // order, which is root-first (the remote head is the first entry, its
      // ancestors follow). `_trackTip` appends to the back of `_recentTips`
      // with LRU semantics, so pushing in root-first order would make the
      // head the *oldest* entry -- and when more than MAX_RECENT_TIPS new
      // entries arrive in one sync, the head would be evicted first. Walk
      // in reverse so the remote head ends up at the back (most-recent),
      // matching the intent of LRU tracking.
      for (let i = newDocumentTips.length - 1; i >= 0; i--) {
        const [cid, kind] = newDocumentTips[i]!;
        this._trackTip(cid, kind);
      }
      assertStillActive();
      await this._fireOrDeferRemoteUpdateHandlers(newDocumentHashes);
    }

    // Then apply missing hashes through a bounded worker pool. Every worker
    // receives the enclosing load signal, and all workers are awaited after
    // cancellation so no queued fetch can apply state after the caller's
    // deadline has rejected. An indeterminate ACL merge instead poisons the
    // document, aborts sibling fetches, and releases the queue immediately;
    // the poison assertion prevents an abort-ignoring fetch from applying
    // state if it ever settles later.
    if (missingDocumentHashes.length > 0) {
      let nextIndex = 0;
      let fetchLimitExceeded = false;
      const appliedMissingDocumentHashes = new Array<string | undefined>(
        missingDocumentHashes.length,
      );
      const fetchController = new AbortController();
      let signalPoisonedWorkerPool!: () => void;
      const poisonedWorkerPool = new Promise<void>((resolve) => {
        signalPoisonedWorkerPool = resolve;
      });
      const forwardAbort = (): void => {
        if (!fetchController.signal.aborted) {
          fetchController.abort(signal?.reason);
        }
      };
      if (signal?.aborted) {
        forwardAbort();
      } else {
        signal?.addEventListener('abort', forwardAbort, { once: true });
      }
      const fetchSignal = fetchController.signal;
      const assertWorkerActive = (): void => {
        assertStillActive();
        throwIfLoadAborted(fetchSignal);
      };
      const worker = async (): Promise<void> => {
        while (!fetchLimitExceeded) {
          assertWorkerActive();
          const index = nextIndex++;
          if (index >= missingDocumentHashes.length) return;
          const [missingHash, missingHashKind] =
            missingDocumentHashes[index]!;
          try {
            const cid = CID.parse(missingHash);
            const prefetched = fetchOptions.prefetchedBlocks;
            const missingChanges = await awaitLoadWork(
              prefetched?.has(missingHash)
                ? this._decodeBlock(
                    cid,
                    prefetched.get(missingHash)!,
                    fetchSignal,
                    fetchOptions.getKey,
                  )
                : this._getBlock(
                    cid,
                    {
                      signal: fetchSignal,
                      maxBlockBytes,
                      consumeBytes,
                    },
                    fetchOptions.getKey,
                  ),
              fetchSignal,
            );
            assertWorkerActive();
            if (!missingChanges) {
              console.error(`Block '${missingHash}' returned nothing`);
              continue;
            }
            switch (missingHashKind) {
              case crdtDocumentChangeNode: {
                this._document = this._crdtProvider.remoteChange(
                  this._document,
                  missingChanges,
                );
                this._hashes.add(missingHash);
                this._documentChangeCount++;
                this._changesSinceSnapshot++;
                this._trackTip(missingHash, missingHashKind);
                break;
              }
              case crdtReaderChangeNode: {
                // Go through `_mergeReaders` to drain any pending BeeKEM
                // Welcomes parked while waiting for this ACL update.
                await this._mergeReaders(
                  missingChanges,
                  assertWorkerActive,
                  fetchSignal,
                );
                assertWorkerActive();
                this._hashes.add(missingHash);
                this._trackTip(missingHash, missingHashKind);
                break;
              }
              case crdtWriterChangeNode: {
                await this._mergeWriters(
                  missingChanges,
                  assertWorkerActive,
                  fetchSignal,
                );
                assertWorkerActive();
                this._hashes.add(missingHash);
                this._trackTip(missingHash, missingHashKind);
                break;
              }
            }
            appliedMissingDocumentHashes[index] = missingHash;
            assertWorkerActive();
          } catch (error) {
            if (this._bootstrapLoadApplicationState === 'poisoned') {
              if (!fetchController.signal.aborted) {
                fetchController.abort();
              }
              signalPoisonedWorkerPool();
              this._assertDocumentStateNotPoisoned();
            }
            if (signal?.aborted) throwIfLoadAborted(signal);
            if (fetchLimitExceeded && fetchController.signal.aborted) return;
            if (error instanceof _LoadFetchLimitExceededError) {
              fetchLimitExceeded = true;
              if (!fetchController.signal.aborted) {
                fetchController.abort(
                  new _LoadFetchLimitExceededError(
                    'Missing change block fetch limits exceeded',
                  ),
                );
              }
              return;
            }
            // A provider/serializer can throw arbitrary values derived from
            // decrypted document bytes. Never pass that value to a logger.
            console.error(
              'Failed to fetch missing change from blockstore:',
              missingHash,
            );
          }
        }
      };
      const workerCount = Math.min(
        LOAD_PREFETCH_MAX_CONCURRENCY,
        missingDocumentHashes.length,
      );
      let workerResults: PromiseSettledResult<void>[];
      try {
        const workersSettled = Promise.allSettled(
          Array.from({ length: workerCount }, () => worker()),
        );
        const workerPoolOutcome = await Promise.race([
          workersSettled.then((results) => ({
            kind: 'settled' as const,
            results,
          })),
          poisonedWorkerPool.then(() => ({ kind: 'poisoned' as const })),
        ]);
        if (workerPoolOutcome.kind === 'poisoned') {
          throw new Error(
            `Document ${this.documentPath} has indeterminate authorization state; ` +
              'discard this document instance before continuing',
          );
        }
        workerResults = workerPoolOutcome.results;
      } finally {
        signal?.removeEventListener('abort', forwardAbort);
      }
      assertStillActive();
      const workerFailure = workerResults.find(
        (result): result is PromiseRejectedResult =>
          result.status === 'rejected',
      );
      if (workerFailure) throw workerFailure.reason;
      if (fetchLimitExceeded) {
        throw new _LoadFetchLimitExceededError(
          'Missing change block fetch limits exceeded',
        );
      }
      const appliedHashes = appliedMissingDocumentHashes.filter(
        (hash): hash is string => hash !== undefined,
      );
      if (appliedHashes.length > 0) {
        assertStillActive();
        await this._fireOrDeferRemoteUpdateHandlers(appliedHashes);
      }
    }
    assertStillActive();

    // Refresh `_lastSyncMessage` so the served frontier reflects what we now
    // hold. Without this, a relay peer that joined via `load()` (or that has
    // only ever applied remote changes via GossipSub) would keep
    // `_lastSyncMessage` undefined and `_servedFrontier()` would return `[]`,
    // making the peer advertise `tipsHash([])` in the initial-load quorum
    // probe AND ship an empty load response. Two such relay peers would
    // agree on the empty-set hash, satisfying quorum, and an honest newcomer
    // would accept an empty document while the mesh actually had data.
    //
    // We update only when the incoming tree subsumes our prior root --
    // i.e., `_lastSyncMessage.changeId` appears as a CID somewhere in the
    // received tree -- so the served-frontier coverage never shrinks. The
    // undefined-prior and same-root cases are also "subsumes" (vacuously
    // and trivially); concurrent independent roots are intentionally left
    // alone (matches the existing single-tree load semantics documented on
    // `_servedFrontier()`). The next local `_makeChange()` cross-links
    // through `_recentTips` regardless, so concurrent heads are recovered
    // on the next local write.
    this._refreshLastSyncMessageFromSync(changeId, changes);

    assertStillActive();
    if (this._isStateApplicationBlocked()) {
      this._bootstrapCompactionDeferred = true;
    } else {
      await this._maybeCompact();
    }
  }

  /**
   * Update `_lastSyncMessage` so it reflects the served frontier of a
   * just-applied remote sync tree. Called by `_syncDocumentChanges()`
   * after the merge has succeeded.
   *
   * Replacement policy: only swap the cached message when the incoming
   * tree *subsumes* the prior cached root, so the served frontier the
   * loader binds against can only grow, never shrink:
   *   - `_lastSyncMessage` is `undefined` (relay peer, no local change
   *     yet): adopt the incoming directly so the relay peer does not serve
   *     an empty frontier.
   *   - prior `changeId` appears anywhere in the incoming tree (root or
   *     descendant): the incoming tree includes the prior root's coverage
   *     by construction, so it is safe to replace.
   *   - prior `changeId` is independent of the incoming tree (concurrent
   *     heads, neither subsumes the other): leave the cached message in
   *     place. The next local `_makeChange()` will bundle both heads via
   *     cross-links from `_recentTips`. This matches the trade-off
   *     documented on `_servedFrontier()` -- a load response only ever
   *     carries one tree, so accepting a single root is the existing
   *     contract.
   *
   * The cached message's `documentId` / `keychainChanges` fields are
   * preserved across the swap. Response-specific fields
   * (`signature`, `tips`, `tipsHash`) are dropped because they are
   * regenerated per-response by the load / tip-advertise handlers; leaving
   * a stale value would be misleading at best, a wire-protocol violation
   * at worst.
   *
   * Idempotent and inexpensive: the subsumption check walks the incoming
   * tree once (bounded by sender compaction config); the field-level
   * replacement is O(1) reference swaps.
   *
   * @internal
   */
  private _refreshLastSyncMessageFromSync(
    receivedChangeId: string | undefined,
    receivedChanges: CRDTChangeNode<ChangesType>,
  ): void {
    // Defensive: if the incoming carries no root CID we cannot meaningfully
    // refresh the served frontier with it. (`computeServedFrontier` will
    // produce `[]` for the resulting `_lastSyncMessage` and we would simply
    // re-introduce the empty-served-frontier bug.)
    if (!receivedChangeId) return;

    const priorChangeId = this._lastSyncMessage?.changeId;

    // Case 1: no prior cached message -- adopt the incoming. A relay peer
    // with no local changes otherwise serves an empty payload because
    // `_lastSyncMessage` is `undefined`.
    if (!priorChangeId) {
      this._lastSyncMessage = {
        ...(this._lastSyncMessage || { documentId: this.documentPath }),
        changeId: receivedChangeId,
        changes: receivedChanges,
        // Drop response-specific fields; they are regenerated per-response.
        signature: undefined,
        tips: undefined,
        tipsHash: undefined,
      };
      return;
    }

    // Case 2: same root -- already up to date, nothing to do. (CIDs are
    // content-addressed so equal `changeId` implies the same subtree.)
    if (priorChangeId === receivedChangeId) return;

    // Case 3: prior root is embedded in the incoming tree -- the incoming
    // subsumes the prior. Replace.
    if (treeContainsCid(receivedChangeId, receivedChanges, priorChangeId)) {
      this._lastSyncMessage = {
        ...this._lastSyncMessage!,
        changeId: receivedChangeId,
        changes: receivedChanges,
        signature: undefined,
        tips: undefined,
        tipsHash: undefined,
      };
      return;
    }

    // Case 4: concurrent / independent roots. Leave the cached message
    // alone so we do not shrink served-frontier coverage. The next local
    // `_makeChange()` cross-links via `_recentTips`, recovering both heads.
  }

  /**
   * Walk the change tree and apply only ACL (reader/writer) nodes.
   * This is a lightweight pre-pass used before snapshot verification to
   * ensure writer keys are populated without applying document changes.
   * ACL merges are idempotent, so re-applying them in the subsequent
   * full _syncDocumentChanges() call is safe.
   */
  private _collectACLFromTree(
    node: CRDTChangeNode<ChangesType>,
    rootId?: string,
  ): {
    readonly aclEntries: BoundedChangeTreeEntry<ChangesType>[];
    readonly changes: CRDTChangeNode<ChangesType>;
  } {
    const { entries, root: changes } = snapshotBoundedChangeTree(rootId, node, {
      canonicalizeNodeId: (nodeId) => CID.parse(nodeId).toString(),
    });
    // Reject conflicting descriptions of one content-addressed node before
    // the ACL pre-pass can apply any of them.
    validateRemoteSyncTreeAliases(rootId, changes);
    return {
      aclEntries: entries.filter(
        ({ kind, change }) =>
          change !== undefined &&
          (kind === crdtWriterChangeNode || kind === crdtReaderChangeNode),
      ),
      changes,
    };
  }

  private async _applyCollectedACL(
    entries: readonly BoundedChangeTreeEntry<ChangesType>[],
    assertStillActive?: () => void,
    signal?: AbortSignal,
  ): Promise<void> {
    for (const { kind, change } of entries) {
      assertStillActive?.();
      if (change === undefined) continue;
      if (kind === crdtWriterChangeNode) {
        await this._mergeWriters(change, assertStillActive, signal);
      } else if (kind === crdtReaderChangeNode) {
        await this._mergeReaders(change, assertStillActive, signal);
      }
      assertStillActive?.();
    }
  }

  private _applyACLFromTree(
    node: CRDTChangeNode<ChangesType>,
  ): Promise<void> {
    const { aclEntries } = this._collectACLFromTree(node);
    return this._applyCollectedACL(aclEntries);
  }

  /**
   * Sanctioned wrapper around `_readers.merge` that also drains any
   * pending BeeKEM Welcomes parked by `handleBeeKEMWelcomeRequestData`
   * because the local user was not yet a reader. Centralizing the
   * post-merge drain here closes the readers-ACL / Welcome reordering
   * race regardless of which code path applied the ACL change.
   *
   * All ACL-merge call sites for the readers ACL must go through this
   * helper -- a bare `_readers.merge(...)` would silently skip the
   * drain, leaving a Welcome parked until the next merge (or TTL
   * eviction) and re-introducing the readers-ACL / Welcome reordering
   * wedge that this buffering / drain pair is designed to close.
   * During a bootstrap load, draining is deferred until the response passes
   * its completeness checks so buffered state cannot build on a partial ACL.
   *
   * Drain is scheduled through the mutation queue because accepting a
   * buffered Welcome mutates keychain and BeeKEM state. It remains
   * fire-and-forget so ACL-merge callers do not await a reentrant queue slot
   * while their enclosing `sync()` still owns the current one. Errors are
   * caught and logged so a malformed buffered Welcome cannot starve the
   * receive path.
   *
   * @internal
   */
  private async _mergeReaders(
    changes: ChangesType,
    assertStillActive?: () => void,
    signal?: AbortSignal,
  ): Promise<void> {
    await retryLoadACLConflict(async () => {
      if (this._readerPublicationsInFlight > 0) {
        throw new Error(
          `Cannot merge a remote reader ACL change for ${this.documentPath} ` +
            'while a staged local reader publication is in flight. Retry the ' +
            'sync through the document membership queue.',
        );
      }
      assertStillActive?.();
      try {
        // Once an opaque merge starts, abort cannot prove that it stopped mutating.
        await awaitLoadWork(this._readers.merge(changes), signal);
      } catch (error) {
        if (!(error instanceof ACLOperationInProgressError)) {
          this._markDocumentStatePoisoned();
        }
        throw error;
      }
    }, signal);
    assertStillActive?.();
    if (!this._isStateApplicationBlocked()) {
      this._schedulePendingWelcomeDrain();
    }
  }

  private _schedulePendingWelcomeDrain(): void {
    if (this._pendingWelcomes.size === 0) return;
    void this._runStateMutation(() => this._drainPendingWelcomesUnlocked())
      .catch(() => {
        console.error('Failed to drain pending BeeKEM Welcomes');
      });
  }

  /**
   * Whether application-level signing is enabled for this document's swarm.
   * Centralizes the `enableSigning` config check to avoid drift across many call sites.
   */
  private _isSigningEnabled(): boolean {
    return this.swarm.config?.enableSigning !== false;
  }

  private async _isLoadRequesterAuthorized(
    message: CRDTLoadRequest,
    retryConflicts = true,
  ): Promise<boolean> {
    if (!this._isSigningEnabled()) return true;
    if (!message.signature) return false;

    let signature: Uint8Array;
    try {
      signature = this._deserializeSignature(message.signature);
    } catch {
      return false;
    }
    const requestBytes = this._encoder.encode(message.documentId);
    const authorizedKeys = (
      await Promise.all(
        retryConflicts
          ? [
              retryACLConflict(() => this._readers.users()),
              retryACLConflict(() => this._writers.users()),
            ]
          : [this._readers.users(), this._writers.users()],
      )
    ).flat();
    for (const key of authorizedKeys) {
      if (
        (await this._authProvider.verify(requestBytes, key, signature)) === true
      ) {
        return true;
      }
    }
    return false;
  }

  private async _sendAuthorizedLoadResponse(
    message: CRDTLoadRequest,
    stream: ProtocolWriteStream,
    data: Iterable<Uint8Array>,
    bootstrapRevision: number,
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<void> {
    const dispatch = await this._runStateMutation(async () => {
      if (!isSharedProtocolHandlerActive(admission)) return;
      // A provider-reported conflict cannot be awaited while this operation
      // owns the document FIFO. Fail closed so a hung provider cannot retain
      // the queue after the request deadline.
      if (!(await this._isLoadRequesterAuthorized(message, false))) {
        if (!isSharedProtocolHandlerActive(admission)) return;
        return { completion: writeStream(stream, [] as Iterable<Uint8Array>) };
      }
      if (!isSharedProtocolHandlerActive(admission)) return;
      this._assertBootstrapResponseRevision(bootstrapRevision);
      return { completion: writeStream(stream, data) };
    });
    await dispatch?.completion;
  }

  /**
   * Returns the current list of authorized writer public keys, populating
   * the document-scoped cache on miss. Callers must not mutate the result.
   * The cache is invalidated by `_mergeWriters` and
   * `_publishPreparedWriterChange` -- the only sanctioned mutation paths for
   * `_writers`.
   *
   * Race-safety has two layers:
   *  - Mutation-in-flight bypass: while `_writerMutationsInFlight > 0`,
   *    skip the cache entirely. Some ACLs mutate their backing state
   *    before their `add`/`remove` Promise resolves, so the cached list
   *    can be stale even though the post-await invalidation has not yet
   *    run. Bypassing forces a fresh `users()` read each call until all
   *    mutations have finished and the cache is re-populated by a clean
   *    miss.
   *  - Version check on cache fill: capture `_writerKeysVersion` before
   *    awaiting. If the version advances mid-fetch, the fetched list
   *    reflects the *pre*-invalidation ACL and is unsafe to return --
   *    discard it and loop. The loop converges once a fetch completes
   *    with no intervening invalidation; under continuous invalidation
   *    it would spin, but invalidations are bounded (one per ACL
   *    mutation) and not adversarial.
   */
  private async _getWriterKeys(): Promise<ReadonlyArray<PublicKey>> {
    while (true) {
      if (
        this._writerMutationsInFlight === 0 &&
        this._cachedWriterKeys !== null
      ) {
        return this._cachedWriterKeys;
      }
      const versionAtStart = this._writerKeysVersion;
      const fetched = await retryACLConflict(() => this._writers.users());
      // Only commit to the cache if (a) the version is still current AND
      // (b) no mutations are in flight. Either condition means the fetch
      // could be racing a still-incomplete mutation; in that case return
      // the freshly fetched list to the caller but leave the cache null
      // so the next caller re-fetches.
      if (
        this._writerKeysVersion === versionAtStart &&
        this._writerMutationsInFlight === 0
      ) {
        this._cachedWriterKeys = fetched;
        return fetched;
      }
      if (this._writerKeysVersion !== versionAtStart) {
        // Version advanced during fetch -- the fetched list reflects the
        // pre-invalidation ACL. Discard it and retry with the post-
        // invalidation state to avoid handing a stale list to signature
        // verification.
        continue;
      }
      // Mutation still in flight but version unchanged: the fetched list
      // reflects whatever the ACL exposed at this moment, which is the
      // best the caller can get. Don't cache (so subsequent reads see
      // the post-mutation state once it lands), but return the value.
      return fetched;
    }
  }

  /** Bump the writer-keys version so any in-flight `_getWriterKeys` aborts
   *  its assignment, and clear the cache for the next caller. */
  private _invalidateWriterKeyCache(): void {
    this._cachedWriterKeys = null;
    this._writerKeysVersion++;
  }

  /**
   * Run a writer-ACL mutation under a guard that closes the gap between
   * "underlying ACL state has changed" and "_getWriterKeys reflects the
   * change." We invalidate the cache *before* the mutation (so any
   * concurrent `_getWriterKeys` re-fetches against whatever state the
   * ACL exposes at that moment) AND set a mutation-in-flight flag that
   * forces `_getWriterKeys` to bypass the cache entirely while the
   * mutation runs. Both bookkeeping operations live in the prelude/
   * finally so they cannot drift out of sync with the underlying call.
   */
  private async _runWriterMutation<T>(op: () => Promise<T> | T): Promise<T> {
    this._writerMutationsInFlight++;
    this._invalidateWriterKeyCache();
    try {
      return await op();
    } finally {
      this._writerMutationsInFlight--;
      // Invalidate again post-mutation: the underlying ACL is now
      // authoritative and any value that landed in the cache during the
      // window must be discarded. Idempotent and cheap.
      this._invalidateWriterKeyCache();
    }
  }

  /** Apply a writer ACL change and invalidate the cached key list. */
  private async _mergeWriters(
    changes: ChangesType,
    assertStillActive?: () => void,
    signal?: AbortSignal,
  ): Promise<void> {
    // Keep the mutation marker set while a transient ACL conflict settles and
    // the synchronous `merge()` is retried. Both invalidations (pre and post)
    // match the async helper's behavior.
    this._writerMutationsInFlight++;
    this._invalidateWriterKeyCache();
    try {
      await retryLoadACLConflict(async () => {
        if (this._writerPublicationsInFlight > 0) {
          throw new Error(
            `Cannot merge a remote writer ACL change for ${this.documentPath} ` +
              'while a staged local writer publication is in flight. Retry the ' +
              'sync through the document membership queue.',
          );
        }
        assertStillActive?.();
        try {
          // Once an opaque merge starts, abort cannot prove that it stopped mutating.
          await awaitLoadWork(this._writers.merge(changes), signal);
        } catch (error) {
          if (!(error instanceof ACLOperationInProgressError)) {
            this._markDocumentStatePoisoned();
          }
          throw error;
        }
      }, signal);
      assertStillActive?.();
    } finally {
      this._writerMutationsInFlight--;
      this._invalidateWriterKeyCache();
    }
  }

  /** Stage a writer addition without changing live authorization. */
  private async _prepareWriterAdd(
    publicKey: PublicKey,
  ): Promise<CapturedPreparedWriterChange<ChangesType>> {
    const prepareAdd = preparedDataProperty(
      this._writers,
      'prepareAdd',
      'Writer ACL prepareAdd',
    );
    if (!prepareAdd.found || typeof prepareAdd.value !== 'function') {
      throw new Error(
        'Writer ACL does not support the staged additions required for safe publication',
      );
    }
    const prepared = await retryACLConflict(() =>
      documentReflectApply(
        prepareAdd.value as (...args: unknown[]) => unknown,
        this._writers,
        [publicKey],
      ),
    );
    return this._capturePreparedWriterChange(prepared, 'addition');
  }

  /** Stage a writer removal without changing live authorization. */
  private async _prepareWriterRemove(
    publicKey: PublicKey,
  ): Promise<CapturedPreparedWriterChange<ChangesType>> {
    const prepareRemove = preparedDataProperty(
      this._writers,
      'prepareRemove',
      'Writer ACL prepareRemove',
    );
    if (!prepareRemove.found || typeof prepareRemove.value !== 'function') {
      throw new Error(
        'Writer ACL does not support the staged removals required for safe publication',
      );
    }
    const prepared = await retryACLConflict(() =>
      documentReflectApply(
        prepareRemove.value as (...args: unknown[]) => unknown,
        this._writers,
        [publicKey],
      ),
    );
    return this._capturePreparedWriterChange(prepared, 'removal');
  }

  /** Capture a staged writer delta and its synchronous commit by identity. */
  private _capturePreparedWriterChange(
    prepared: unknown,
    changeName: 'addition' | 'removal',
  ): CapturedPreparedWriterChange<ChangesType> {
    const changes = preparedDataProperty(
      prepared,
      'changes',
      `Prepared writer ACL ${changeName} changes`,
    );
    if (!changes.found) {
      throw new TypeError(
        `Prepared writer ACL ${changeName} must provide changes`,
      );
    }
    const commit = capturePreparedDataMethod(
      prepared,
      'commit',
      `Prepared writer ACL ${changeName} commit`,
    );
    return {
      changes: changes.value as ChangesType,
      commit,
    };
  }

  /** Stage and capture a reader addition without changing live authorization. */
  private async _prepareReaderAdd(
    publicKey: PublicKey,
  ): Promise<CapturedPreparedReaderChange<ChangesType>> {
    const prepareAdd = capturePreparedDataMethod(
      this._readers,
      'prepareAdd',
      'Reader ACL prepareAdd',
    );
    const prepared = await retryACLConflict(() =>
      documentReflectApply(prepareAdd.method, prepareAdd.receiver, [publicKey]),
    );
    const changes = preparedDataProperty(
      prepared,
      'changes',
      'Prepared reader ACL changes',
    );
    if (!changes.found) {
      throw new TypeError('Prepared reader ACL change must provide changes');
    }
    const claimCommit = preparedDataProperty(
      prepared,
      'claimCommit',
      'Prepared reader ACL claimCommit',
    );
    if (!claimCommit.found || typeof claimCommit.value !== 'function') {
      throw new Error(
        `Cannot add reader to "${this.documentPath}": the reader ACL ` +
          'must support commit claims for atomic onboarding.',
      );
    }
    return {
      changes: changes.value as ChangesType,
      claimCommit: {
        receiver: prepared as object,
        method: claimCommit.value as (...args: unknown[]) => unknown,
      },
    };
  }

  /** Stage and capture a reader removal without changing live authorization. */
  private async _prepareReaderRemove(
    publicKey: PublicKey,
  ): Promise<CapturedPreparedReaderChange<ChangesType>> {
    const prepareRemove = capturePreparedDataMethod(
      this._readers,
      'prepareRemove',
      'Reader ACL prepareRemove',
    );
    const prepared = await retryACLConflict(() =>
      documentReflectApply(prepareRemove.method, prepareRemove.receiver, [
        publicKey,
      ]),
    );
    const changes = preparedDataProperty(
      prepared,
      'changes',
      'Prepared reader ACL changes',
    );
    if (!changes.found) {
      throw new TypeError('Prepared reader ACL change must provide changes');
    }
    const claimCommit = preparedDataProperty(
      prepared,
      'claimCommit',
      'Prepared reader ACL claimCommit',
    );
    if (!claimCommit.found || typeof claimCommit.value !== 'function') {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": the ACL and ` +
          'keychain must support composed commit claims.',
      );
    }
    return {
      changes: changes.value as ChangesType,
      claimCommit: {
        receiver: prepared as object,
        method: claimCommit.value as (...args: unknown[]) => unknown,
      },
    };
  }

  /** Stage and capture the epoch-key side of a reader revocation. */
  private async _prepareReaderRevocationEpoch(
    epochId: Uint8Array,
    documentKey: DocumentKey,
  ): Promise<CapturedDataMethod> {
    const prepareProperty = preparedDataProperty(
      this._keychain,
      'prepareEpochKey',
      'Reader revocation keychain prepareEpochKey',
    );
    if (!prepareProperty.found || typeof prepareProperty.value !== 'function') {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": the keychain ` +
          'does not support transactional epoch-key staging.',
      );
    }
    const prepared = await documentReflectApply(
      prepareProperty.value,
      this._keychain,
      [epochId, documentKey],
    );
    const claimCommit = preparedDataProperty(
      prepared,
      'claimCommit',
      'Prepared reader-revocation epoch claimCommit',
    );
    if (!claimCommit.found || typeof claimCommit.value !== 'function') {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": the ACL and ` +
          'keychain must support composed commit claims.',
      );
    }
    return {
      receiver: prepared as object,
      method: claimCommit.value as (...args: unknown[]) => unknown,
    };
  }

  /** Invoke a captured provider claim and fail closed if its state is uncertain. */
  private _claimPreparedCommit(
    claimCommit: CapturedDataMethod,
    label: string,
  ): CapturedCommitFinalizer {
    try {
      return invokePreparedCommitClaim(claimCommit, label);
    } catch (error) {
      // Once a custom claim method is invoked it may have mutated provider
      // state before throwing or returning an invalid asynchronous shape.
      this._markDocumentStatePoisoned();
      throw error;
    }
  }

  /** Publish a staged writer change, then commit it before local handlers run. */
  private async _publishPreparedWriterChange(
    prepared: CapturedPreparedWriterChange<ChangesType>,
    operation: string,
  ): Promise<void> {
    this._writerPublicationsInFlight++;
    try {
      await this._runWriterMutation(() =>
        this._makeChange(prepared.changes, crdtWriterChangeNode, {
          operation,
          commit: () => {
            finalizePreparedCommitClaim(
              {
                receiver: prepared.commit.receiver,
                finalize: prepared.commit.method,
              },
              'Writer ACL staged commit',
            );
            // Commit is synchronous, so this version bump is the first
            // observable step after live writer membership changes. Any
            // users() read started against the pre-commit ACL must retry
            // instead of returning that stale snapshot during handlers.
            this._invalidateWriterKeyCache();
          },
        }),
      );
    } finally {
      this._writerPublicationsInFlight--;
    }
  }

  /** Publish a staged reader change, then run its composed local commit. */
  private async _publishPreparedReaderChange(
    prepared: CapturedPreparedReaderChange<ChangesType>,
    operation: string,
    commit: () => void,
  ): Promise<void> {
    this._readerPublicationsInFlight++;
    try {
      await this._makeChange(prepared.changes, crdtReaderChangeNode, {
        operation,
        commit,
      });
    } finally {
      this._readerPublicationsInFlight--;
    }
  }

  /** Reconstruct a detached identity from its canonical encoding. */
  private async _snapshotMembershipPublicKey(
    publicKey: PublicKey,
    featureName: string,
  ): Promise<{ publicKey: PublicKey; serialized: string }> {
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      featureName,
    );
    const serialized = await serializePublicKey(publicKey);
    if (typeof serialized !== 'string' || serialized.length === 0) {
      throw new TypeError(
        `${featureName} requires a non-empty canonical public-key encoding`,
      );
    }
    const mutableIdentity =
      (typeof publicKey === 'object' && publicKey !== null) ||
      typeof publicKey === 'function';
    const deserializePublicKey = this._authProvider.deserializePublicKey;
    if (typeof deserializePublicKey !== 'function') {
      if (mutableIdentity) {
        requireDeserializePublicKey(this._authProvider, featureName);
      }
      return { publicKey, serialized };
    }
    const stablePublicKey = await deserializePublicKey.call(
      this._authProvider,
      serialized,
    );
    if (mutableIdentity && stablePublicKey === publicKey) {
      throw new Error(
        `${featureName} requires AuthProvider.deserializePublicKey to ` +
          'return a detached identity',
      );
    }
    if ((await serializePublicKey(stablePublicKey)) !== serialized) {
      throw new Error(
        `${featureName} rejected a non-canonical public-key round trip`,
      );
    }
    return { publicKey: stablePublicKey, serialized };
  }

  /** Start caller-input capture before waiting for the mutation queue. */
  private _startMembershipPublicKeySnapshot(
    publicKey: PublicKey,
    featureName: string,
  ): Promise<{ publicKey: PublicKey; serialized: string }> {
    const snapshot = this._snapshotMembershipPublicKey(publicKey, featureName);
    void snapshot.catch(() => undefined);
    return snapshot;
  }

  private async _verifyWriterSignature(raw: Uint8Array, signature: string) {
    if (!this._isSigningEnabled()) {
      return true;
    }

    const writerKeys = await this._getWriterKeys();
    // Short-circuit: with no writers, no signature can verify. Avoids the
    // base64 decode for an unverifiable input.
    if (writerKeys.length === 0) {
      return false;
    }
    // Malformed base64 throws inside js-base64. A bad signature must surface
    // as a verification failure, not an exception -- the topic validator path
    // turns thrown errors into Ignore (effectively dropping the message
    // silently), which is a DoS surface for malformed input. Treat decode
    // failure as `false`.
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = this._deserializeSignature(signature);
    } catch {
      return false;
    }
    const verificationTasks: Promise<boolean>[] = [];
    for (const writerKey of writerKeys) {
      verificationTasks.push(
        this._authProvider.verify(
          new Uint8Array(raw),
          writerKey,
          new Uint8Array(signatureBytes),
        ),
      );
    }
    return firstTrue(verificationTasks);
  }

  /**
   * Verify a snapshot signature by trying all authorized writers.
   * Unlike sync message signatures (which are string-encoded), snapshot
   * signatures are raw Uint8Array. This avoids depending on the snapshot's
   * embedded publicKey field which may not survive serialization for all
   * key types (e.g. CryptoKey).
   */
  private async _verifySnapshotSignature(payload: Uint8Array, signature: Uint8Array) {
    if (!this._isSigningEnabled()) {
      return true;
    }

    const writerKeys = await this._getWriterKeys();
    const verificationTasks: Promise<boolean>[] = [];
    for (const writerKey of writerKeys) {
      verificationTasks.push(
        this._authProvider.verify(payload, writerKey, signature),
      );
    }
    return firstTrue(verificationTasks);
  }

  private async _signAsWriter(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    if (!this._isSigningEnabled()) {
      return '';
    }

    return this._signAsWriterUnconditional(message);
  }

  /**
   * Sign a sync message as a writer **regardless of the swarm-wide
   * `enableSigning` config**. Used exclusively by membership-control paths
   * that always require writer authentication.
   *
   * SECURITY: callers that go through `_signAsWriter` should keep doing
   * so -- it preserves the existing `enableSigning` toggle for normal
   * sync-message signing. Only paths that have a documented "writer-auth
   * is mandatory" requirement should use the unconditional variant.
   */
  private async _signAsWriterUnconditional(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    const { signature: oldSignature, ...messageWithoutSignature } = message;

    const raw = this._syncMessageSerializer.serializeSyncMessage(
      messageWithoutSignature,
    );
    const rawSignature = await this._authProvider.sign(raw, this._userKey);
    return this._serializeSignature(rawSignature);
  }

  /**
   * Sign a BeeKEM Welcome as a writer. Unlike `_signAsWriter`, this is
   * NOT gated on the swarm-wide `enableSigning` config: Welcomes are
   * always writer-authenticated, regardless of whether document-change
   * signing is enabled (see `beekem-welcome-handler.ts` for the receive
   * side and the SECURITY NOTE there for the threat model).
   */
  private async _signWelcomeAsWriter(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    return this._signAsWriterUnconditional(message);
  }

  /**
   * Verify a writer signature on a membership-control message. Unlike
   * `_verifyWriterSignature`, this is NOT gated on the swarm-wide
   * `enableSigning` config.
   */
  private async _verifyMembershipWriterSignature(
    raw: Uint8Array,
    signature: string,
  ): Promise<boolean> {
    const writerKeys = await this._getWriterKeys();
    if (writerKeys.length === 0) {
      return false;
    }
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = this._deserializeSignature(signature);
    } catch {
      return false;
    }
    const verificationTasks: Promise<boolean>[] = [];
    for (const writerKey of writerKeys) {
      verificationTasks.push(
        this._authProvider.verify(
          new Uint8Array(raw),
          writerKey,
          new Uint8Array(signatureBytes),
        ),
      );
    }
    return firstTrue(verificationTasks);
  }

  private _encoder = new TextEncoder();

  private _deserializeSignature(signature: string): Uint8Array {
    return Base64.toUint8Array(signature);
  }

  private _serializeSignature(signature: Uint8Array): string {
    return Base64.fromUint8Array(signature);
  }

  private async _makeChange(
    changes: ChangesType,
    kind: CRDTChangeNodeKind = crdtDocumentChangeNode,
    postPublishCommit?: PostPublishCommit,
  ) {
    // A staged ACL change does not mutate live authorization until publication
    // resolves. Every caller supplying `postPublishCommit` owns the shared
    // membership queue, so supported remote sync cannot interleave with these
    // snapshots. A rejected publication restores exactly this call's DAG
    // bookkeeping and cannot be attached as an ancestor or cross-link by a
    // later message. A commit exception also rolls back the DAG, but a generic
    // ACL may already have changed its backing state; that path poisons the
    // document instance rather than assuming the staged mutation was atomic.
    // The encrypted block itself may remain orphaned in the content-addressed
    // blockstore, but no in-memory DAG root points to it.
    // GossipSub does not expose an acknowledgement that distinguishes
    // "rejected before send" from "accepted by the transport, then rejected
    // locally." In that narrow delivery-ambiguous case a remote peer may have
    // applied a delta that this sender rolls back; a later sync/load must
    // reconcile it. This boundary prevents deterministic local reattachment,
    // not a distributed publish transaction.
    const lastSyncMessageBefore = this._lastSyncMessage;
    const recentTipsBefore = postPublishCommit
      ? [...this._recentTips]
      : undefined;
    const newlyReferencedAncestors: string[] = [];
    let hash = '';
    let hashWasKnown = false;
    let commitResolved = false;
    try {
      // Store changes in blockstore.
      hash = await this._putBlock(changes);
      hashWasKnown = this._hashes.has(hash);
      this._hashes.add(hash);

      // Send new message.
      let updateMessage = this._createSyncMessage('ordinary-sync-v1');
      const changeNode: CRDTChangeNode<ChangesType> = { kind, change: changes };
      const primaryParentId = updateMessage.changeId;
      if (primaryParentId && updateMessage.changes) {
        // Primary back-pointer: include the previous head's subtree inline so
        // peers can apply our change without an extra round-trip for the parent.
        changeNode.children = {};
        changeNode.children[primaryParentId] = updateMessage.changes;

        // Cross-links (Merkle CRDT paper §VI.B.e): additionally reference other
        // recent tips so a peer who missed an intermediate message can still
        // discover the missing CID via a later message. Cross-link entries
        // are emitted as *deferred* nodes (no `change` payload, no `children`)
        // -- they carry only the CID + kind. Receivers that don't already have
        // the block trigger a blockstore fetch in `_syncDocumentChanges`.
        // Receivers that already have the block treat the entry as a no-op
        // (deduplicated via `_hashes`).
        const crossLinkTips = selectCrossLinks(
          this._recentTips,
          primaryParentId,
          hash,
          MAX_CROSS_LINKS,
        );
        for (const tip of crossLinkTips) {
          // Skip if the tip is already a direct child of the new change node.
          if (changeNode.children[tip.cid]) continue;
          // Deferred leaf: no `change` payload, no `children`. Receivers fetch
          // the block from Helia if they don't already have it.
          changeNode.children[tip.cid] = { kind: tip.kind };
        }
      }
      updateMessage.changeId = hash;
      updateMessage.changes = changeNode;

      // Record every CID this new change references as a parent / cross-link
      // target. The primary parent and all cross-link tips become *referenced
      // ancestors* and drop out of `_currentFrontier()`. Walks just the new
      // `changeNode` (not the full inherited subtree below it) because the
      // inherited subtree's ancestor relationships were already recorded
      // when each of those nodes was created or applied.
      if (changeNode.children) {
        for (const childCid of Object.keys(changeNode.children)) {
          if (!this._referencedAncestors.has(childCid)) {
            newlyReferencedAncestors.push(childCid);
          }
          this._referencedAncestors.add(childCid);
        }
      }

      // Track this new tip for future cross-linking. The primary parent is
      // also retained -- it's the immediate predecessor of *this* tip and may
      // still be useful as a cross-link target for the *next* change if a
      // later remote sync arrives in between.
      this._trackTip(hash, kind);

      // Sign new message.
      updateMessage.signature = await this._signAsWriter(updateMessage);

      if (!postPublishCommit) {
        this._lastSyncMessage = updateMessage;
      }
      const serializedUpdate =
        this._syncMessageSerializer.serializeSyncMessage(updateMessage);

      // Encrypt sync message.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serializedUpdate,
        documentKey,
      );
      if (!nonce) {
        throw new Error(`Failed to encrypt sync message! Nonce cannot be empty`);
      }
      await this.swarm.heliaNode.libp2p.services.pubsub.publish(
        this._topic,
        concatUint8Arrays(documentKeyID, nonce, data),
      );
      // This is the sole live-authorization commit point for staged writer
      // changes: publication has resolved, but no local observer has run yet.
      if (postPublishCommit) {
        try {
          postPublishCommit.commit();
        } catch (error) {
          // Custom ACL providers may mutate partially before throwing. The DAG
          // rollback below cannot prove their backing authorization reverted,
          // so every commit exception makes this instance unusable.
          this._markDocumentStatePoisoned();
          throw error;
        }
      }
      if (postPublishCommit) {
        this._lastSyncMessage = updateMessage;
      }
      commitResolved = true;
    } catch (error) {
      if (postPublishCommit && !commitResolved) {
        if (hash && !hashWasKnown) {
          this._hashes.delete(hash);
        }
        for (const childCid of newlyReferencedAncestors) {
          this._referencedAncestors.delete(childCid);
        }
        this._recentTips = recentTipsBefore!;
        this._lastSyncMessage = lastSyncMessageBefore;
      }
      throw error;
    }

    // Fire change handlers. Once the staged commit above succeeds, handler
    // failures are observer failures rather than retryable ACL publication
    // failures. Report them, but preserve the successful membership result.
    try {
      await this._fireLocalUpdateHandlers(
        [hash],
        postPublishCommit?.operation,
      );
    } catch (error) {
      if (!postPublishCommit) throw error;
      this._reportLocalUpdateHandlerFailure(postPublishCommit.operation);
    }

    // Track document changes for compaction.
    if (kind === crdtDocumentChangeNode) {
      this._documentChangeCount++;
      this._changesSinceSnapshot++;
      await this._maybeCompact();
    }
  }

  /**
   * Returns the keychain changes to include in a load response based on
   * the document's history visibility setting.
   *
   * `since_invited` requires `_invitationEpoch` to be set (typically by the
   * BeeKEM Welcome flow when the local node joined). When it is unset --
   * e.g. for the original group creator that never received a Welcome --
   * the call falls back to `current_only` semantics rather than full
   * history. The intent of `since_invited` is to bound what *new joiners*
   * receive; emitting the full keychain whenever the local boundary is
   * unknown undermines that goal (and leaks every prior epoch to any
   * peer the local node responds to). Operators that genuinely want
   * founders to share full history should configure the document with
   * `historyVisibility: 'full_history'` explicitly.
   */
  private async _keychainChangesForVisibility(): Promise<ChangesType> {
    switch (this._historyVisibility) {
      case 'full_history':
        // Send all retained epoch keys.
        return this._keychain.history();
      case 'since_invited':
        if (this._invitationEpoch === undefined) {
          // No recorded invitation epoch (founding member, or a node that
          // joined before Welcome wiring landed). Request the narrowest
          // distribution interpretation. The provider rejects if its CRDT
          // cannot represent the isolated current key replay-safely.
          return await this._keychain.currentKeyChange();
        }
        // `historySince` is optional on the Keychain interface for source
        // compatibility. The helper rejects when the provider omits it because
        // core cannot assume a freshly synthesized current-key delta is safe to
        // regenerate or replay.
        return await keychainHistorySinceOrReject(this._keychain)(
          this._invitationEpoch,
        );
      case 'current_only':
      default:
        // Request only the current key. Providers reject when their CRDT cannot
        // represent that isolated change replay-safely.
        return await this._keychain.currentKeyChange();
    }
  }

  /**
   * Returns the keychain changes to include in a BeeKEM Welcome to a
   * newly-added reader.
   *
   * The visibility computation here is from the **recipient's**
   * perspective, not the inviter's:
   *
   * - `current_only`: request only the current key. Providers reject when
   *   their CRDT cannot export it replay-safely. This does not redact retained
   *   CRDT history.
   * - `since_invited`: request only the current key. From the recipient's
   *   perspective, "since I was invited" is the current epoch
   *   (`welcomeEpochId`) onward, so the Welcome itself should carry
   *   exactly the current key (subsequent rotations arrive via the
   *   key-update protocol). Using `_keychainChangesForVisibility()` here
   *   would instead leak the *inviter's* post-invite slice (or, for
   *   founders, the full history), violating the recipient's intended join
   *   boundary. Providers reject when they cannot make this isolated export
   *   replay-safe.
   * - `full_history`: send the full keychain so the recipient can audit
   *   or replay all prior blocks (matches the inviter-side visibility
   *   semantics).
   */
  private async _keychainChangesForWelcome(): Promise<ChangesType> {
    switch (this._historyVisibility) {
      case 'full_history':
        return this._keychain.history();
      case 'since_invited':
      case 'current_only':
      default:
        return await this._keychain.currentKeyChange();
    }
  }

  /**
   * Check if automatic compaction should be triggered based on the config.
   */
  private async _maybeCompact() {
    if (!this._compactionConfig.enabled || this._snapshotUnsupported) {
      return;
    }

    // Prevent overlapping snapshot() calls from concurrent async paths.
    if (this._compactionInProgress) {
      return;
    }

    // Check cheap thresholds before the async writer ACL check to avoid
    // repeated crypto/ACL work on every change.
    if (this._documentChangeCount < this._compactionConfig.minChangesBeforeSnapshot) {
      return;
    }
    if (this._changesSinceSnapshot < this._compactionConfig.snapshotInterval) {
      return;
    }

    // Only writers can create snapshots; read-only peers must not attempt compaction.
    if (
      (await retryACLConflict(() =>
        this._writers.check(this._userPublicKey),
      )) !== true
    ) {
      return;
    }
    this._compactionInProgress = true;
    try {
      await this._snapshotUnlocked();
    } finally {
      this._compactionInProgress = false;
    }
  }

  /**
   * Prune the change tree in the last sync message. After a BFS traversal
   * retains `keepCount` document nodes, remaining children are removed.
   * Note: in branching histories, nodes already enqueued in the BFS before
   * the limit is reached are also retained, so the actual count may exceed
   * `keepCount`.
   *
   * @param keepCount Maximum number of change nodes to retain in the sync tree.
   * @returns Set of CID strings for document nodes that were pruned from the tree.
   *   ACL node CIDs are never included (they are always preserved).
   */
  private _pruneChanges(keepCount: number): Set<string> {
    const prunedCIDs = new Set<string>();

    if (keepCount <= 0) {
      // Pruning everything (including root) is destructive and nonsensical; skip.
      return prunedCIDs;
    }
    if (!this._lastSyncMessage?.changes || !this._lastSyncMessage.changeId) {
      return prunedCIDs;
    }

    // Collect all ACL nodes from a subtree that is about to be pruned.
    // Re-attached ACL nodes are stored as leaf nodes (children stripped) so they
    // don't keep nested children subtrees alive after pruning.
    // Non-ACL (document) node CIDs are added to the prunedCIDs set.
    const collectACLNodes = (
      children: Record<string, CRDTChangeNode<ChangesType>>,
      out: Record<string, CRDTChangeNode<ChangesType>>,
    ) => {
      const pending = Object.entries(children).reverse();
      while (pending.length > 0) {
        const [childHash, childNode] = pending.pop()!;
        if (
          childNode.kind === crdtReaderChangeNode ||
          childNode.kind === crdtWriterChangeNode
        ) {
          // Shallow copy without children to avoid retaining the full subtree.
          const { children: _dropped, ...leafNode } = childNode;
          out[childHash] = leafNode as CRDTChangeNode<ChangesType>;
        } else {
          // Document node being pruned -- record its CID.
          prunedCIDs.add(childHash);
        }
        if (
          childNode.children !== undefined &&
          childNode.children !== crdtChangeNodeDeferred
        ) {
          const nested = Object.entries(childNode.children);
          for (let index = nested.length - 1; index >= 0; index--) {
            pending.push(nested[index]!);
          }
        }
      }
    };

    // Validate, budget, and detach the entire retained tree before pruning.
    // All later traversal uses this immutable structural snapshot, so a proxy
    // cannot expose a different tree between preflight and mutation.
    const { root: preflightRoot } = snapshotBoundedChangeTree(
      this._lastSyncMessage.changeId,
      this._lastSyncMessage.changes,
      {
        canonicalizeNodeId: (nodeId) => CID.parse(nodeId).toString(),
      },
    );
    validateRemoteSyncTreeAliases(
      this._lastSyncMessage.changeId,
      preflightRoot,
    );

    // Work on a detached mutable copy and publish it only after the complete
    // prune succeeds. Change payloads remain shared, but traversal containers
    // are plain data objects captured by the preflight walk.
    const prunedRoot = { ...preflightRoot } as CRDTChangeNode<ChangesType>;
    const cloneQueue: Array<
      readonly [CRDTChangeNode<ChangesType>, CRDTChangeNode<ChangesType>]
    > = [[preflightRoot, prunedRoot]];
    for (let cloneIndex = 0; cloneIndex < cloneQueue.length; cloneIndex++) {
      const [source, target] = cloneQueue[cloneIndex]!;
      if (
        source.children === undefined ||
        source.children === crdtChangeNodeDeferred
      ) {
        continue;
      }
      const children: Record<string, CRDTChangeNode<ChangesType>> =
        Object.create(null);
      target.children = children;
      for (const [childId, child] of Object.entries(source.children)) {
        const childClone = { ...child } as CRDTChangeNode<ChangesType>;
        children[childId] = childClone;
        cloneQueue.push([child, childClone]);
      }
    }

    // BFS traversal to collect nodes up to the limit.
    // ACL nodes (reader/writer) are always preserved regardless of keepCount.
    //
    // When a document node at the boundary is pruned, ACL nodes from the
    // entire pruned subtree are collected and re-attached. This prevents
    // losing ACL state during pruning.
    //
    // For branching histories (DAG with multiple branches), keepCount is applied
    // globally across all branches. Once the limit is reached, all further
    // document nodes in any branch are pruned.
    const queue: Array<CRDTChangeNode<ChangesType>> = [
      prunedRoot,
    ];
    let documentNodesVisited = 0;
    let qi = 0;

    while (qi < queue.length) {
      const current = queue[qi++]!;

      // ACL nodes are always kept -- never count them toward the limit.
      const isACLNode =
        current.kind === crdtReaderChangeNode ||
        current.kind === crdtWriterChangeNode;

      if (!isACLNode) {
        documentNodesVisited++;
      }

      if (
        current.children !== undefined &&
        current.children !== crdtChangeNodeDeferred
      ) {
        if (!isACLNode && documentNodesVisited >= keepCount) {
          // This document node is at the boundary -- prune its children,
          // but preserve any ACL nodes within the entire subtree.
          const preservedACL: Record<string, CRDTChangeNode<ChangesType>> = {};
          collectACLNodes(current.children, preservedACL);
          if (Object.keys(preservedACL).length > 0) {
            current.children = preservedACL;
          } else {
            delete current.children;
          }
        } else {
          for (const [, childNode] of Object.entries(current.children)) {
            queue.push(childNode);
          }
        }
      }
    }

    console.log(
      `Pruned change tree for ${this.documentPath}: kept ${documentNodesVisited} document nodes, pruned ${prunedCIDs.size} blocks`,
    );
    this._lastSyncMessage = {
      ...this._lastSyncMessage,
      changes: prunedRoot,
    };

    return prunedCIDs;
  }

  /**
   * Delete pruned blocks from the Helia blockstore. Unpins each block first
   * (if pinned), then deletes the raw block data. CIDs are intentionally
   * kept in `_hashes` so that `_mergeSyncTree()` still deduplicates if a
   * peer re-sends the same change block.
   *
   * Errors on individual blocks are logged but do not abort the overall GC pass.
   */
  private async _gcPrunedBlocks(prunedCIDs: Set<string>): Promise<void> {
    if (prunedCIDs.size === 0) {
      return;
    }

    const blockstore = this.swarm.heliaNode.blockstore;
    const pins = this.swarm.heliaNode.pins;
    let deleted = 0;

    for (const cidStr of prunedCIDs) {
      try {
        const cid = CID.parse(cidStr);

        // Unpin first -- pins.rm is an AsyncGenerator, drain it.
        try {
          for await (const _ of pins.rm(cid)) { /* drain */ }
        } catch (unpinErr) {
          const msg = String(unpinErr);
          if (!msg.includes('not pinned') && !msg.includes('is not pinned')) {
            throw unpinErr;
          }
          console.debug(`Unpin skipped for ${cidStr} (not pinned)`);
        }

        // Delete the raw block from the blockstore.
        // Note: we intentionally keep the CID in _hashes so that
        // _mergeSyncTree() still deduplicates if a peer re-sends
        // the same change block (e.g., a peer that hasn't compacted).
        await blockstore.delete(cid);
        deleted++;
      } catch (err) {
        console.error(`Failed to GC block ${cidStr}:`, err);
      }
    }

    console.log(
      `Blockstore GC for ${this.documentPath}: deleted ${deleted}/${prunedCIDs.size} blocks`,
    );
  }

  /**
   * Handles a doc-load request with pre-read stream data. Called by the
   * shared protocol handler in Peerborne after reading and routing.
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleLoadRequestData(
    message: CRDTLoadRequest,
    stream: ProtocolWriteStream,
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<void> {
    try {
      const bootstrapRevision = this._captureBootstrapResponseRevision();
      if (!isSharedProtocolHandlerActive(admission)) return;
      if (message.documentId !== this.documentPath) {
        console.warn('Shared doc-load request targeted the wrong document');
        await writeStream(stream, [] as Iterable<Uint8Array>);
        return;
      }

      if (!(await this._isLoadRequesterAuthorized(message))) {
        console.warn('Shared doc-load request was unauthorized');
        if (isSharedProtocolHandlerActive(admission)) {
          await writeStream(stream, [] as Iterable<Uint8Array>);
        }
        return;
      }
      if (!isSharedProtocolHandlerActive(admission)) return;

      // Construct load response based on history visibility setting.
      const loadMessage = this._createSyncMessage('load-response-v3');

      loadMessage.keychainChanges = await this._keychainChangesForVisibility();

      // Include the latest snapshot if available, to accelerate initial sync.
      if (this._latestSnapshot) {
        loadMessage.snapshot = this._latestSnapshot;
      }

      // Attach an explicit tip-set advertisement so the loader can apply
      // a defense-in-depth consistency check against this responder's
      // self-attested served frontier (issue #186 / #189 §5.4.2).
      //
      // The loader's PRIMARY binding is derived STRUCTURALLY from the
      // served `changes`/`snapshot` payload via
      // `computeServedFrontier`; the responder's `tips` array is NOT
      // trusted as the source of truth (a Byzantine peer can populate
      // it with the agreed CIDs while serving a divergent payload).
      // `tips` is still emitted by honest responders because the loader
      // ALSO verifies that the responder's own attestation hashes to
      // the same value as the structurally-derived served frontier --
      // a peer whose `tips` contradicts their own served payload is
      // caught at the secondary check.
      //
      // `tips` is the *served* frontier
      // (`_servedFrontier()`) -- i.e. the heads of the change tree this
      // load response actually carries -- NOT the full local DAG
      // frontier (`_currentFrontier()`). The two differ when this peer
      // has multiple concurrent heads but `_lastSyncMessage` only roots
      // at one of them (the load wire shape only ships a single tree).
      // The tip-advertise handler hashes the same served frontier, so
      // the probe and the load round bind against a byte-identical tip
      // set even when the responder is holding remotely-applied heads
      // that aren't yet cross-linked into `_lastSyncMessage.changes`.
      // This field is part of the SIGNED v3 payload; see
      // `wire-protocols.ts` for the version-bump rationale.
      loadMessage.tips = this._servedFrontier();

      // Sign new message.
      loadMessage.signature = await this._signAsWriter(loadMessage);

      const serializedLoad =
        this._syncMessageSerializer.serializeSyncMessage(loadMessage);

      // Encrypt the load response so keychain is not sent in plaintext.
      // NOTE: This uses the current key, which works for existing peers requesting
      // a reload (they already have the key). For NEW members being onboarded for
      // the first time, the key must be delivered out-of-band via BeeKEM Welcome
      // message -- they cannot decrypt this load response without the key.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serializedLoad,
        documentKey,
      );
      if (!nonce) {
        throw new Error(`Failed to encrypt sync message! Nonce cannot be empty`);
      }
      const assembled = concatUint8Arrays(documentKeyID, nonce, data);
      assertSharedProtocolRequestSize(
        assembled.byteLength,
        'Encrypted document-load response',
      );
      console.log('Sending encrypted shared doc-load response');

      await this._sendAuthorizedLoadResponse(
        message,
        stream,
        [assembled] as Iterable<Uint8Array>,
        bootstrapRevision,
        admission,
      );
    } catch {
      console.error('Shared doc-load request handling failed');
      // Ensure the stream is closed so the requester doesn't hang.
      try {
        if (isSharedProtocolHandlerActive(admission)) {
          await writeStream(stream, [] as Iterable<Uint8Array>);
        }
      } catch {
        // The shared handler owns final stream teardown.
      }
    }
  }

  /**
   * Handles a snapshot-load request with pre-read stream data. Called by
   * the shared protocol handler in Peerborne after reading and routing.
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleSnapshotLoadRequestData(
    message: CRDTLoadRequest,
    stream: ProtocolWriteStream,
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<void> {
    try {
      const bootstrapRevision = this._captureBootstrapResponseRevision();
      if (!isSharedProtocolHandlerActive(admission)) return;
      if (message.documentId !== this.documentPath) {
        console.warn(
          'Shared snapshot-load request targeted the wrong document',
        );
        await writeStream(stream, [] as Iterable<Uint8Array>);
        return;
      }

      if (!(await this._isLoadRequesterAuthorized(message))) {
        console.warn('Shared snapshot-load request was unauthorized');
        if (isSharedProtocolHandlerActive(admission)) {
          await writeStream(stream, [] as Iterable<Uint8Array>);
        }
        return;
      }
      if (!isSharedProtocolHandlerActive(admission)) return;

      if (!this._latestSnapshot) {
        // No snapshot available -- respond with empty payload so the peer
        // can fall back to the normal doc-load protocol.
        console.log('No snapshot available; sending an empty response');
        await writeStream(stream, [] as Iterable<Uint8Array>);
        return;
      }

      // Build a complete sync message with the snapshot, post-snapshot
      // changes, and keychain so the peer can fully catch up.
      const snapshotMessage = this._createSyncMessage('load-response-v3');
      snapshotMessage.snapshot = this._latestSnapshot;
      snapshotMessage.keychainChanges = await this._keychainChangesForVisibility();
      // Tip-set advertisement for the pre-apply structural binding check
      // (see the doc-load handler above and the in-line check in
      // `_sendLoadRequestAndSync` for the rationale).
      //
      // This is the *served* frontier (`_servedFrontier()`)
      // -- the heads of the served payload (`_lastSyncMessage.changes`
      // tree plus the snapshot boundary) -- NOT the full local DAG
      // frontier (`_currentFrontier()`). When this peer holds concurrent
      // heads that `_lastSyncMessage` does not yet root over, the
      // load response only carries one head's subtree, so the
      // advertised `tips` must match that subset to satisfy the
      // loader's structural bind check. Part of the signed v3 payload
      // -- the version bump (snapshotLoadV2 -> snapshotLoadV3) is
      // required because `tips` is now covered by the writer signature.
      snapshotMessage.tips = this._servedFrontier();
      snapshotMessage.signature = await this._signAsWriter(snapshotMessage);

      const serialized =
        this._syncMessageSerializer.serializeSyncMessage(snapshotMessage);

      // Encrypt the response.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serialized,
        documentKey,
      );
      if (!nonce) {
        throw new Error(`Failed to encrypt snapshot response! Nonce cannot be empty`);
      }
      const assembled = concatUint8Arrays(documentKeyID, nonce, data);
      assertSharedProtocolRequestSize(
        assembled.byteLength,
        'Encrypted snapshot-load response',
      );
      console.log('Sending encrypted shared snapshot-load response');

      await this._sendAuthorizedLoadResponse(
        message,
        stream,
        [assembled] as Iterable<Uint8Array>,
        bootstrapRevision,
        admission,
      );
    } catch {
      console.error('Shared snapshot-load request handling failed');
      // Ensure the stream is closed so the requester doesn't hang.
      try {
        if (isSharedProtocolHandlerActive(admission)) {
          await writeStream(stream, [] as Iterable<Uint8Array>);
        }
      } catch {
        // The shared handler owns final stream teardown.
      }
    }
  }

  /**
   * Handles an initial-load quorum tip-advertise request with pre-read
   * stream data. Called by the shared protocol handler in Peerborne
   * after reading and routing.
   *
   * Closes the "no quorum protocol for verifying initial document state"
   * gap tracked under issue #189 §5.4 item 2 (also bulleted in #186).
   * The wire protocol is `tipAdvertiseV1` (see `wire-protocols.ts`);
   * this method returns either an empty payload (decline) or an
   * encrypted `CRDTSyncMessage` whose only populated payload field is
   * `tipsHash`. The loader on the other side compares hashes across
   * multiple peers and requires Q-of-K agreement before accepting any
   * peer's full document state. See `load-quorum.ts` for the decision
   * logic.
   *
   * Authorization mirrors the doc-load / snapshot-load handlers: when
   * signing is enabled the requester must sign the document path with
   * a key that appears in the readers or writers ACL. The response is
   * encrypted under the document's current key so a peer that does
   * not already possess the key cannot use the tip hash as an oracle
   * (key delivery is handled by the BeeKEM Welcome path).
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleTipAdvertiseRequestData(
    message: CRDTLoadRequest,
    stream: ProtocolWriteStream,
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<void> {
    try {
      const bootstrapRevision = this._captureBootstrapResponseRevision();
      if (!isSharedProtocolHandlerActive(admission)) return;
      // Tip-advertise runs on every `open()` from every peer that opens
      // this document, so a per-request log line scales with mesh size.
      // Drop the unconditional log entirely; the only field the handler
      // would have logged is attacker-controlled (`message`), and the
      // mismatch/unauthorized branches below already emit targeted
      // warnings when they fail.

      if (message.documentId !== this.documentPath) {
        console.warn(
          'Shared tip-advertise request targeted the wrong document',
        );
        await writeStream(stream, [] as Iterable<Uint8Array>);
        return;
      }

      // Signing-disabled deployments retain the same trust posture across
      // all shared load protocols through the common authorization helper.
      if (!(await this._isLoadRequesterAuthorized(message))) {
        console.warn('Shared tip-advertise request was unauthorized');
        if (isSharedProtocolHandlerActive(admission)) {
          await writeStream(stream, [] as Iterable<Uint8Array>);
        }
        return;
      }
      if (!isSharedProtocolHandlerActive(admission)) return;

      // Compute the canonical tip-set hash from the document's *served*
      // frontier — the heads of the payload this peer would actually ship
      // in a `documentLoadV3` / `snapshotLoadV3` round (computed via
      // `computeServedFrontier` over `_lastSyncMessage.changes` plus
      // `_latestSnapshot?.lastChangeNodeCID`, the exact same sources
      // `handleLoadRequestData` / `handleSnapshotLoadRequestData` populate
      // into the load response).
      //
      // This used to hash `_currentFrontier()` -- the full
      // local DAG frontier (`_hashes \ _referencedAncestors`). That
      // produces a hash an honest peer cannot bind against if it holds
      // multiple concurrent heads: `_currentFrontier()` returns every
      // head (including remotely-applied tips not yet cross-linked into
      // `_lastSyncMessage.changes`), but the load response only carries
      // one head's tree, so the loader's structural derivation of the
      // served frontier produces a different (smaller) set. Hashing the
      // served frontier here closes that gap -- a probe-then-load
      // round-trip from this responder always binds against a
      // byte-identical tip set. See `_servedFrontier()` for the
      // full rationale.
      //
      // Two peers with the same `_lastSyncMessage` / `_latestSnapshot`
      // produce byte-identical hashes; see `tips-hash.ts` for the
      // canonicalization (sort + `\n` separator + SHA-256).
      const hash = await tipsHash(this._servedFrontier());

      const advertisement: CRDTSyncMessage<ChangesType, PublicKey> = {
        documentId: this.documentPath,
        signatureContext: 'tip-advertisement-v1',
        tipsHash: hash,
      };

      // Sign the advertisement so the loader can verify the responder is
      // an authorized writer (the same trust bar applied to load responses
      // above). `_signAsWriter` returns '' when signing is disabled, in
      // which case the loader's pre-load verification block is also a
      // no-op -- mirrors the doc-load / snapshot-load handlers' pattern.
      advertisement.signature = await this._signAsWriter(advertisement);

      const serialized =
        this._syncMessageSerializer.serializeSyncMessage(advertisement);

      // Encrypt the response with the document's current key so that an
      // unauthorized peer that managed to connect to us but does not have
      // the key cannot read (or use as an oracle) the tip hash.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serialized,
        documentKey,
      );
      if (!nonce) {
        throw new Error(`Failed to encrypt tip-advertise response! Nonce cannot be empty`);
      }
      const assembled = concatUint8Arrays(documentKeyID, nonce, data);
      console.log('Sending encrypted shared tip-advertise response');

      await this._sendAuthorizedLoadResponse(
        message,
        stream,
        [assembled] as Iterable<Uint8Array>,
        bootstrapRevision,
        admission,
      );
    } catch {
      console.error('Shared tip-advertise request handling failed');
      // Ensure the stream is closed so the requester doesn't hang.
      try {
        if (isSharedProtocolHandlerActive(admission)) {
          await writeStream(stream, [] as Iterable<Uint8Array>);
        }
      } catch {
        // The shared handler owns final stream teardown.
      }
    }
  }

  /**
   * Build the deterministic binary payload used for snapshot signing/verification.
   *
   * Binary layout (big-endian integers):
   *   [0]       uint8   version (1)
   *   [1..8]    uint64  timestamp
   *   [9..12]   uint32  compactedCount
   *   [13..16]  uint32  cidLen
   *   [17..]    bytes   UTF-8(lastChangeNodeCID)
   *   [..]      uint32  stateLen
   *   [..]      bytes   stateBytes
   */
  private _buildSnapshotSignPayload(
    stateBytes: Uint8Array,
    lastChangeNodeCID: string,
    timestamp: number,
    compactedCount: number,
  ): Uint8Array {
    // Validate inputs to prevent runtime errors (e.g. BigInt(NaN) throws TypeError)
    // and silent uint32 overflow/truncation via DataView.setUint32.
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
      throw new Error(`Invalid snapshot timestamp: ${timestamp}`);
    }
    if (!Number.isInteger(compactedCount) || compactedCount < 0 || compactedCount > 0xFFFFFFFF) {
      throw new Error(`Invalid snapshot compactedCount: ${compactedCount}`);
    }
    const cidBytes = this._encoder.encode(lastChangeNodeCID);
    if (cidBytes.length > 0xFFFFFFFF) {
      throw new Error(`lastChangeNodeCID too large: ${cidBytes.length} bytes`);
    }
    if (stateBytes.length > 0xFFFFFFFF) {
      throw new Error(`Snapshot state too large: ${stateBytes.length} bytes`);
    }
    // 1 (version) + 8 (timestamp) + 4 (compactedCount) + 4 (cidLen) + cidBytes + 4 (stateLen) + stateBytes
    const totalLen = 1 + 8 + 4 + 4 + cidBytes.length + 4 + stateBytes.length;
    const buf = new ArrayBuffer(totalLen);
    const view = new DataView(buf);
    const out = new Uint8Array(buf);
    let offset = 0;

    // version
    view.setUint8(offset, 1);
    offset += 1;

    // timestamp as uint64
    view.setBigUint64(offset, BigInt(timestamp), false);
    offset += 8;

    // compactedCount as uint32
    view.setUint32(offset, compactedCount, false);
    offset += 4;

    // lastChangeNodeCID (length-prefixed)
    view.setUint32(offset, cidBytes.length, false);
    offset += 4;
    out.set(cidBytes, offset);
    offset += cidBytes.length;

    // stateBytes (length-prefixed)
    view.setUint32(offset, stateBytes.length, false);
    offset += 4;
    out.set(stateBytes, offset);

    return out;
  }

  private async _ensureCurrentUserCanWrite() {
    // Check that we are a writer (allowed to write to this document).
    if (
      (await retryACLConflict(() =>
        this._writers.check(this._userPublicKey),
      )) !== true
    ) {
      throw new Error(
        `Current user does not have write permissions for: ${this.documentPath}`,
      );
    }
  }

  /**
   * Send a load request over the given stream and apply the response.
   *
   * @returns `true` if a non-empty response was received and successfully synced.
   *   Returns `false` when:
   *   - The peer responded with an empty payload (e.g., peer has no snapshot).
   *   - The response payload is too short to contain a valid encrypted header.
   *   - The encryption keyID is not recognized (key not in our keychain).
   *   - The response documentId did not match the expected document.
   *   - Writer signature verification failed (when signing is enabled).
   *   - `sync()` rejected the response (e.g., invalid inner signatures or auth failure).
   *
   * @throws When `decrypt()` itself fails (i.e., the keyID was recognized but
   *   decryption produced no output), or on other unexpected protocol errors.
   *   Callers (e.g., `load()`) should wrap calls in a try/catch and handle both a
   *   `false` return value (by trying the next available peer) and thrown errors.
   */
  private async _sendLoadRequestAndSync(
    stream: Pick<Stream, 'send' | 'onDrain' | 'close' | 'abort' | typeof Symbol.asyncIterator>,
    serializedRequest: Uint8Array,
    expectedTipsHashHex: string | null = null,
    requiredResponseSigner?: PublicKey,
    maxResponseBytes?: number,
    requireCompleteCids = false,
    configuredResponseTimeoutMs?: number,
    beforeBootstrapComplete?: () => Promise<void>,
    signal?: AbortSignal,
    bootstrapContinuation?: InvitationBootstrapContinuation,
  ): Promise<boolean> {
    const continuingInvitationBootstrap =
      this._isActiveInvitationBootstrapContinuation(bootstrapContinuation);
    if (continuingInvitationBootstrap && requiredResponseSigner === undefined) {
      throw new Error(
        'Invitation bootstrap continuation requires a pinned response signer',
      );
    }
    const canUseCurrentBootstrapState = (): boolean =>
      continuingInvitationBootstrap
        ? this._bootstrapLoadApplicationState === 'pending' &&
          this._isActiveInvitationBootstrapContinuation(
            bootstrapContinuation,
          )
        : !this._isStateApplicationBlocked() &&
          this._activeInvitationBootstrapContinuation === undefined;
    const responseLimit = Math.min(MAX_SHARED_PROTOCOL_REQUEST_BYTES, assertPositiveSafeByteLimit(
      maxResponseBytes ?? MAX_DOCUMENT_LOAD_RESPONSE_SIZE,
      'Document load response byte limit',
    ));
    const aggregateBudget: DocumentChangeFetchBudget = {
      maxBytes: responseLimit,
      consumedBytes: 0,
    };
    const prefetchedBlocks = new Map<string, Uint8Array>();
    let changeFetchOptions: DocumentChangeFetchOptions<DocumentKey> = {
      signal,
      prefetchedBlocks,
      assertStillActive: continuingInvitationBootstrap
        ? () => {
            if (!canUseCurrentBootstrapState()) {
              throw new Error(
                `Invitation bootstrap continuation for ${this.documentPath} is no longer active`,
              );
            }
          }
        : undefined,
    };
    const responseTimeoutMs = documentLoadResponseTimeoutMs(
      configuredResponseTimeoutMs ?? this.swarm.config?.loadQuorumTimeoutMs,
    );
    let responseDeadline: ReturnType<typeof setTimeout> | undefined;
    const clearResponseDeadline = (): void => {
      if (responseDeadline !== undefined) {
        clearTimeout(responseDeadline);
        responseDeadline = undefined;
      }
    };
    let responseAborted = false;
    const abortResponse = (error: Error): void => {
      if (responseAborted) return;
      responseAborted = true;
      try {
        stream.abort(error);
      } catch {
        // The stream may already have been reset by the transport.
      }
    };
    // Reject a poisoned instance before sending or consuming any more load
    // protocol traffic. Abort the already-dialed stream so this overlap does
    // not leak transport resources. The second check after response parsing
    // closes the race where another bootstrap becomes pending in flight.
    throwIfLoadAborted(signal);
    if (!canUseCurrentBootstrapState()) {
      abortResponse(new Error('Document load rejected on poisoned instance'));
      return false;
    }
    const deadline = new Promise<never>((_resolve, reject) => {
      responseDeadline = setTimeout(() => {
        const error = new Error('Document load response deadline exceeded');
        abortResponse(error);
        reject(error);
      }, responseTimeoutMs);
    });
    try {
      await Promise.race([writeStream(stream, [serializedRequest]), deadline]);
    } catch (error) {
      clearResponseDeadline();
      throw error;
    }
    return await pipe(
      stream,
      async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
        let assembled: Uint8Array;
        const readResponse = readUint8Iterable(source, responseLimit).catch(
          (error) => {
            abortResponse(new Error('Document load response rejected'));
            throw error;
          },
        );
        try {
          assembled = await Promise.race([readResponse, deadline]);
        } finally {
          clearResponseDeadline();
        }
        throwIfLoadAborted(signal);
        if (!canUseCurrentBootstrapState()) return false;

        // Empty response means the peer couldn't serve this request.
        if (assembled.length === 0) {
          return false;
        }

        // Decrypt the response. Extract the keyID from the header and
        // look it up in the keychain. Responses shorter than the encryption
        // header are treated as malformed and rejected.
        const keyIDLength = this._keychainProvider.keyIDLength;
        const nonceLength = this._authProvider.nonceBytes;
        if (
          !Number.isSafeInteger(keyIDLength) ||
          keyIDLength <= 0 ||
          !Number.isSafeInteger(nonceLength) ||
          nonceLength <= 0 ||
          !Number.isSafeInteger(keyIDLength + nonceLength + 1) ||
          keyIDLength + nonceLength + 1 > responseLimit
        ) {
          console.warn(
            `Load response for ${this.documentPath}: invalid provider framing widths`,
          );
          return false;
        }
        const headerLength = keyIDLength + nonceLength;
        let rawContent: Uint8Array;
        if (assembled.length <= headerLength) {
          // Too short to contain a valid encrypted payload -- reject.
          console.warn(
            `Load response for ${this.documentPath}: payload too short (${assembled.length} <= ${headerLength}), skipping peer`,
          );
          return false;
        }

        const blockKeyID = assembled.slice(0, keyIDLength);
        const key = this._keychain.getKey(blockKeyID);
        if (key) {
          const blockNonce = assembled.slice(keyIDLength, headerLength);
          const blockData = assembled.slice(headerLength);
          const decrypted = await awaitLoadWork(
            this._authProvider.decrypt(blockData, key, blockNonce),
            signal,
          );
          if (!decrypted) {
            throw new Error(
              `Failed to decrypt load response for ${this.documentPath}`,
            );
          }
          try {
            rawContent = copyUnsharedUint8Array(
              decrypted,
              1,
              responseLimit,
              'Load response plaintext',
            );
          } catch {
            console.warn(
              `Load response for ${this.documentPath}: malformed plaintext, skipping peer`,
            );
            return false;
          }
        } else {
          // KeyID not recognized -- peer sent encrypted data with a key we
          // don't have. Fail and let the caller try the next peer.
          console.warn(
            `Load response for ${this.documentPath}: unrecognized keyID, skipping peer`,
          );
          return false;
        }

        let message: CRDTSyncMessage<ChangesType, PublicKey>;
        try {
          message = snapshotSyncMessageForContext<ChangesType, PublicKey>(
            this._syncMessageSerializer.deserializeSyncMessage(rawContent),
            'load-response-v3',
          );
        } catch {
          console.warn(
            `Load response for ${this.documentPath}: malformed or cross-context message, skipping peer`,
          );
          return false;
        }
        throwIfLoadAborted(signal);
        if (message.documentId !== this.documentPath) {
          console.warn(
            `Load response documentId mismatch: expected ${this.documentPath}, got ${message.documentId}`,
          );
          return false;
        }
        if (
          !Array.isArray(message.tips) ||
          message.tips.some((tip) => typeof tip !== 'string')
        ) {
          console.warn(
            `Load response for ${this.documentPath}: missing required v3 tips, skipping peer`,
          );
          if (expectedTipsHashHex !== null) {
            throw new _QuorumBindCheckFailedError(
              '(missing tips)',
              'Quorum frontier binding: responder omitted required valid `tips` ' +
                'attestation on a v3 load response.',
            );
          }
          return false;
        }
        // A partially-applied bootstrap cannot be repaired in place because
        // later trusted state would merge atop the prior live poison. Reject
        // every response, including an explicitly signer-pinned one, before
        // consulting the potentially attacker-shaped writer ACL.
        if (!canUseCurrentBootstrapState()) {
          return false;
        }
        const loadWriterKeysVersion = this._writerKeysVersion;
        const hasCurrentLoadWriterAdmission = (): boolean => {
          const current = this._writerKeysVersion === loadWriterKeysVersion &&
            !(this._writerMutationsInFlight > 0);
          if (!current && requiredResponseSigner !== undefined) {
            throw new _LoadWriterVersionConflictError();
          }
          return current;
        };
        let loadWriterAdmission:
          | 'unsigned'
          | 'pinned'
          | 'bootstrap'
          | 'current-writer' = this._isSigningEnabled()
            ? 'bootstrap'
            : 'unsigned';
        const originalSignature = message.signature;
        let originalSignedRaw: Uint8Array | undefined;
        const { signature: _signature, ...expectedUnsigned } = message;
        let messageWithoutSignature: CRDTSyncMessage<ChangesType, PublicKey> | undefined;
        if (
          (requiredResponseSigner !== undefined || this._isSigningEnabled()) &&
          originalSignature
        ) {
          try {
            messageWithoutSignature = snapshotSyncMessageForContext<ChangesType, PublicKey>(expectedUnsigned, 'load-response-v3');
            originalSignedRaw = copyUnsharedUint8Array(
              this._syncMessageSerializer.serializeSyncMessage(messageWithoutSignature),
              1,
              responseLimit,
              'Unsigned load response',
            );
            if (!syncMessageMatchesSnapshot(expectedUnsigned, messageWithoutSignature, 'load-response-v3')) return false;
          } catch {
            return false;
          }
        }
        let originalSignatureBytes: Uint8Array | undefined;
        const getOriginalSignatureBytes = (): Uint8Array | undefined => {
          if (originalSignatureBytes) return originalSignatureBytes;
          if (!originalSignature) return undefined;
          try {
            originalSignatureBytes = this._deserializeSignature(
              originalSignature,
            );
            return originalSignatureBytes;
          } catch {
            return undefined;
          }
        };
        const verifyOriginalLoadSignature = async (
          writerKeys: readonly PublicKey[],
        ): Promise<boolean> => {
          const signatureBytes = getOriginalSignatureBytes();
          if (!originalSignedRaw || !signatureBytes) return false;
          // Every verifier owns its arguments; sequential attempts limit the
          // live copies and stop once an authorized writer verifies the body.
          for (const writerKey of writerKeys) {
            if (await this._authProvider.verify(
              new Uint8Array(originalSignedRaw),
              writerKey,
              new Uint8Array(signatureBytes),
            ) === true) return true;
          }
          return false;
        };
        // Verify the outer message signature before applying changes.
        // On subsequent loads (writers already known), verify against the
        // existing trusted writer set BEFORE sync() mutates state. This
        // prevents a malicious peer from injecting ACL changes that add
        // its own key.
        // On first load (_writers is empty / bootstrapping), we cannot
        // verify -- trust relies on the encrypted channel (only peers
        // with the document key can decrypt the response).
        if (requiredResponseSigner !== undefined || this._isSigningEnabled()) {
          const preLoadWriters =
            requiredResponseSigner === undefined
              ? await awaitLoadWork(this._getWriterKeys(), signal)
              : [];
          loadWriterAdmission = requiredResponseSigner === undefined
            ? preLoadWriters.length > 0
              ? 'current-writer'
              : 'bootstrap'
            : 'pinned';
          if (
            requiredResponseSigner !== undefined ||
            preLoadWriters.length > 0
          ) {
            if (!originalSignature || !originalSignedRaw || !messageWithoutSignature) {
              console.warn(
                `Load response for ${this.documentPath}: missing signature, skipping peer`,
              );
              return false;
            }
            // Mirror `_verifyWriterSignature`: a malformed/non-string signature
            // can cause `js-base64` to throw. Treat decode failure as a
            // verification failure for this peer (skip and let the caller try
            // the next one) rather than letting the exception escape -- the
            // outer snapshot-load attempt swallows errors via a blanket
            // catch{}, which would hide the malformed input entirely.
            const signatureBytes = getOriginalSignatureBytes();
            if (!signatureBytes) {
              console.warn(
                `Load response for ${this.documentPath}: malformed signature, skipping peer`,
              );
              return false;
            }
            const verified =
              requiredResponseSigner === undefined
                ? await awaitLoadWork(
                    verifyOriginalLoadSignature(preLoadWriters),
                    signal,
                  )
                : await awaitLoadWork(
                    this._authProvider.verify(
                      new Uint8Array(originalSignedRaw),
                      requiredResponseSigner,
                      new Uint8Array(signatureBytes),
                    ),
                    signal,
                  );
            if (verified !== true) {
              console.warn(
                `Load response for ${this.documentPath} failed writer signature verification, skipping peer`,
              );
              return false;
            }
            let rawAfterVerification: Uint8Array;
            try {
              rawAfterVerification = copyUnsharedUint8Array(
                this._syncMessageSerializer.serializeSyncMessage(
                  messageWithoutSignature,
                ),
                1,
                responseLimit,
                'Unsigned load response',
              );
            } catch {
              console.warn(
                `Load response for ${this.documentPath}: changed during verification, skipping peer`,
              );
              return false;
            }
            if (!constantTimeEqual(originalSignedRaw, rawAfterVerification) || !syncMessageMatchesSnapshot(expectedUnsigned, messageWithoutSignature, 'load-response-v3')) {
              console.warn(
                `Load response for ${this.documentPath}: changed during verification, skipping peer`,
              );
              return false;
            }
          }
        }
        const trackedBootstrapLoad =
          loadWriterAdmission === 'bootstrap' ||
          loadWriterAdmission === 'pinned' ||
          loadWriterAdmission === 'unsigned';
        if (trackedBootstrapLoad) {
          changeFetchOptions = {
            ...changeFetchOptions,
            maxBlockBytes: responseLimit,
            maxAggregateBlockBytes: responseLimit,
            aggregateBudget,
          };
        }
        let beganBootstrapStateApplication = false;
        let trackedLoadHadEstablishedState = false;
        let trackedLoadMadeReplicatedProgress = false;
        let trackedLoadMadeLogicalKeychainProgress = false;
        const assertBootstrapCanComplete = async (): Promise<void> => {
          throwIfLoadAborted(signal);
          if (
            continuingInvitationBootstrap &&
            !canUseCurrentBootstrapState()
          ) {
            throw new Error(
              `Invitation bootstrap continuation for ${this.documentPath} is no longer active`,
            );
          }
          await awaitLoadWork(beforeBootstrapComplete?.(), signal);
          throwIfLoadAborted(signal);
          if (
            continuingInvitationBootstrap &&
            !canUseCurrentBootstrapState()
          ) {
            throw new Error(
              `Invitation bootstrap continuation for ${this.documentPath} is no longer active`,
            );
          }
        };
        const completeBootstrapStateApplication = async (): Promise<void> => {
          if (beganBootstrapStateApplication) {
            await this._mutationQueue.run(() => {
              throwIfLoadAborted(signal);
              return this._completeBootstrapStateApplicationUnlocked(
                assertBootstrapCanComplete,
                () => throwIfLoadAborted(signal),
              );
            });
          }
        };
        const beginBootstrapStateApplication = (): void => {
          throwIfLoadAborted(signal);
          this._markBootstrapStateApplicationPending();
          beganBootstrapStateApplication = true;
        };
        const hasReplicatedState = (): boolean =>
          this._hashes.size > 0 ||
          this._lastSyncMessage !== undefined ||
          this._latestSnapshot !== undefined;
        const syncTrackedLoadMessageUnlocked = async (): Promise<boolean> => {
          if (!hasCurrentLoadWriterAdmission()) return false;
          // Established pinned/unsigned catch-up can temporarily return a
          // complete document to the pending bootstrap state. Do not begin
          // that transition while an older observer notification is waiting:
          // finalization cannot await the observer without retaining this
          // queue slot, and dispatching first would overtake it.
          if (this._remoteUpdateNotificationTail) return false;
          const hashesBefore = this._hashes.size;
          const lastSyncMessageBefore = this._lastSyncMessage;
          const latestSnapshotBefore = this._latestSnapshot;
          trackedLoadHadEstablishedState =
            this._bootstrapLoadApplicationState === 'complete' ||
            hasReplicatedState();

          throwIfLoadAborted(signal);
          if (!canUseCurrentBootstrapState()) return false;
          const synced = await this._syncUnlocked(
            message,
            false,
            'load-response-v3',
            continuingInvitationBootstrap
              ? undefined
              : beginBootstrapStateApplication,
            continuingInvitationBootstrap,
            () => {
              trackedLoadMadeLogicalKeychainProgress = true;
            },
            changeFetchOptions,
          );
          throwIfLoadAborted(signal);
          if (
            continuingInvitationBootstrap &&
            !canUseCurrentBootstrapState()
          ) {
            return false;
          }
          trackedLoadMadeReplicatedProgress =
            ((loadWriterAdmission === 'pinned' ||
              loadWriterAdmission === 'unsigned') &&
              trackedLoadMadeLogicalKeychainProgress) ||
            this._hashes.size > hashesBefore ||
            this._lastSyncMessage !== lastSyncMessageBefore ||
            this._latestSnapshot !== latestSnapshotBefore;

          if (
            synced === true &&
            loadWriterAdmission === 'pinned' &&
            !beganBootstrapStateApplication &&
            trackedLoadHadEstablishedState
          ) {
            await assertBootstrapCanComplete();
          }
          return synced;
        };
        const trackedLoadIsVacuous = (): boolean =>
          trackedBootstrapLoad &&
          !trackedLoadHadEstablishedState &&
          (!beganBootstrapStateApplication ||
            !trackedLoadMadeReplicatedProgress);
        const syncLoadMessage = (): Promise<boolean> => {
          if (loadWriterAdmission === 'current-writer') {
            // Reverify while holding the membership queue. The writer set may
            // have changed after the early load-response admission check.
            return this._mutationQueue.run(async () => {
              if (!hasCurrentLoadWriterAdmission()) return false;
              if (!canUseCurrentBootstrapState()) {
                return false;
              }
              const currentWriters = await awaitLoadWork(
                this._getWriterKeys(),
                signal,
              );
              if (
                (await awaitLoadWork(
                  verifyOriginalLoadSignature(currentWriters),
                  signal,
                )) !== true
              ) {
                return false;
              }
              if (!hasCurrentLoadWriterAdmission()) return false;
              return this._syncUnlocked(
                message,
                false,
                'load-response-v3',
                undefined,
                false,
                undefined,
                changeFetchOptions,
              );
            });
          }
          if (loadWriterAdmission === 'bootstrap') {
            // First-load encrypted-channel bootstrap is valid only while the
            // writer ACL and local DAG are still pristine at the queued
            // application boundary. An existing document whose raw/legacy ACL
            // reached zero writers must not regain bootstrap authority merely
            // because a peer still holds an old document key.
            return this._mutationQueue.run(async () => {
              if (!canUseCurrentBootstrapState()) {
                return false;
              }
              const currentWriters = await awaitLoadWork(
                this._getWriterKeys(),
                signal,
              );
              if (currentWriters.length > 0) {
                if (
                  (await awaitLoadWork(
                  verifyOriginalLoadSignature(currentWriters),
                  signal,
                )) !== true
                ) {
                  return false;
                }
                return syncTrackedLoadMessageUnlocked();
              }
              if (
                this._bootstrapLoadApplicationState !== 'pristine' ||
                this._hashes.size > 0 ||
                this._lastSyncMessage !== undefined ||
                this._latestSnapshot !== undefined ||
                this._subscribed ||
                this._createdLocally
              ) {
                return false;
              }
              return syncTrackedLoadMessageUnlocked();
            });
          }
          // Pinned invitation catch-up and signing-disabled loads still use
          // the same fail-closed application marker. A pinned signer cannot
          // recover an instance after a partial bootstrap because that would
          // merge trusted data atop unknown live state.
          if (continuingInvitationBootstrap) {
            // Invitation acceptance already owns the mutation FIFO across
            // open and catch-up. Re-entering it here would deadlock; the
            // unforgeable continuation capability confines this unlocked
            // path to that one in-progress transaction.
            return canUseCurrentBootstrapState()
              ? syncTrackedLoadMessageUnlocked()
              : Promise.resolve(false);
          }
          return this._mutationQueue.run(() =>
            canUseCurrentBootstrapState()
              ? syncTrackedLoadMessageUnlocked()
              : Promise.resolve(false),
          );
        };
        // Quorum frontier binding (#186 / #189 §5.4.2). When the loader
        // ran a quorum probe round, the served full-load payload must
        // structurally describe the same tip set the responder voted
        // for. Done BEFORE `this.sync(...)` so a Byzantine peer that
        // voted hash X but serves a load with a different frontier
        // never gets to mutate the in-memory document.
        //
        // CRITICAL: the bind decision is derived from the ACTUAL served
        // payload, NOT from the responder-supplied `message.tips`.
        // Trusting `message.tips` creates a hole: a Byzantine peer could
        // vote hash X, put the matching
        // tip CIDs in `message.tips`, and then serve a `changes` /
        // `snapshot` payload describing a completely different state.
        // The advertised-vs-claimed check would pass even though the
        // application would receive divergent content. Frontier
        // computation therefore delegates to `computeServedFrontier`, which
        // walks the served `changes` tree (plus the snapshot boundary
        // CID) and returns the set of payload CIDs that no other node
        // in the same payload references as a parent -- i.e. the heads
        // of what was actually served. We then hash that frontier and
        // compare to `winningHashHex`.
        //
        // We additionally REQUIRE `message.tips` on every v3 load response.
        // The v3 load-response contract mandates the responder commit
        // to an explicit frontier attestation; a responder that omits
        // `tips` is recorded as a per-peer bind failure so the loader
        // retries the next agreeing peer. The structural check above
        // is the primary defense; the explicit `tips` requirement
        // ensures protocol compliance AND that the defense-in-depth
        // check below (verifying `tips` matches the structurally-
        // derived served frontier) actually runs. Catches the
        // responder-equivocation mode where `tips` and `changes` were
        // assembled inconsistently — e.g. a peer that claims extra
        // heads in `tips` that are not present in the served tree.
        //
        // Throws the module-private `_QuorumBindCheckFailedError` on
        // mismatch so the surrounding `load()` loop can record this
        // peer as a bind-failure and proceed to the NEXT peer in the
        // agreeing cohort. Previously this site threw
        // `LoadQuorumFailedError` directly, which `load()` re-raised --
        // letting a single malicious peer in the agreeing cohort vote
        // for the majority hash, serve a mismatched full load, and
        // unilaterally DoS the entire load by aborting before the
        // honest agreeing peers could be tried. `load()` only escalates to
        // a structured `LoadQuorumFailedError` with reason
        // `bind-check-failed-all-agreeing-peers`
        // when EVERY narrowed peer fails the bind step.
        if (expectedTipsHashHex !== null) {
          // Derive the served frontier STRUCTURALLY from the payload
          // the responder is asking us to apply -- not from the
          // responder's own `tips` attestation.
          const servedFrontier = computeServedFrontier(
            message.changeId,
            message.changes,
            message.snapshot?.lastChangeNodeCID,
          );
          const servedBytes = await awaitLoadWork(tipsHash(servedFrontier), signal);
          const servedHex = tipsHashToHex(servedBytes);
          if (!constantTimeHexEquals(expectedTipsHashHex, servedHex)) {
            console.warn(
              `[${this.documentPath}] Quorum frontier binding FAILED: ` +
                `expected tipsHash=${expectedTipsHashHex.slice(0, 12)}... but ` +
                `served payload's frontier hashes to ${servedHex.slice(0, 12)}.... ` +
                `An agreeing peer voted for one tip set and served a ` +
                `different one; treating as Byzantine equivocation.`,
            );
            throw new _QuorumBindCheckFailedError(
              servedHex,
              `Quorum frontier binding mismatch (served payload): expected ` +
                `${expectedTipsHashHex.slice(0, 12)}... got ${servedHex.slice(0, 12)}...`,
            );
          }
          // Defense-in-depth: the responder-supplied `tips` must hash
          // to the same value as the structurally-derived served
          // frontier. A peer whose attested `tips` contradicts their
          // own served payload (e.g. claims extra heads that are not
          // present in the served tree) is misbehaving.
          const advertisedBytes = await awaitLoadWork(tipsHash(message.tips), signal);
          const advertisedHex = tipsHashToHex(advertisedBytes);
          if (!constantTimeHexEquals(servedHex, advertisedHex)) {
            console.warn(
              `[${this.documentPath}] Quorum frontier binding FAILED: ` +
                `served payload frontier hashes to ${servedHex.slice(0, 12)}... ` +
                `but responder advertised tips hashing to ${advertisedHex.slice(0, 12)}.... ` +
                `Responder's own attestation contradicts the served payload.`,
            );
            throw new _QuorumBindCheckFailedError(
              advertisedHex,
              `Quorum frontier binding mismatch (advertised vs served): ` +
                `advertised ${advertisedHex.slice(0, 12)}... served ` +
                `${servedHex.slice(0, 12)}...`,
            );
          }

          // Content-address verification.
          //
          // The structural bind above proves Q peers agree on the
          // FRONTIER CIDs and that those CIDs appear as keys in the
          // served tree. It does NOT prove the inline `change` content
          // for each CID actually hashes back to that CID -- a Byzantine
          // peer could vote for the agreed frontier and then serve a
          // tree whose `children` map uses the agreed CIDs as keys but
          // whose inline `change` values are forged.
          //
          // On a FIRST load (`_writers` empty), per-change signature
          // verification inside the CRDT merge cannot fire -- there are
          // no writer keys to verify against -- so forged inline content
          // would otherwise reach `_crdtProvider.remoteChange`/
          // `_mergeWriters`/`_mergeReaders` unchecked.
          //
          // Defense: strip inline `change` content from every node in
          // the served tree before applying. `sync()` then routes each
          // CID through `missingDocumentHashes -> _getBlock(cid) ->
          // helia.blockstore.get(cid)`, which content-validates the
          // fetched bytes against the CID intrinsically (a Byzantine
          // peer cannot serve bytes that hash to a CID they did not
          // produce, and bitswap will retrieve from an honest peer in
          // the agreeing cohort that does hold the legitimate block).
          //
          // Cost: N bitswap roundtrips instead of one inline load. Paid
          // only on quorum-bound loads; the legacy `winningHashHex ===
          // null` path is untouched.
          //
          // Snapshots: `CRDTSnapshotNode.state` is NOT CID-addressed --
          // the snapshot's `lastChangeNodeCID` only identifies the
          // boundary, not the snapshot bytes. Defense is the writer
          // signature (`_verifySnapshotSignature`), which fails on
          // first load (writers empty) and rejects the snapshot
          // automatically. On subsequent loads writers are known and
          // the signature is the source of truth. We drop the snapshot
          // entirely on first load below so a malicious snapshot
          // signature forged with an attacker-controlled key (which
          // would be admitted if the inline ACL pre-pass were trusted)
          // never reaches `applySnapshot`.
          // Capture every CID that appears in the served tree BEFORE
          // stripping. `_syncDocumentChanges` swallows per-block fetch
          // failures (logs + returns); without a post-sync verification
          // step a transient bitswap/blockstore miss would let this
          // method return `true` with only a partially-applied document
          // and `load()` report success. After `sync()` we re-check that
          // every captured CID is now in `_hashes`; any missing CID is
          // surfaced as a per-peer bind failure so the loader can retry
          // the next peer in the agreeing cohort.
          const provenSnapshotBoundariesBeforeSync =
            this._latestSnapshot?.lastChangeNodeCID === undefined
              ? new Set<string>()
              : new Set([this._latestSnapshot.lastChangeNodeCID]);
          const expectedCids = collectInvitationCidsToInstall(
            message.changeId,
            message.changes,
            provenSnapshotBoundariesBeforeSync,
          );

          stripInlineChanges(message.changes);
          const preLoadWriterCount = (
            await retryLoadACLConflict(() => this._writers.users(), signal)
          ).length;
          if (preLoadWriterCount === 0 && message.snapshot) {
            console.warn(
              `[${this.documentPath}] Dropping snapshot from quorum-bound ` +
                `first load: writers ACL is not yet populated so the ` +
                `snapshot signature cannot be verified. The receiver will ` +
                `rebuild state from individual change blocks via Helia ` +
                `(each block content-validated against its CID).`,
            );
            message.snapshot = undefined;
          }

          // Snapshot-only first-load detection: after the snapshot drop
          // above, if the response now carries NO changes tree AND NO
          // snapshot, the responder served us nothing usable. Without
          // this guard the path falls through to the validated load-response
          // sync boundary
          // (which returns `true` for a vacuously-empty message because
          // there is nothing to merge / reject) and this method reports
          // success — `load()` then returns `true` with neither state
          // applied nor an opportunity to retry. Treat as a per-peer
          // bind failure so the agreeing-cohort load loop tries the
          // next peer (which may serve a real changes tree).
          if (
            message.changes === undefined &&
            message.snapshot === undefined
          ) {
            console.warn(
              `[${this.documentPath}] Quorum-bound first-load response ` +
                `carries neither a changes tree nor a snapshot after the ` +
                `defensive snapshot drop. Treating as bind failure so the ` +
                `loader tries the next agreeing peer.`,
            );
            throw new _QuorumBindCheckFailedError(
              '(snapshot-only first-load)',
              `Quorum-bound first-load response had only a snapshot (now ` +
                `dropped because writers are not yet populated) and no ` +
                `changes tree; no state can be applied.`,
            );
          }

          // PRE-FETCH gate.
          //
          // A POST-sync `_hashes`-coverage check alone is insufficient because
          // `sync()` mutates the document as each fetched block lands
          // -- so a missing CID would still leave the document
          // partially mutated by the time the post-check threw a bind
          // failure. To keep a failed quorum-bound load from altering
          // local state at all, pull every required block from Helia
          // here (BEFORE `sync()` is allowed to mutate). Helia's
          // blockstore content-validates each fetch against its CID
          // intrinsically; bitswap retrieves from any peer in the swarm
          // that holds the legitimate block. If ANY fetch fails (CID
          // not retrievable from any peer, content/CID mismatch, or
          // timeout inside Helia), throw a per-peer bind failure with
          // ZERO state mutation -- the load loop can cleanly retry the
          // next peer in the agreeing cohort, or escalate to
          // `bind-check-failed-all-agreeing-peers` if every peer
          // exhausts.
          //
          // Run via a bounded worker pool so a single slow peer cannot
          // pessimize the load AND a large load response (many CIDs)
          // cannot trigger a burst of parallel `blockstore.get()` fetches
          // that exhaust libp2p/Helia per-connection stream quotas or
          // pressure memory by buffering N inline payloads at once. The
          // previous implementation used `Promise.allSettled` over the
          // full `expectedCids` list with no concurrency cap, which
          // worked fine for typical loads but scaled linearly with the
          // worst-case adversary-shaped response. `LOAD_PREFETCH_MAX_CONCURRENCY`
          // (8) is a balance: large enough to overlap WAN-latency-bound
          // bitswap fetches, small enough to bound peak resource use on
          // the loader. Block bytes are cached locally on success; the
          // subsequent `sync()` call only does local lookups for those
          // CIDs and applies them.
          let cidsToPrefetch: string[] = [];
          if (expectedCids.length > 0) {
            // Snapshot only committed-known hashes while serialized with state
            // mutation. Reading the live Set outside the queue could observe a
            // hash installed by a mutation that later rolls back, skip its
            // prefetch, and let sync partially mutate before discovering the
            // block is unavailable. Invitation catch-up already owns this
            // queue slot, so its direct snapshot is equally stable.
            const knownHashesBeforePrefetch = continuingInvitationBootstrap
              ? canUseCurrentBootstrapState()
                ? new Set(this._hashes)
                : undefined
              : await this._mutationQueue.run(async () =>
                  canUseCurrentBootstrapState()
                    ? new Set(this._hashes)
                    : undefined,
                );
            if (knownHashesBeforePrefetch === undefined) return false;
            cidsToPrefetch = expectedCids.filter(
              (cid) => !knownHashesBeforePrefetch.has(cid),
            );
          }
          if (cidsToPrefetch.length > 0) {
            const missingCids: string[] = [];
            let nextIndex = 0;
            let prefetchLimitExceeded = false;
            const consumePrefetchedBytes = (byteLength: number): void =>
              consumeDocumentChangeFetchBytes(aggregateBudget, byteLength);
            const prefetchController = new AbortController();
            const forwardPrefetchAbort = (): void => {
              if (!prefetchController.signal.aborted) {
                prefetchController.abort(signal?.reason);
              }
            };
            if (signal?.aborted) {
              forwardPrefetchAbort();
            } else {
              signal?.addEventListener('abort', forwardPrefetchAbort, {
                once: true,
              });
            }
            const prefetchSignal = prefetchController.signal;
            const workerCount = Math.min(
              LOAD_PREFETCH_MAX_CONCURRENCY,
              cidsToPrefetch.length,
            );
            const worker = async (): Promise<void> => {
              while (!prefetchLimitExceeded) {
                throwIfLoadAborted(signal);
                const i = nextIndex++;
                if (i >= cidsToPrefetch.length) return;
                const cidStr = cidsToPrefetch[i]!;
                try {
                  const cid = CID.parse(cidStr);
                  // Fetch once before state application. Helia validates
                  // content vs CID on `get`; caching the bounded raw block lets
                  // `_syncDocumentChanges` decrypt and deserialize that exact
                  // value without a second blockstore read or byte budget.
                  const block = await this._readBlock(cid, {
                    signal: prefetchSignal,
                    maxBlockBytes: trackedBootstrapLoad
                      ? responseLimit
                      : undefined,
                    consumeBytes: trackedBootstrapLoad
                      ? consumePrefetchedBytes
                      : undefined,
                  });
                  throwIfLoadAborted(prefetchSignal);
                  prefetchedBlocks.set(cidStr, block);
                } catch (error) {
                  if (signal?.aborted) throwIfLoadAborted(signal);
                  if (
                    prefetchLimitExceeded &&
                    prefetchController.signal.aborted
                  ) {
                    return;
                  }
                  if (error instanceof _LoadFetchLimitExceededError) {
                    prefetchLimitExceeded = true;
                    prefetchController.abort(
                      new _LoadFetchLimitExceededError(
                        'Load pre-fetch limits exceeded',
                      ),
                    );
                    return;
                  }
                  missingCids.push(cidStr);
                }
              }
            };
            let prefetchResults: PromiseSettledResult<void>[];
            try {
              prefetchResults = await Promise.allSettled(
                Array.from({ length: workerCount }, () => worker()),
              );
            } finally {
              signal?.removeEventListener('abort', forwardPrefetchAbort);
            }
            throwIfLoadAborted(signal);
            const prefetchFailure = prefetchResults.find(
              (result): result is PromiseRejectedResult =>
                result.status === 'rejected',
            );
            if (prefetchFailure) throw prefetchFailure.reason;
            if (prefetchLimitExceeded) {
              throw new _QuorumBindCheckFailedError(
                '(prefetch-limits-exceeded)',
                'Quorum-bound load pre-fetch exceeded block retrieval limits',
              );
            }
            if (missingCids.length > 0) {
              console.warn(
                `[${this.documentPath}] Quorum-bound load pre-fetch ` +
                  `failed: ${missingCids.length} of ${cidsToPrefetch.length} ` +
                  `expected CIDs were not retrievable from Helia (e.g. ` +
                  `${missingCids
                    .slice(0, 3)
                    .map((c) => c.slice(0, 12) + '...')
                    .join(', ')}). Recording peer as bind-failed BEFORE ` +
                  `any state mutation; the loader will try the next ` +
                  `agreeing peer with a clean document.`,
              );
              throw new _QuorumBindCheckFailedError(
                '(prefetch-missing-blocks)',
                `Quorum-bound load pre-fetch could not retrieve ` +
                  `${missingCids.length} of ${cidsToPrefetch.length} expected ` +
                  `CIDs from Helia; aborting before sync() so document ` +
                  `state is unchanged.`,
              );
            }
          }

          const syncResult = await syncLoadMessage();
          throwIfLoadAborted(signal);
          if (syncResult !== true) {
            console.warn(
              `sync rejected message during load for ${this.documentPath}`,
            );
            // Return false so the caller tries the next peer.
            return false;
          }
          // Post-sync verification: every
          // CID we expected from the (stripped) served tree must have
          // landed in `_hashes` via either inline application (for the
          // non-stripped path this branch never reaches) or via the
          // `_getBlock(cid)` Helia fetch path inside
          // `_syncDocumentChanges`. A missing CID means bitswap could
          // not retrieve that block; without surfacing this the load
          // would silently report success with a partial document.
          const missingCids: string[] = [];
          for (const cid of expectedCids) {
            if (!this._hashes.has(cid)) missingCids.push(cid);
          }
          if (missingCids.length > 0) {
            console.warn(
              `[${this.documentPath}] Quorum-bound load did not complete: ` +
                `${missingCids.length} of ${expectedCids.length} expected ` +
                `CIDs were not fetched from Helia (e.g. ${missingCids
                  .slice(0, 3)
                  .map((c) => c.slice(0, 12) + '...')
                  .join(', ')}). Recording peer as bind-failed so the ` +
                `loader tries the next agreeing peer.`,
            );
            throw new _QuorumBindCheckFailedError(
              '(missing-blocks)',
              `Quorum-bound load completed sync() but ${missingCids.length} ` +
                `of ${expectedCids.length} expected CIDs were not retrievable; ` +
                `served tree had stripped inline content and bitswap could ` +
                `not retrieve the missing blocks.`,
            );
          }

          if (trackedLoadIsVacuous()) {
            console.warn(
              `Bootstrap load for ${this.documentPath} applied no state; skipping peer`,
            );
            return false;
          }

          await completeBootstrapStateApplication();
          throwIfLoadAborted(signal);
          return true;
        }

        const snapshotBoundaryBeforeSync =
          this._latestSnapshot?.lastChangeNodeCID;
        // Legacy/non-quorum loads need the same advertised-CID completeness
        // gate as invitation catch-up. `_syncDocumentChanges` deliberately
        // logs and swallows individual block fetch failures, so `true` alone
        // is not evidence that a bootstrap installed its entire tree.
        const syncResult = requireCompleteCids || trackedBootstrapLoad
          ? await syncInvitationMessageCompletely(
              message,
              this._hashes,
              syncLoadMessage,
              loadWriterAdmission === 'pinned' ? 'catch-up' : 'bootstrap',
              {
                provenSnapshotBoundariesBeforeSync:
                  snapshotBoundaryBeforeSync === undefined
                    ? undefined
                    : new Set([snapshotBoundaryBeforeSync]),
                isSnapshotApplied: () =>
                  this._latestSnapshot === message.snapshot,
              },
            )
          : await syncLoadMessage();
        throwIfLoadAborted(signal);
        if (syncResult !== true) {
          console.warn(
            `sync rejected message during load for ${this.documentPath}`,
          );
          // Return false so the caller tries the next peer.
          return false;
        }
        if (trackedLoadIsVacuous()) {
          console.warn(
            `Bootstrap load for ${this.documentPath} applied no state; skipping peer`,
          );
          return false;
        }
        await completeBootstrapStateApplication();
        throwIfLoadAborted(signal);
        return true;
      },
    );
  }

  /**
   * Send a single `tipAdvertiseV1` probe to one peer and decrypt the
   * response to extract the peer's `tipsHash`. Returns one of:
   *
   *   - `Uint8Array` -- the peer's advertised `tipsHash` (32 bytes).
   *   - `'unknown-doc'` -- the peer explicitly disclaimed the document
   *     (returned the 1-byte `0xFF` UNKNOWN_DOC sentinel). This is the
   *     signal `Peerborne.tipAdvertiseHandler` emits when no document
   *     is registered for the requested path. Distinguishing this from
   *     `null` lets the orchestrator tally `'unknown-doc'` exactly like
   *     a tip-hash vote so that when a Q-of-K majority of peers all
   *     disclaim the document, `load()` returns `false` to let a fresh
   *     `open()` create the document on top of an existing swarm. The
   *     previous design returned `null` for the unknown-doc case, which
   *     was indistinguishable from a partition / timeout and made
   *     new-document creation in an existing mesh fail with
   *     `LoadQuorumFailedError`.
   *   - `null` -- any other non-vote outcome: empty response, decryption
   *     failure with an unknown key (peer has a different keychain),
   *     missing/invalid signature, deserialization failure, document-id
   *     mismatch, missing/short tip hash, or thrown errors. Timeouts are
   *     handled at the caller level via Promise.race.
   *
   * Returns rather than throws so the caller can record this peer as a
   * non-vote (NOT a disagreement) and `decideLoadQuorum` can apply the
   * correct quorum semantics. See `load-quorum.ts` for the
   * timeout-vs-disagreement-vs-unknown-doc distinction.
   *
   * @internal
   */
  private async _probeTipAdvertise(
    peer: import('@multiformats/multiaddr').Multiaddr,
    serializedRequest: Uint8Array,
    signal?: AbortSignal,
  ): Promise<Uint8Array | 'unknown-doc' | null> {
    // Capture the underlying v3 Stream so the signal handler below can abort
    // it directly. Without this, a probe that loses the Promise.race to the
    // timeout would leak its stream until the libp2p connection itself
    // closed -- on partitioned/slow peers, each `load()` could leak K
    // streams, exhausting per-connection stream quotas.
    let rawStream: import('@libp2p/interface').Stream;
    let stream: Stream;
    try {
      rawStream = await this.libp2p.dialProtocol(peer, [tipAdvertiseV1], {
        runOnLimitedConnection: true,
        signal,
      });
      stream = rawStream;
    } catch {
      // Peer doesn't support tip-advertise or dial failed -- treat as non-vote.
      return null;
    }
    let streamAborted = false;
    const abortStream = (message: string): void => {
      if (streamAborted) return;
      streamAborted = true;
      try {
        rawStream.abort(new Error(message));
      } catch {
        void Promise.resolve()
          .then(() => rawStream.close())
          .catch(() => undefined);
        void Promise.resolve()
          .then(() => rawStream.closeRead())
          .catch(() => undefined);
      }
    };
    // Abort handler: tear down the v3 stream bidirectionally so a timed-out
    // probe doesn't strand the libp2p resource. `abort()` is the v3 full
    // teardown ("close stream for reading and writing"); `close()` would
    // only half-close the write side. Re-checking `signal?.aborted` after
    // attaching handles the race where the signal fired between dial and
    // listener attach. The handler also resolves `pipe()` / read promises
    // below with `AbortError`, which we swallow in the outer catch.
    const onAbort = () => abortStream('tip-advertise probe aborted');
    if (signal) {
      if (signal.aborted) {
        abortStream('tip-advertise probe aborted');
        return null;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }
    try {
      await writeStream(stream, [serializedRequest]);
      // Size-bound the tip-advertise response read. A `tipAdvertiseV1`
      // body is an encrypted `CRDTSyncMessage` carrying the `documentId`
      // (up to `MAX_DOCUMENT_PATH_LENGTH` bytes BEFORE encryption — this
      // dominates the size), a 32-byte `tipsHash`, and (optionally) a
      // writer signature. The cap is derived from
      // `MAX_DOCUMENT_PATH_LENGTH` plus JSON / Base64 / AES-GCM / signature
      // overheads (see `MAX_TIP_ADVERTISE_RESPONSE_SIZE` docstring above
      // for the breakdown). The previous 2 KiB cap was smaller than the
      // `documentId` field alone, so any document with a maximal path was
      // surfaced as a non-vote and quorum could never pass for it. 6 KiB
      // is generous for legitimate peers but prevents a malicious peer
      // from streaming an unbounded payload to force `load()` to buffer
      // it all before returning a non-vote. If the read overruns the cap,
      // `readUint8Iterable` throws a `RangeError` that is caught by the
      // surrounding `try { ... } catch { return null; }` — surfacing as a
      // non-vote (same outcome as a timeout), NOT a quorum disagreement.
      const assembled = await readUint8Iterable(
        stream,
        MAX_TIP_ADVERTISE_RESPONSE_SIZE,
      );
      if (assembled.length === 0) {
        // Peer declined (unauthorized, decryption failure, document-id
        // mismatch, etc.). Distinct from the 1-byte UNKNOWN_DOC sentinel
        // handled below, which signals "I don't have this document at all"
        // (a distinguishable case used to let new-doc creation succeed
        // in an existing swarm; see method docstring).
        return null;
      }
      // 1-byte UNKNOWN_DOC sentinel response: `Peerborne.tipAdvertiseHandler`
      // emits this when no document is registered for the requested path.
      // The orchestrator counts these toward a separate "unknown-doc"
      // tally so a Q-of-K majority of disclaims becomes a clean
      // new-doc-creation signal rather than a `LoadQuorumFailedError`.
      // See `_probeTipAdvertise`'s docstring for the rationale.
      if (assembled.length === 1 && assembled[0] === 0xff) {
        return 'unknown-doc';
      }
      const keyIDLength = this._keychainProvider.keyIDLength;
      const nonceLength = this._authProvider.nonceBytes;
      if (
        !Number.isSafeInteger(keyIDLength) ||
        keyIDLength <= 0 ||
        !Number.isSafeInteger(nonceLength) ||
        nonceLength <= 0 ||
        !Number.isSafeInteger(keyIDLength + nonceLength + 1) ||
        keyIDLength + nonceLength + 1 > MAX_TIP_ADVERTISE_RESPONSE_SIZE
      ) {
        return null;
      }
      const headerLength = keyIDLength + nonceLength;
      if (assembled.length <= headerLength) {
        // Too short to be a valid encrypted payload.
        return null;
      }
      const blockKeyID = assembled.slice(0, keyIDLength);
      const key = this._keychain.getKey(blockKeyID);
      if (!key) {
        // Responder used a key we don't have. Treat as non-vote rather than
        // an attack: a freshly-onboarded reader may legitimately not have
        // every historical key yet. The decryption-side check on the full
        // load that follows will still gate trust on the actual state.
        return null;
      }
      const blockNonce = assembled.slice(keyIDLength, headerLength);
      const blockData = assembled.slice(headerLength);
      const decrypted = await this._authProvider.decrypt(blockData, key, blockNonce);
      if (!decrypted) {
        return null;
      }
      let stablePlaintext: Uint8Array;
      try {
        stablePlaintext = copyUnsharedUint8Array(
          decrypted,
          1,
          MAX_TIP_ADVERTISE_RESPONSE_SIZE,
          'Tip advertisement plaintext',
        );
      } catch {
        return null;
      }
      let message: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        message = snapshotSyncMessageForContext<ChangesType, PublicKey>(
          this._syncMessageSerializer.deserializeSyncMessage(stablePlaintext),
          'tip-advertisement-v1',
        );
      } catch {
        return null;
      }
      if (message.documentId !== this.documentPath) {
        return null;
      }
      let stableTipsHash: Uint8Array;
      try {
        stableTipsHash = copyUnsharedUint8Array(
          message.tipsHash,
          TIPS_HASH_LENGTH,
          TIPS_HASH_LENGTH,
          'Tip advertisement hash',
        );
      } catch {
        return null;
      }
      if (this._writerMutationsInFlight !== 0) {
        return null;
      }
      const writerKeysVersion = this._writerKeysVersion;
      // Verify the writer signature on the advertisement when possible.
      // On first load (_writers empty) we cannot verify -- trust falls
      // back to the encryption envelope (only a peer that already holds
      // the current key could produce this response) plus the quorum
      // requirement that multiple such peers agree. This matches the
      // bootstrapping behaviour of `_sendLoadRequestAndSync`.
      if (this._isSigningEnabled()) {
        const preLoadWriters = await this._getWriterKeys();
        if (
          this._writerKeysVersion !== writerKeysVersion ||
          this._writerMutationsInFlight !== 0
        ) {
          return null;
        }
        if (preLoadWriters.length > 0) {
          if (!message.signature) {
            return null;
          }
          let messageWithoutSignature: CRDTSyncMessage<
            ChangesType,
            PublicKey
          >;
          let raw: Uint8Array;
          try {
            const verificationMessage = snapshotSyncMessageForContext<
              ChangesType,
              PublicKey
            >(message, 'tip-advertisement-v1');
            const { signature: _signature, ...unsigned } =
              verificationMessage;
            messageWithoutSignature = unsigned;
            raw = copyUnsharedUint8Array(
              this._syncMessageSerializer.serializeSyncMessage(
                messageWithoutSignature,
              ),
              1,
              MAX_SHARED_PROTOCOL_REQUEST_BYTES,
              'Unsigned tip advertisement',
            );
          } catch {
            return null;
          }
          let signatureBytes: Uint8Array;
          try {
            signatureBytes = this._deserializeSignature(message.signature);
          } catch {
            return null;
          }
          const verifyTasks = preLoadWriters.map((writerKey) =>
            this._authProvider.verify(
              new Uint8Array(raw),
              writerKey,
              new Uint8Array(signatureBytes),
            ),
          );
          if ((await firstTrue(verifyTasks)) !== true) {
            return null;
          }
          let rawAfterVerification: Uint8Array;
          try {
            rawAfterVerification = copyUnsharedUint8Array(
              this._syncMessageSerializer.serializeSyncMessage(
                messageWithoutSignature,
              ),
              1,
              MAX_SHARED_PROTOCOL_REQUEST_BYTES,
              'Unsigned tip advertisement',
            );
          } catch {
            return null;
          }
          if (!constantTimeEqual(raw, rawAfterVerification)) {
            return null;
          }
        }
      }
      if (
        this._writerKeysVersion !== writerKeysVersion ||
        this._writerMutationsInFlight !== 0
      ) {
        return null;
      }
      return stableTipsHash;
    } catch {
      return null;
    } finally {
      // Always detach the listener and reset both directions. A completion
      // detector or malformed response can return before the remote sends
      // FIN, and `close()` alone only half-closes the write side.
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
      abortStream('tip-advertise probe completed');
    }
  }

  /**
   * Run a single tip-advertise probe with a hard timeout. The probe itself
   * never throws (`_probeTipAdvertise` returns `null` on any failure
   * mode); a timeout also resolves to `null` so the caller can treat the
   * peer as a non-vote rather than a disagreement.
   *
   * Stream cancellation: when the timeout wins the race, the underlying
   * probe's libp2p stream is torn down via an AbortController so the
   * pending probe doesn't keep the resource alive in the background. Prior
   * to this fix, every timed-out probe leaked one libp2p stream per
   * `load()` call; under partitions or slow peers, K such leaks per load
   * could exhaust per-connection stream quotas.
   *
   * @internal
   */
  private async _raceTipAdvertiseProbe(
    peer: import('@multiformats/multiaddr').Multiaddr,
    serializedRequest: Uint8Array,
    timeoutMs: number,
  ): Promise<Uint8Array | 'unknown-doc' | null> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), timeoutMs);
    });
    try {
      return await Promise.race([
        this._probeTipAdvertise(peer, serializedRequest, controller.signal),
        timeout,
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      // Whether the probe won or the timeout won, abort the controller so
      // any in-flight probe (loser of the race, still pending on the event
      // loop) tears down its stream. Aborting AFTER the probe has already
      // resolved is a no-op: the probe's finally block will have already
      // detached the listener and closed the stream itself.
      controller.abort();
    }
  }

  /**
   * Extract the remote peer-id portion of a Multiaddr in a form suitable
   * for keying the quorum decision map. For relay-circuit multiaddrs (e.g.
   * `.../p2p/<relay>/p2p-circuit/p2p/<remote>`), the remote peer-id is the
   * LAST `/p2p/<id>` segment. Falls back to the full multiaddr string when
   * no `/p2p/<id>` segment is present so two responses from the same peer
   * always collide on the same map key.
   *
   * @internal
   */
  private _peerIdOf(peer: import('@multiformats/multiaddr').Multiaddr): string {
    const str = peer.toString();
    const matches = [...str.matchAll(/\/p2p\/([^/]+)/g)];
    return matches.length > 0 ? matches[matches.length - 1][1] : str;
  }

  // API Methods --------------------------------------------------------------

  /**
   * Close the subscription race after a verified invitation bootstrap by
   * loading directly from the exact endpoint named by the signed offer. This
   * deliberately bypasses the ordinary initial-load quorum only for this
   * issuer-pinned response; normal `load()` behavior is unchanged.
   */
  private async _loadInvitationCatchUp(
    founderAddress: string,
    issuerPublicKey: PublicKey,
    role: 'reader' | 'editor',
    bootstrapContinuation?: InvitationBootstrapContinuation,
  ): Promise<boolean> {
    if (
      !this._isActiveInvitationBootstrapContinuation(bootstrapContinuation) ||
      this._bootstrapLoadApplicationState !== 'pending'
    ) {
      this._assertNoIncompleteBootstrapLoad();
      throw new Error(
        `Invitation catch-up for ${this.documentPath} requires an active bootstrap transaction`,
      );
    }
    const signatureBytes = await this._authProvider.sign(
      this._encoder.encode(this.documentPath),
      this._userKey,
    );
    const serializedRequest =
      this._loadMessageSerializer.serializeLoadRequest({
        documentId: this.documentPath,
        signature: this._serializeSignature(signatureBytes),
      });
    const deadline = Date.now() + INVITATION_STREAM_TIMEOUT_MS;
    for (let attempt = 0; attempt < 3; attempt++) {
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        throw new Error('Invitation catch-up deadline exceeded');
      }
      try {
        return await withIssuerPinnedInvitationStream(
          founderAddress,
          (address, signal) =>
            this.libp2p.dialProtocol(multiaddr(address) as any, [documentLoadV3], {
              runOnLimitedConnection: true,
              signal,
            }),
          (rawStream, signal) =>
            this._sendLoadRequestAndSync(
              rawStream,
              serializedRequest,
              null,
              issuerPublicKey,
              MAX_INVITATION_MESSAGE_BYTES,
              true,
              remainingMs,
              () => this._assertAcceptedInvitationMembership(issuerPublicKey, role, signal),
              signal,
              bootstrapContinuation,
            ),
          remainingMs,
        );
      } catch (error) {
        if (!(error instanceof _LoadWriterVersionConflictError) || attempt === 2) {
          throw error;
        }
      }
    }
    throw new Error('Invitation catch-up exhausted its retry limit');
  }

  // https://gist.github.com/alanshaw/591dc7dd54e4f99338a347ef568d6ee9#duplex-it
  /**
   * Load sends a new load request to any connected peer (each peer is tried one at a time). The expected
   * response from a load request is a sync message containing all document change hashes.
   *
   * Load is used to fetch any new changes that a connecting node is missing.
   *
   * @param preferredPeer Optional peer to try first (typically a PeerId from a
   *   pubsub message sender). Matched against peers by extracting the `/p2p/<id>`
   *   substring from each peer's `Multiaddr.toString()` (the canonical string
   *   form), since `@multiformats/multiaddr` v13 dropped the `getPeerId()`
   *   helper and `getComponents()` may surface the `/p2p` value as bytes.
   * **Initial-load quorum gate.** When
   * `PeerborneConfig.loadQuorumEnabled` is `true` (the default), `load()`
   * first queries up to `loadQuorumK` peers in parallel via the
   * `tipAdvertiseV1` protocol for a lightweight tip-set hash. The full
   * document-load only proceeds against a peer that participated in a
   * majority (`loadQuorumQ`-of-K) agreement on the tip set, defending
   * against a single malicious or partitioned peer unilaterally serving a
   * stale or maliciously-crafted initial state. The gate runs uniformly
   * regardless of local `_hashes` state (an empty local `_hashes` is the
   * exact state the gate must defend on first `open()` of an existing
   * document — bypassing it then would be unsafe). If quorum is not met,
   * `load()` rejects with a `LoadQuorumFailedError` (see
   * `load-quorum.ts`). The gate can be disabled wholesale via
   * `loadQuorumEnabled: false` for single-peer dev/test scenarios; the
   * single-peer edge case is covered by `loadQuorumAllowSinglePeer`. Tip-
   * advertise responses with an unknown encryption key, missing/invalid
   * writer signature, document-id mismatch, or short/missing tip hash are
   * recorded as non-votes (NOT disagreements) so a stale peer cache does
   * not flip a partition into a Byzantine-failure verdict. The probe
   * round dedupes peers by libp2p PeerId so a single peer with multiple
   * open connections cannot cast multiple votes. The legacy load loop
   * (when `loadQuorumEnabled: false`) keeps the ORIGINAL un-deduped
   * peer list so it can retry across multiple multiaddrs for the same
   * peer id (e.g. a direct connection + a relay-circuit fallback).
   *
   * After quorum passes, the served full state is bound to the agreed
   * hash STRUCTURALLY -- the loader derives the responder's served
   * frontier from the actual `changes`/`snapshot` payload via
   * `computeServedFrontier`, hashes that, and verifies it equals
   * `winningHashHex` BEFORE applying the response. The
   * responder-supplied `message.tips` array must not be trusted as the
   * source of truth: doing so lets a Byzantine peer vote hash X, put X's
   * tips in `message.tips`, and serve a divergent payload. When present,
   * `message.tips` is additionally checked to
   * hash to the same value as the structurally-derived served
   * frontier; this catches the responder-internal-equivocation case
   * where the served `changes` and the advertised `tips` were
   * assembled inconsistently. An
   * agreeing peer whose served payload's structural frontier hashes to
   * something other than `winningHashHex` is treated as a PER-PEER bind
   * failure: the loader records the offending peer in
   * `agreeingPeerBindFailures`, skips it, and tries the next peer in
   * the agreeing cohort. This prevents a single malicious peer in the
   * agreeing cohort from DoS'ing the entire load by voting for the
   * majority hash (passing quorum) and then serving a mismatched full
   * load. Only after EVERY peer in the agreeing cohort has bind-failed
   * does the loader throw `LoadQuorumFailedError(reason: 'bind-check-
   * failed-all-agreeing-peers')`, with `agreeingPeerBindFailures`
   * recording per-peer what each Byzantine peer served instead.
   * Closes the gap tracked under issue #189 §5.4 item 2 (and bulleted
   * in #186).
   *
   * @returns `true` if the document was successfully loaded from a peer.
   *   `false` if no peer could provide the document -- this is ambiguous: it
   *   may mean the document is brand new (no peers have it) OR that all peers
   *   failed to respond, failed to decrypt, or failed signature verification.
   *   Note: `open()` treats `false` as "new document" only when no existing
   *   document state has already been loaded.
   * @throws {LoadQuorumFailedError} When the initial-load quorum gate is
   *   enabled and fewer than `loadQuorumQ` peers agreed on the same tip
   *   hash within the configured timeout. Callers can `instanceof`-check
   *   this error to distinguish quorum failure from other I/O errors
   *   raised inside `load()`. The original single-peer
   *   "return false on no peers" behaviour is preserved when the quorum
   *   gate is disabled (`loadQuorumEnabled: false`).
   * @throws {Error} When an earlier encrypted-channel bootstrap began
   *   applying state but did not complete. The document instance remains
   *   fail-closed and must be discarded.
   */
  public async load(preferredPeer?: PeerId | string): Promise<boolean> {
    // A failed bootstrap may have partially changed ACL/keychain state without
    // producing a DAG head. Do not let a later load retry or `open()` interpret
    // that state as a safe new-document result.
    this._assertNoIncompleteBootstrapLoad();

    // Pick a peer. All peers come from getConnections() so they already have
    // open connections. dialProtocol reuses existing connections internally,
    // so no additional connection management is needed here.
    const shuffledPeers = await this._shuffledPeers();
    if (shuffledPeers.length === 0) {
      this._assertNoIncompleteBootstrapLoad();
      return false;
    }

    const orderedPeers = [...shuffledPeers];

    // If a preferred peer is specified, move it to the front.
    // The peer list contains Multiaddrs while preferredPeer is typically a PeerId,
    // so we compare by extracting the PeerId component from each Multiaddr.
    if (preferredPeer) {
      const preferredId = preferredPeer.toString();
      const preferredIdx = orderedPeers.findIndex(p => {
        // Only compare against the PeerId component of the Multiaddr.
        // Falling back to a full-string equality check would compare against
        // the full multiaddr string (e.g. "/ip4/.../p2p/<id>") which will
        // never match a plain PeerId string.
        //
        // `@multiformats/multiaddr` v13 (bundled by libp2p v3) dropped the
        // `getPeerId()` helper. `getComponents()` exists, but its component
        // `value` field can be either a string or bytes depending on how the
        // multiaddr was parsed, so a direct `=== preferredId` comparison is
        // unreliable. `Multiaddr.toString()` always returns the canonical
        // string form, so extract the `/p2p/<id>` substring from there.
        //
        // For relay-circuit multiaddrs (e.g.
        // `.../p2p/<relay>/p2p-circuit/p2p/<remote>`), there are multiple
        // `/p2p/<id>` segments; the remote peer id is always the LAST one,
        // so iterate all matches and use the final occurrence.
        const matches = [...p.toString().matchAll(/\/p2p\/([^/]+)/g)];
        const peerId = matches.length > 0 ? matches[matches.length - 1][1] : null;
        return peerId != null && peerId === preferredId;
      });
      if (preferredIdx > 0) {
        const [preferred] = orderedPeers.splice(preferredIdx, 1);
        orderedPeers.unshift(preferred);
      }
    }

    let signature = '';
    if (this._isSigningEnabled()) {
      const signatureBytes = await this._authProvider.sign(
        this._encoder.encode(this.documentPath),
        this._userKey,
      );
      signature = this._serializeSignature(signatureBytes);
    }
    const loadRequest: CRDTLoadRequest = {
      documentId: this.documentPath,
      signature,
    };
    const serializedRequest = this._loadMessageSerializer.serializeLoadRequest(loadRequest);

    // Dedupe peers by peer id ONLY for the quorum probe round.
    // `getConnections()` returns one entry per OPEN connection, and libp2p
    // maintains separate connections per multiaddr / per transport — so a
    // single remote peer with two open connections (e.g. direct +
    // relay-circuit) shows up twice. Without dedup, that peer would cast
    // two votes in the quorum tally, allowing a single malicious peer with
    // multiple connections to dominate the agreement count. Dedup by
    // `_peerIdOf` (which extracts the LAST `/p2p/<id>` segment, i.e. the
    // remote peer's libp2p PeerId for both direct and circuit-relay
    // multiaddrs). Preserves first-seen order so the preferredPeer (placed
    // at index 0 above) remains first.
    //
    // IMPORTANT: dedup applies only to `quorumPeers`. The legacy
    // single-peer load path (when `loadQuorumEnabled: false`) keeps the
    // ORIGINAL `orderedPeers` so it can retry across multiple multiaddrs
    // for the same peer id -- e.g. a direct connection + a relay-circuit
    // fallback. Collapsing those to one entry pre-quorum would silently
    // break the legacy fallback even when the quorum gate is off.
    const quorumPeers = dedupePeersByPeerId(
      orderedPeers,
      (p) => this._peerIdOf(p),
    );

    // Initial-load quorum gate (#189 §5.4.2 / #186).
    //
    // Run BEFORE the existing single-peer snapshot/doc-load loop so that a
    // failed quorum aborts the load entirely (the caller cannot accidentally
    // accept a single peer's response). When the gate is disabled we fall
    // through to the legacy loop unchanged so existing callers see the same
    // behaviour.
    //
    // `winningHashHex` (set when quorum passes) is also used below as the
    // per-peer binding check inside `_sendLoadRequestAndSync`. The check
    // is purely structural and runs BEFORE the served state is applied:
    // the loader hashes `computeServedFrontier(message.changeId,
    // message.changes, message.snapshot?.lastChangeNodeCID)` and compares
    // to `winningHashHex`. If they disagree, an agreeing peer voted for
    // one tip set and served a different one (Byzantine equivocation):
    // the peer is recorded as a bind failure and the loader retries the
    // next agreeing peer without ever mutating in-memory state. The
    // pre-apply ordering is the load-bearing property -- a Byzantine peer
    // cannot poison the in-memory document because the bind decision
    // happens before `sync()` runs.
    // NOTE: previously this block bypassed the gate when `_hashes.size === 0`
    // on the assumption it identified a "founding-member" brand-new document.
    // That bypass was unsafe: `_hashes` is ALSO empty on the first `open()`
    // of an EXISTING document (before load populates it), which is exactly
    // the case the gate is meant to protect. We no longer special-case empty
    // local state; the gate runs uniformly. New-document creation in an
    // EXISTING swarm is handled by the `'unknown-doc'` probe sentinel: each
    // peer that does not have the document responds with the 1-byte UNKNOWN_DOC
    // marker (see `Peerborne.tipAdvertiseHandler`), the orchestrator tallies
    // these alongside tip-hash votes, and a Q-of-K majority of disclaims
    // surfaces as `{ newDoc: true }` here -- the loader returns `false` and
    // `open()` proceeds to create the doc fresh. True founders (no peers in
    // the mesh) are still handled by the `peers.length === 0` short-circuit
    // at the top of `load()` plus the `k === 0` branch inside `runLoadQuorum`
    // (which returns `{ skipped: true }`).
    //
    // The K-of-Q decision logic itself lives in `runLoadQuorum`
    // (`load-quorum-orchestrator.ts`) so the orchestration can be unit-tested
    // without standing up a libp2p/Helia stack. The orchestrator is given a
    // probe-fn closure that captures this document's `_raceTipAdvertiseProbe`
    // (the only network-touching call); narrowing, agreement counting, and
    // single-peer fallback all happen in pure code.
    const timeoutMs = this.swarm.config?.loadQuorumTimeoutMs ?? 5000;
    const quorumResult = await runLoadQuorum({
      protocol: 'tip-advertise-v1',
      peers: quorumPeers,
      peerIdOf: (p) => this._peerIdOf(p),
      probeFn: (peer) =>
        this._raceTipAdvertiseProbe(peer, serializedRequest, timeoutMs),
      documentPath: this.documentPath,
      config: {
        enabled: this.swarm.config?.loadQuorumEnabled ?? true,
        k: this.swarm.config?.loadQuorumK ?? 3,
        q: this.swarm.config?.loadQuorumQ,
        timeoutMs,
        allowSinglePeer:
          this.swarm.config?.loadQuorumAllowSinglePeer ?? false,
      },
    });

    let winningHashHex: string | null = null;
    if ('skipped' in quorumResult) {
      // `runLoadQuorum` returns `{ skipped: true }` in two cases: (a) the
      // gate is disabled wholesale (`loadQuorumEnabled: false`), or (b) the
      // effective K resolved to 0 because no peers were known. For (a) we
      // fall through to the legacy single-peer load loop unchanged --
      // `orderedPeers` is intentionally NOT deduped here so the loop can
      // retry across multiple multiaddrs for the same peer id (e.g. a
      // direct connection + a relay-circuit fallback). For (b) there is
      // nothing to load against — treat as new document. The peer-list
      // empty short-circuit at the top of `load()` already covers the
      // trivial "no peers" path; this branch is reached when quorum is
      // enabled with a valid K but the post-dedup `quorumPeers` happens
      // to be empty.
      //
      // Note: a misconfigured `loadQuorumK <= 0` no longer reaches this
      // branch — `runLoadQuorum` throws `LoadQuorumFailedError(invalid-
      // config)` for that case so the misconfiguration is loud at
      // `open()` time instead of silently forking the document.
      const quorumWasEnabled = this.swarm.config?.loadQuorumEnabled ?? true;
      if (quorumWasEnabled && quorumPeers.length === 0) {
        this._assertNoIncompleteBootstrapLoad();
        return false;
      }
      // Else: gate disabled. Fall through with the original (un-deduped)
      // `orderedPeers` so the legacy loop can retry per-multiaddr.
    } else if ('newDoc' in quorumResult) {
      // A Q-of-K majority of probed peers explicitly disclaimed the
      // document via the `'unknown-doc'` sentinel. Return `false` so
      // `open()` can create the document fresh on top of the existing
      // swarm. Without this branch, the previous design conflated
      // unknown-doc with partition / timeout and surfaced
      // `LoadQuorumFailedError` -- preventing new-document creation in
      // any swarm with online peers.
      this._assertNoIncompleteBootstrapLoad();
      return false;
    } else {
      winningHashHex = quorumResult.winningHashHex;
      // Quorum succeeded: narrow the load loop to the agreeing cohort.
      // The narrowed list is already deduped (it is a filter of
      // `quorumPeers`), so we replace `orderedPeers` wholesale.
      orderedPeers.length = 0;
      orderedPeers.push(...quorumResult.narrowedPeers);
    }

    // Capture the post-narrow cohort size so the failure-reason decision
    // below can distinguish "every agreeing peer bind-failed" (coordinated
    // Byzantine equivocation on the load step -- the dedicated
    // `bind-check-failed-all-agreeing-peers` reason) from "some agreeing
    // peers bind-failed, others failed for transport/protocol reasons"
    // (mixed failure -- caller should treat as transient and retry, the
    // `agreeing-peers-unreachable` reason). The previous logic used
    // `bind-check-failed-all-agreeing-peers` whenever ANY bind failure was
    // recorded, which contradicted the reason's public name and could
    // make callers treat a mixed transient retrieval failure as
    // coordinated Byzantine behaviour.
    // For the legacy non-quorum path (`winningHashHex === null`), this
    // value is unused -- the failure block guards on `winningHashHex`.
    const narrowedCohortSize = orderedPeers.length;

    // Try snapshot-load first for faster initial sync.
    // If the peer returns an empty response (no snapshot available),
    // fall back to the regular doc-load protocol.
    //
    // Quorum frontier binding: when `winningHashHex` is non-null,
    // `_sendLoadRequestAndSync` derives the responder's served frontier
    // STRUCTURALLY from the actual `changes`/`snapshot` payload via
    // `computeServedFrontier`, hashes that, and verifies it equals
    // `winningHashHex` BEFORE applying the sync, so a Byzantine peer
    // that voted for one tip set and serves a different one never gets
    // to mutate in-memory document state. The responder-supplied
    // `message.tips` is checked as a defense-in-depth consistency
    // requirement but is NOT the source of truth -- previous implementations
    // trusted it as such, which let a Byzantine peer game the binding
    // by populating `tips` with the agreed CIDs while serving a
    // divergent `changes` payload.
    //
    // Per-peer bind failures (`_QuorumBindCheckFailedError`) are NOT
    // fatal to the whole load -- they only disqualify the offending
    // peer. The loop records the failure and continues to the NEXT
    // peer in the agreeing cohort, so a single malicious peer that
    // voted for the majority hash and then served a mismatched full
    // load cannot DoS the entire load. Only after every peer in the
    // narrowed cohort has bind-failed does `load()` escalate to
    // `LoadQuorumFailedError(bind-check-failed-all-agreeing-peers)`.
    //
    // The `agreeingPeerBindFailures` map records, per peer, the hex
    // hash the served payload's structural frontier actually hashed to
    // (or the hex of the responder's contradicting `tips` attestation
    // when the defense-in-depth secondary check fails). This is
    // threaded into the final error so callers / operators can see
    // which peers in the agreeing cohort equivocated between the
    // probe round and the load round and what they served instead.
    const agreeingPeerBindFailures = new Map<string, string>();
    for (const peer of orderedPeers) {
      let peerBindFailed = false;
      // An explicitly disabled compaction policy cannot produce snapshots in
      // this swarm. Avoid an empty request/response round-trip—especially on
      // limited circuit-relay connections—before the real document load.
      if (this._compactionConfig.enabled) {
        try {
          console.log('Trying snapshot-load from peer:', peer.toString());
          const snapshotStream = await this.libp2p.dialProtocol(peer, [
            snapshotLoadV3,
          ], { runOnLimitedConnection: true });
          const loaded = await this._sendLoadRequestAndSync(
            snapshotStream,
            serializedRequest,
            winningHashHex,
          );
          if (loaded) {
            this._assertNoIncompleteBootstrapLoad();
            return true;
          }
          // Empty response -- peer has no snapshot, try doc-load below.
        } catch (err) {
          this._assertNoIncompleteBootstrapLoad();
          if (err instanceof _QuorumBindCheckFailedError) {
            // This peer voted hash X in the probe round but the structural
            // frontier of their served payload hashes to something else
            // (or their advertised `tips` contradicts the served payload).
            // Record the failure and skip the doc-load fallback for this
            // peer -- a peer that equivocated once is not given a second
            // chance on the same load round.
            console.warn(
              `[${this.documentPath}] Agreeing peer ${peer.toString()} failed ` +
                `quorum frontier bind on snapshot-load (offending hash ${err.advertisedHex}); ` +
                `marking peer as Byzantine for this load and trying next peer in agreeing cohort.`,
            );
            agreeingPeerBindFailures.set(this._peerIdOf(peer), err.advertisedHex);
            peerBindFailed = true;
          }
          // Else: peer doesn't support snapshot-load protocol, or some
          // other transient error -- fall through to doc-load below.
        }
      }

      if (peerBindFailed) {
        // Don't retry doc-load against a peer that already equivocated
        // on snapshot-load -- continue to the next peer in the cohort.
        continue;
      }

      try {
        console.log('Trying doc-load from peer:', peer.toString());
        const docStream = await this.libp2p.dialProtocol(peer, [
          documentLoadV3,
        ], { runOnLimitedConnection: true });
        const loaded = await this._sendLoadRequestAndSync(
          docStream,
          serializedRequest,
          winningHashHex,
        );
        if (loaded) {
          this._assertNoIncompleteBootstrapLoad();
          return true;
        }
      } catch (err) {
        this._assertNoIncompleteBootstrapLoad();
        if (err instanceof _QuorumBindCheckFailedError) {
          console.warn(
            `[${this.documentPath}] Agreeing peer ${peer.toString()} failed ` +
              `quorum frontier bind on doc-load (offending hash ${err.advertisedHex}); ` +
              `marking peer as Byzantine for this load and trying next peer in agreeing cohort.`,
          );
          agreeingPeerBindFailures.set(this._peerIdOf(peer), err.advertisedHex);
          continue;
        }
        console.warn(
          `Failed to load document via ${documentLoadV3}:`,
          peer.toString(),
        );
      }
    }

    // If quorum was actually run (`winningHashHex !== null`) but the
    // load loop is exhausted, the cohort agreed the document exists
    // yet none of them could serve it. Three sub-cases:
    //
    //   a) `agreeingPeerBindFailures.size === narrowedCohortSize` --
    //      EVERY peer in the agreeing cohort voted for the agreed
    //      hash and then served a divergent payload. Coordinated
    //      Byzantine behaviour is the only explanation; we escalate
    //      with the dedicated `bind-check-failed-all-agreeing-peers`
    //      reason whose public docs say exactly this.
    //
    //   b) `agreeingPeerBindFailures.size > 0` but less than the
    //      cohort size -- MIXED failure: some peers bind-failed
    //      (suspicious) and others failed for transport/protocol
    //      reasons (likely transient). We can't conclude coordinated
    //      Byzantine equivocation across the whole cohort, so we
    //      report `'agreeing-peers-unreachable'` and let the caller
    //      retry. Using `bind-check-failed-all-agreeing-peers` here
    //      would contradict the reason's public name/docs and could
    //      make callers wrongly treat a mixed transient failure as
    //      coordinated Byzantine behaviour. The `agreeingPeerBindFailures`
    //      map is still threaded through for diagnostics so operators
    //      can see which peers in the cohort did bind-fail.
    //
    //   c) `agreeingPeerBindFailures.size === 0` -- every agreeing
    //      peer failed for a transport/protocol reason; we surface
    //      the failure with `'agreeing-peers-unreachable'` so the
    //      caller decides whether to retry or surface to the user.
    //      We MUST NOT fall through to `return false` -- that would
    //      let `open()` initialize a brand-new document despite
    //      quorum just attesting that the document exists.
    //
    // Only after a TRUE no-quorum-was-run outcome (winningHashHex
    // is null -- legacy non-quorum load or quorum disabled / no
    // peers / etc.) is `return false` the right answer.
    if (winningHashHex !== null) {
      if (
        narrowedCohortSize > 0 &&
        agreeingPeerBindFailures.size === narrowedCohortSize
      ) {
        throw new LoadQuorumFailedError({
          documentPath: this.documentPath,
          reason: 'bind-check-failed-all-agreeing-peers',
          respondingCount: 0,
          requiredQ: 0,
          agreement: new Map([[winningHashHex, 0]]),
          agreeingPeerBindFailures,
        });
      }
      throw new LoadQuorumFailedError({
        documentPath: this.documentPath,
        reason: 'agreeing-peers-unreachable',
        respondingCount: 0,
        requiredQ: 0,
        agreement: new Map([[winningHashHex, 0]]),
        agreeingPeerBindFailures,
      });
    }

    // No peer could provide the document -- assume new document.
    this._assertNoIncompleteBootstrapLoad();
    console.log(`No connected peer served ${this.documentPath}`);
    return false;
  }

  /**
   * Opens this peerborne document. The sequence of operations is:
   *
   * 1. Call `.load()` to fetch the document from an existing peer via direct dial.
   * 2. If the document is new (load returned false), run `validateDocumentPath`
   *    (if configured) to ensure the path is allowed before proceeding.
   * 3. Assign the pubsub message handler, subscribe to the document's GossipSub
   *    pubsub topic, and register protocol handlers for load, key-update, and
   *    snapshot-load requests.
   * 4. If `enableTopicValidators` is set, register a GossipSub topic validator
   *    that rejects messages that fail signature verification.
   * 5. For new documents, add the current user as a writer and generate an
   *    initial document encryption key.
   *
   * Once opened, a document can be closed with `.close()`.
   *
   * **Design note:** `load()` runs before protocol handlers are registered, so
   * this node cannot serve incoming load/key-update requests for *this* document
   * during the load window. This is intentional -- validation must complete before
   * subscribing to pubsub to prevent briefly joining an unauthorized topic, and
   * the document is not yet fully open so it has nothing to serve.
   *
   * **Race window:** Messages published by peers between the `load()` response
   * and the `pubsub.subscribe()` call will be missed. This is a deliberate
   * trade-off: validation must complete before subscribing to prevent briefly
   * joining an unauthorized topic. The window is mitigated by the fact that
   * subsequent messages will arrive once subscribed, and the underlying CRDT
   * guarantees eventual consistency. Callers who need to ensure no messages
   * were missed should call `load()` again after `open()` resolves to re-sync
   * the latest state from a peer.
   *
   * @returns `false` when `load()` returned `false` and no existing state had
   *   already been loaded. In that case `open()` treats the document as new by
   *   adding the current user as a writer and generating an initial encryption
   *   key. Note that `load()` returning `false` is ambiguous: it may also mean
   *   all peers failed (see `load()` docs for details).
   * @throws {Error} If `validateDocumentPath` is configured and rejects the path
   *   for a new document. Validation runs before subscribing to pubsub or
   *   registering protocol handlers, so no cleanup is needed on rejection.
   */
  public async open(): Promise<boolean> {
    return this._open();
  }

  private async _open(
    bootstrapContinuation?: InvitationBootstrapContinuation,
  ): Promise<boolean> {
    const continuingInvitationBootstrap =
      this._isActiveInvitationBootstrapContinuation(bootstrapContinuation);
    const assertCanOpen = (): void => {
      if (continuingInvitationBootstrap) {
        if (this._bootstrapLoadApplicationState !== 'pending') {
          throw new Error(
            `Invitation activation for ${this.documentPath} requires pending bootstrap state`,
          );
        }
        return;
      }
      this._assertNoIncompleteBootstrapLoad();
    };
    assertCanOpen();
    if (continuingInvitationBootstrap && !this._invitationBootstrapReady) {
      throw new Error(
        `Invitation activation for ${this.documentPath} requires verified bootstrap state`,
      );
    }
    // Cache the topic once so that subscribe and unsubscribe always target
    // the same string, even if config.pubsubDocumentPrefix changes later.
    this._topic = this._computeTopic();

    // A verified invitation bootstrap already supplied and authenticated the
    // complete state. Skip the normal load in that one-shot case: a failed
    // network load must never make an invited joiner create a divergent new
    // document. The flag is consumed before any await so it cannot leak into a
    // retry after a later failure.
    const bootstrappedFromInvitation = this._invitationBootstrapReady;
    this._invitationBootstrapReady = false;
    const loadedFromPeer = bootstrappedFromInvitation
      ? true
      : await this.load();
    assertCanOpen();
    const isExisting = loadedFromPeer || this._hashes.size > 0;

    // Validate document path BEFORE subscribing to pubsub or registering
    // protocol handlers. This prevents temporarily joining an unauthorized topic.
    // _pubsubHandler is not yet assigned, so if validation throws, close() will
    // not attempt to unsubscribe from a subscription that was never created.
    if (!isExisting) {
      const validateFn = this.swarm.config?.validateDocumentPath;
      if (validateFn) {
        let allowed: boolean;
        try {
          allowed = await validateFn(this.documentPath, this._userPublicKey);
        } catch (err) {
          throw err instanceof Error ? err : new Error(String(err));
        }
        if (allowed !== true) {
          throw new Error(
            `Document path "${this.documentPath}" is not allowed for the current user`,
          );
        }
      }
    }
    assertCanOpen();

    // Assign pubsub handler AFTER validation succeeds. This ensures close()
    // won't try to unsubscribe if open() failed during validation.
    this._pubsubHandler = (rawMessage) => {
      if (rawMessage.detail.topic !== this._topic) return;

      // Decrypt sync message.
      const blockKeyID = rawMessage.detail.data.slice(
        0,
        this._keychainProvider.keyIDLength,
      );
      const blockNonce = rawMessage.detail.data.slice(
        this._keychainProvider.keyIDLength,
        this._keychainProvider.keyIDLength + this._authProvider.nonceBytes,
      );
      const blockData = rawMessage.detail.data.slice(
        this._keychainProvider.keyIDLength + this._authProvider.nonceBytes,
      );
      void this._decryptBlock(blockKeyID, blockNonce, blockData)
        .then((rawContent) => {
          if (!rawContent) {
            // Unauthenticated packets must not trigger network load amplification.
            return;
          }

          const message = snapshotSyncMessageForContext<
            ChangesType,
            PublicKey
          >(
            this._syncMessageSerializer.deserializeSyncMessage(rawContent),
            'ordinary-sync-v1',
          );
          if (message.documentId !== this.documentPath) return;

          return this.sync(message);
        })
        .catch(() => {
          console.error('Inbound sync message handling failed');
        });
    };

    // All registration and subscription steps are inside try/catch so that
    // close() cleans up any partially-registered state on failure.
    const pubsub = this.swarm.heliaNode.libp2p.services
      .pubsub as GossipSub;

    try {
      assertCanOpen();
      // Register this document with the swarm BEFORE subscribing to pubsub.
      // registerDocument() throws on duplicate document paths; doing this first
      // avoids subscribing to a topic that would then be unsubscribed by close()
      // on failure, which could disrupt an already-open instance for the same path.
      this.swarm.registerDocument(this.documentPath, this);

      // Subscribe to pubsub topic.
      // Cast required: EventHandler<CustomEvent<Message>> is incompatible with PubSubBaseProtocol's
      // addEventListener due to duplicate @libp2p/interface versions in the dependency tree
      pubsub.addEventListener('message', this._pubsubHandler as EventListener);
      pubsub.subscribe(this._topic);
      this._subscribed = true;

      // Register GossipSub topic validator for authorization enforcement.
      // When enabled, messages from unauthorized peers are rejected at the
      // transport layer with a P4 penalty in peer scoring.
      // Skip entirely when signing is disabled to avoid unnecessary per-message decryption.
      if (this.swarm.config?.enableTopicValidators && this._isSigningEnabled()) {
        if (typeof pubsub.topicValidators?.set === 'function') {
          const topicValidator: TopicValidatorFn = async (
              _peerId: PeerId,
              message: Message,
            ): Promise<TopicValidatorResult> => {
              try {
                // Keep attacker-controlled decryption and decoding outside the
                // shared state queue. Only the final health and current-writer
                // authorization decision must be serialized with mutations.
                const blockKeyID = message.data.slice(
                  0,
                  this._keychainProvider.keyIDLength,
                );
                const blockNonce = message.data.slice(
                  this._keychainProvider.keyIDLength,
                  this._keychainProvider.keyIDLength +
                    this._authProvider.nonceBytes,
                );
                const blockData = message.data.slice(
                  this._keychainProvider.keyIDLength +
                    this._authProvider.nonceBytes,
                );
                const rawContent = await this._decryptBlock(
                  blockKeyID,
                  blockNonce,
                  blockData,
                );
                if (!rawContent) {
                  // Decryption failed -- key may not be in keychain yet
                  console.warn(
                    `[${this.documentPath}] Topic validator: decryption failed, ignoring message`,
                  );
                  return TopicValidatorResult.Ignore;
                }

                let syncMessage: CRDTSyncMessage<ChangesType, PublicKey>;
                try {
                  syncMessage = snapshotSyncMessageForContext<
                    ChangesType,
                    PublicKey
                  >(
                    this._syncMessageSerializer.deserializeSyncMessage(
                      rawContent,
                    ),
                    'ordinary-sync-v1',
                  );
                } catch {
                  return TopicValidatorResult.Reject;
                }

                if (syncMessage.documentId !== this.documentPath) {
                  return TopicValidatorResult.Reject;
                }

                if (!syncMessage.signature) {
                  return TopicValidatorResult.Reject;
                }

                const { signature, ...messageWithoutSignature } = syncMessage;
                let raw: Uint8Array;
                try {
                  raw = copyUnsharedUint8Array(
                    this._syncMessageSerializer.serializeSyncMessage(
                      messageWithoutSignature,
                    ),
                    1,
                    MAX_SHARED_PROTOCOL_REQUEST_BYTES,
                    'Unsigned sync message',
                  );
                } catch {
                  return TopicValidatorResult.Reject;
                }

                return this._runStateMutation(async () => {
                // Verify the message was signed by an authorized writer for this document
                if ((await this._verifyWriterSignature(raw, signature)) !== true) {
                  return TopicValidatorResult.Reject;
                }
                let rawAfterVerification: Uint8Array;
                try {
                  rawAfterVerification = copyUnsharedUint8Array(
                    this._syncMessageSerializer.serializeSyncMessage(
                      messageWithoutSignature,
                    ),
                    1,
                    MAX_SHARED_PROTOCOL_REQUEST_BYTES,
                    'Unsigned sync message',
                  );
                } catch {
                  return TopicValidatorResult.Reject;
                }
                return constantTimeEqual(raw, rawAfterVerification)
                  ? TopicValidatorResult.Accept
                  : TopicValidatorResult.Reject;
                });
              } catch {
                console.warn(`[${this.documentPath}] Topic validator: unexpected error, ignoring message`);
                return TopicValidatorResult.Ignore;
              }
            };
          this._topicValidator = topicValidator;
          pubsub.topicValidators.set(this._topic, topicValidator);
        }
      }

      if (!isExisting) {
        await this._runStateMutation(async () => {
          if (
            this._bootstrapLoadApplicationState !== 'pristine' ||
            this._hashes.size > 0 ||
            this._lastSyncMessage !== undefined ||
            this._latestSnapshot !== undefined
          ) {
            throw new Error(
              `Document state changed while opening ${this.documentPath}`,
            );
          }
          this._createdLocally = true;
          // Stage the current user as the founder writer. Live authorization is
          // installed only after the replicated ACL change is published.
          const founderWriter = await this._prepareWriterAdd(
            this._userPublicKey,
          );

          // Add initial document key.
          console.log(`Adding a key to ${this.documentPath}`);
          await this._keychain.add();

          // The founder ACL must be part of the replicated change DAG. Keeping
          // it only in the creator's in-memory ACL lets first-load peers decrypt
          // document state but leaves them unable to authenticate later writer
          // updates (or write as the same restored identity).
          await this._publishPreparedWriterChange(
            founderWriter,
            'open founder writer',
          );
        });
      }
    } catch (err) {
      // Clean up any partially-registered state to avoid leaked handlers,
      // subscriptions, or registry entries.
      await this.close().catch(() => {});
      throw err;
    }

    return isExisting;
  }

  /**
   * Disconnects from this peerborne document. Running this method disconnects from the
   * document pubsub topic.
   *
   * Multiple open `PeerborneDocument` instances sharing the same
   * `documentPath` are not supported. Cleanup is instance-safe, so a failed or
   * stale instance does not unregister a newer live document.
   */
  public async close() {
    // Use the cached topic for cleanup; it is initialized in the constructor.
    const topic = this._topic;

    if (this._pubsubHandler) {
      const pubsub = this.swarm.heliaNode.libp2p.services
        .pubsub as GossipSub;

      // Only unsubscribe if this instance actually subscribed. If open()
      // failed before pubsub.subscribe() completed, unsubscribing here
      // would remove a subscription belonging to another instance.
      if (this._subscribed) {
        pubsub.unsubscribe(topic);
        this._subscribed = false;
      }

      // Cast required: see addEventListener comment above
      pubsub.removeEventListener('message', this._pubsubHandler as EventListener);

      if (
        this._topicValidator &&
        pubsub.topicValidators?.get(topic) === this._topicValidator
      ) {
        pubsub.topicValidators.delete(topic);
      }
      this._topicValidator = undefined;
    }

    // Unregister this document from the shared V2 protocol handler registry.
    // Pass `this` so only this instance is removed (instance-safe).
    this.swarm.unregisterDocument(this.documentPath, this);
  }

  /**
   * Given a sync message containing a list of hashes:
   * - Fetch new changes that are only hashes (missing change itself) from the blockstore (using the hash).
   * - Apply new changes to the existing CRDT document.
   *
   * @param message A sync message to apply.
   * @returns `true` if the message was applied successfully, `false` if rejected due to auth failure.
   *
   * **BREAKING CHANGE:** Return type changed from `Promise<void>` to
   * `Promise<boolean>`. TypeScript callers with explicit `Promise<void>` type
   * annotations will need to update. Callers should now check the returned
   * boolean to determine whether the message was applied successfully. The
   * former public `verifySignature` bypass was also removed; ordinary sync
   * always verifies signatures when signing is enabled. Protocol handlers
   * that already verified a specialized message use an internal boundary.
   */
  public async sync(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<boolean> {
    return this._runStateMutation(() =>
      this._syncUnlocked(message, true, 'ordinary-sync-v1'),
    );
  }

  /** Apply a sync message after any required membership-queue admission. */
  private async _syncUnlocked(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    verifySignature: boolean,
    context: Extract<SyncMessageContext, 'ordinary-sync-v1' | 'load-response-v3' | 'invitation-bootstrap-v1'>,
    onStateApplicationStart?: () => void,
    continuePendingBootstrapApplication = false,
    onLogicalKeychainChange?: () => void,
    changeFetchOptions: DocumentChangeFetchOptions<DocumentKey> = {},
  ): Promise<boolean> {
    try {
      message = snapshotSyncMessageForContext<ChangesType, PublicKey>(
        message,
        context,
      );
    } catch {
      return false;
    }
    if (message.documentId !== this.documentPath) {
      return false;
    }
    const assertStillActive = (): void => {
      throwIfLoadAborted(changeFetchOptions.signal);
      changeFetchOptions.assertStillActive?.();
    };
    assertStillActive();
    if (continuePendingBootstrapApplication) {
      if (this._bootstrapLoadApplicationState !== 'pending') {
        throw new Error(
          `Bootstrap sync for ${this.documentPath} requires pending state`,
        );
      }
    } else {
      this._assertNoIncompleteBootstrapLoad();
    }
    const signature = message.signature;
    const signingEnabled = this._isSigningEnabled();
    if (signingEnabled && !signature) {
      return false;
    }

    // Only serialize for signature verification -- skip when signing is disabled
    // to avoid expensive serialization of large messages.
    if (signingEnabled && verifySignature) {
      const { signature: _signature, ...expectedUnsigned } = message;
      let messageWithoutSignature: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        const verificationMessage = snapshotSyncMessageForContext<
          ChangesType,
          PublicKey
        >(message, context);
        const { signature: _signature, ...unsigned } = verificationMessage;
        messageWithoutSignature = unsigned;
      } catch {
        return false;
      }
      let raw: Uint8Array;
      try {
        raw = copyUnsharedUint8Array(
          this._syncMessageSerializer.serializeSyncMessage(
            messageWithoutSignature,
          ),
          1,
          MAX_SHARED_PROTOCOL_REQUEST_BYTES,
          'Unsigned sync message',
        );
      } catch {
        return false;
      }
      if (!syncMessageMatchesSnapshot(expectedUnsigned, messageWithoutSignature, context)) {
        return false;
      }
      if ((await awaitLoadWork(this._verifyWriterSignature(raw, signature!), changeFetchOptions.signal)) !== true) {
        console.warn(
          `Received a sync message with an invalid signature for ${message.documentId}`,
        );
        return false;
      }
      let rawAfterVerification: Uint8Array;
      try {
        rawAfterVerification = copyUnsharedUint8Array(
          this._syncMessageSerializer.serializeSyncMessage(
            messageWithoutSignature,
          ),
          1,
          MAX_SHARED_PROTOCOL_REQUEST_BYTES,
          'Unsigned sync message',
        );
      } catch {
        return false;
      }
      if (!constantTimeEqual(raw, rawAfterVerification) || !syncMessageMatchesSnapshot(expectedUnsigned, messageWithoutSignature, context)) {
        return false;
      }
    }

    // Validate and collect the complete ACL pre-pass before any keychain, ACL,
    // snapshot, or document mutation. This makes malformed/over-budget change
    // trees all-or-nothing at the sync boundary.
    let changeTreePreflight:
      | ReturnType<typeof this._collectACLFromTree>
      | undefined;
    const incomingChanges = message.changes;
    const incomingChangeId = message.changeId;
    if (incomingChanges !== undefined) {
      if (incomingChangeId === undefined) {
        throw new TypeError('Change tree is missing its root CID');
      }
      changeTreePreflight = this._collectACLFromTree(
        incomingChanges,
        incomingChangeId,
      );
    }
    assertStillActive();

    let stateApplicationStarted = false;
    const beginStateApplication = (): void => {
      assertStillActive();
      if (stateApplicationStarted) return;
      stateApplicationStarted = true;
      onStateApplicationStart?.();
    };

    // Keychain changes are provider-opaque. Only an absent wire field is a
    // generic no-op; concrete providers decide whether any present value is a
    // semantic no-op through a staged state commitment below.
    const keychainChanges = message.keychainChanges;
    const hasKeychainChanges = keychainChanges !== undefined;

    // The built-in providers do not share one byte-level empty encoding. When
    // staging and logical commitments are available,
    // compare the live and projected key sequences before reserving a bootstrap
    // instance. A semantic no-op is still committed atomically so providers
    // retain causal metadata, but it does not expose new logical key state.
    // Opaque legacy keychains retain the conservative begin-before-merge behavior.
    const preparedKeychainMerge =
      hasKeychainChanges &&
      onStateApplicationStart !== undefined &&
      this._keychain.prepareMerge
        ? this._keychain.prepareMerge(keychainChanges)
        : undefined;
    let logicalKeychainStateChanged: boolean | undefined;
    if (
      preparedKeychainMerge?.stateCommitment &&
      this._keychain.stateCommitment
    ) {
      const [liveCommitment, preparedCommitment] = await awaitLoadWork(
        Promise.all([
          this._keychain.stateCommitment(),
          preparedKeychainMerge.stateCommitment(),
        ]),
        changeFetchOptions.signal,
      );
      logicalKeychainStateChanged = !constantTimeEqual(
        liveCommitment,
        preparedCommitment,
      );
    }
    assertStillActive();
    // Update/replace list of document keys (if provided).
    if (hasKeychainChanges) {
      try {
        if (preparedKeychainMerge) {
          if (logicalKeychainStateChanged !== false) {
            await awaitLoadWork(
              preparedKeychainMerge.hydrateKeys(),
              changeFetchOptions.signal,
            );
            assertStillActive();
            beginStateApplication();
          }
          assertStillActive();
          try {
            preparedKeychainMerge.commit();
          } catch (error) {
            // A provider-reported no-op can still partially mutate before throwing.
            this._markBootstrapStateApplicationPending();
            throw error;
          }
        } else {
          beginStateApplication();
          this._keychain.merge(keychainChanges);
        }
        if (logicalKeychainStateChanged === true) {
          onLogicalKeychainChange?.();
        }
        console.log(`Updated keychain in ${this.documentPath}`);
      } catch (e) {
        console.error(
          `Failed to merge keychain changes in ${this.documentPath}`,
        );
        throw e;
      }
    }

    // Pre-pass: apply only ACL nodes from the change tree to populate
    // _writers/_readers. This is needed before snapshot verification since
    // _verifySnapshotSignature() requires writer keys. ACL merges are
    // idempotent, so re-applying them in _syncDocumentChanges() is safe.
    if (changeTreePreflight && changeTreePreflight.aclEntries.length > 0) {
      beginStateApplication();
      await this._applyCollectedACL(
        changeTreePreflight.aclEntries,
        assertStillActive,
        changeFetchOptions.signal,
      );
      assertStillActive();
    }

    // Apply snapshot if present and more recent than ours.
    // Happens before full change sync so document changes that are already
    // covered by the snapshot don't need to be applied first (CRDTs handle
    // duplicate application correctly, but this avoids unnecessary work).
    if (message.snapshot) {
      const incoming = message.snapshot;
      if (
        !this._latestSnapshot ||
        incoming.compactedCount > this._latestSnapshot.compactedCount ||
        (incoming.compactedCount === this._latestSnapshot.compactedCount &&
          String(incoming.lastChangeNodeCID ?? '') >
            String(this._latestSnapshot.lastChangeNodeCID ?? ''))
      ) {
        // Verify the snapshot signature against the deterministic payload
        // by trying all authorized writers (publicKey may not survive
        // serialization for all key types, e.g. CryptoKey).
        // When signing is disabled, skip serialization and signature
        // verification -- accept the snapshot unconditionally.
        // WARNING: This means any peer can inject arbitrary snapshot state when
        // signing is disabled. Only disable signing in trusted or development
        // environments where all peers are known and authenticated by other means.
        let snapshotSignatureValid = !signingEnabled;
        if (signingEnabled) {
          try {
            const stateBytes = this._changesSerializer.serializeChanges(incoming.state);
            const signPayload = this._buildSnapshotSignPayload(
              stateBytes, incoming.lastChangeNodeCID, incoming.timestamp, incoming.compactedCount,
            );
            snapshotSignatureValid = await awaitLoadWork(
              this._verifySnapshotSignature(signPayload, incoming.signature),
              changeFetchOptions.signal,
            );
          } catch {
            console.warn(
              `Rejected snapshot for ${this.documentPath}: malformed snapshot fields`,
            );
          }
        }
        if (!snapshotSignatureValid) {
          console.warn(
            `Rejected snapshot for ${this.documentPath}: no authorized writer produced a valid signature`,
          );
        } else {
          // Apply the snapshot state. Use applySnapshot when available (e.g.
          // Automerge save format differs from incremental changes), otherwise
          // fall back to remoteChange (works for Yjs where snapshots are valid updates).
          beginStateApplication();
          this._document = this._crdtProvider.applySnapshot
            ? this._crdtProvider.applySnapshot(this._document, incoming.state)
            : this._crdtProvider.remoteChange(this._document, incoming.state);
          this._latestSnapshot = incoming;
          // Ensure our local document change count is at least as high as
          // the snapshot's compactedCount. This prevents re-triggering
          // compaction below the threshold after applying a remote snapshot.
          this._documentChangeCount = Math.max(
            this._documentChangeCount,
            incoming.compactedCount,
          );
          this._changesSinceSnapshot = 0;
          // Mark the snapshot boundary CID as seen so _mergeSyncTree skips
          // it and all ancestor nodes. This prevents re-applying pre-snapshot
          // changes (which the snapshot already covers) and avoids inflating
          // _documentChangeCount / _changesSinceSnapshot.
          if (incoming.lastChangeNodeCID) {
            this._hashes.add(incoming.lastChangeNodeCID);
          }
          console.log(
            `Applied remote snapshot for ${this.documentPath}: ${incoming.compactedCount} nodes compacted`,
          );
        }
      }
    }

    // Full change sync: process all nodes (document + ACL) from the DAG.
    // ACL nodes applied in the pre-pass above will be re-merged idempotently.
    if (changeTreePreflight) {
      beginStateApplication();
      await this._syncDocumentChanges(
        message.changeId,
        changeTreePreflight.changes,
        changeFetchOptions,
      );
      assertStillActive();
    }

    assertStillActive();
    return true;
  }

  /**
   * Subscribes a change handler to the document. Use this method to receive real-time
   * updates to the document.
   *
   * @param id A unique id for this handler. Used to unsubscribe this handler.
   * @param handler A function that is called when a change is received.
   * @param originFilter Determines what kinds of change events trigger the handler.
   *     'remote' indicates that the change was received from a remote peer.
   *     'local' indicates that the change was received from the local document.
   *     'all' indicates that all changes should be handled.
   */
  public subscribe(
    id: string,
    handler: PeerborneDocumentChangeHandler<DocType, PublicKey>,
    originFilter: 'all' | 'remote' | 'local' = 'all',
  ) {
    this._assertNoIncompleteBootstrapLoad();
    switch (originFilter) {
      case 'all': {
        this._remoteHandlers[id] = handler;
        this._localHandlers[id] = handler;
        break;
      }
      case 'remote': {
        this._remoteHandlers[id] = handler;
        break;
      }
      case 'local': {
        this._localHandlers[id] = handler;
        break;
      }
    }
  }

  /**
   * Unsubscribes a change handler from the document.
   *
   * @param id The id of the handler to unsubscribe.
   */
  public unsubscribe(id: string) {
    if (this._remoteHandlers[id]) {
      delete this._remoteHandlers[id];
    }
    if (this._localHandlers[id]) {
      delete this._localHandlers[id];
    }
  }

  // TODO: Unit tests for PeerborneDocument require mocking libp2p, Helia,
  // and all providers -- deferred to integration testing (see e2e/).

  /**
   * Start a change transaction. Changes made via `addChange()` will be batched
   * and applied atomically when `endChange()` is called.
   */
  public startChange() {
    this._assertNoIncompleteBootstrapLoad();
    if (this._inTransaction) {
      throw new Error('Transaction already in progress');
    }
    this._inTransaction = true;
    this._pendingChangeFns = [];
  }

  /**
   * Queue a change function within an active transaction.
   * Must be called between `startChange()` and `endChange()`.
   */
  public addChange(changeFn: ChangeFnType) {
    this._assertNoIncompleteBootstrapLoad();
    if (!this._inTransaction) {
      throw new Error('No transaction in progress. Call startChange() first.');
    }
    if (this._committing) {
      throw new Error('Cannot add changes while endChange() is committing.');
    }
    this._pendingChangeFns.push(changeFn);
  }

  /**
   * End the transaction and apply all queued changes atomically.
   * This sends a single sync message for all batched changes.
   *
   * On failure (from any step: write check, CRDT apply, or network publish),
   * the transaction is aborted and the document reference is rolled back.
   * For immutable CRDT providers (e.g. Automerge), rollback is reliable
   * because `localChange()` returns a new document object.
   *
   * **Known limitation -- in-place mutating providers:** For CRDT providers
   * that mutate in place (e.g. Yjs), rollback does NOT undo mutations.
   * Yjs's `localChange()` mutates the document object directly and returns
   * the same reference, so restoring the saved reference after failure has
   * no effect -- the mutations have already been applied to the shared
   * Y.Doc. Callers using Yjs should treat a failed transaction as leaving
   * the local document in a potentially inconsistent state and consider
   * re-syncing from peers.
   *
   * **Known limitation -- concurrent remote changes during rollback:** The
   * rollback sets `_document` back to the snapshot captured when
   * `endChange()` is called (before applying the pending change functions).
   * Because `_makeChange()` is async and the node remains
   * subscribed to pubsub throughout, remote sync messages may arrive and be
   * applied to `_document` between the start of the transaction and the
   * point of failure. Rolling back to the original snapshot **reverts those
   * remote changes as well**, not just the local batch. This is acceptable
   * because the CRDT layer guarantees eventual consistency -- the reverted
   * remote changes will be re-applied on the next sync cycle or document
   * load. If transaction failure is critical, callers should re-sync the
   * document after a failed transaction (e.g. call `load()` or wait for
   * the next pubsub round) to ensure remote state is promptly restored.
   *
   * **Known limitation -- partial internal state on failure:** If
   * `_makeChange()` fails partway through (e.g. encryption succeeds but
   * pubsub publish throws), `_hashes` may retain CIDs for the rolled-back
   * change (see below). Other counters and bookkeeping fields
   * (`_lastSyncMessage`, `_documentChangeCount`, `_changesSinceSnapshot`,
   * `_recentTips`) ARE restored from snapshots captured before
   * `_makeChange()` -- see the "Internal metadata rollback" section below
   * for details.
   *
   * **Specifically, `_hashes` may retain CIDs for the rolled-back change.**
   * Because `_hashes` is used to skip already-seen changes during sync,
   * any CID added before the failure will cause that change to be silently
   * skipped if it arrives again via pubsub or `load()`. This means the
   * rolled-back change is effectively "lost" from this peer's perspective
   * until `_hashes` is rebuilt. **Callers should call `load()` after a
   * failed transaction** to re-sync the full document state from a peer
   * and restore consistency. A new transaction must be started after a
   * failure.
   *
   * **Internal metadata rollback:** On failure, `_lastSyncMessage`,
   * `_documentChangeCount`, `_changesSinceSnapshot`, and `_recentTips`
   * are restored from snapshots captured before `_makeChange()`.
   * (`_recentTips` is bounded to `MAX_RECENT_TIPS` entries so the snapshot
   * is a cheap shallow array copy.) For `_hashes` and
   * `_referencedAncestors`, all entries added to each Set after its
   * pre-attempt size are removed. Because the node remains
   * subscribed to pubsub during the async transaction, this may include
   * CIDs appended by concurrent remote syncs, not just local ones.
   * This is acceptable because CRDT convergence guarantees those remote
   * CIDs will be re-added on the next sync cycle or document load.
   * The approach is O(n) iteration but O(delta) memory -- no full
   * array clone -- and avoids disrupting any concurrent sync iteration
   * that `clear()` would break. A new transaction must be started after
   * a failure.
   *
   * @throws {Error} If any step in the commit pipeline fails.
   */
  public async endChange(message?: string) {
    return this._runStateMutation(() => this._endChangeUnlocked(message));
  }

  private async _endChangeUnlocked(message?: string) {
    if (!this._inTransaction) {
      throw new Error('No transaction in progress. Call startChange() first.');
    }
    if (this._committing) {
      throw new Error('endChange() is already in progress. Await the previous call.');
    }

    // Snapshot pending fns so late addChange() calls during await don't
    // unpredictably modify the batch being committed.
    const pendingFns = [...this._pendingChangeFns];
    if (pendingFns.length === 0) {
      this._inTransaction = false;
      this._pendingChangeFns = [];
      return;
    }

    const originalDocument = this._document;
    // Snapshot internal metadata so we can restore on failure.
    // Only track the Set size (O(1)) instead of cloning the entire Set (O(n)):
    // _makeChange adds at most one CID, and JS Sets iterate in insertion order,
    // so on rollback we remove only entries appended after this point.
    const hashSizeBefore = this._hashes.size;
    const referencedAncestorsSizeBefore = this._referencedAncestors.size;
    const lastSyncSnapshot = this._lastSyncMessage;
    const changeCountSnapshot = this._documentChangeCount;
    const compactionCountSnapshot = this._changesSinceSnapshot;
    // Bounded copy (max MAX_RECENT_TIPS entries) -- cheap to snapshot.
    const recentTipsSnapshot = [...this._recentTips];

    this._committing = true;
    try {
      await this._ensureCurrentUserCanWrite();

      // Compose all queued change functions into a single localChange call
      // to produce one atomic delta. This ensures providers like Automerge
      // (which return incremental deltas) don't drop earlier changes.
      const composedFn = ((doc: any) => {
        for (const fn of pendingFns) {
          (fn as any)(doc);
        }
      }) as ChangeFnType;

      // Note: YjsProvider.localChange mutates the document in-place and returns
      // the same reference, so rollback on failure is best-effort for Yjs.
      // Automerge returns a new immutable document, so rollback is reliable.
      const [newDocument, changes] = this._crdtProvider.localChange(
        this._document,
        message || '',
        composedFn,
      );
      this._document = newDocument;

      await this._makeChange(changes);

      // Success -- clear transaction state.
      this._inTransaction = false;
      this._pendingChangeFns = [];
    } catch (err) {
      // Abort transaction on ANY error (ensureWrite, localChange, or makeChange).
      // Roll back document and internal metadata (best-effort for in-place
      // mutating providers like Yjs).
      this._document = originalDocument;
      // Remove only the CIDs appended by _makeChange instead of clearing and
      // re-populating the entire Set. This avoids mutating the Set during
      // concurrent sync (clear() would disrupt any in-progress iteration)
      // and is O(delta) instead of O(n).
      // Iterate the Set (O(n)) but only collect entries past the snapshot
      // threshold into a small buffer (O(delta) memory) -- avoids cloning
      // the entire Set into an array via spread.
      if (this._hashes.size > hashSizeBefore) {
        const toRemove: string[] = [];
        let i = 0;
        for (const hash of this._hashes) {
          if (i >= hashSizeBefore) {
            toRemove.push(hash);
          }
          i++;
        }
        for (const hash of toRemove) {
          this._hashes.delete(hash);
        }
      }
      // Mirror the `_hashes` rollback for `_referencedAncestors`: remove
      // only entries appended past the pre-attempt size. Same rationale --
      // insertion-ordered Set iteration plus O(delta) memory -- and same
      // best-effort caveat for concurrent sync that may have inserted into
      // either set in parallel.
      if (this._referencedAncestors.size > referencedAncestorsSizeBefore) {
        const toRemoveRefs: string[] = [];
        let j = 0;
        for (const cid of this._referencedAncestors) {
          if (j >= referencedAncestorsSizeBefore) {
            toRemoveRefs.push(cid);
          }
          j++;
        }
        for (const cid of toRemoveRefs) {
          this._referencedAncestors.delete(cid);
        }
      }
      this._lastSyncMessage = lastSyncSnapshot;
      this._documentChangeCount = changeCountSnapshot;
      this._changesSinceSnapshot = compactionCountSnapshot;
      this._recentTips = recentTipsSnapshot;
      this._inTransaction = false;
      this._pendingChangeFns = [];
      throw err;
    } finally {
      this._committing = false;
    }
  }

  /**
   * Applies a new local change (defined by `changeFn`) to the peerborne document and updates
   * all peers.
   *
   * @param changeFn A function that makes changes to the current CRDT document.
   * @param message An optional change message/description to include.
   */
  public async change(changeFn: ChangeFnType, message?: string) {
    return this._runStateMutation(() =>
      this._changeUnlocked(changeFn, message),
    );
  }

  private async _changeUnlocked(changeFn: ChangeFnType, message?: string) {
    if (this._inTransaction) {
      throw new Error('Cannot call change() during an active transaction. Use addChange() instead.');
    }
    await this._ensureCurrentUserCanWrite();

    const [newDocument, changes] = this._crdtProvider.localChange(
      this._document,
      message || '',
      changeFn,
    );
    // Apply local change w/ automerge.
    this._document = newDocument;

    await this._makeChange(changes);
  }

  /**
   * Returns the total number of change nodes (including ACL nodes) tracked
   * in the current document history. This is a count of all known CIDs,
   * not the depth of the longest path in the DAG.
   */
  public historySize(): number {
    this._assertNoIncompleteBootstrapLoad();
    return this._hashes.size;
  }

  /**
   * Returns the current snapshot, if one exists.
   */
  public get latestSnapshot(): CRDTSnapshotNode<ChangesType, PublicKey> | undefined {
    this._assertNoIncompleteBootstrapLoad();
    return this._latestSnapshot;
  }

  /**
   * Lazy-load a historical change block by CID.
   *
   * Used to fetch change data on demand for history-visibility consumers (e.g.
   * audit UI, diff viewers) when the change has been pruned from the in-memory
   * sync tree but the block is still present in the Helia blockstore. The
   * returned `ChangesType` is the deserialized, decrypted payload.
   *
   * Returns `undefined` when:
   * - The CID is not in `_hashes` (we have never seen this change).
   * - The block is missing from the blockstore (e.g. it was GC'd locally and
   *   no peer has re-served it yet). Callers that need stronger guarantees can
   *   fall back to dialing peers via the existing sync protocols.
   *
   * Throws when:
   * - The CID is malformed.
   * - The block is present locally but decryption fails (wrong/missing
   *   keychain entry) or the payload fails to deserialize (corrupted data).
   *   These are treated as hard errors so callers can distinguish a recoverable
   *   "missing block" condition from a stronger data-integrity issue.
   *
   * @param cid CID string of the change block to load.
   * @returns The deserialized change payload, or `undefined` if unavailable.
   */
  public async loadChangeBlock(cid: string): Promise<ChangesType | undefined> {
    this._assertNoIncompleteBootstrapLoad();
    const changes = await lazyLoadChangeBlock<CID, ChangesType>(
      cid,
      this._hashes,
      (c) => CID.parse(c),
      (parsedCID) => this._getBlock(parsedCID),
      // Intentionally no-op onMissing: missing-after-GC is an expected outcome
      // for the lazy-load path (audit UIs, diff viewers) and should not spam
      // logs. Callers that want visibility can detect `undefined` themselves.
    );
    this._assertNoIncompleteBootstrapLoad();
    return changes;
  }

  /**
   * Check whether a CID is known to this document (i.e. present in the
   * in-memory `_hashes` set). Useful for callers that want to confirm a
   * change exists before attempting a lazy load.
   *
   * Note: returning `true` only proves the CID has been observed (it is
   * tracked in `_hashes` for sync-message dedup). It does NOT guarantee the
   * underlying block is locally available -- after `gcAfterPrune` runs, the
   * CID remains in `_hashes` even though the block has been removed from the
   * blockstore. Callers should therefore still handle `loadChangeBlock(cid)`
   * resolving to `undefined` (and may need to fall back to dialing peers).
   */
  public hasChange(cid: string): boolean {
    this._assertNoIncompleteBootstrapLoad();
    return this._hashes.has(cid);
  }

  /**
   * Creates a snapshot of the current document state.
   *
   * The snapshot compacts all current change nodes into a single state representation.
   * Requires `CRDTProvider.getSnapshot()` to be implemented.
   *
   * @returns The created snapshot node, or undefined if the provider does not support snapshots.
   * @throws {Error} If the current user does not have write access to this document.
   *   Only writers are authorized to create snapshots.
   */
  public async snapshot(): Promise<CRDTSnapshotNode<ChangesType, PublicKey> | undefined> {
    return this._runStateMutation(() => this._snapshotUnlocked());
  }

  private async _snapshotUnlocked(): Promise<CRDTSnapshotNode<ChangesType, PublicKey> | undefined> {
    await this._ensureCurrentUserCanWrite();

    if (!this._crdtProvider.getSnapshot) {
      console.warn('CRDTProvider does not implement getSnapshot(); compaction disabled.');
      this._snapshotUnsupported = true;
      return undefined;
    }

    const state = this._crdtProvider.getSnapshot(this._document);
    const lastChangeNodeCID = this._lastSyncMessage?.changeId ?? '';
    const timestamp = Date.now();

    // Create a deterministic, unambiguous binary payload to sign.
    // Use _documentChangeCount (document-kind changes only) rather than
    // _hashes.size (which includes ACL nodes) to keep the semantic consistent.
    // Binary layout with length prefixes avoids ambiguity and is efficient
    // for large state blobs (no JSON/Array.from overhead).
    const compactedCount = this._documentChangeCount;
    const stateBytes = this._changesSerializer.serializeChanges(state);
    let signature: Uint8Array;
    if (this._isSigningEnabled()) {
      const signPayload = this._buildSnapshotSignPayload(
        stateBytes, lastChangeNodeCID, timestamp, compactedCount,
      );
      signature = await this._authProvider.sign(signPayload, this._userKey);
    } else {
      signature = new Uint8Array(0);
    }

    const snapshotNode: CRDTSnapshotNode<ChangesType, PublicKey> = {
      state,
      lastChangeNodeCID,
      compactedCount,
      signature,
      publicKey: this._userPublicKey,
      timestamp,
    };

    this._latestSnapshot = snapshotNode;
    this._changesSinceSnapshot = 0;

    // Prune old change nodes from the in-memory sync tree if configured.
    // The snapshot is NOT stored on _lastSyncMessage -- it is only included
    // in load/snapshot-load responses via _latestSnapshot, to avoid bloating
    // every incremental pubsub sync message with the full snapshot state.
    if (this._lastSyncMessage && this._compactionConfig.pruneAfterSnapshot) {
      const prunedCIDs = this._pruneChanges(this._compactionConfig.keepRecentNodes);

      // Delete pruned blocks from the Helia blockstore asynchronously, but only
      // when explicitly opted-in via `gcAfterPrune`. Filter out any CIDs that
      // remain reachable from the post-prune sync tree (e.g. ACL nodes that
      // were re-attached as leaves) and the snapshot boundary CID itself.
      // Fire-and-forget: GC errors are logged but don't block snapshot creation.
      if (
        this._compactionConfig.gcAfterPrune &&
        prunedCIDs.size > 0 &&
        this._lastSyncMessage?.changes &&
        this._lastSyncMessage.changeId
      ) {
        const protectedCIDs = lastChangeNodeCID
          ? [lastChangeNodeCID]
          : [];
        const deletable = filterDeletableCIDs(
          prunedCIDs,
          this._lastSyncMessage.changeId,
          this._lastSyncMessage.changes,
          protectedCIDs,
        );
        if (deletable.size > 0) {
          this._gcPrunedBlocks(deletable).catch((err) => {
            console.error(`Blockstore GC failed for ${this.documentPath}:`, err);
          });
        }
      }
    }

    console.log(
      `Created snapshot for ${this.documentPath}: ${snapshotNode.compactedCount} nodes compacted`,
    );

    return snapshotNode;
  }

  /**
   * Get list of writers.
   *
   * @return List of public keys with write access.
   */
  public async getWriters(): Promise<PublicKey[]> {
    this._assertNoIncompleteBootstrapLoad();
    const writers = await retryACLConflict(() => this._writers.users());
    this._assertNoIncompleteBootstrapLoad();
    return writers;
  }

  /**
   * Grant write authorization to an existing explicit reader. Users are
   * identified by their public keys. Call `addReader()` before promoting a new
   * writer so a later `removeWriter()` can safely return them to read-only
   * access without misrepresenting retained document-key access as revocation.
   *
   * The local ACL commits only after GossipSub publication resolves. A rejected
   * publish rolls back local DAG bookkeeping, but transport rejection is
   * delivery-ambiguous: a remote peer may already have received the delta.
   * This is a local publication boundary, not a distributed transaction.
   *
   * @param writer User's public key
   */
  public async addWriter(writer: PublicKey) {
    this._assertNoIncompleteBootstrapLoad();
    if (typeof this._authProvider.serializePublicKey !== 'function') {
      const stableIdentity =
        (typeof writer !== 'object' || writer === null) &&
        typeof writer !== 'function';
      return this._runStateMutation(() =>
        this._addWriterUnlocked(
          writer,
          undefined,
          stableIdentity,
          typeof writer === 'string' && writer.length > 0
            ? writer
            : undefined,
        ),
      );
    }
    const snapshot = this._startMembershipPublicKeySnapshot(
      writer,
      'Writer addition',
    );
    return this._runStateMutation(async () => {
      const {
        publicKey: stableWriter,
        serialized: serializedWriter,
      } = await snapshot;
      return this._addWriterUnlocked(
        stableWriter,
        undefined,
        true,
        serializedWriter,
      );
    });
  }

  private async _addWriterUnlocked(
    stableWriter: PublicKey,
    beginMutation?: () => void,
    stableIdentity = false,
    serializedWriter?: string,
  ): Promise<void> {
    await this._ensureCurrentUserCanWrite();

    if (!stableIdentity) {
      requireSerializePublicKey(this._authProvider, 'Writer addition');
      throw new Error(
        'Writer addition requires a public-key snapshot before it is queued',
      );
    }

    if (serializedWriter === undefined) {
      const serializePublicKey = this._authProvider.serializePublicKey;
      if (typeof serializePublicKey === 'function') {
        serializedWriter = await serializePublicKey.call(
          this._authProvider,
          stableWriter,
        );
      } else if (
        typeof stableWriter === 'string' &&
        stableWriter.length > 0
      ) {
        serializedWriter = stableWriter;
      } else {
        requireSerializePublicKey(this._authProvider, 'Writer promotion');
      }
    }
    if (
      typeof serializedWriter !== 'string' ||
      serializedWriter.length === 0
    ) {
      throw new TypeError(
        'Writer promotion requires a non-empty canonical public-key encoding',
      );
    }
    if (
      (await retryACLConflict(() =>
        this._readers.check(stableWriter),
      )) !== true
    ) {
      throw new Error(
        `Cannot add writer to "${this.documentPath}": the target must first ` +
          'be added to the explicit readers ACL and have a locally registered ' +
          'BeeKEM leaf.',
      );
    }

    if (!this._beekemInitialized || !this._beekem) {
      throw new Error(
        `Cannot add writer to "${this.documentPath}": the local BeeKEM tree ` +
          'has not been initialized, so the target\'s live reader membership ' +
          'cannot be verified.',
      );
    }

    const recordedKemPublicKey =
      this._readerKemPublicKeys.get(serializedWriter);
    if (
      !recordedKemPublicKey ||
      recordedKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH
    ) {
      throw new Error(
        `Cannot add writer to "${this.documentPath}": the target has no valid ` +
          'identity-bound reader KEM public key recorded locally. Register ' +
          'the reader\'s BeeKEM leaf before promotion.',
      );
    }

    const liveLeafIndex = await this._beekem.findLeafByPublicKey(
      new Uint8Array(recordedKemPublicKey),
    );
    if (liveLeafIndex === undefined) {
      throw new Error(
        `Cannot add writer to "${this.documentPath}": the target\'s recorded ` +
          'KEM public key does not resolve to exactly one live, non-blanked ' +
          'BeeKEM leaf.',
      );
    }

    if (liveLeafIndex === this._beekem.myLeafIndex) {
      throw new Error(
        `Cannot add writer to "${this.documentPath}": the identity-bound ` +
          'KEM key resolves to the local BeeKEM leaf, not a remote member.',
      );
    }

    const cachedLeafIndex = this._readerLeafIndices.get(serializedWriter);
    if (
      cachedLeafIndex !== undefined &&
      cachedLeafIndex !== liveLeafIndex
    ) {
      throw new Error(
        `Cannot add writer to "${this.documentPath}": the target\'s cached ` +
          'BeeKEM leaf does not match the live tree. Refusing promotion from ' +
          'divergent membership state.',
      );
    }
    // Run every onboarding check above even for a legacy ACL that already
    // lists the target as a writer. A no-op must not bless malformed state.
    if (
      (await retryACLConflict(() =>
        this._writers.check(stableWriter),
      )) === true
    ) {
      return;
    }

    // Construct a detached writer ACL change. The invitation admission guard
    // runs immediately before the first live/DAG mutation, not during staging.
    const prepared = await this._prepareWriterAdd(stableWriter);
    beginMutation?.();
    await this._publishPreparedWriterChange(prepared, 'addWriter');
    if (cachedLeafIndex === undefined) {
      this._readerLeafIndices.set(serializedWriter, liveLeafIndex);
    }
  }

  /**
   * Remove a user's explicit write authorization while preserving their
   * explicit reader authorization. A writer-only legacy member is rejected:
   * this operation does not rotate document keys, so silently removing its
   * only ACL row would misrepresent retained read access as full revocation.
   * To fully revoke an editor, first downgrade it here, then call
   * `removeReader` so the reader-removal flow rotates the BeeKEM epoch.
   *
   * The local ACL commits only after GossipSub publication resolves. A rejected
   * publish rolls back local DAG bookkeeping, but transport rejection is
   * delivery-ambiguous: a remote peer may already have received the delta.
   * This is a local publication boundary, not a distributed transaction.
   *
   * @param writer User's public key
   */
  public async removeWriter(writer: PublicKey) {
    this._assertNoIncompleteBootstrapLoad();
    if (typeof this._authProvider.serializePublicKey !== 'function') {
      const stableIdentity =
        (typeof writer !== 'object' || writer === null) &&
        typeof writer !== 'function';
      return this._runStateMutation(() =>
        this._removeWriterUnlocked(writer, stableIdentity),
      );
    }
    const localWriterSnapshot = this._startMembershipPublicKeySnapshot(
      this._userPublicKey,
      'Writer removal local identity',
    );
    const writerSnapshot = this._startMembershipPublicKeySnapshot(
      writer,
      'Writer removal',
    );
    return this._runStateMutation(async () => {
      const {
        publicKey: stableWriter,
        serialized: serializedWriter,
      } = await writerSnapshot;
      return this._removeWriterUnlocked(
        stableWriter,
        true,
        serializedWriter,
        localWriterSnapshot,
      );
    });
  }

  private async _removeWriterUnlocked(
    stableWriter: PublicKey,
    stableIdentity = false,
    serializedWriter?: string,
    localWriterSnapshot?: Promise<{
      publicKey: PublicKey;
      serialized: string;
    }>,
  ): Promise<void> {
    await this._ensureCurrentUserCanWrite();

    // Preserve the historical idempotent no-op for absent targets without
    // requiring identity codecs from legacy providers.
    if (
      (await retryACLConflict(() =>
        this._writers.check(stableWriter),
      )) !== true
    ) {
      return;
    }

    if (!stableIdentity) {
      requireSerializePublicKey(this._authProvider, 'Writer removal');
      throw new Error(
        'Writer removal requires a public-key snapshot before it is queued',
      );
    }
    let isLocalWriter = false;
    if (serializedWriter !== undefined) {
      if (localWriterSnapshot === undefined) {
        throw new Error(
          'Writer removal requires a local identity snapshot before it is ' +
            'queued',
        );
      }
      isLocalWriter =
        serializedWriter ===
        (await localWriterSnapshot).serialized;
    } else {
      isLocalWriter = Object.is(stableWriter, this._userPublicKey);
    }
    if (isLocalWriter) {
      throw new Error(
        `Cannot remove the local writer from "${this.documentPath}". ` +
          'Another authorized writer must perform that role transition.',
      );
    }
    if (
      (await retryACLConflict(() =>
        this._readers.check(stableWriter),
      )) !== true
    ) {
      throw new Error(
        `Cannot remove writer from "${this.documentPath}": the target must ` +
          'remain explicitly authorized as a reader. Add or repair its ' +
          'reader membership before downgrading it.',
      );
    }

    // Keep live authorization unchanged until the ACL delta is published.
    const prepared = await this._prepareWriterRemove(stableWriter);
    await this._publishPreparedWriterChange(prepared, 'removeWriter');
  }

  /**
   * Returns a list of all public keys with read access.
   *
   * Deduplicates users that appear in both reader and writer ACLs,
   * which can occur due to concurrent edits or manual addition to both lists.
   *
   * @return List of public keys with read access.
   */
  public async getReaders(): Promise<PublicKey[]> {
    this._assertNoIncompleteBootstrapLoad();
    const [readers, writers] = await Promise.all([
      retryACLConflict(() => this._readers.users()),
      retryACLConflict(() => this._writers.users()),
    ]);
    if (writers.length === 0) {
      this._assertNoIncompleteBootstrapLoad();
      return [...readers];
    }
    if (readers.length === 0) {
      this._assertNoIncompleteBootstrapLoad();
      return [...writers];
    }
    const serializer = this._authProvider.serializePublicKey;
    if (serializer !== undefined) {
      if (typeof serializer !== 'function') {
        throw new TypeError(
          'AuthProvider.serializePublicKey must be a function',
        );
      }
      const serializePublicKey = serializer.bind(this._authProvider);
      const readerIdentities = new Set<string>();
      // Keep identity-codec work bounded to one in-flight call. Custom auth
      // providers are not required to support unbounded parallel invocation.
      for (const reader of readers) {
        const identity = await serializePublicKey(reader);
        assertCanonicalACLIdentity(identity);
        readerIdentities.add(identity);
      }
      const filteredWriters: PublicKey[] = [];
      for (const writer of writers) {
        const identity = await serializePublicKey(writer);
        assertCanonicalACLIdentity(identity);
        if (!readerIdentities.has(identity)) filteredWriters.push(writer);
      }
      this._assertNoIncompleteBootstrapLoad();
      return [...readers, ...filteredWriters];
    }

    // Legacy providers without canonical serialization must use ACL.check.
    // Keep those calls serial because serialized ACLs reject overlap; a
    // Promise.all fan-out would turn N checks into a quadratic retry storm.
    const filteredWriters: PublicKey[] = [];
    for (const writer of writers) {
      if (
        (await retryACLConflict(() => this._readers.check(writer))) !==
        true
      ) {
        filteredWriters.push(writer);
      }
    }
    this._assertNoIncompleteBootstrapLoad();
    return [...readers, ...filteredWriters];
  }

  /**
   * Add a new user as a valid reader. Users are identified by their public keys.
   *
   * After updating the readers ACL, this attempts to send a BeeKEM Welcome
   * to the new reader so they receive (a) the keychain changes appropriate
   * for the document's `historyVisibility` setting (so they can decrypt at
   * least the current state), and (b) the invitation epoch ID they should
   * record for subsequent `since_invited` history filtering. The Welcome
   * is delivered via the `beekemWelcomeV2` protocol to every
   * currently-connected peer; the receiving document ignores Welcomes
   * addressed to a different reader.
   *
   * When a recipient KEM key is supplied, the BeeKEM registration is prepared
   * on a detached tree and the reader ACL is claimed before publication. Live
   * authorization is granted only after publication resolves, in the same
   * synchronous turn that installs the prepared tree and identity caches.
   *
   * The initial release supports the first reader plus exact retries for that
   * identity. After `removeReader` advances the BeeKEM tree, adding a
   * replacement is rejected before ACL or BeeKEM state changes.
   *
   * CONFIDENTIALITY: the Welcome's keychain delta is sealed with ECIES
   * (P-256 ECDH + AES-256-GCM) under `readerKemPublicKey`, so only the
   * intended recipient can decrypt it. The recipient binding
   * (`welcomeRecipient`) is the **authorization** gate; the sealed
   * payload is the **confidentiality** gate. See `_sendBeeKEMWelcome`
   * for the full construction.
   *
   * @param reader User's identity (signing) public key.
   * @param readerKemPublicKey Optional raw SEC1-uncompressed P-256
   *   ECDH public key (65 bytes) of the reader's KEM key pair. The
   *   reader must hold the matching private key (see
   *   `setKemKeyPair`). When this is `undefined`, the readers-ACL
   *   update is still broadcast but **no Welcome is sent**. The caller must
   *   later re-invoke `addReader` with the recipient KEM key or arrange an
   *   explicit key-recovery path; an ordinary load cannot bootstrap a peer
   *   that lacks the current document key. (The library refuses to broadcast
   *   an un-sealed Welcome because that would leak key material.)
   * @returns The BeeKEM Welcome used for this reader, or `null` when no
   *   recipient KEM key was supplied or recoverable.
   */
  public async addReader(
    reader: PublicKey,
    readerKemPublicKey?: Uint8Array,
  ): Promise<BeeKEMWelcomeV2 | null> {
    this._assertNoIncompleteBootstrapLoad();
    const stableReaderKemPublicKey =
      readerKemPublicKey === undefined
        ? undefined
        : copyUnsharedUint8Array(
            readerKemPublicKey,
            ECIES_P256_PUBLIC_KEY_LENGTH,
            ECIES_P256_PUBLIC_KEY_LENGTH,
            'Reader KEM public key',
          );
    const snapshot = this._startMembershipPublicKeySnapshot(
      reader,
      'BeeKEM reader onboarding',
    );
    return this._runStateMutation(async () => {
      const {
        publicKey: stableReader,
        serialized: serializedReader,
      } = await snapshot;
      return this._addReaderUnlocked(
        stableReader,
        serializedReader,
        stableReaderKemPublicKey,
      );
    });
  }

  private async _addReaderUnlocked(
    stableReader: PublicKey,
    serializedReader: string,
    readerKemPublicKey?: Uint8Array,
    broadcastWelcome = true,
    beginMutation?: () => void,
  ): Promise<BeeKEMWelcomeV2 | null> {
    await this._ensureCurrentUserCanWrite();

    if (this._beekemInitialized !== (this._beekem !== null)) {
      throw new Error(
        `[${this.documentPath}] addReader: BeeKEM initialization state is ` +
          'internally inconsistent; discard this document instance.',
      );
    }

    // Validate prerequisites BEFORE mutating any ACL state. The founder
    // (writer who created the document) MUST have called `setKemKeyPair`
    // before they can seed the BeeKEM tree. The leaf key pair must be a
    // real ECDH key pair the founder controls so future joiners that
    // decrypt path-key encryptions against this node land on consistent
    // key material. A founder that calls `addReader` before
    // `setKemKeyPair` is misconfigured -- surface the error before any
    // ACL change is committed, so a half-applied state (ACL row added
    // but no BeeKEM seeding / Welcome sent) is impossible.
    if (!this._beekemInitialized && !this._kemKeyPair) {
      throw new Error(
        `[${this.documentPath}] addReader: cannot seed the BeeKEM ratchet ` +
          `tree because the local user has not installed a KEM key pair ` +
          `via setKemKeyPair. Call setKemKeyPair with a P-256 ECDH key ` +
          `pair before adding readers.`,
      );
    }

    // Snapshot and validate the complete P-256 point before committing an ACL
    // row. Length alone is insufficient: WebCrypto also rejects off-curve
    // points, and discovering that after `_makeChange` would permanently
    // occupy the founder-plus-one slot without a usable BeeKEM leaf.
    const validatedReaderKemPublicKey = readerKemPublicKey === undefined
      ? undefined
      : new Uint8Array(readerKemPublicKey);
    if (
      validatedReaderKemPublicKey !== undefined &&
      validatedReaderKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH
    ) {
      throw new Error(
        `[${this.documentPath}] addReader: readerKemPublicKey must be ` +
          `${ECIES_P256_PUBLIC_KEY_LENGTH} bytes (SEC1-uncompressed P-256), ` +
          `got ${validatedReaderKemPublicKey.byteLength}`,
      );
    }
    if (validatedReaderKemPublicKey) {
      await importEciesPublicKey(validatedReaderKemPublicKey);
    }

    // Founder-vs-joined-writer gate. The BeeKEM tree is rooted in
    // exactly one of two ways (see the long comment on `_beekem`):
    //   - **Founder**: a writer who CREATED the document. `open()` records
    //     that provenance explicitly in `_createdLocally` before onboarding
    //     prepares a tree seeded with their local KEM key pair at leaf 0.
    //   - **Joined writer**: a writer who was added to an existing
    //     document by another writer. They MUST receive a BeeKEM
    //     Welcome (which bootstraps their tree via `processWelcome`)
    //     before they can manipulate the tree.
    //
    // Without this gate, a joined writer whose `_beekemInitialized` is still
    // false (no Welcome received yet) could prepare and install a divergent
    // founder tree from non-empty document state. Their later PathUpdates and
    // Welcomes would come from a tree shape that no other peer shares.
    //
    // Change count cannot identify founders: normal `open()` has already
    // replicated the founder-writer ACL before the first addReader call.
    // Use the explicit creation provenance instead.
    if (!this._beekemInitialized && !this._createdLocally) {
      throw new Error(
        `[${this.documentPath}] addReader: cannot register a reader -- ` +
          `this writer has document state but no BeeKEM tree bootstrapped ` +
          `from a Welcome. A joined writer must complete the signed ` +
          `invitation bootstrap before they can add or remove readers ` +
          `cryptographically. Initializing a fresh founder tree here would ` +
          `silently diverge from every other peer's tree state.`,
      );
    }

    // Idempotent on the ACL side, but if the caller has only now obtained
    // the recipient's KEM public key (e.g. a previous `addReader` call
    // skipped the Welcome because the key was unknown), still emit the
    // Welcome so the existing ACL row can be paired with keychain
    // material. Without this branch the warning emitted below on the
    // first call would point at a recovery path that is itself a no-op.
    const alreadyReader =
      (await retryACLConflict(() => this._readers.check(stableReader))) === true;
    if (
      !alreadyReader &&
      (await retryACLConflict(() => this._readers.users())).length > 0
    ) {
      throw new Error(
        `[${this.documentPath}] addReader: the initial release supports ` +
          `one active collaborator per document (founder plus one reader). ` +
          `Adding another reader would require an add-side BeeKEM PathUpdateV2 ` +
          `that is not implemented yet.`,
      );
    }
    if (!alreadyReader && (this._beekem?.memberCount ?? 0) > 1) {
      throw new Error(
        `[${this.documentPath}] addReader: replacement readers are not ` +
          `supported after BeeKEM membership has advanced. Create a new ` +
          `document instead of reusing the revoked membership tree.`,
      );
    }
    if (!alreadyReader && validatedReaderKemPublicKey) {
      await this._assertKemPublicKeyAvailableForNewLeaf(
        validatedReaderKemPublicKey,
      );
    }

    // Freeze the visibility-filtered keychain payload before changing the ACL
    // or BeeKEM tree. Some providers cannot safely project an isolated current
    // key once the keychain has more than one epoch; discovering that only
    // while sending the Welcome would leave an authorized reader without key
    // material. Invitation bootstrap performs its own complete capacity
    // preflight and supplies the Welcome in its signed response.
    let preparedWelcomeKeychain: Uint8Array | undefined;
    if (broadcastWelcome && validatedReaderKemPublicKey) {
      const keychainChanges = await this._keychainChangesForWelcome();
      const serializedKeychain =
        this._changesSerializer.serializeChanges(keychainChanges);
      assertSharedProtocolRequestSize(
        serializedKeychain.byteLength,
        'BeeKEM Welcome keychain preflight',
      );
      preparedWelcomeKeychain = new Uint8Array(serializedKeychain);
      const envelopeWithoutBeeKEM = welcomeKeychainEnvelopeBytes(
        preparedWelcomeKeychain.byteLength,
      );
      assertProjectedInitialInvitationWelcomeCapacity(
        envelopeWithoutBeeKEM,
        this.documentPath,
      );
    }
    // Prepare the BeeKEM registration on a detached tree before staging the
    // ACL change. A crypto/import/tree failure therefore cannot leave live
    // authorization ahead of the key-distribution state needed to revoke the
    // reader later.
    let preparedRegistration: PreparedBeeKEMReaderRegistration | undefined;
    if (validatedReaderKemPublicKey) {
      preparedRegistration = await this._prepareBeeKEMReaderRegistration(
        serializedReader,
        validatedReaderKemPublicKey,
      );
    }

    // Record the new reader in the BeeKEM ratchet tree so:
    //   a) a future `removeReader` call can cryptographically revoke
    //      them (their leaf is blanked and the path re-keyed), and
    //   b) the inviter can ship the resulting BeeKEM `Welcome` (the
    //      path keys encrypted under the joiner's leaf public key)
    //      inside the sealed Welcome payload so the joiner can
    //      bootstrap their local BeeKEM state and apply subsequent
    //      PathUpdates.
    //
    // The leaf is seeded with `readerKemPublicKey` -- the reader's own
    // KEM public key, also used as the ECIES recipient for the sealed
    // payload. The reader holds the matching private key, so they can
    // decrypt the path-key chain in the Welcome (see
    // `BeeKEM.processWelcome`).
    //
    // When `readerKemPublicKey` is absent the leaf is left
    // UNALLOCATED: an unrelated placeholder key would let
    // `removeReader` find a leaf to blank, but the joiner could
    // never bootstrap their own BeeKEM state without the private
    // material that matches the placeholder. The library refuses
    // that ambiguous half-onboarded state and surfaces the warning
    // below directing the caller to re-invoke with the KEM key.
    //
    // The ACL provider and BeeKEM tree now share one synchronous local commit
    // boundary. Obtain the ACL claim before publication, install the already
    // prepared BeeKEM snapshot first, and grant authorization last. All work
    // after publication resolves is limited to claimed finalization and
    // prebuilt reference swaps.
    if (!alreadyReader) {
      const preparedReader = await this._prepareReaderAdd(stableReader);
      const readerClaim = this._claimPreparedCommit(
        preparedReader.claimCommit,
        'Reader ACL commit claim',
      );
      beginMutation?.();
      await this._publishPreparedReaderChange(
        preparedReader,
        'add reader',
        () => {
          preparedRegistration?.install?.();
          finalizePreparedCommitClaim(
            readerClaim,
            'Reader ACL commit claim',
          );
        },
      );
    } else if (preparedRegistration?.install) {
      // Exact retries can repair a missing local cache/tree installation for
      // an ACL member. No provider claim is needed because authorization is
      // already live and this branch only swaps document-owned staged state.
      beginMutation?.();
      preparedRegistration.install();
    }
    const beekemWelcomeForJoiner = preparedRegistration?.welcome ?? null;

    // Without the recipient's KEM public key we cannot seal the
    // Welcome payload, and we will NEVER send an un-sealed Welcome --
    // that would broadcast `keychainChanges` to every connected peer.
    if (!validatedReaderKemPublicKey) {
      if (!alreadyReader) {
        console.warn(
          `[${this.documentPath}] addReader: BeeKEM Welcome skipped because ` +
            `the caller did not provide \`readerKemPublicKey\`. The reader ` +
            `has been added to the readers ACL, but to deliver the document ` +
            `key the caller must either (a) re-invoke \`addReader(reader, ` +
            `readerKemPublicKey)\` once the recipient's raw SEC1 P-256 ECDH ` +
            `public key is available, or arrange another explicit ` +
            `key-recovery path. An ordinary document load cannot bootstrap ` +
            `a recipient that lacks the current document key.`,
          );
      }
      return null;
    }

    // The signed invitation acceptance carries this same recipient-bound
    // Welcome directly. Skip fan-out in that path: awaiting every
    // connected peer would let an unrelated non-draining stream stall the
    // membership lock and the invitation response.
    if (!broadcastWelcome) {
      return beekemWelcomeForJoiner;
    }

    if (!preparedWelcomeKeychain || !beekemWelcomeForJoiner) {
      throw new Error('BeeKEM Welcome preflight was not completed');
    }

    // Send a BeeKEM Welcome with the visibility-filtered epoch keys + BeeKEM
    // bootstrap so the new reader can decrypt eligible epochs and apply future
    // PathUpdates. This does not redact retained operations within an epoch.
    // Failures are logged but do not abort because the ACL change has already
    // been broadcast. Recovery requires another recipient-bound Welcome or an
    // explicit key-recovery path; ordinary load responses use the current key.
    try {
      await this._sendBeeKEMWelcome(
        stableReader,
        validatedReaderKemPublicKey,
        beekemWelcomeForJoiner,
        preparedWelcomeKeychain,
      );
    } catch (err) {
      console.warn(
        `Failed to send BeeKEM Welcome for ${this.documentPath}:`,
        err,
      );
    }
    return beekemWelcomeForJoiner;
  }

  /**
   * Grant an invitation recipient access and construct the encrypted material
   * returned by the invitation join protocol. The caller is responsible for
   * signing the outer acceptance and enforcing single-use offer semantics.
   * Membership work is not transactional: an error after mutation begins can
   * leave partial or complete recipient membership without a returned bundle.
   * Only an exact, same-process retry is eligible to repair and attest that
   * state.
   *
   * @internal
   */
  public async buildInvitationBootstrap(
    reader: PublicKey,
    readerKemPublicKey: Uint8Array,
    role: 'reader' | 'editor',
    assertCanMutate?: () => void,
  ): Promise<InvitationBootstrapBundle> {
    this._assertNoIncompleteBootstrapLoad();
    const stableReaderKemPublicKey = copyUnsharedUint8Array(
      readerKemPublicKey,
      ECIES_P256_PUBLIC_KEY_LENGTH,
      ECIES_P256_PUBLIC_KEY_LENGTH,
      'Invitation recipient KEM public key',
    );
    const snapshot = this._startMembershipPublicKeySnapshot(
      reader,
      'Public invitations',
    );
    return this._runStateMutation(async () => {
      const {
        publicKey: stableReader,
        serialized: serializedReader,
      } = await snapshot;
      return this._buildInvitationBootstrapUnlocked(
        stableReader,
        serializedReader,
        stableReaderKemPublicKey,
        role,
        assertCanMutate,
      );
    });
  }

  private async _initialInvitationMembershipState(
    recipient: PublicKey,
  ): Promise<InitialInvitationMembershipState> {
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'Public invitations',
    );
    const [founder, serializedRecipient, readers, writers] = await Promise.all([
      serializePublicKey(this._userPublicKey),
      serializePublicKey(recipient),
      retryACLConflict(() => this._readers.users()),
      retryACLConflict(() => this._writers.users()),
    ]);
    const [serializedReaders, serializedWriters] = await Promise.all([
      Promise.all(readers.map((readerKey) => serializePublicKey(readerKey))),
      Promise.all(writers.map((writerKey) => serializePublicKey(writerKey))),
    ]);
    return {
      createdLocally: this._createdLocally,
      founder,
      recipient: serializedRecipient,
      readers: serializedReaders,
      writers: serializedWriters,
    };
  }

  private async _buildInvitationBootstrapUnlocked(
    reader: PublicKey,
    serializedReader: string,
    readerKemPublicKey: Uint8Array,
    role: 'reader' | 'editor',
    assertCanMutate?: () => void,
  ): Promise<InvitationBootstrapBundle> {
    assertCanMutate?.();
    assertInitialInvitationHistoryVisibility(this._historyVisibility);
    if (role !== 'reader' && role !== 'editor') {
      throw new Error(`Unsupported invitation role: ${String(role)}`);
    }

    const capacityPlan = await this._prepareInvitationBootstrapCapacity(reader);

    const beginMutation = createInvitationMutationAdmission(assertCanMutate);

    const kemPublicKey = new Uint8Array(readerKemPublicKey);
    const beekemWelcome = await prepareInitialInvitationMembership({
      role,
      getState: () => this._initialInvitationMembershipState(reader),
      // The public wrappers use this same queue, so internal composition must
      // call the unlocked helpers to avoid a reentrant wait on our own slot.
      addReader: async () => {
        // Recheck after asynchronous capacity and topology preflight. The
        // one-shot guard passed below checks again immediately before the
        // first ACL or BeeKEM state writer, then admits the rest of that commit.
        assertCanMutate?.();
        const welcome = await this._addReaderUnlocked(
          reader,
          serializedReader,
          kemPublicKey,
          false,
          beginMutation,
        );
        if (!welcome) {
          throw new Error(
            `Cannot build invitation bootstrap for ${this.documentPath}: ` +
              'no BeeKEM Welcome is available for the recipient',
          );
        }
        return welcome;
      },
      addWriter: () =>
        this._addWriterUnlocked(
          reader,
          beginMutation,
          true,
          serializedReader,
        ),
      repairReaders: async () => {
        beginMutation();
        return this._makeChange(
          await retryACLConflict(() => this._readers.current()),
          crdtReaderChangeNode,
        );
      },
      repairWriters: async () => {
        beginMutation();
        return this._makeChange(
          await retryACLConflict(() => this._writers.current()),
          crdtWriterChangeNode,
        );
      },
    });

    const [welcomeEpochId, documentKey] = await this._keychain.current();
    const keychainChanges = capacityPlan.keychainChanges;
    const sealedPayload = encodeWelcomeSealedPayloadV2({
      keychainChanges:
        this._changesSerializer.serializeChanges(keychainChanges),
      beekemWelcome,
    });
    const sealedWelcome = await eciesSeal(
      sealedPayload,
      await importEciesPublicKey(kemPublicKey),
    );
    if (
      sealedWelcome.byteLength - capacityPlan.welcomeWithoutBeeKEMBytes >
      INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES
    ) {
      throw new Error(
        `Invitation Welcome for ${this.documentPath} exceeded the declared attested-profile growth bound`,
      );
    }
    assertInvitationOpaquePayloadCapacity(
      sealedWelcome,
      'Welcome',
      this.documentPath,
    );

    const bootstrapMessage = this._createSyncMessage('invitation-bootstrap-v1');
    bootstrapMessage.keychainChanges = keychainChanges;
    if (capacityPlan.snapshot) {
      bootstrapMessage.snapshot = capacityPlan.snapshot;
    }
    bootstrapMessage.tips = computeServedFrontier(
      bootstrapMessage.changeId,
      bootstrapMessage.changes,
      capacityPlan.snapshot?.lastChangeNodeCID,
    );
    bootstrapMessage.signature =
      await this._signAsWriterUnconditional(bootstrapMessage);
    if (
      Base64.toUint8Array(bootstrapMessage.signature).byteLength >
      INITIAL_INVITATION_MAX_SIGNATURE_BYTES
    ) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} exceeded the declared signature bound`,
      );
    }
    const bootstrapPlaintext =
      this._syncMessageSerializer.serializeSyncMessage(bootstrapMessage);
    if (
      bootstrapPlaintext.byteLength -
        capacityPlan.serializedBootstrapBaselineBytes >
      INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES
    ) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} exceeded the declared attested-profile membership-growth bound`,
      );
    }
    const encrypted = await this._authProvider.encrypt(
      bootstrapPlaintext,
      documentKey,
    );
    if (!encrypted.nonce) {
      throw new Error(
        `Cannot build invitation bootstrap for ${this.documentPath}: ` +
          'encryption returned no nonce',
      );
    }

    const encryptedBootstrap = concatUint8Arrays(
      welcomeEpochId,
      encrypted.nonce,
      encrypted.data,
    );
    if (
      encryptedBootstrap.byteLength - bootstrapPlaintext.byteLength >
      INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES
    ) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} exceeded the declared encryption bound`,
      );
    }
    assertInvitationOpaquePayloadCapacity(
      encryptedBootstrap,
      'bootstrap',
      this.documentPath,
    );

    return {
      welcomeEpochId: new Uint8Array(welcomeEpochId),
      sealedWelcome,
      encryptedBootstrap,
    };
  }

  /** Freeze and size the complete bootstrap before changing ACL/BeeKEM state. */
  private async _prepareInvitationBootstrapCapacity(
    reader: PublicKey,
  ): Promise<
    InvitationBootstrapCapacityPlan<ChangesType, PublicKey>
  > {
    this._assertInitialInvitationCapacityProfile();

    // Detach provider-owned and caller-supplied aliases synchronously before
    // the first await. The queue excludes Peerborne API writers; these round
    // trips also keep a previously supplied sync tree or returned snapshot
    // reference from changing the bytes underneath the capacity projection.
    const frozenCurrentMessage =
      this._syncMessageSerializer.deserializeSyncMessage(
        this._syncMessageSerializer.serializeSyncMessage(
          this._createSyncMessage('ordinary-sync-v1'),
        ),
      );
    this._lastSyncMessage = frozenCurrentMessage;
    const snapshot = this._latestSnapshot
      ? {
          ...this._latestSnapshot,
          state: this._changesSerializer.deserializeChanges(
            this._changesSerializer.serializeChanges(
              this._latestSnapshot.state,
            ),
          ),
          signature: new Uint8Array(this._latestSnapshot.signature),
        }
      : undefined;
    const frozenTips = computeServedFrontier(
      frozenCurrentMessage.changeId,
      frozenCurrentMessage.changes,
      snapshot?.lastChangeNodeCID,
    );

    const readerAlreadyPresent =
      (await retryACLConflict(() => this._readers.check(reader))) === true;
    let hasRetryLeaf = false;
    let hasRetryWelcome = false;
    if (this._beekem?.memberCount === 2 && readerAlreadyPresent) {
      const serializePublicKey = requireSerializePublicKey(
        this._authProvider,
        'Invitation BeeKEM retry validation',
      );
      const serializedReader = await serializePublicKey(reader);
      const leafIndex = this._readerLeafIndices.get(serializedReader);
      hasRetryLeaf = leafIndex !== undefined;
      hasRetryWelcome =
        leafIndex !== undefined && this._beekemWelcomeByLeaf.has(leafIndex);
    }
    assertInitialInvitationBeeKEMCapacity(
      this._beekem?.memberCount,
      readerAlreadyPresent,
      this.documentPath,
      hasRetryLeaf,
      hasRetryWelcome,
    );
    assertInitialInvitationHistoryVisibility(this._historyVisibility);

    const [rawKeychainChanges, rawFullKeychainChanges] = await Promise.all([
      this._keychainChangesForWelcome(),
      this._keychain.history(),
    ]);
    const keychainChanges = this._changesSerializer.deserializeChanges(
      this._changesSerializer.serializeChanges(rawKeychainChanges),
    );
    const fullKeychainChanges = this._changesSerializer.deserializeChanges(
      this._changesSerializer.serializeChanges(rawFullKeychainChanges),
    );
    const projection = projectInitialInvitationBootstrapCapacity({
      currentMessage: frozenCurrentMessage,
      keychainChanges: fullKeychainChanges,
      snapshot,
      tips: frozenTips,
      serializer: this._syncMessageSerializer,
    });
    assertProjectedInitialInvitationBootstrapCapacity(
      projection,
      this.documentPath,
    );

    const welcomeWithoutBeeKEM = welcomeKeychainEnvelopeBytes(
      this._changesSerializer.serializeChanges(keychainChanges).byteLength,
    );
    assertProjectedInitialInvitationWelcomeCapacity(
      welcomeWithoutBeeKEM,
      this.documentPath,
    );
    return {
      keychainChanges,
      snapshot,
      serializedBootstrapBaselineBytes: projection.serializedBaselineBytes,
      welcomeWithoutBeeKEMBytes: welcomeWithoutBeeKEM,
    };
  }

  private async _assertAcceptedInvitationMembership(
    issuerPublicKey: PublicKey,
    role: 'reader' | 'editor',
    signal?: AbortSignal,
  ): Promise<void> {
    throwIfLoadAborted(signal);
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'Public invitations',
    );
    const [issuer, recipient, readers, writers] = await awaitLoadWork(
      Promise.all([
        serializePublicKey(issuerPublicKey),
        serializePublicKey(this._userPublicKey),
        retryLoadACLConflict(() => this._readers.users(), signal),
        retryLoadACLConflict(() => this._writers.users(), signal),
      ]),
      signal,
    );
    const [serializedReaders, serializedWriters] = await awaitLoadWork(
      Promise.all([
        Promise.all(readers.map((readerKey) => serializePublicKey(readerKey))),
        Promise.all(writers.map((writerKey) => serializePublicKey(writerKey))),
      ]),
      signal,
    );
    throwIfLoadAborted(signal);
    assertAcceptedInvitationMembershipTopology(
      {
        issuer,
        recipient,
        readers: serializedReaders,
        writers: serializedWriters,
      },
      role,
    );
  }

  private async _activateAcceptedInvitationBootstrap(
    founderAddress: string,
    issuerPublicKey: PublicKey,
    role: 'reader' | 'editor',
    bootstrapContinuation: InvitationBootstrapContinuation,
  ): Promise<void> {
    try {
      const existing = await this._open(bootstrapContinuation);
      if (!existing) {
        throw new Error('Invitation bootstrap attempted to create a new document');
      }
      if (
        !(await this._loadInvitationCatchUp(
          founderAddress,
          issuerPublicKey,
          role,
          bootstrapContinuation,
        ))
      ) {
        throw new Error('Invitation bootstrap catch-up load failed');
      }
      await this._assertAcceptedInvitationMembership(issuerPublicKey, role);
      if (
        !this._isActiveInvitationBootstrapContinuation(bootstrapContinuation)
      ) {
        throw new Error('Invitation bootstrap continuation is no longer active');
      }
      // No continuation path is needed beyond this point. Retire the exact
      // capability while state is still pending so completion can publish a
      // healthy document to synchronous handlers and reentrant public reads.
      // If finalization fails, the pending marker remains the durable gate.
      this._activeInvitationBootstrapContinuation = undefined;
      await this._completeBootstrapStateApplicationUnlocked();
    } catch (error) {
      this._invitationBootstrapReady = false;
      // The invitation remains pending throughout open and catch-up. Cleanup
      // never publishes a transient complete state, so synchronous getters,
      // observers, and queued public mutations remain fail-closed.
      if (this._bootstrapLoadApplicationState !== 'pending') {
        this._markBootstrapStateApplicationPending();
      }
      await this.close().catch(() => {});
      throw error;
    }
  }

  /**
   * Apply a recipient-bound invitation bootstrap and activate the document
   * without invoking normal first-load/new-document detection.
   *
   * The outer invitation acceptance must be verified against
   * `issuerPublicKey` before this method is called. This method independently
   * verifies the enclosed bootstrap signature against that exact key. It may
   * only run on the reserved candidate created by `Peerborne.acceptInvitation`;
   * failures discard that unexposed instance rather than returning partial
   * provider state to application code.
   *
   * @internal
   */
  public async acceptInvitationBootstrap(
    bundle: InvitationBootstrapBundle,
    issuerPublicKey: PublicKey,
    role: 'reader' | 'editor',
    founderAddress: string,
  ): Promise<void> {
    if (this._bootstrapLoadApplicationState !== 'pristine' || !this.swarm.isPendingInvitationDocument(this.documentPath, this)) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} requires a pristine document instance`,
      );
    }
    if (role !== 'reader' && role !== 'editor') {
      throw new Error(`Unsupported invitation role: ${String(role)}`);
    }
    if (this._hashes.size > 0 || this._subscribed) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} requires a fresh document instance`,
      );
    }
    const kemKeyPair = this._kemKeyPair;
    if (!kemKeyPair || !this._kemPublicKeyRaw) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} requires a KEM key pair ` +
          'installed via setKemKeyPair',
      );
    }
    const invitationKemKeyPair = kemKeyPair;
    const invitationKemPublicKeyRaw = new Uint8Array(this._kemPublicKeyRaw);
    const invitationBundle = snapshotInvitationBootstrapBundle(
      bundle,
      this._keychainProvider.keyIDLength,
      this._authProvider.nonceBytes,
    );
    const invitationEpoch = new Uint8Array(invitationBundle.welcomeEpochId);

    let welcomeEnvelope;
    try {
      welcomeEnvelope = decodeWelcomeSealedPayloadV2(
        await eciesOpen(
          invitationBundle.sealedWelcome,
          invitationKemKeyPair.privateKey,
        ),
      );
    } catch {
      throw new Error('Invitation sealed Welcome could not be opened');
    }
    if (!welcomeEnvelope.beekemWelcome) {
      throw new Error('Invitation sealed Welcome is missing BeeKEM bootstrap state');
    }

    assertInitialInvitationBeeKEMWelcomeShape(
      welcomeEnvelope.beekemWelcome,
    );

    const beekem = new BeeKEM();
    try {
      await beekem.processWelcome(
        welcomeEnvelope.beekemWelcome,
        invitationKemKeyPair.privateKey,
        invitationKemKeyPair.publicKey,
      );
    } catch {
      throw new Error('Invitation BeeKEM bootstrap could not be processed');
    }
    if (beekem.memberCount !== 2 || beekem.myLeafIndex !== 2) {
      throw new Error(
        'Invitation BeeKEM bootstrap did not produce the founder-plus-one recipient state',
      );
    }

    const keychainChanges = this._changesSerializer.deserializeChanges(
      welcomeEnvelope.keychainChanges,
    );
    const prepareKeychainMerge = this._keychain.prepareMerge;
    if (!prepareKeychainMerge) {
      throw new Error(
        `Invitation bootstrap for ${this.documentPath} requires transactional keychain merge support`,
      );
    }
    await this._runInvitationBootstrapStateApplication(
      async (beginStateApplication, bootstrapContinuation) => {
        const preparedKeychainMerge = prepareKeychainMerge.call(
          this._keychain,
          keychainChanges,
        );
        if (
          preparedKeychainMerge.currentKeyId === undefined ||
          !constantTimeEqual(
            preparedKeychainMerge.currentKeyId,
            invitationBundle.welcomeEpochId,
          )
        ) {
          throw new Error(
            'Invitation Welcome epoch is not the staged keychain current epoch',
          );
        }
        const hydratedKeys = await preparedKeychainMerge.hydrateKeys();
        const epochPresent = hydratedKeys.some(([keyId]) =>
          constantTimeEqual(keyId, invitationBundle.welcomeEpochId),
        );
        if (
          !epochPresent ||
          !preparedKeychainMerge.getKey(invitationBundle.welcomeEpochId)
        ) {
          throw new Error(
            'Invitation Welcome did not install its advertised epoch key',
          );
        }

        const headerLength =
          this._keychainProvider.keyIDLength + this._authProvider.nonceBytes;
        const bootstrapKeyId = invitationBundle.encryptedBootstrap.subarray(
          0,
          this._keychainProvider.keyIDLength,
        );
        assertInvitationBootstrapEpochBinding(
          invitationBundle.welcomeEpochId,
          bootstrapKeyId,
        );
        const bootstrapKey = preparedKeychainMerge.getKey(bootstrapKeyId);
        if (!bootstrapKey) {
          throw new Error('Invitation encrypted bootstrap uses an unknown key');
        }
        const nonce = invitationBundle.encryptedBootstrap.subarray(
          this._keychainProvider.keyIDLength,
          headerLength,
        );
        const ciphertext =
          invitationBundle.encryptedBootstrap.subarray(headerLength);
        let bootstrapPlaintext: Uint8Array;
        try {
          bootstrapPlaintext = await this._authProvider.decrypt(
            ciphertext,
            bootstrapKey,
            nonce,
          );
        } catch {
          throw new Error(
            'Invitation encrypted bootstrap could not be decrypted',
          );
        }

        let bootstrapMessage: CRDTSyncMessage<ChangesType, PublicKey>;
        try {
          bootstrapMessage = snapshotSyncMessageForContext<
            ChangesType,
            PublicKey
          >(
            this._syncMessageSerializer.deserializeSyncMessage(
              bootstrapPlaintext,
            ),
            'invitation-bootstrap-v1',
          );
        } catch {
          throw new Error(
            'Invitation bootstrap contains malformed or cross-context fields',
          );
        }
        if (bootstrapMessage.documentId !== this.documentPath) {
          throw new Error('Invitation bootstrap document binding does not match');
        }
        if (
          !Array.isArray(bootstrapMessage.tips) ||
          bootstrapMessage.tips.some((tip) => typeof tip !== 'string')
        ) {
          throw new Error('Invitation bootstrap is missing required tips');
        }
        if (!bootstrapMessage.signature) {
          throw new Error('Invitation bootstrap is missing its issuer signature');
        }
        let signature: string;
        let unsignedBootstrap: CRDTSyncMessage<ChangesType, PublicKey>;
        try {
          const verificationMessage = snapshotSyncMessageForContext<
            ChangesType,
            PublicKey
          >(bootstrapMessage, 'invitation-bootstrap-v1');
          const { signature: verificationSignature, ...unsigned } =
            verificationMessage;
          if (!verificationSignature) {
            throw new TypeError('Invitation bootstrap signature is missing');
          }
          signature = verificationSignature;
          unsignedBootstrap = unsigned;
        } catch {
          throw new Error('Invitation bootstrap signature is malformed');
        }
        let signatureBytes: Uint8Array;
        try {
          signatureBytes = this._deserializeSignature(signature);
        } catch {
          throw new Error('Invitation bootstrap signature is malformed');
        }
        let signedBytes: Uint8Array;
        try {
          signedBytes = copyUnsharedUint8Array(
            this._syncMessageSerializer.serializeSyncMessage(unsignedBootstrap),
            1,
            MAX_INVITATION_MESSAGE_BYTES,
            'Unsigned invitation bootstrap',
          );
        } catch {
          throw new Error('Invitation bootstrap signed content is malformed');
        }
        if (
          (await this._authProvider.verify(
            new Uint8Array(signedBytes),
            issuerPublicKey,
            new Uint8Array(signatureBytes),
          )) !== true
        ) {
          throw new Error('Invitation bootstrap signature does not match the offer issuer');
        }
        let signedBytesAfterVerification: Uint8Array;
        try {
          signedBytesAfterVerification = copyUnsharedUint8Array(
            this._syncMessageSerializer.serializeSyncMessage(unsignedBootstrap),
            1,
            MAX_INVITATION_MESSAGE_BYTES,
            'Unsigned invitation bootstrap',
          );
        } catch {
          throw new Error('Invitation bootstrap changed during verification');
        }
        if (!constantTimeEqual(signedBytes, signedBytesAfterVerification)) {
          throw new Error('Invitation bootstrap changed during verification');
        }

        if (
          bootstrapMessage.keychainChanges === undefined ||
          !constantTimeEqual(
            this._changesSerializer.serializeChanges(
              bootstrapMessage.keychainChanges,
            ),
            welcomeEnvelope.keychainChanges,
          )
        ) {
          throw new Error(
            'Invitation bootstrap keychain does not match its sealed Welcome',
          );
        }
        // The original signed payload above authenticated this exact keychain
        // delta. Apply it only through the detached transaction, not a second
        // time through `_syncUnlocked` before the bootstrap gates have passed.
        const bootstrapMessageForSync = { ...bootstrapMessage };
        delete bootstrapMessageForSync.keychainChanges;

        beginStateApplication();
        if (
          !(await syncInvitationMessageCompletely(
            bootstrapMessageForSync,
            this._hashes,
            () =>
              this._syncUnlocked(
                bootstrapMessageForSync,
                false,
                'invitation-bootstrap-v1',
                undefined,
                true,
                undefined,
                {
                  maxBlockBytes: MAX_INVITATION_MESSAGE_BYTES,
                  maxAggregateBlockBytes: MAX_INVITATION_MESSAGE_BYTES,
                  getKey: (keyID) => preparedKeychainMerge.getKey(keyID),
                },
              ),
            'bootstrap',
            {
              isSnapshotApplied: () =>
                this._latestSnapshot === bootstrapMessageForSync.snapshot,
            },
          ))
        ) {
          throw new Error('Invitation bootstrap state was rejected');
        }
        await this._assertAcceptedInvitationMembership(issuerPublicKey, role);

        // The pinned catch-up response is encrypted under the installed live
        // current key, so this staged merge must commit before activation can
        // dial and decrypt it. A custom provider that mutates and then throws
        // has an indeterminate live state; the already-pending document must
        // therefore remain permanently discard-only on every later failure.
        preparedKeychainMerge.commit();
        this._beekem = beekem;
        this._beekemInitialized = true;
        this._invitationEpoch = invitationEpoch;
        this._invitationBootstrapReady = true;
        await this._activateAcceptedInvitationBootstrap(
          founderAddress,
          issuerPublicKey,
          role,
          bootstrapContinuation,
        );
      },
      () => {
        const currentKemKeyPair = this._kemKeyPair;
        const currentKemPublicKeyRaw = this._kemPublicKeyRaw;
        if (
          !currentKemKeyPair ||
          currentKemKeyPair.privateKey !== invitationKemKeyPair.privateKey ||
          currentKemKeyPair.publicKey !== invitationKemKeyPair.publicKey ||
          !currentKemPublicKeyRaw ||
          !constantTimeEqual(
            currentKemPublicKeyRaw,
            invitationKemPublicKeyRaw,
          )
        ) {
          throw new Error(
            `Invitation bootstrap for ${this.documentPath} requires the KEM key pair to remain unchanged`,
          );
        }
      },
    );
  }

  /**
   * Build and send a BeeKEM Welcome message to a newly-added reader.
   *
   * The Welcome payload is a `CRDTSyncMessage` carrying:
   * - `welcomeEpochId`: the current keychain key ID, which the recipient
   *   records as their `_invitationEpoch` for later `since_invited` history
   *   filtering.
   * - `welcomeRecipient`: serialized public key of the intended recipient.
   *   The inviter cannot identify which connected peer is the new reader,
   *   so Welcomes are broadcast to every peer; the recipient binding
   *   ensures a *well-behaved* non-target peer drops the Welcome rather
   *   than installing the document key. The binding is covered by the
   *   writer signature, so a non-writer cannot redirect a Welcome to a
   *   different recipient.
   * - `welcomeRecipientKemPublicKey`: raw SEC1 P-256 ECDH public key of
   *   the recipient. Also covered by the writer signature -- the writer
   *   commits to a specific encryption key for a specific identity, so
   *   an attacker that owns one of those two values alone cannot
   *   redirect the sealed payload.
   * - `eciesSealed`: the inviter-side serialized keychain delta
   *   encrypted under the recipient's ECDH key via ECIES (see
   *   `ecies.ts`). This is the confidentiality control: a
   *   non-recipient peer that receives the broadcast cannot decrypt
   *   the keychain delta. The keychain plaintext is filtered per the
   *   document's `historyVisibility` **from the recipient's
   *   perspective** (see `_keychainChangesForWelcome()`).
   * - `signature`: writer signature over the message so the receiver can
   *   confirm a legitimate writer is the inviter (and ignore forgeries).
   *   Crucially, the signature covers the **sealed** bytes, not the
   *   plaintext, so a replayed or tampered sealed payload fails
   *   signature verification.
   *
   * Confidentiality: the keychain delta is end-to-end encrypted to the
   * recipient at the application layer. libp2p's Noise/TLS transport
   * still protects on-wire bytes against off-path observers, but the
   * application-layer ECIES seal is the primary confidentiality
   * guarantee against on-path connected peers.
   *
   * Wire format:
   *   [4-byte BE doc-path length] [UTF-8 doc-path] [serialized sync message]
   */
  private async _sendBeeKEMWelcome(
    reader: PublicKey,
    readerKemPublicKey: Uint8Array,
    beekemWelcome: BeeKEMWelcomeV2,
    keychainPlaintextBytes: Uint8Array,
  ): Promise<void> {
    // Validate the recipient KEM public key length up front so a
    // malformed caller fails fast at the call site rather than deep
    // inside the WebCrypto import.
    if (readerKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH) {
      throw new Error(
        `BeeKEM Welcome for ${this.documentPath}: readerKemPublicKey ` +
          `must be ${ECIES_P256_PUBLIC_KEY_LENGTH} raw SEC1 bytes (P-256 ` +
          `uncompressed), got ${readerKemPublicKey.byteLength}`,
      );
    }

    // Defensive copy: snapshot the recipient's KEM public key bytes once
    // at the entry point so a caller that reuses or mutates the same
    // buffer (or shares it across async tasks) after `addReader` returns
    // cannot corrupt the in-flight Welcome. Both the signed message
    // field (`welcomeRecipientKemPublicKey`) and the WebCrypto import
    // must observe the *same* byte sequence; otherwise the receiver
    // would see a signature/payload mismatch.
    const kemPub = new Uint8Array(readerKemPublicKey);

    // Build the welcome message.
    const welcomeMessage: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: this.documentPath,
      signatureContext: 'beekem-welcome-v2',
    };

    // The invitation epoch is the *current* keychain key ID at the time
    // of invitation -- the boundary between "before I joined" and "from
    // when I joined". `_keychain.current()` throws on an empty keychain;
    // in practice that cannot happen here because the inviter is in the
    // group (and so has at least one key), but if it ever does we surface
    // the error to the caller of `addReader` rather than silently sending
    // a Welcome with no epoch ID.
    const [currentKeyID] = await this._keychain.current();
    welcomeMessage.welcomeEpochId = currentKeyID;

    // Recipient binding: serialize the new reader's public key so
    // recipients that aren't this reader can drop the broadcast Welcome.
    // The signed payload covers this field, so only an authorized writer
    // can claim a specific recipient. `serializePublicKey` is optional
    // on `AuthProvider` for backwards compatibility, but Welcome
    // onboarding cannot function without it.
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM Welcome onboarding',
    );
    welcomeMessage.welcomeRecipient = await serializePublicKey(reader);
    welcomeMessage.welcomeRecipientKemPublicKey = kemPub;

    // Visibility-filtered keychain so the new reader receives the selected
    // epoch-key window. This does not redact retained CRDT operations. Note:
    // this uses
    // `_keychainChangesForWelcome()` (recipient's perspective), NOT
    // `_keychainChangesForVisibility()` (sender's perspective) -- the
    // latter would, in `since_invited` mode, leak the inviter's
    // post-invite slice (or, for founders, the full history) to a
    // reader whose invitation epoch starts at this moment.
    const sealedPayloadBytes = encodeWelcomeSealedPayloadV2({
      keychainChanges: keychainPlaintextBytes,
      beekemWelcome,
    });
    assertSharedProtocolRequestSize(
      sealedPayloadBytes.byteLength,
      'BeeKEM Welcome sealed payload',
    );

    // Seal the envelope to the recipient's ECDH public key. Only the
    // recipient holding the matching ECDH private key can recover the
    // plaintext; every other connected peer that observes the
    // broadcast sees only opaque ciphertext + ephemeral public key +
    // nonce + AES-GCM tag.
    const recipientKemKey = await importEciesPublicKey(kemPub);
    welcomeMessage.eciesSealed = await eciesSeal(
      sealedPayloadBytes,
      recipientKemKey,
    );

    // Sign so the receiver can verify the inviter is an authorized
    // writer. Welcomes are ALWAYS writer-authenticated, regardless of
    // the swarm-wide `enableSigning` toggle that gates normal
    // sync-message signing (see SECURITY NOTE in
    // `beekem-welcome-handler.ts`). The signature covers the sealed
    // bytes (`eciesSealed`) and the recipient bindings
    // (`welcomeRecipient` + `welcomeRecipientKemPublicKey`), so an
    // attacker cannot redirect or substitute the sealed payload
    // without invalidating the signature.
    welcomeMessage.signature = await this._signWelcomeAsWriter(welcomeMessage);

    const serialized =
      this._syncMessageSerializer.serializeSyncMessage(welcomeMessage);

    // Build the path-prefixed payload that the shared handler routes.
    const pathBytes = this._encoder.encode(this.documentPath);
    if (pathBytes.length === 0 || pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
      throw new Error(
        `Document path "${this.documentPath}" encoded length (${pathBytes.length}) exceeds ` +
          `the maximum allowed path length (${MAX_DOCUMENT_PATH_LENGTH} bytes) for the BeeKEM Welcome V2 protocol`,
      );
    }
    const pathHeader = new Uint8Array(4);
    pathHeader[0] = (pathBytes.length >> 24) & 0xff;
    pathHeader[1] = (pathBytes.length >> 16) & 0xff;
    pathHeader[2] = (pathBytes.length >> 8) & 0xff;
    pathHeader[3] = pathBytes.length & 0xff;

    assertSharedProtocolRequestSize(
      pathHeader.byteLength + pathBytes.byteLength + serialized.byteLength,
      'BeeKEM Welcome shared protocol request',
    );
    const payload = concatUint8Arrays(pathHeader, pathBytes, serialized);
    assertSharedProtocolRequestSize(
      payload.byteLength,
      'BeeKEM Welcome shared protocol request',
    );

    // Best-effort fan-out to all connected peers. Each peer will either
    // process the Welcome (if it identifies as the new reader) or drop it.
    // We do not have a way to know which peer is the new reader from the
    // libp2p connection alone, so broadcasting is the conservative choice.
    const peers = this.swarm.heliaNode.libp2p
      .getConnections()
      ?.map((x) => x.remoteAddr) ?? [];

    const failedPeers: string[] = [];
    for (const peer of peers) {
      try {
        const stream = await this.libp2p.dialProtocol(peer, [beekemWelcomeV2], {
            runOnLimitedConnection: true,
          });
        await writeStream(stream, [payload]);
      } catch (err) {
        failedPeers.push(peer.toString());
        console.warn(
          `Failed to send BeeKEM Welcome to peer:`,
          peer.toString(),
          err,
        );
      }
    }

    if (failedPeers.length > 0) {
      console.warn(
        `BeeKEM Welcome for ${this.documentPath} failed to reach ${failedPeers.length} peer(s):`,
        failedPeers,
      );
    }
  }

  /**
   * Handles an incoming BeeKEM Welcome message with pre-read payload. Called
   * by the shared protocol handler in Peerborne after the document path
   * header has been stripped and the document looked up in the registry.
   *
   * Verifies the writer signature on the message, merges the included
   * keychain changes so future blocks can be decrypted, and records the
   * `welcomeEpochId` as `_invitationEpoch` so subsequent `since_invited`
   * history responses are correctly filtered.
   *
   * @internal
   * @param payload The serialized sync message (without the document path
   *   header that the shared handler already stripped).
   */
  public async handleBeeKEMWelcomeRequestData(
    payload: Uint8Array,
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<void> {
    return this._runStateMutation(async () => {
      if (!isSharedProtocolHandlerActive(admission)) return;
      await this._handleBeeKEMWelcomeRequestDataUnlocked(
        payload,
        admission,
      );
    });
  }

  private async _handleBeeKEMWelcomeRequestDataUnlocked(
    payload: Uint8Array,
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<void> {
    try {
      const stablePayload = copyUnsharedUint8Array(
        payload,
        1,
        MAX_SHARED_PROTOCOL_REQUEST_BYTES,
        'BeeKEM Welcome message',
      );
      const message = this._syncMessageSerializer.deserializeSyncMessage(
        stablePayload,
      );
      await this._evaluateAndApplyBeeKEMWelcome(
        message,
        { fromBuffer: false },
        admission,
      );
    } catch {
      console.error('Shared BeeKEM Welcome handling failed');
    }
  }

  /**
   * Shared receive-path body for both freshly-arrived Welcomes (called
   * from `handleBeeKEMWelcomeRequestData`) and Welcomes replayed from the
   * pending-welcomes buffer (called from `_drainPendingWelcomesUnlocked` after a
   * readers-ACL update unblocks a previously-dropped Welcome).
   *
   * @param message The deserialized sync message.
   * @param opts.fromBuffer When `true`, the message is being replayed from
   *   the pending-welcomes buffer; we suppress re-buffering on
   *   `not-in-readers-acl` to avoid an infinite drain loop and instead
   *   leave the entry in place for the next drain cycle (or TTL
   *   eviction).
   * @returns `applied` after a complete state commit, `terminal` when an
   *   authenticated replay or permanently invalid transition is safe to
   *   discard, and `retry` when a buffered Welcome may become applicable
   *   after local state changes.
   *
   * @internal
   */
  private async _evaluateAndApplyBeeKEMWelcome(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    opts: { fromBuffer: boolean; failClosedOnCommitError?: boolean },
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<BeeKEMWelcomeApplicationOutcome> {
    // Run the pure validation gates (extracted to
    // `beekem-welcome-handler.ts` so they can be unit-tested without
    // a full libp2p/Helia stack). On `accept` we apply the keychain
    // merge + invitation-epoch assignment below. `serializePublicKey`
    // is required on the AuthProvider for the recipient-binding gate;
    // we surface a clear error instead of silently dropping
    // every Welcome for misconfigured providers.
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM Welcome onboarding',
    );
    const writerKeysVersion = this._writerKeysVersion;
    const decision = await evaluateBeeKEMWelcome(message, {
      documentPath: this.documentPath,
      localUserPublicKey: this._userPublicKey,
      serializePublicKey,
      isReader: (pk) =>
        retryACLConflict(() => this._readers.check(pk)),
      // Welcomes always require writer-auth, independent of the
      // swarm-wide `enableSigning` toggle -- wire the unconditional
      // verifier so the validator can't be downgraded by config.
      verifyWriterSignature: (raw, signature) =>
        this._verifyMembershipWriterSignature(raw, signature),
      syncMessageSerializer: this._syncMessageSerializer,
    });
    if (!isSharedProtocolHandlerActive(admission)) return 'retry';

    if (decision.kind !== 'accept') {
      switch (decision.kind) {
        case 'drop-not-for-us':
          // Legitimate Welcome to another peer flowing past our
          // connection -- silently ignore.
          return 'terminal';
        case 'drop-malformed':
          console.warn('Dropping malformed BeeKEM Welcome');
          return 'terminal';
        case 'drop-unauthorized':
          // If the Welcome was dropped solely because the local user is
          // not yet a reader (ACL update + Welcome can reorder;
          // `_sendBeeKEMWelcome` is fire-and-forget), park the Welcome
          // in a small bounded buffer and replay it after the next
          // readers-ACL merge. Without this buffer, a transiently-late
          // ACL update would permanently wedge onboarding.
          if (
            decision.reason === 'not-in-readers-acl' &&
            !opts.fromBuffer &&
            decision.message?.welcomeEpochId !== undefined &&
            decision.message.welcomeEpochId.byteLength === EPOCH_ID_LENGTH
          ) {
            const pendingWelcome = decision.message;
            const buffered = await runSharedProtocolMutation(
              admission,
              () => this._bufferPendingWelcome(pendingWelcome),
            );
            if (!buffered.admitted) return 'retry';
          } else if (
            opts.fromBuffer &&
            decision.reason === 'not-in-readers-acl'
          ) {
            // A buffered Welcome that is still blocked by
            // `not-in-readers-acl` on a drain cycle is the expected
            // steady state until the readers-ACL catches up. The
            // first-arrival case (above) already logged via
            // `_bufferPendingWelcome`; emitting `console.warn` on every
            // subsequent drain produces noisy spam (and is
            // attacker-triggerable via repeated ACL merges). Use
            // `console.debug` so operators can still trace if needed.
            console.debug('Buffered BeeKEM Welcome is still unauthorized');
          } else {
            console.warn('Dropping unauthorized BeeKEM Welcome');
          }
          return 'retry';
      }
    }

    // Continue only with the detached canonical message whose exact bytes the
    // validator authenticated, never the caller-owned serializer result.
    message = decision.message;

    // Open the sealed keychain delta. We must hold the matching ECDH
    // private key (see `setKemKeyPair`); without it, even a Welcome
    // that addresses us by identity and KEM public key cannot be
    // applied. Drop in that case; the recipient must install its KEM key pair
    // and obtain a fresh Welcome or use another explicit recovery path.
    //
    // Defense in depth: if the writer-signed `welcomeRecipientKemPublicKey`
    // does NOT match the local installed KEM public key, the writer
    // is claiming a different encryption key than the one we hold.
    // Refuse to attempt decryption: this prevents an attacker who
    // somehow registered a fake KEM key (e.g. via a parallel
    // out-of-band channel) from getting us to silently install
    // keychain state under a key we don't actually control. A
    // legitimate writer who follows the documented onboarding flow
    // will always echo back the recipient's own KEM public key.
    if (!this._kemKeyPair || !this._kemPublicKeyRaw) {
      console.warn('Dropping BeeKEM Welcome without a local KEM key pair');
      return 'retry';
    }
    // Use the eagerly-cached raw bytes from `setKemKeyPair` rather
    // than re-exporting on every Welcome.
    const localKemPublicRaw = this._kemPublicKeyRaw;
    const messageKemPublic = message.welcomeRecipientKemPublicKey;
    if (
      !messageKemPublic ||
      messageKemPublic.byteLength !== localKemPublicRaw.byteLength ||
      !this._constantTimeEquals(messageKemPublic, localKemPublicRaw)
    ) {
      console.warn('Dropping BeeKEM Welcome for a different KEM public key');
      return 'retry';
    }

    const newEpochId = copyUnsharedUint8Array(
      message.welcomeEpochId,
      EPOCH_ID_LENGTH,
      EPOCH_ID_LENGTH,
      'BeeKEM Welcome epoch ID',
    );
    const existingInvitationEpoch =
      this._invitationEpoch === undefined
        ? undefined
        : new Uint8Array(this._invitationEpoch);
    const sameInvitationEpoch =
      existingInvitationEpoch !== undefined &&
      constantTimeEqual(existingInvitationEpoch, newEpochId);
    const hasInstalledBeeKEM =
      this._beekemInitialized === true && this._beekem != null;
    if (sameInvitationEpoch && hasInstalledBeeKEM) {
      return 'terminal';
    }

    let keychainPlaintext: ChangesType;
    let bootstrapWelcome: BeeKEMWelcomeV2;
    try {
      const sealed = message.eciesSealed as Uint8Array;
      const plaintextBytes = await eciesOpen(
        sealed,
        this._kemKeyPair.privateKey,
      );
      const envelope = decodeWelcomeSealedPayloadV2(plaintextBytes);
      keychainPlaintext = this._changesSerializer.deserializeChanges(
        envelope.keychainChanges,
      );
      bootstrapWelcome = envelope.beekemWelcome;
      if (!bootstrapWelcome) throw new Error('Welcome tree is required');
    } catch {
      console.warn('Failed to open sealed BeeKEM Welcome payload');
      return 'terminal';
    }

    let preparedKeychainMerge: CapturedPreparedKeychainMerge;
    try {
      const prepareMerge = capturePreparedDataMethod(
        this._keychain,
        'prepareMerge',
        'Welcome keychain prepareMerge',
      );
      const prepared = documentReflectApply(
        prepareMerge.method,
        prepareMerge.receiver,
        [keychainPlaintext],
      );
      preparedKeychainMerge = capturePreparedKeychainMerge(prepared);

      if (existingInvitationEpoch !== undefined) {
        let existingIndex = -1;
        let incomingIndex = -1;
        for (
          let index = 0;
          index < preparedKeychainMerge.keyIds.length;
          index++
        ) {
          const keyId = preparedKeychainMerge.keyIds[index];
          if (constantTimeEqual(keyId, existingInvitationEpoch)) {
            existingIndex = index;
          }
          if (constantTimeEqual(keyId, newEpochId)) {
            incomingIndex = index;
          }
        }
        if (existingIndex === -1 || incomingIndex === -1) {
          console.warn(
            'Dropping BeeKEM Welcome with a divergent staged keychain',
          );
          return 'terminal';
        }
        if (incomingIndex < existingIndex) {
          console.warn('Ignoring out-of-order BeeKEM Welcome');
          return 'terminal';
        }
        if (incomingIndex === existingIndex && !sameInvitationEpoch) {
          return 'terminal';
        }
      }

      if (!constantTimeEqual(preparedKeychainMerge.currentKeyId, newEpochId)) {
        console.warn(
          'Dropping BeeKEM Welcome whose epoch is not the staged current key',
        );
        return 'terminal';
      }

      const hydrated = await documentReflectApply(
        preparedKeychainMerge.hydrateKeys.method,
        preparedKeychainMerge.hydrateKeys.receiver,
        emptyCommitArguments,
      );
      if (!hasCompleteHydratedKeychain(hydrated, preparedKeychainMerge.keyIds)) {
        console.warn('Dropping BeeKEM Welcome with incomplete hydrated history');
        return 'retry';
      }
      for (const keyId of preparedKeychainMerge.keyIds) {
        const hydratedKey = documentReflectApply(
          preparedKeychainMerge.getKey.method,
          preparedKeychainMerge.getKey.receiver,
          [new Uint8Array(keyId)],
        );
        if (hydratedKey === undefined) {
          console.warn('Dropping BeeKEM Welcome with unavailable history keys');
          return 'retry';
        }
      }
    } catch {
      console.warn('Failed to stage BeeKEM Welcome keychain state');
      return 'retry';
    }

    let stagedBeeKEM: BeeKEM;
    try {
      stagedBeeKEM = new BeeKEM();
      await stagedBeeKEM.processWelcome(
        bootstrapWelcome,
        this._kemKeyPair.privateKey,
        this._kemKeyPair.publicKey,
      );
      const currentGeneration = this._beekem?.generation;
      if (currentGeneration != null && bootstrapWelcome.generation <= currentGeneration) {
        console.warn('Dropping non-increasing BeeKEM Welcome generation');
        return 'terminal';
      }
    } catch {
      console.warn('Dropping BeeKEM Welcome with invalid bootstrap state');
      return 'terminal';
    }

    try {
      const committed = await runSharedProtocolMutation(
        admission,
        () => {
          const keychainCommit = this._claimPreparedCommit(
            preparedKeychainMerge.claimCommit,
            'Welcome keychain commit claim',
          );
          try {
            finalizePreparedCommitClaim(
              keychainCommit,
              'Welcome keychain commit claim',
            );
            this._beekem = stagedBeeKEM;
            this._beekemInitialized = true;
            this._invitationEpoch = newEpochId;
          } catch (error) {
            this._markDocumentStatePoisoned();
            throw error;
          }
        },
      );
      if (!committed.admitted) return 'retry';
    } catch (error) {
      console.error('Failed to commit BeeKEM Welcome state');
      if (opts.failClosedOnCommitError) {
        throw error;
      }
      return 'retry';
    }
    console.log('Recorded BeeKEM Welcome invitation epoch');
    return 'applied';
  }

  /**
   * Buffer a Welcome that was dropped solely because the local user is
   * not yet in the readers ACL. The entry is keyed by
   * `hex(welcomeEpochId)` so duplicate Welcomes for the same epoch
   * coalesce automatically. The canonical serialized body is capped at
   * `PENDING_WELCOME_MAX_BODY_BYTES`; retained bodies are bounded by both
   * entry count and `PENDING_WELCOMES_MAX_RETAINED_BYTES`, with oldest-first
   * eviction. Buffered bytes are replayed by `_drainPendingWelcomesUnlocked()`
   * after the next readers-ACL merge.
   *
   * Idempotent and safe to call repeatedly with the same epoch ID --
   * the buffer is conceptually a set keyed on epoch ID, with
   * insertion-order eviction.
   *
   * @internal
   */
  private _bufferPendingWelcome(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): void {
    const epochId = message.welcomeEpochId;
    if (!epochId || epochId.byteLength !== EPOCH_ID_LENGTH) return;
    const key = this._hexEncode(epochId);
    try {
      // Retain bytes rather than the decoded object graph. This makes byte
      // accounting exact, prevents aliases from changing parked state, and
      // forces every replay through deserialization and writer authentication.
      const result = this._pendingWelcomes.storeMessage(
        key,
        message,
        this._syncMessageSerializer,
        this._now(),
      );
      if (result.evictedKeys.length > 0) {
        console.warn(
          'Pending BeeKEM Welcome buffer reached its count or byte limit; ' +
            `evicting ${result.evictedKeys.length} oldest entr${
              result.evictedKeys.length === 1 ? 'y' : 'ies'
            }`,
        );
      }
    } catch (error) {
      if (!(error instanceof PendingWelcomeBodyLimitError)) throw error;
      console.warn(
        'Dropping authenticated BeeKEM Welcome that cannot fit the pending ' +
          `buffer's ${PENDING_WELCOME_MAX_BODY_BYTES}-byte body limit`,
      );
      return;
    }
    console.log('Buffered BeeKEM Welcome pending readers-ACL update');
  }

  /**
   * Replay buffered BeeKEM Welcomes whose recipient is now in the
   * readers ACL. Called after every readers-ACL `merge` so a Welcome
   * that arrived ahead of the ACL update on this node is unblocked as
   * soon as the ACL catches up. Also discards entries past their TTL
   * (`PENDING_WELCOMES_TTL_MS`) so the buffer cannot retain stale
   * Welcomes indefinitely.
   *
   * Each accepted Welcome is removed from the buffer; entries that
   * still return `not-in-readers-acl` (e.g. the ACL merge didn't
   * add this user; the merge added someone else) stay in the buffer
   * until they either resolve or expire.
   *
   * @internal
   */
  private async _drainPendingWelcomesUnlocked(
    failClosedOnCommitError = false,
  ): Promise<void> {
    if (this._pendingWelcomes.size === 0) return;
    const now = this._now();
    // Iterate over a key snapshot because replay deletes accepted/expired
    // entries. `get` returns one detached body at a time, keeping retained
    // storage immutable without duplicating the whole aggregate budget.
    const keys = this._pendingWelcomes.keysSnapshot();
    for (const key of keys) {
      const entry = this._pendingWelcomes.get(key);
      if (entry === undefined) continue;
      if (now - entry.bufferedAtMs > PENDING_WELCOMES_TTL_MS) {
        this._pendingWelcomes.delete(key);
        console.warn(
          `Discarding stale buffered BeeKEM Welcome for ${this.documentPath} ` +
            `(age=${now - entry.bufferedAtMs}ms ` +
            `exceeds TTL=${PENDING_WELCOMES_TTL_MS}ms)`,
        );
        continue;
      }
      let message: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        message = this._syncMessageSerializer.deserializeSyncMessage(
          entry.body,
        );
      } catch {
        this._pendingWelcomes.delete(key);
        console.warn('Discarding undecodable buffered BeeKEM Welcome');
        continue;
      }
      const outcome = await this._evaluateAndApplyBeeKEMWelcome(
        message,
        {
          fromBuffer: true,
          failClosedOnCommitError,
        },
      );
      if (this._bootstrapLoadApplicationState === 'poisoned') return;
      if (outcome !== 'retry') {
        this._pendingWelcomes.delete(key);
        if (outcome === 'applied') {
          console.log(
            `Replayed buffered BeeKEM Welcome for ${this.documentPath} ` +
              `after readers-ACL update`,
          );
        } else {
          console.debug(
            `Discarded terminal buffered BeeKEM Welcome for ${this.documentPath}`,
          );
        }
      }
    }
  }

  /** Indirection so unit tests can stub the wall clock. */
  private _now(): number {
    return Date.now();
  }

  /** Lower-case hex encoding of a `Uint8Array`. */
  private _hexEncode(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
  }

  /**
   * Constant-time byte-equality check. Used by the BeeKEM Welcome
   * receive path to compare the writer-signed
   * `welcomeRecipientKemPublicKey` against the locally-installed KEM
   * public key without leaking byte-position timing on a mismatch.
   * Callers must supply equal-length buffers.
   */
  private _constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  /**
   * Test/inspection helper: number of BeeKEM Welcomes currently parked
   * in the pending-welcomes buffer awaiting a readers-ACL update.
   *
   * @internal exposed only for unit tests.
   */
  public get pendingWelcomesCount(): number {
    return this._pendingWelcomes.size;
  }

  /** Exact number of serialized Welcome bytes retained by the buffer. */
  public get pendingWelcomesRetainedBytes(): number {
    return this._pendingWelcomes.retainedBytes;
  }

  /**
   * Test/inspection helper: returns a copy of the recorded invitation
   * epoch, or `undefined` if no Welcome has been processed (e.g.
   * founding member). The returned `Uint8Array` is a defensive copy so
   * external callers cannot mutate the document's internal state and
   * alter subsequent `since_invited` filtering behavior.
   */
  public get invitationEpoch(): Uint8Array | undefined {
    this._assertNoIncompleteBootstrapLoad();
    return this._invitationEpoch === undefined
      ? undefined
      : new Uint8Array(this._invitationEpoch);
  }

  /**
   * Compatibility helper for comparing two invitation epochs against the live
   * keychain order. The inbound Welcome transaction now performs its security
   * decision against the detached staged projection before commit.
   *
   * @deprecated Internal callers should use the staged Welcome transaction.
   * @internal
   */
  public async _shouldAdvanceInvitationEpoch(
    existing: Uint8Array,
    incoming: Uint8Array,
  ): Promise<boolean> {
    const stableExisting = new Uint8Array(existing);
    const stableIncoming = new Uint8Array(incoming);
    if (constantTimeEqual(stableExisting, stableIncoming)) return false;

    let allKeys: [Uint8Array, unknown][];
    try {
      allKeys = await this._keychain.keys();
    } catch {
      return false;
    }
    let existingIndex = -1;
    let incomingIndex = -1;
    for (let index = 0; index < allKeys.length; index++) {
      const keyId = allKeys[index][0];
      if (constantTimeEqual(keyId, stableExisting)) existingIndex = index;
      if (constantTimeEqual(keyId, stableIncoming)) incomingIndex = index;
    }
    return existingIndex !== -1 && incomingIndex > existingIndex;
  }

  /**
   * Remove a user as a valid reader. Users are identified by their public keys.
   *
   * The target must first be downgraded from writer. Revocation resolves the
   * target's identity-bound KEM key to one unique live BeeKEM leaf, stages any
   * reader-ACL delta, and performs the tree rotation on a clone. An already
   * absent ACL row does not suppress a still-live leaf: the cryptographic
   * removal proceeds.
   *
   * The new local epoch key is staged before publication. Every participating
   * provider must supply a commit claim: all fallible work finishes before
   * publication, then captured nonthrowing finalizers install ACL, keychain,
   * tree, and identity-cache state in one synchronous turn. A publication
   * failure after valid claims leaves compliant providers on their original
   * state. An invoked claim that throws or returns a malformed/asynchronous
   * record, or a finalizer that throws or returns a value, violates the provider
   * contract and poisons this document instance because partial application
   * cannot be ruled out.
   *
   * PathUpdateV2 delivery remains best effort after the local transition. A
   * surviving member that misses it needs an explicit recipient-bound recovery
   * or re-invitation; an ordinary load is encrypted under the unknown new key.
   * These are cooperative local-API invariants. Incoming raw ACL deltas are not
   * yet checked against replicated identity/KEM transition records.
   *
   * @param reader User's public key.
   * @throws If the BeeKEM tree has no record of this reader (e.g.
   *   `addReader` did not seed a leaf for them, or BeeKEM membership
   *   was lost). Callers must surface this rather than silently
   *   degrading: a removeReader that "succeeded" without rotating the
   *   key would leave the removed reader with full ongoing access.
   * @throws If identity/KEM/tree state is missing or divergent, a required
   *   commit claim is unavailable, or ACL publication fails.
   */
  public async removeReader(reader: PublicKey) {
    this._assertNoIncompleteBootstrapLoad();
    const snapshot = this._startMembershipPublicKeySnapshot(
      reader,
      'BeeKEM reader revocation',
    );
    return this._runStateMutation(async () => {
      const {
        publicKey: stableReader,
        serialized: serializedReader,
      } = await snapshot;
      return this._removeReaderUnlocked(stableReader, serializedReader);
    });
  }

  private async _removeReaderUnlocked(
    stableReader: PublicKey,
    serializedReader: string,
  ) {
    await this._ensureCurrentUserCanWrite();

    // Writers are implicit readers and must be downgraded first.
    if (
      (await retryACLConflict(() =>
        this._writers.check(stableReader),
      )) === true
    ) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}" while the target ` +
          'is still an authorized writer. Call removeWriter first, then ' +
          'removeReader to revoke read access and rotate the BeeKEM epoch.',
      );
    }

    const isExplicitReader =
      (await retryACLConflict(() =>
        this._readers.check(stableReader),
      )) === true;
    const recordedKemPublicKey =
      this._readerKemPublicKeys.get(serializedReader);
    const cachedLeafIndex = this._readerLeafIndices.get(serializedReader);

    // A completed prior removal clears both identity-bound caches. Preserve an
    // idempotent no-op only when the ACL and local cryptographic membership
    // evidence agree that there is nothing left to revoke.
    if (
      !isExplicitReader &&
      recordedKemPublicKey === undefined &&
      cachedLeafIndex === undefined
    ) {
      if (
        !this._beekemInitialized ||
        !this._beekem ||
        !this._beekem.hasOnlyLocalLiveLeaf()
      ) {
        throw new Error(
          `Cannot remove reader from "${this.documentPath}": the ACL and ` +
            'identity-bound BeeKEM caches are absent, but the live tree does ' +
            'not prove that every remote leaf has already been revoked.',
        );
      }
      return;
    }

    if (!this._beekemInitialized || !this._beekem) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": BeeKEM tree has ` +
          `not been initialized. This is only possible if the local user is ` +
          `neither the founder nor has received a BeeKEM Welcome -- in either ` +
          `case the user should not be calling removeReader.`,
      );
    }
    const beekem = this._beekem;

    if (
      !recordedKemPublicKey ||
      recordedKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH
    ) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": no valid ` +
          'identity-bound reader KEM public key is recorded locally, so ' +
          'cryptographic membership cannot be revoked safely.',
      );
    }

    const leafIndex = await beekem.findLeafByPublicKey(
      new Uint8Array(recordedKemPublicKey),
    );
    if (leafIndex === undefined) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": the recorded KEM ` +
          'public key does not resolve to exactly one live, non-blanked ' +
          'BeeKEM leaf. Use an explicit recipient-bound recovery or ' +
          're-invitation flow to repair local membership state.',
      );
    }
    if (leafIndex === beekem.myLeafIndex) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": the identity-bound ` +
          'KEM key resolves to the local BeeKEM leaf, not a remote member.',
      );
    }
    if (
      cachedLeafIndex !== undefined &&
      cachedLeafIndex !== leafIndex
    ) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": the cached BeeKEM ` +
          'leaf does not match the unique live identity-bound leaf.',
      );
    }

    const preparedReaderRemoval = isExplicitReader
      ? await this._prepareReaderRemove(stableReader)
      : undefined;
    const stagedBeeKEM = beekem.clone();

    // 1. Blank the leaf and re-key our path. `removeMember` re-derives
    //    key material along the entire path and returns the
    //    `PathUpdateV2` to broadcast plus the new root secret. We use
    //    those return values directly -- no follow-up `update()` is
    //    needed (it would only discard `removeMember`'s fresh
    //    material in favour of yet-another rotation).
    const { pathUpdate, rootSecret } =
      await stagedBeeKEM.removeMember(leafIndex);

    // 2. Derive the new document key + 32-byte epoch ID from the root
    //    secret. **Hold these locally; do NOT install in the keychain
    //    yet.** Installing now would flip `_keychain.current()` to the
    //    new key, and the ACL-change broadcast in step 3 (which goes
    //    through `_makeChange`) would then encrypt the readers-ACL
    //    removal under the **new** key. Surviving readers would not
    //    yet have the new key (they get it from the PathUpdateV2 in
    //    step 4, delivered separately and possibly out of order
    //    relative to the gossipsub-broadcast ACL change), and so
    //    would be unable to decrypt the ACL change.
    //
    //    The full 32-byte ID is both what we put on the wire AND what
    //    the keychain stores: `keyIDLength` is now 32 in the shipped
    //    providers (matches `deriveEpochIdFromRootSecret`), so there is
    //    no truncation step. Earlier revisions truncated to 16 bytes
    //    here, which collided with the keychain providers' UUID-style
    //    cache-key encoding for 16-byte inputs and produced a
    //    deterministic post-rotation decrypt failure on the receiver
    //    side (key stored under hex, looked up under UUID format).
    const [newKey, derivedEpochId32] = await Promise.all([
      deriveDocumentKeyFromRootSecret(rootSecret),
      deriveEpochIdFromRootSecret(rootSecret),
    ]);

    const epochClaimCommit = await this._prepareReaderRevocationEpoch(
      derivedEpochId32,
      newKey as unknown as DocumentKey,
    );

    // Build every document-owned replacement before claiming either provider.
    // The commit turn below performs only captured finalizers and reference
    // swaps, so compliant providers cannot expose a fallible prefix.
    const committedReaderLeafIndices = new Map(this._readerLeafIndices);
    committedReaderLeafIndices.delete(serializedReader);
    const committedReaderKemPublicKeys = new Map(
      this._readerKemPublicKeys,
    );
    committedReaderKemPublicKeys.delete(serializedReader);
    const committedWelcomes = new Map(this._beekemWelcomeByLeaf);
    committedWelcomes.delete(leafIndex);
    const installBeeKEMRemoval = () => {
      this._beekem = stagedBeeKEM;
      this._readerLeafIndices = committedReaderLeafIndices;
      this._readerKemPublicKeys = committedReaderKemPublicKeys;
      this._beekemWelcomeByLeaf = committedWelcomes;
    };

    // Both method identities and their receivers were captured from data
    // properties before invocation. A custom provider cannot replace a method
    // between claim and finalization, and accessor-backed or async-shaped
    // claims are rejected without assimilating a hostile thenable.
    const readerCommit = preparedReaderRemoval
      ? this._claimPreparedCommit(
          preparedReaderRemoval.claimCommit,
          'Reader ACL commit claim',
        )
      : undefined;
    const epochCommit = this._claimPreparedCommit(
      epochClaimCommit,
      'Reader-revocation epoch commit claim',
    );
    const finalizeLocalRevocation = () => {
      if (readerCommit) {
        finalizePreparedCommitClaim(readerCommit, 'Reader ACL commit claim');
      }
      finalizePreparedCommitClaim(
        epochCommit,
        'Reader-revocation epoch commit claim',
      );
      installBeeKEMRemoval();
    };

    if (preparedReaderRemoval) {
      // Publish the ACL delta under the previous epoch. Once publication
      // resolves, `_makeChange` runs the composed finalizer before exposing the
      // new DAG head to local observers and poisons the instance if a custom
      // provider violates its nonthrowing finalizer contract.
      await this._publishPreparedReaderChange(
        preparedReaderRemoval,
        'removeReader',
        finalizeLocalRevocation,
      );
    } else {
      // The ACL row may already be absent while its BeeKEM leaf remains live.
      // There is no publication boundary in that recovery case, but epoch,
      // tree, and identity-cache state still finalize in one synchronous turn.
      try {
        finalizeLocalRevocation();
      } catch (error) {
        this._markDocumentStatePoisoned();
        throw error;
      }
    }

    // PathUpdateV2 delivery is best effort after the complete local transition.
    // A survivor that misses it needs recipient-bound recovery or a fresh
    // invitation; an ordinary load is encrypted under the unknown new key.
    try {
      await this._distributeBeeKEMPathUpdate(pathUpdate, derivedEpochId32);
    } catch (err) {
      console.warn(
        `[${this.documentPath}] removeReader: PathUpdateV2 broadcast failed; ` +
          'BeeKEM state and the new key committed locally. Affected readers ' +
          'need explicit recipient-bound recovery or re-invitation.',
        err,
      );
    }
  }

  private async _assertKemPublicKeyAvailableForNewLeaf(
    readerKemPublicKey: Uint8Array,
  ): Promise<void> {
    if (this._beekemInitialized) {
      if (!this._beekem) {
        throw new Error(
          `[${this.documentPath}] addReader: BeeKEM is marked initialized ` +
            'but the live tree is unavailable, so KEM leaf uniqueness cannot ' +
            'be verified.',
        );
      }
      if (
        await this._beekem.hasLiveLeafWithPublicKey(
          new Uint8Array(readerKemPublicKey),
        )
      ) {
        throw new Error(
          `[${this.documentPath}] addReader: readerKemPublicKey is already ` +
            'owned by a live BeeKEM leaf. Each member must use a unique KEM ' +
            'public key.',
        );
      }
      return;
    }

    if (!this._kemPublicKeyRaw) {
      throw new Error(
        `[${this.documentPath}] addReader: the founder KEM public key is ` +
          'unavailable, so KEM leaf uniqueness cannot be verified.',
      );
    }
    if (constantTimeEqual(this._kemPublicKeyRaw, readerKemPublicKey)) {
      throw new Error(
        `[${this.documentPath}] addReader: readerKemPublicKey matches the ` +
          'founder\'s BeeKEM leaf. Each member must use a unique KEM public key.',
      );
    }
  }

  /**
   * Prepare a reader registration on detached BeeKEM and cache state.
   *
   * The returned installer performs only reference swaps and runs at the
   * staged reader-ACL publication boundary. Until then, crypto or tree
   * failures leave live membership unchanged. The returned Welcome can be
   * sent inside the recipient-sealed envelope after the local commit.
   *
   * **Idempotency / re-send**: if the same reader is registered
   * again (`addReader` invoked twice with the same KEM key), the
   * method does NOT re-call `BeeKEM.addMember` (which would mutate
   * the tree and produce a Welcome that no longer matches the
   * joiner's actual leaf index). Instead it returns the cached
   * Welcome from `_beekemWelcomeByLeaf`, so `addReader` can re-send
   * the same Welcome bytes. If the cache is empty for the existing
   * leaf (writer restarted), `null` is returned and the caller falls
   * back to the existing "no BeeKEM bootstrap available, recipient
   * must recover via a fresh document load" path.
   *
   * The path update produced by `BeeKEM.addMember` is not broadcast here.
   * Existing members therefore cannot safely track a second active joiner.
   * `addReader` enforces the initial-release founder-plus-one limit before
   * mutating the ACL; lifting that limit requires a verified add-side
   * PathUpdateV2 delivery and convergence path.
   */
  private async _prepareBeeKEMReaderRegistration(
    serializedReader: string,
    readerKemPublicKey: Uint8Array,
  ): Promise<PreparedBeeKEMReaderRegistration> {
    // Validate the recipient KEM public key length BEFORE any state
    // mutation. Without this gate a malformed buffer would still be
    // recorded in `_readerKemPublicKeys` and seeded into the BeeKEM
    // leaf (via `crypto.subtle.importKey`), at which point WebCrypto
    // surfaces a low-signal `DataError` after we have already mutated
    // identity-keyed state. Fail fast here so callers (and `addReader`)
    // see a precise, actionable error before any commitment.
    if (readerKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH) {
      throw new Error(
        `[${this.documentPath}] _prepareBeeKEMReaderRegistration: readerKemPublicKey ` +
          `must be ${ECIES_P256_PUBLIC_KEY_LENGTH} bytes (SEC1-uncompressed ` +
          `P-256), got ${readerKemPublicKey.byteLength}`,
      );
    }

    const previousKemPublicKey =
      this._readerKemPublicKeys.get(serializedReader);
    if (
      previousKemPublicKey &&
      !constantTimeEqual(previousKemPublicKey, readerKemPublicKey)
    ) {
      throw new Error(
        `[${this.documentPath}] _prepareBeeKEMReaderRegistration: this reader is ` +
          `already bound to a different KEM public key`,
      );
    }

    // Idempotency: if a leaf is already recorded (e.g. addReader was
    // re-invoked because the initial Welcome was dropped), we do NOT
    // call `BeeKEM.addMember` again -- that would mutate the tree
    // and produce a Welcome that no longer matches the joiner's
    // actual leaf index. Instead we return the cached Welcome (if
    // any) so the caller can re-send.
    const existingLeaf = this._readerLeafIndices.get(serializedReader);
    if (existingLeaf !== undefined) {
      if (!previousKemPublicKey) {
        throw new Error(
          `[${this.documentPath}] _prepareBeeKEMReaderRegistration: the existing reader ` +
            'leaf has no recoverable KEM binding',
        );
      }
      if (!this._beekemInitialized || !this._beekem) {
        throw new Error(
          `[${this.documentPath}] _prepareBeeKEMReaderRegistration: the cached reader ` +
            'leaf exists but the live BeeKEM tree is unavailable',
        );
      }
      const liveLeaf = await this._beekem.findLeafByPublicKey(
        new Uint8Array(readerKemPublicKey),
      );
      if (liveLeaf === this._beekem.myLeafIndex) {
        throw new Error(`[${this.documentPath}] _prepareBeeKEMReaderRegistration: Cannot register a remote reader at the local BeeKEM leaf`);
      }
      if (liveLeaf !== existingLeaf) {
        throw new Error(
          `[${this.documentPath}] _prepareBeeKEMReaderRegistration: the cached reader ` +
            'leaf does not match the unique live KEM-key owner',
        );
      }
      const cachedWelcome = this._beekemWelcomeByLeaf.get(existingLeaf);
      if (!cachedWelcome) {
        throw new Error('Cannot resend BeeKEM Welcome without the complete cached tree');
      }
      return {
        welcome: copyBeeKEMWelcome(cachedWelcome),
      };
    }

    // The index map is only a cache. If the identity-to-KEM binding and live
    // tree still agree, recover the unique leaf before running the new-leaf
    // duplicate gate. This keeps an exact retry from rejecting its own leaf.
    if (previousKemPublicKey) {
      if (!this._beekemInitialized || !this._beekem) {
        throw new Error(
          `[${this.documentPath}] _prepareBeeKEMReaderRegistration: the existing reader ` +
            'KEM binding cannot be resolved because the live BeeKEM tree is ' +
            'unavailable',
        );
      }
      const recoveredLeaf = await this._beekem.findLeafByPublicKey(
        new Uint8Array(readerKemPublicKey),
      );
      if (recoveredLeaf === undefined) {
        throw new Error(
          `[${this.documentPath}] _prepareBeeKEMReaderRegistration: the existing reader ` +
            'KEM binding does not resolve to exactly one live BeeKEM leaf',
        );
      }
      if (recoveredLeaf === this._beekem.myLeafIndex) {
        throw new Error(`[${this.documentPath}] _prepareBeeKEMReaderRegistration: Cannot register a remote reader at the local BeeKEM leaf`);
      }
      const committedReaderLeafIndices = new Map(this._readerLeafIndices);
      committedReaderLeafIndices.set(serializedReader, recoveredLeaf);
      const cachedWelcome = this._beekemWelcomeByLeaf.get(recoveredLeaf);
      if (!cachedWelcome) {
        throw new Error('Cannot resend BeeKEM Welcome without the complete cached tree');
      }
      return {
        welcome: copyBeeKEMWelcome(cachedWelcome),
        install: () => {
          this._readerLeafIndices = committedReaderLeafIndices;
        },
      };
    }

    // A KEM key is a unique live-leaf identifier. The public addReader path
    // performs the same check before its ACL mutation; this second gate covers
    // retries where the ACL row exists but no identity cache survived.
    await this._assertKemPublicKeyAvailableForNewLeaf(readerKemPublicKey);

    // Bootstrap the local BeeKEM tree if needed. On the founder's
    // first `addReader` this initializes leaf 0 with the founder's
    // KEM key pair. On a non-founder writer this branch is invalid
    // (writers other than the founder must themselves have been
    // bootstrapped via a Welcome before they can call `addReader`).
    //
    // Defense-in-depth gate: the caller path through `addReader`
    // already rejects a joined writer before running `_makeChange`, so by
    // the time we reach here `_createdLocally` must identify the genuine
    // founder. A future caller that invokes this preparation helper
    // outside `addReader` without that provenance would silently
    // create a divergent founder tree on a peer that already has
    // shared state. Throw rather than spawn the rogue tree; the
    // upstream `addReader` gate's recovery message points at the
    // right path.
    let beekem: BeeKEM;
    if (!this._beekemInitialized) {
      if (!this._createdLocally) {
        throw new Error(
          `[${this.documentPath}] _prepareBeeKEMReaderRegistration: cannot ` +
            `initialize a fresh founder BeeKEM tree because the local ` +
            `replica did not create this document locally. A ` +
            `joined writer must bootstrap via a signed invitation acceptance ` +
            `before they can register ` +
            `readers cryptographically.`,
        );
      }
      if (!this._kemKeyPair) {
        throw new Error(
          `[${this.documentPath}] BeeKEM founder initialization requires a ` +
            'KEM key pair installed via setKemKeyPair.',
        );
      }
      beekem = new BeeKEM();
      await beekem.initialize(
        this._kemKeyPair.privateKey,
        this._kemKeyPair.publicKey,
      );
    } else {
      if (!this._beekem) {
        throw new Error(
          `[${this.documentPath}] BeeKEM tree is not initialized; ` +
            'cannot register a new reader.',
        );
      }
      beekem = this._beekem.clone();
    }
    if (beekem.memberCount >= 2) {
      throw new Error(
        `[${this.documentPath}] _prepareBeeKEMReaderRegistration: cannot add another ` +
          'leaf when the exact existing reader Welcome is unavailable',
      );
    }

    // Import the reader's own KEM public key as their leaf. This is
    // critical for joiner-side decryption: `BeeKEM.processWelcome`
    // uses the leaf private key (held by the joiner) to decrypt the
    // first path-key encryption in the Welcome. If the leaf were
    // seeded with a placeholder key the joiner could never bootstrap.
    //
    // Imported as `extractable=true`: BeeKEM's tree-hash computation
    // (`_computeTreeHash`) calls `exportKey('raw', publicKey)` over
    // every non-blanked tree node, so a non-extractable leaf public
    // key would crash subsequent `addMember` / `removeMember` calls.
    // `importEciesPublicKey` defaults to non-extractable for ECIES
    // recipient-key use, where extractability is wasted; for BeeKEM
    // leaf use we need the extractable variant.
    const memberPublicKey = await crypto.subtle.importKey(
      'raw',
      readerKemPublicKey as unknown as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' },
      true, // extractable
      [],
    );
    const result = await beekem.addMember(memberPublicKey);
    const committedReaderKemPublicKeys = new Map(
      this._readerKemPublicKeys,
    );
    committedReaderKemPublicKeys.set(
      serializedReader,
      new Uint8Array(readerKemPublicKey),
    );
    // `BeeKEMWelcomeV2.leafIndex` is the node index of the new leaf
    // (even-numbered slot in the tree-math layout), which is exactly
    // what `removeMember` consumes.
    const committedReaderLeafIndices = new Map(this._readerLeafIndices);
    committedReaderLeafIndices.set(
      serializedReader,
      result.welcome.leafIndex,
    );
    // Cache the Welcome under its leaf index so a subsequent
    // `addReader` re-invocation can re-emit it without mutating the
    // tree. Keyed by leaf index (not identity) so revocation can
    // clear the cache atomically when the leaf is blanked.
    const committedWelcomes = new Map(this._beekemWelcomeByLeaf);
    committedWelcomes.set(
      result.welcome.leafIndex,
      copyBeeKEMWelcome(result.welcome),
    );
    const welcomeForCaller = copyBeeKEMWelcome(result.welcome);
    return {
      welcome: welcomeForCaller,
      install: () => {
        this._beekem = beekem;
        this._beekemInitialized = true;
        this._readerKemPublicKeys = committedReaderKemPublicKeys;
        this._readerLeafIndices = committedReaderLeafIndices;
        this._beekemWelcomeByLeaf = committedWelcomes;
      },
    };
  }

  /**
   * Broadcast a BeeKEM `PathUpdateV2` to every connected peer over the
   * `beekemPathUpdateV2` protocol. Used by `removeReader` after a
   * successful `removeMember` rotation (the leaf-blank + path re-key
   * are both performed inside `removeMember`; no follow-up
   * `BeeKEM.update()` call is involved).
   *
   * Wire format starts with a 4-byte big-endian
   * document-path length, the UTF-8 path bytes, then the serialized
   * sync message body (which carries the `pathUpdate` /
   * `pathUpdateEpochId` / `signature` fields). The message is
   * **writer-signed unconditionally** (independent of the swarm-wide
   * `enableSigning` toggle) so a malicious peer cannot inject a
   * forged PathUpdateV2 that steers surviving readers onto an
   * attacker-controlled ratchet state.
   *
   * Best-effort fan-out: each failed dial is logged but does not
   * abort the broadcast. A surviving reader that misses the
   * PathUpdateV2 needs explicit recovery or re-invitation to regain current key
   * state.
   */
  private async _distributeBeeKEMPathUpdate(
    pathUpdate: PathUpdateV2,
    pathUpdateEpochId: Uint8Array,
  ): Promise<void> {
    const message: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: this.documentPath,
      signatureContext: 'beekem-path-update-v2',
      pathUpdate: serializePathUpdateV2ForWire(pathUpdate),
      pathUpdateEpochId,
    };

    // Always writer-sign (mirrors the BeeKEM Welcome flow). Signing
    // is mandatory here: an unsigned PathUpdateV2 would let any
    // connected peer rewrite every surviving reader's BeeKEM state.
    message.signature = await this._signAsWriterUnconditional(message);

    const serialized = this._syncMessageSerializer.serializeSyncMessage(message);

    const pathBytes = this._encoder.encode(this.documentPath);
    if (pathBytes.length === 0 || pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
      throw new Error(
        `Document path "${this.documentPath}" encoded length (${pathBytes.length}) exceeds ` +
          `the maximum allowed path length (${MAX_DOCUMENT_PATH_LENGTH} bytes) for the BeeKEM PathUpdate V2 protocol`,
      );
    }
    const pathHeader = new Uint8Array(4);
    pathHeader[0] = (pathBytes.length >> 24) & 0xff;
    pathHeader[1] = (pathBytes.length >> 16) & 0xff;
    pathHeader[2] = (pathBytes.length >> 8) & 0xff;
    pathHeader[3] = pathBytes.length & 0xff;

    assertSharedProtocolRequestSize(
      pathHeader.byteLength + pathBytes.byteLength + serialized.byteLength,
      'BeeKEM PathUpdateV2 shared protocol request',
    );
    const payload = concatUint8Arrays(pathHeader, pathBytes, serialized);
    assertSharedProtocolRequestSize(
      payload.byteLength,
      'BeeKEM PathUpdateV2 shared protocol request',
    );

    const peers =
      this.swarm.heliaNode.libp2p
        .getConnections()
        ?.map((x) => x.remoteAddr) ?? [];

    const failedPeers: string[] = [];
    for (const peer of peers) {
      try {
        const stream = await this.libp2p.dialProtocol(peer, [beekemPathUpdateV2], {
            runOnLimitedConnection: true,
          });
        await writeStream(stream, [payload]);
      } catch (err) {
        failedPeers.push(peer.toString());
        console.warn(
          `Failed to send BeeKEM PathUpdateV2 to peer:`,
          peer.toString(),
          err,
        );
      }
    }

    if (failedPeers.length > 0) {
      console.warn(
        `BeeKEM PathUpdateV2 for ${this.documentPath} failed to reach ${failedPeers.length} peer(s):`,
        failedPeers,
        'Affected peers may be unable to decrypt subsequent messages until they reload the document.',
      );
    }
  }

  /**
   * Handle an inbound `beekemPathUpdateV2` payload (already
   * de-framed of the path-prefix header by the shared handler in
   * `peerborne.ts`).
   *
   * Validates the writer signature, deserializes the carried
   * `PathUpdateV2`, applies it to the local BeeKEM tree via
   * `processPathUpdate`, and installs the resulting document key
   * under the supplied epoch ID. Mirrors the wire framing used by
   * `handleBeeKEMWelcomeRequestData`.
   *
   * SECURITY: the writer signature is **always** verified, regardless
   * of the swarm-wide `enableSigning` toggle. An unsigned or
   * invalid-signature PathUpdateV2 is dropped without applying any
   * state change. The receiver also validates that the epoch ID it
   * derives locally matches the sender's `pathUpdateEpochId` -- a
   * mismatch indicates either a peer with stale local BeeKEM state
   * or a tampered payload, and is treated as a hard error.
   *
   * @internal Invoked by the shared protocol handler in `peerborne.ts`.
   */
  public async handleBeeKEMPathUpdateRequestData(
    payload: Uint8Array,
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<void> {
    return this._runStateMutation(async () => {
      if (!isSharedProtocolHandlerActive(admission)) return;
      await this._handleBeeKEMPathUpdateRequestDataUnlocked(
        payload,
        admission,
      );
    });
  }

  private async _handleBeeKEMPathUpdateRequestDataUnlocked(
    payload: Uint8Array,
    admission?: SharedProtocolHandlerAdmission,
  ): Promise<void> {
    try {
      let message: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        const stablePayload = copyUnsharedUint8Array(
          payload,
          1,
          MAX_SHARED_PROTOCOL_REQUEST_BYTES,
          'BeeKEM PathUpdate message',
        );
        message = snapshotSyncMessageForContext<ChangesType, PublicKey>(
          snapshotPathUpdateMessage<ChangesType, PublicKey>(this._syncMessageSerializer.deserializeSyncMessage(stablePayload)),
          'beekem-path-update-v2',
        );
      } catch {
        console.warn('Dropping malformed BeeKEM PathUpdateV2');
        return;
      }

      // Defense-in-depth against misrouted payloads (the shared
      // handler already routes by document path).
      if (message.documentId !== this.documentPath) {
        console.warn('Ignoring BeeKEM PathUpdateV2 for the wrong document');
        return;
      }

      // Writer signature is mandatory.
      if (!message.signature) {
        console.warn('Dropping BeeKEM PathUpdateV2 without a signature');
        return;
      }
      if (!message.pathUpdate) {
        console.warn('Dropping BeeKEM PathUpdateV2 without an update payload');
        return;
      }
      if (!message.pathUpdateEpochId) {
        console.warn('Dropping BeeKEM PathUpdateV2 without an epoch ID');
        return;
      }

      try {
        copyUnsharedUint8Array(
          message.pathUpdateEpochId,
          EPOCH_ID_LENGTH,
          EPOCH_ID_LENGTH,
          'BeeKEM PathUpdateV2 epoch ID',
        );
      } catch {
        console.warn('Dropping malformed BeeKEM PathUpdateV2 payload');
        return;
      }

      const { signature, ...expectedUnsigned } = message;
      const messageWithoutSignature = snapshotSyncMessageForContext<ChangesType, PublicKey>(expectedUnsigned, 'beekem-path-update-v2');
      const writerKeysVersion = this._writerKeysVersion;
      let raw: Uint8Array;
      try {
        raw = copyUnsharedUint8Array(
          this._syncMessageSerializer.serializeSyncMessage(
            messageWithoutSignature,
          ),
          1,
          MAX_SHARED_PROTOCOL_REQUEST_BYTES,
          'BeeKEM PathUpdateV2 signature encoding',
        );
      } catch {
        console.warn('Dropping malformed BeeKEM PathUpdateV2 payload');
        return;
      }
      if (!syncMessageMatchesSnapshot(expectedUnsigned, messageWithoutSignature, 'beekem-path-update-v2')) return;
      if (
        (await this._verifyMembershipWriterSignature(
          new Uint8Array(raw),
          signature,
        )) !== true
      ) {
        console.warn('Dropping BeeKEM PathUpdateV2 with an invalid signature');
        return;
      }

      if (this._writerKeysVersion !== writerKeysVersion || !syncMessageMatchesSnapshot(expectedUnsigned, messageWithoutSignature, 'beekem-path-update-v2')) return;

      let pathUpdate: PathUpdateV2;
      let senderEpochId32: Uint8Array;
      try {
        const authenticatedMessage = snapshotPathUpdateMessage<ChangesType, PublicKey>(
          this._syncMessageSerializer.deserializeSyncMessage(raw),
        );
        if (
          authenticatedMessage.documentId !== this.documentPath ||
          !authenticatedMessage.pathUpdate ||
          !syncMessageMatchesSnapshot(expectedUnsigned, authenticatedMessage, 'beekem-path-update-v2')
        ) {
          throw new TypeError('Authenticated BeeKEM PathUpdateV2 is malformed');
        }
        senderEpochId32 = copyUnsharedUint8Array(
          authenticatedMessage.pathUpdateEpochId,
          EPOCH_ID_LENGTH,
          EPOCH_ID_LENGTH,
          'Authenticated BeeKEM PathUpdateV2 epoch ID',
        );
        pathUpdate = deserializePathUpdateV2FromWire(
          authenticatedMessage.pathUpdate,
        );
      } catch {
        console.warn('Dropping malformed authenticated BeeKEM PathUpdateV2');
        return;
      }

      // Apply the path update to the local BeeKEM tree. Two failure
      // modes need different handling here:
      //
      //  - **No local BeeKEM state at all**: this peer has not gone
      //    through founder bootstrap or processed a Welcome yet, so
      //    initializing a fresh founder tree on the fly would only
      //    produce a different root than the sender's. The
      //    epoch-ID gate further down would reject it, but that
      //    would also do unnecessary cryptographic work and (worse)
      //    leave a stranded fresh tree behind for the next
      //    PathUpdateV2 to confuse. Drop the message explicitly and
      //    log: the user will recover keychain state via a fresh
      //    document load against an authorized peer.
      //
      //  - **Stale local state**: `processPathUpdate` throws (the
      //    sender's path doesn't intersect our blanked path, or
      //    our tree state has drifted). Surface the failure but
      //    do not crash the inbound handler.
      if (!this._beekemInitialized || !this._beekem) {
        console.warn(
          'Dropping BeeKEM PathUpdateV2 without initialized local BeeKEM state',
        );
        return;
      }
      const beekem = this._beekem.clone();
      let rootSecret: Uint8Array;
      try {
        rootSecret = await beekem.processPathUpdate(pathUpdate);
      } catch {
        console.warn(
          'Failed to apply BeeKEM PathUpdateV2; an authenticated Welcome or persisted ratchet recovery is required',
        );
        return;
      }
      if (this._writerKeysVersion !== writerKeysVersion) {
        console.warn('Dropping BeeKEM PathUpdate after writer ACL changed');
        return;
      }

      // Validate the sender's epoch ID against our locally-derived
      // value. The wire carries the FULL 32-byte HKDF output and the
      // keychain installs under the same 32-byte ID -- no truncation
      // step on either side, so the wire-format and storage key are
      // byte-identical to what both ends will key on for future
      // encrypted-block lookups.
      const localEpochId32 = await deriveEpochIdFromRootSecret(rootSecret);
      if (!constantTimeEqual(localEpochId32, senderEpochId32)) {
        console.warn('Dropping BeeKEM PathUpdateV2 with a mismatched epoch ID');
        return;
      }

      const newKey = await deriveDocumentKeyFromRootSecret(rootSecret);
      let epochClaimCommit: CapturedDataMethod;
      try {
        const prepareEpochKey = capturePreparedDataMethod(
          this._keychain,
          'prepareEpochKey',
          'PathUpdateV2 keychain prepareEpochKey',
        );
        const preparedEpoch = await documentReflectApply(
          prepareEpochKey.method,
          prepareEpochKey.receiver,
          [localEpochId32, newKey as unknown as DocumentKey],
        );
        epochClaimCommit = capturePreparedDataMethod(
          preparedEpoch,
          'claimCommit',
          'Prepared PathUpdateV2 epoch claimCommit',
        );
      } catch {
        console.error('Failed to stage BeeKEM-derived epoch key');
        return;
      }

      try {
        const committed = await runSharedProtocolMutation(admission, () => {
          if (this._writerKeysVersion !== writerKeysVersion) {
            throw new Error('Writer ACL changed before PathUpdate commit');
          }
          const epochCommit = this._claimPreparedCommit(
            epochClaimCommit,
            'PathUpdateV2 epoch commit claim',
          );
          try {
            finalizePreparedCommitClaim(
              epochCommit,
              'PathUpdateV2 epoch commit claim',
            );
            this._beekem = beekem;
          } catch (error) {
            this._markDocumentStatePoisoned();
            throw error;
          }
        });
        if (!committed.admitted) return;
      } catch {
        console.error('Failed to install BeeKEM-derived epoch key');
        return;
      }

      console.log('Installed BeeKEM-derived epoch key via PathUpdateV2');
    } catch {
      console.error('Shared BeeKEM PathUpdateV2 handling failed');
    }
  }

}
