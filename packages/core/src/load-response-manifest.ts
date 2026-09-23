import { defineEnumerableDataProperty } from './internal/data-property.js';
import {
  CRDTChangeNode,
  CRDTChangeNodeKind,
  crdtChangeNodeDeferred,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import { snapshotBoundedChangeTree } from './change-tree-walk.js';
import { MAX_MERKLE_DAG_DEPTH } from './merkle-dag-serialization.js';
import { copyUnsharedUint8Array } from './utils.js';
import {
  concatenate,
  encodeUtf8,
  isWellFormedUtf16,
  uint32,
} from './internal/canonical-encoding.js';

const LOAD_RESPONSE_MANIFEST_DOMAIN =
  'peerborne/load-response-manifest/v1\0';

export const LOAD_RESPONSE_MANIFEST_HASH_LENGTH = 32;
export const MAX_LOAD_RESPONSE_MANIFEST_NODES = 4096;
export const MAX_LOAD_RESPONSE_MANIFEST_EDGES = 16384;
export const MAX_LOAD_RESPONSE_MANIFEST_OCCURRENCES =
  MAX_LOAD_RESPONSE_MANIFEST_EDGES + 1;
export const MAX_LOAD_RESPONSE_MANIFEST_ID_BYTES = 1024;
export const MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES = 16 * 1024 * 1024;

const LOAD_RESPONSE_MANIFEST_INPUT_FIELDS = [
  'changeId',
  'changes',
  'serializeChange',
  'snapshot',
  'keychainChangesBytes',
] as const;
const LOAD_RESPONSE_MANIFEST_SNAPSHOT_FIELDS = [
  'stateBytes',
  'lastChangeNodeCID',
  'compactedCount',
  'timestamp',
] as const;
const arrayIsArray = Array.isArray;
const objectCreate = Object.create;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;



export interface LoadResponseManifestSnapshot {
  readonly stateBytes: Uint8Array;
  readonly lastChangeNodeCID: string;
  readonly compactedCount: number;
  readonly timestamp: number;
}

export interface LoadResponseManifestInput<ChangesType> {
  readonly changeId?: string;
  readonly changes?: CRDTChangeNode<ChangesType>;
  /** Canonical wire serializer for each inline CRDT change payload. */
  readonly serializeChange?: (change: ChangesType) => Uint8Array;
  readonly snapshot?: LoadResponseManifestSnapshot;
  readonly keychainChangesBytes?: Uint8Array;
}

interface NodeDescriptor {
  readonly kind: CRDTChangeNodeKind;
  readonly keyID?: string;
  readonly hasInlineChange: boolean;
  readonly inlineChangeBytes?: Uint8Array;
  readonly childrenMode: 0 | 1 | 2;
  readonly childIds: readonly string[];
}

interface NodeRecord {
  readonly kind: CRDTChangeNodeKind;
  full?: NodeDescriptor;
  sparseKeyID?: string;
}

function uint8(value: number): Uint8Array {
  return new Uint8Array([value]);
}

function uint64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

function requireString(
  name: string,
  value: unknown,
  options: { allowEmpty?: boolean } = {},
): string {
  if (
    typeof value !== 'string' ||
    (!options.allowEmpty && value.length === 0)
  ) {
    throw new TypeError(`${name} must be a ${
      options.allowEmpty ? '' : 'non-empty '
    }string`);
  }
  if (!isWellFormedUtf16(value)) {
    throw new TypeError(`${name} must be well-formed UTF-16`);
  }
  if (encodeUtf8(value).length > MAX_LOAD_RESPONSE_MANIFEST_ID_BYTES) {
    throw new RangeError(
      `${name} exceeds ${MAX_LOAD_RESPONSE_MANIFEST_ID_BYTES} UTF-8 bytes`,
    );
  }
  return value;
}

function stringParts(value: string): Uint8Array[] {
  const bytes = encodeUtf8(value);
  return [uint32(bytes.length), bytes];
}

function kindByte(kind: CRDTChangeNodeKind): number {
  switch (kind) {
    case crdtDocumentChangeNode:
      return 0;
    case crdtReaderChangeNode:
      return 1;
    case crdtWriterChangeNode:
      return 2;
    default:
      throw new TypeError(`invalid CRDT change-node kind: ${String(kind)}`);
  }
}

function requirePlainNode<ChangesType>(
  node: CRDTChangeNode<ChangesType>,
): void {
  if (node === null || typeof node !== 'object' || reflectApply(arrayIsArray, Array, [node])) {
    throw new TypeError('load response manifest node must be an object');
  }
  kindByte(node.kind);
  if (node.keyID !== undefined) {
    requireString('change-node keyID', node.keyID);
  }
  if (
    node.children !== undefined &&
    node.children !== crdtChangeNodeDeferred
  ) {
    if (
      node.children === null ||
      typeof node.children !== 'object' ||
      reflectApply(arrayIsArray, Array, [node.children])
    ) {
      throw new TypeError(
        'change-node children must be an object, false, or undefined',
      );
    }
    const prototype = reflectApply(objectGetPrototypeOf, Object, [node.children]);
    if (prototype !== objectPrototype && prototype !== null) {
      throw new TypeError('change-node children must be a plain object');
    }
  }
}

function describeNode<ChangesType>(
  node: CRDTChangeNode<ChangesType>,
  serializeChange: ((change: ChangesType) => Uint8Array) | undefined,
): NodeDescriptor {
  requirePlainNode(node);
  let inlineChangeBytes: Uint8Array | undefined;
  if (node.change !== undefined) {
    if (serializeChange === undefined) {
      throw new TypeError(
        'load response manifest requires serializeChange for inline changes',
      );
    }
    inlineChangeBytes = snapshotPayloadBytes(
      'inline changes',
      serializeChange(node.change),
    );
  }
  let childrenMode: 0 | 1 | 2 = 0;
  let childIds: string[] = [];
  if (node.children === crdtChangeNodeDeferred) {
    childrenMode = 1;
  } else if (node.children !== undefined) {
    childrenMode = 2;
    childIds = Object.keys(node.children).map((childId) =>
      requireString('change-node CID', childId),
    );
    childIds.sort();
  }
  return {
    kind: node.kind,
    keyID: node.keyID,
    hasInlineChange: node.change !== undefined,
    inlineChangeBytes,
    childrenMode,
    childIds,
  };
}

function sameBytes(
  first: Uint8Array | undefined,
  second: Uint8Array | undefined,
): boolean {
  if (first === undefined || second === undefined) return first === second;
  return (
    first.byteLength === second.byteLength &&
    first.every((byte, index) => byte === second[index])
  );
}

function sameDescriptor(a: NodeDescriptor, b: NodeDescriptor): boolean {
  if (
    a.kind !== b.kind ||
    a.keyID !== b.keyID ||
    a.hasInlineChange !== b.hasInlineChange ||
    !sameBytes(a.inlineChangeBytes, b.inlineChangeBytes) ||
    a.childrenMode !== b.childrenMode ||
    a.childIds.length !== b.childIds.length
  ) {
    return false;
  }
  return a.childIds.every((childId, index) => childId === b.childIds[index]);
}

function isSparseDescriptor(descriptor: NodeDescriptor): boolean {
  return !descriptor.hasInlineChange && descriptor.childrenMode === 0;
}

function canonicalDescriptor(record: NodeRecord): NodeDescriptor {
  const descriptor =
    record.full ??
    ({
      kind: record.kind,
      hasInlineChange: false,
      inlineChangeBytes: undefined,
      childrenMode: 0,
      childIds: [],
    } satisfies NodeDescriptor);
  const keyID = descriptor.keyID ?? record.sparseKeyID;
  return keyID === descriptor.keyID
    ? descriptor
    : {
        ...descriptor,
        keyID,
      };
}

function descriptorParts(descriptor: NodeDescriptor): Uint8Array[] {
  const parts: Uint8Array[] = [
    uint8(kindByte(descriptor.kind)),
    uint8(descriptor.keyID === undefined ? 0 : 1),
  ];
  if (descriptor.keyID !== undefined) {
    parts.push(...stringParts(descriptor.keyID));
  }
  parts.push(
    uint8(descriptor.hasInlineChange ? 1 : 0),
  );
  if (descriptor.inlineChangeBytes !== undefined) {
    parts.push(
      uint32(descriptor.inlineChangeBytes.byteLength),
      descriptor.inlineChangeBytes,
    );
  }
  parts.push(uint8(descriptor.childrenMode), uint32(descriptor.childIds.length));
  for (const childId of descriptor.childIds) {
    parts.push(...stringParts(childId));
  }
  return parts;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    bytes as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(digest);
}

function snapshotManifestOwnDataFields<Fields extends readonly string[]>(
  value: unknown,
  fields: Fields,
  label: string,
  required: boolean,
): Record<Fields[number], unknown> {
  if (value === null || typeof value !== 'object') {
    throw new TypeError(`${label} must be a plain record`);
  }
  let isArray: boolean;
  let prototype: object | null;
  let prototypeParent: object | null = null;
  try {
    isArray = reflectApply(arrayIsArray, Array, [value]) as boolean;
    prototype = reflectApply(objectGetPrototypeOf, Object, [value]) as
      | object
      | null;
    if (prototype !== null) {
      prototypeParent = reflectApply(objectGetPrototypeOf, Object, [
        prototype,
      ]) as object | null;
    }
  } catch {
    throw new TypeError(`${label} must be a plain record`);
  }
  if (isArray || (prototype !== null && prototypeParent !== null)) {
    throw new TypeError(`${label} must be a plain record`);
  }

  const snapshot = reflectApply(objectCreate, Object, [null]) as Record<
    Fields[number],
    unknown
  >;
  for (const field of fields) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
        value,
        field,
      ]) as PropertyDescriptor | undefined;
    } catch {
      throw new TypeError(`${label} must expose stable own data properties`);
    }
    if (descriptor === undefined) {
      if (required) {
        throw new TypeError(
          `${label} ${field} must be an enumerable own data property`,
        );
      }
      defineEnumerableDataProperty(snapshot, field, undefined);
      continue;
    }
    if (descriptor.enumerable !== true || !('value' in descriptor)) {
      throw new TypeError(
        `${label} ${field} must be an enumerable own data property`,
      );
    }
    defineEnumerableDataProperty(snapshot, field, descriptor.value);
  }
  return snapshot;
}

function snapshotPayloadBytes(name: string, value: unknown): Uint8Array {
  try {
    return copyUnsharedUint8Array(
      value,
      0,
      MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES,
      name,
    );
  } catch {
    throw new TypeError(
      `${name} exceeds ${MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES} bytes or is not an unshared Uint8Array`,
    );
  }
}

/**
 * Hash the complete state-mutating plan carried by one V4 load response.
 *
 * The canonical manifest binds root identity, every named node's CID and
 * classification, directed child edges, canonically serialized inline change
 * bytes, the canonical full representation of each CID, snapshot state plus
 * metadata, and keychain changes. Sparse cross-link aliases are reconciled
 * with that full representation. The response bytes are never trusted as a
 * precomputed manifest: advertisers and loaders using this protocol must
 * independently derive this digest from the actual plan they would serve or
 * apply.
 */
export async function loadResponseManifestHash<ChangesType>(
  input: LoadResponseManifestInput<ChangesType>,
): Promise<Uint8Array> {
  // Capture all known input fields through own data descriptors before
  // invoking serializeChange or crossing an async digest boundary. Reading
  // properties directly would let accessors synthesize a manifest from states
  // that never coexisted.
  const inputFields = snapshotManifestOwnDataFields(
    input,
    LOAD_RESPONSE_MANIFEST_INPUT_FIELDS,
    'load response manifest input',
    false,
  );
  const rawSnapshot = inputFields.snapshot;
  const snapshotFields =
    rawSnapshot === undefined
      ? undefined
      : snapshotManifestOwnDataFields(
          rawSnapshot,
          LOAD_RESPONSE_MANIFEST_SNAPSHOT_FIELDS,
          'load response manifest snapshot',
          true,
        );
  const snapshot =
    snapshotFields === undefined
      ? undefined
      : {
          stateBytes: snapshotPayloadBytes(
            'snapshot state',
            snapshotFields.stateBytes,
          ),
          lastChangeNodeCID: snapshotFields.lastChangeNodeCID,
          compactedCount: snapshotFields.compactedCount,
          timestamp: snapshotFields.timestamp,
        };
  const inputKeychainChangesBytes = inputFields.keychainChangesBytes;
  const keychainChangesBytes =
    inputKeychainChangesBytes === undefined
      ? undefined
      : snapshotPayloadBytes(
          'keychain changes',
          inputKeychainChangesBytes,
        );
  const changeId = inputFields.changeId as string | undefined;
  const changes = inputFields.changes as CRDTChangeNode<ChangesType> | undefined;
  const serializeChange = inputFields.serializeChange as
    | ((change: ChangesType) => Uint8Array)
    | undefined;

  if (changes === undefined && changeId !== undefined) {
    throw new TypeError(
      'load response manifest cannot name a change root without a tree',
    );
  }
  let changesSnapshot: Readonly<CRDTChangeNode<ChangesType>> | undefined;
  try {
    changesSnapshot =
      changes === undefined
        ? undefined
        : snapshotBoundedChangeTree(changeId, changes).root;
  } catch (cause) {
    if (
      cause instanceof RangeError &&
      cause.message ===
        `change tree exceeds maximum depth ${MAX_MERKLE_DAG_DEPTH}`
    ) {
      throw new RangeError(
        `load response manifest exceeds ${MAX_MERKLE_DAG_DEPTH} tree depth`,
      );
    }
    throw cause;
  }

  const records = new Map<string, NodeRecord>();
  const visiting = new Set<string>();
  let edgeCount = 0;
  let occurrenceCount = 0;
  let traversedEdgeCount = 0;
  let inlineChangeByteCount = 0;

  const accountOccurrence = (): void => {
    occurrenceCount++;
    if (occurrenceCount > MAX_LOAD_RESPONSE_MANIFEST_OCCURRENCES) {
      throw new RangeError(
        `load response manifest exceeds ${MAX_LOAD_RESPONSE_MANIFEST_OCCURRENCES} node occurrences`,
      );
    }
  };

  const accountDescriptor = (descriptor: NodeDescriptor): void => {
    traversedEdgeCount += descriptor.childIds.length;
    if (traversedEdgeCount > MAX_LOAD_RESPONSE_MANIFEST_EDGES) {
      throw new RangeError(
        `load response manifest exceeds ${MAX_LOAD_RESPONSE_MANIFEST_EDGES} traversed edges`,
      );
    }
    inlineChangeByteCount += descriptor.inlineChangeBytes?.byteLength ?? 0;
    if (inlineChangeByteCount > MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES) {
      throw new RangeError(
        `load response manifest inline changes exceed ${MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES} bytes`,
      );
    }
  };

  type NamedWalkFrame =
    | {
        readonly phase: 'enter';
        readonly cid: string;
        readonly node: CRDTChangeNode<ChangesType>;
        readonly depth: number;
      }
    | { readonly phase: 'leave'; readonly cid: string };

  const walkNamed = (
    initialCid: string,
    initialNode: CRDTChangeNode<ChangesType>,
    initialDepth = 1,
  ): void => {
    const pending: NamedWalkFrame[] = [
      {
        phase: 'enter',
        cid: initialCid,
        node: initialNode,
        depth: initialDepth,
      },
    ];
    while (pending.length > 0) {
      const frame = pending.pop()!;
      if (frame.phase === 'leave') {
        visiting.delete(frame.cid);
        continue;
      }

      const { cid, node, depth } = frame;
      if (depth > MAX_MERKLE_DAG_DEPTH) {
        throw new RangeError(
          `load response manifest exceeds ${MAX_MERKLE_DAG_DEPTH} tree depth`,
        );
      }
      requireString('change-node CID', cid);
      if (visiting.has(cid)) {
        throw new TypeError(
          `load response manifest contains a cycle at ${cid}`,
        );
      }
      accountOccurrence();
      const descriptor = describeNode(node, serializeChange);
      accountDescriptor(descriptor);
      let record = records.get(cid);
      if (record === undefined) {
        if (records.size >= MAX_LOAD_RESPONSE_MANIFEST_NODES) {
          throw new RangeError(
            `load response manifest exceeds ${MAX_LOAD_RESPONSE_MANIFEST_NODES} nodes`,
          );
        }
        record = { kind: descriptor.kind };
        records.set(cid, record);
      } else if (record.kind !== descriptor.kind) {
        throw new TypeError(
          `load response manifest contains conflicting descriptions for CID ${cid}`,
        );
      }

      if (isSparseDescriptor(descriptor)) {
        if (
          descriptor.keyID !== undefined &&
          ((record.sparseKeyID !== undefined &&
            record.sparseKeyID !== descriptor.keyID) ||
            (record.full?.keyID !== undefined &&
              record.full.keyID !== descriptor.keyID))
        ) {
          throw new TypeError(
            `load response manifest contains conflicting descriptions for CID ${cid}`,
          );
        }
        record.sparseKeyID ??= descriptor.keyID;
      } else if (record.full !== undefined) {
        if (!sameDescriptor(record.full, descriptor)) {
          throw new TypeError(
            `load response manifest contains conflicting descriptions for CID ${cid}`,
          );
        }
      } else {
        if (
          record.sparseKeyID !== undefined &&
          descriptor.keyID !== undefined &&
          record.sparseKeyID !== descriptor.keyID
        ) {
          throw new TypeError(
            `load response manifest contains conflicting descriptions for CID ${cid}`,
          );
        }
        record.full = descriptor;
        edgeCount += descriptor.childIds.length;
        if (edgeCount > MAX_LOAD_RESPONSE_MANIFEST_EDGES) {
          throw new RangeError(
            `load response manifest exceeds ${MAX_LOAD_RESPONSE_MANIFEST_EDGES} edges`,
          );
        }
      }
      if (
        node.children === undefined ||
        node.children === crdtChangeNodeDeferred
      ) {
        continue;
      }

      visiting.add(cid);
      pending.push({ phase: 'leave', cid });
      for (let index = descriptor.childIds.length - 1; index >= 0; index--) {
        const childId = descriptor.childIds[index]!;
        pending.push({
          phase: 'enter',
          cid: childId,
          node: node.children[childId]!,
          depth: depth + 1,
        });
      }
    }
  };

  let anonymousRoot: NodeDescriptor | undefined;
  if (changesSnapshot !== undefined) {
    if (changeId === undefined) {
      accountOccurrence();
      anonymousRoot = describeNode(changesSnapshot, serializeChange);
      accountDescriptor(anonymousRoot);
      edgeCount += anonymousRoot.childIds.length;
      if (edgeCount > MAX_LOAD_RESPONSE_MANIFEST_EDGES) {
        throw new RangeError(
          `load response manifest exceeds ${MAX_LOAD_RESPONSE_MANIFEST_EDGES} edges`,
        );
      }
      if (
        changesSnapshot.children !== undefined &&
        changesSnapshot.children !== crdtChangeNodeDeferred
      ) {
        for (const childId of anonymousRoot.childIds) {
          // The anonymous root itself occupies depth one.
          walkNamed(childId, changesSnapshot.children[childId]!, 2);
        }
      }
    } else {
      walkNamed(
        requireString('change root CID', changeId),
        changesSnapshot,
      );
    }
  }

  const parts: Uint8Array[] = [encodeUtf8(LOAD_RESPONSE_MANIFEST_DOMAIN)];
  if (changesSnapshot === undefined) {
    parts.push(uint8(0));
  } else if (changeId === undefined) {
    parts.push(uint8(1), ...descriptorParts(anonymousRoot!));
  } else {
    parts.push(uint8(2), ...stringParts(changeId));
  }

  const sortedRecords = [...records.entries()]
    .map(([cid, record]) => [cid, canonicalDescriptor(record)] as const)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const totalNodeCount =
    sortedRecords.length + (anonymousRoot === undefined ? 0 : 1);
  if (totalNodeCount > MAX_LOAD_RESPONSE_MANIFEST_NODES) {
    throw new RangeError(
      `load response manifest exceeds ${MAX_LOAD_RESPONSE_MANIFEST_NODES} nodes`,
    );
  }
  parts.push(uint32(totalNodeCount), uint32(edgeCount));
  for (const [cid, descriptor] of sortedRecords) {
    parts.push(...stringParts(cid), ...descriptorParts(descriptor));
  }

  if (snapshot === undefined) {
    parts.push(uint8(0));
  } else {
    const snapshotCid = requireString(
      'snapshot lastChangeNodeCID',
      snapshot.lastChangeNodeCID,
      { allowEmpty: true },
    );
    const compactedCount = snapshot.compactedCount;
    if (
      typeof compactedCount !== 'number' ||
      !Number.isInteger(compactedCount) ||
      compactedCount < 0 ||
      compactedCount > 0xffffffff
    ) {
      throw new RangeError('snapshot compactedCount must be a uint32');
    }
    const timestamp = snapshot.timestamp;
    if (
      typeof timestamp !== 'number' ||
      !Number.isSafeInteger(timestamp) ||
      timestamp < 0
    ) {
      throw new RangeError(
        'snapshot timestamp must be a non-negative safe integer',
      );
    }
    parts.push(
      uint8(1),
      ...stringParts(snapshotCid),
      uint32(compactedCount),
      uint64(timestamp),
      uint32(snapshot.stateBytes.byteLength),
      await sha256(snapshot.stateBytes),
    );
  }

  if (keychainChangesBytes === undefined) {
    parts.push(uint8(0));
  } else {
    parts.push(
      uint8(1),
      uint32(keychainChangesBytes.byteLength),
      await sha256(keychainChangesBytes),
    );
  }

  return sha256(concatenate(parts));
}
