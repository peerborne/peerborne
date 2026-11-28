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
import { copyUnsharedUint8Array } from './internal/bytes.js';
import {
  concatenate,
  encodeUtf8,
  assertBoundedUtf8,
  uint32,
} from './internal/canonical-encoding.js';
import { sha256 } from './internal/digest.js';

const LOAD_RESPONSE_MANIFEST_DOMAIN = 'peerborne/load-response-manifest/v2\0';

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
  'snapshot',
  'keychainChangesBytes',
] as const;
const LOAD_RESPONSE_MANIFEST_SNAPSHOT_FIELDS = [
  'stateBytes',
  'lastChangeNodeCID',
] as const;
const arrayIsArray = Array.isArray;
const objectCreate = Object.create;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;

/**
 * The snapshot state a load response would apply. The signer, signature,
 * timestamp and compacted count are deliberately absent: honest writers sign
 * their own snapshots of the same state, and the loader authenticates the
 * signature separately against the document's writers.
 */
export interface LoadResponseManifestSnapshot {
  readonly stateBytes: Uint8Array;
  readonly lastChangeNodeCID: string;
}

export interface LoadResponseManifestInput<ChangesType> {
  readonly changeId?: string;
  readonly changes?: CRDTChangeNode<ChangesType>;
  readonly snapshot?: LoadResponseManifestSnapshot;
  readonly keychainChangesBytes?: Uint8Array;
}

interface NodeDescriptor {
  readonly kind: CRDTChangeNodeKind;
  readonly childrenMode: 0 | 1 | 2;
  readonly childIds: readonly string[];
}

interface NodeRecord {
  readonly kind: CRDTChangeNodeKind;
  full?: NodeDescriptor;
}

function uint8(value: number): Uint8Array {
  return new Uint8Array([value]);
}

function requireString(
  name: string,
  value: unknown,
  options: { allowEmpty?: boolean } = {},
): string {
  assertBoundedUtf8(
    value,
    MAX_LOAD_RESPONSE_MANIFEST_ID_BYTES,
    name,
    options.allowEmpty,
  );
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
  if (
    node === null ||
    typeof node !== 'object' ||
    reflectApply(arrayIsArray, Array, [node])
  ) {
    throw new TypeError('load response manifest node must be an object');
  }
  kindByte(node.kind);
  if (node.children !== undefined && node.children !== crdtChangeNodeDeferred) {
    if (
      node.children === null ||
      typeof node.children !== 'object' ||
      reflectApply(arrayIsArray, Array, [node.children])
    ) {
      throw new TypeError(
        'change-node children must be an object, false, or undefined',
      );
    }
    const prototype = reflectApply(objectGetPrototypeOf, Object, [
      node.children,
    ]);
    if (prototype !== objectPrototype && prototype !== null) {
      throw new TypeError('change-node children must be a plain object');
    }
  }
}

function describeNode<ChangesType>(
  node: CRDTChangeNode<ChangesType>,
): NodeDescriptor {
  requirePlainNode(node);
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
    childrenMode,
    childIds,
  };
}

function sameDescriptor(a: NodeDescriptor, b: NodeDescriptor): boolean {
  if (
    a.kind !== b.kind ||
    a.childrenMode !== b.childrenMode ||
    a.childIds.length !== b.childIds.length
  ) {
    return false;
  }
  return a.childIds.every((childId, index) => childId === b.childIds[index]);
}

function isSparseDescriptor(descriptor: NodeDescriptor): boolean {
  return descriptor.childrenMode === 0;
}

function canonicalDescriptor(record: NodeRecord): NodeDescriptor {
  return (
    record.full ??
    ({
      kind: record.kind,
      childrenMode: 0,
      childIds: [],
    } satisfies NodeDescriptor)
  );
}

function descriptorParts(descriptor: NodeDescriptor): Uint8Array[] {
  const parts: Uint8Array[] = [
    uint8(kindByte(descriptor.kind)),
    uint8(descriptor.childrenMode),
    uint32(descriptor.childIds.length),
  ];
  for (const childId of descriptor.childIds) {
    parts.push(...stringParts(childId));
  }
  return parts;
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
      object | null;
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
 * Hash the state a V4 load response would apply, independent of how the
 * holder happens to represent it.
 *
 * The canonical manifest binds root identity, every named node's CID and
 * classification, directed child edges and deferred-children markers, the
 * snapshot's boundary CID and state bytes, and keychain changes. A change CID
 * addresses its encrypted block, so it binds the change content; inline
 * payloads are not hashed because a quorum-bound load discards them and
 * fetches every CID from the blockstore. Sparse cross-link aliases are
 * reconciled with the full representation of their CID. The snapshot's
 * signature, timestamp and compacted count are excluded so writers that
 * signed their own snapshot of one state agree; loaders verify that signature
 * against the document's writers before applying the snapshot. The response
 * bytes are never trusted as a precomputed manifest: advertisers and loaders
 * must independently derive this digest from the actual plan they would serve
 * or apply.
 */
export async function loadResponseManifestHash<ChangesType>(
  input: LoadResponseManifestInput<ChangesType>,
): Promise<Uint8Array> {
  // Capture all known input fields through own data descriptors before
  // crossing an async digest boundary. Reading properties directly would let
  // accessors synthesize a manifest from states that never coexisted.
  const inputFields = snapshotManifestOwnDataFields(
    input,
    LOAD_RESPONSE_MANIFEST_INPUT_FIELDS,
    'load response manifest input',
    false,
  );
  const changeId = inputFields.changeId as string | undefined;
  const changes = inputFields.changes as
    CRDTChangeNode<ChangesType> | undefined;
  if (changes === undefined && changeId !== undefined) {
    throw new TypeError(
      'load response manifest cannot name a change root without a tree',
    );
  }
  if (changeId !== undefined) requireString('change root CID', changeId);
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
  let snapshot: LoadResponseManifestSnapshot | undefined;
  if (snapshotFields !== undefined) {
    const lastChangeNodeCID = requireString(
      'snapshot lastChangeNodeCID',
      snapshotFields.lastChangeNodeCID,
      { allowEmpty: true },
    );
    snapshot = {
      stateBytes: snapshotPayloadBytes(
        'snapshot state',
        snapshotFields.stateBytes,
      ),
      lastChangeNodeCID,
    };
  }
  const inputKeychainChangesBytes = inputFields.keychainChangesBytes;
  const keychainChangesBytes =
    inputKeychainChangesBytes === undefined
      ? undefined
      : snapshotPayloadBytes('keychain changes', inputKeychainChangesBytes);
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
      const descriptor = describeNode(node);
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

      if (!isSparseDescriptor(descriptor)) {
        if (record.full === undefined) {
          record.full = descriptor;
          edgeCount += descriptor.childIds.length;
          if (edgeCount > MAX_LOAD_RESPONSE_MANIFEST_EDGES) {
            throw new RangeError(
              `load response manifest exceeds ${MAX_LOAD_RESPONSE_MANIFEST_EDGES} edges`,
            );
          }
        } else if (!sameDescriptor(record.full, descriptor)) {
          throw new TypeError(
            `load response manifest contains conflicting descriptions for CID ${cid}`,
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
      anonymousRoot = describeNode(changesSnapshot);
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
      walkNamed(changeId, changesSnapshot);
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
    parts.push(
      uint8(1),
      ...stringParts(snapshot.lastChangeNodeCID),
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
