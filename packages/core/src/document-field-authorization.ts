import type { PreparedDocumentChange } from './document-crdt-session.js';
import { isWellFormedUtf16 } from './internal/canonical-encoding.js';
import {
  canAdmitFieldInspection,
  firstUnauthorizedFieldPath,
} from './policy/field-authorization.js';
import { consumeWorkBudget } from './policy/work-budget.js';

/** Map-key segments. A grant covers its entire subtree; sequence containers are indivisible. */
export type DocumentFieldPath = readonly string[];
export type DocumentWritePaths = readonly DocumentFieldPath[];

/** @internal One bounded aggregate for all field grants in an authority roster. */
export class DocumentFieldScopeBudget {
  private paths = 0;
  private segments = 0;
  private units = 0;
  charge(paths: number, segments: number, units: number): void {
    const nextPaths = consumeWorkBudget(this.paths, paths, 4096);
    const nextSegments = consumeWorkBudget(this.segments, segments, 32768);
    const nextUnits = consumeWorkBudget(this.units, units, 1048576);
    if (nextPaths < 0 || nextSegments < 0 || nextUnits < 0)
      throw new RangeError(
        'Document field authorization exceeds aggregate bounds',
      );
    this.paths = nextPaths;
    this.segments = nextSegments;
    this.units = nextUnits;
  }
}

const ownDescriptor = Object.getOwnPropertyDescriptor;
function own(value: unknown, key: PropertyKey): unknown {
  if (value === null || typeof value !== 'object')
    throw new TypeError('Invalid document field authorization');
  const descriptor = ownDescriptor(value, key);
  if (!descriptor || !('value' in descriptor))
    throw new TypeError('Invalid document field authorization');
  return descriptor.value;
}

function count(value: unknown, maximum: number): number {
  if (!Array.isArray(value))
    throw new TypeError('Invalid document field authorization');
  const length = own(value, 'length');
  if (
    typeof length !== 'number' ||
    !Number.isSafeInteger(length) ||
    length < 0 ||
    length > maximum
  )
    throw new TypeError('Document field authorization exceeds bounds');
  return length;
}

/** Capture own scalar data without invoking getters or retaining caller arrays. */
export function copyDocumentFieldPaths(
  value: unknown,
  maximum = 64,
  budget?: DocumentFieldScopeBudget,
): DocumentWritePaths {
  const length = count(value, maximum);
  budget?.charge(length, 0, 0);
  const paths: DocumentFieldPath[] = [];
  let units = 0;
  for (let index = 0; index < length; index++) {
    const source = own(value, index),
      depth = count(source, 32);
    budget?.charge(0, depth, 0);
    const path: string[] = [];
    for (let segment = 0; segment < depth; segment++) {
      const key = own(source, segment);
      if (
        typeof key !== 'string' ||
        key.length > 1024 ||
        !isWellFormedUtf16(key) ||
        key.length > 1048576 - units
      )
        throw new TypeError('Document field authorization exceeds bounds');
      units += key.length;
      budget?.charge(0, 0, key.length);
      path.push(key);
    }
    paths.push(Object.freeze(path));
  }
  return Object.freeze(paths);
}

export function captureDocumentWritePaths(
  member: unknown,
  budget?: DocumentFieldScopeBudget,
): DocumentWritePaths | undefined {
  if (member === null || typeof member !== 'object')
    throw new TypeError('Invalid document field authorization');
  const descriptor = ownDescriptor(member, 'writePaths');
  if (!descriptor) return undefined;
  if (!('value' in descriptor))
    throw new TypeError('Invalid document field authorization');
  return descriptor.value === undefined
    ? undefined
    : copyDocumentFieldPaths(descriptor.value, 64, budget);
}

/** Bounded, detached native operation targets. Repeated paths still consume scan work. */
export class DocumentOperationTargets {
  private scanned = 0;
  private units = 0;
  private paths = new Map<string, DocumentFieldPath>();

  add(path: DocumentFieldPath, work = 1): void {
    const [owned] = copyDocumentFieldPaths([path], 1);
    const key = JSON.stringify(owned),
      known = this.paths.has(key);
    const added = known
      ? 0
      : owned.reduce((sum, segment) => sum + segment.length, 0);
    if (
      !Number.isSafeInteger(work) ||
      work < 0 ||
      !canAdmitFieldInspection(
        this.scanned,
        work,
        this.paths.size,
        known,
        this.units,
        added,
      )
    )
      throw new RangeError('Document operation inspection exceeds bounds');
    this.scanned += work;
    this.units += added;
    if (!known) this.paths.set(key, owned);
  }

  snapshot(): DocumentWritePaths {
    return Object.freeze([...this.paths.values()]);
  }
}

export function assertDocumentOperationsAllowed<Changes>(
  plan: PreparedDocumentChange<Changes>,
  grants: DocumentWritePaths | undefined,
): void {
  if (grants === undefined) return;
  if (typeof plan.operationPaths !== 'function')
    throw new Error('CRDT provider cannot inspect document operations');
  const paths = copyDocumentFieldPaths(plan.operationPaths(), 4096);
  if (firstUnauthorizedFieldPath(grants, paths) !== -1)
    throw new Error('Document operation is outside the signed field grants');
}
