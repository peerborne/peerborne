import { ownDataProperty } from './data-property.js';
import { snapshotPlainDataObject } from './plain-data.js';

const reflectApply = Reflect.apply;
const regExpExec = RegExp.prototype.exec;
const numberIsInteger = Number.isInteger;
const CANONICAL_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;

/** @internal Protocol IDs, outbox kinds and algorithm names share one ASCII identifier grammar. */
export function isCanonicalIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    reflectApply(regExpExec, CANONICAL_IDENTIFIER, [value]) !== null
  );
}

/** @internal A canonical identifier paired with an unsigned 16-bit version. */
export function isCanonicalProtocol(id: unknown, version: unknown): boolean {
  return (
    isCanonicalIdentifier(id) &&
    typeof version === 'number' &&
    numberIsInteger(version) &&
    version >= 0 &&
    version <= 0xffff
  );
}

/** @internal Protocol identity compares by ID and version only. */
export function sameProtocol(
  left: { readonly id: string; readonly version: number },
  right: { readonly id: string; readonly version: number },
): boolean {
  return left.id === right.id && left.version === right.version;
}

/** @internal Detach an exact `{ id, version }` object holding a canonical protocol identifier. */
export function snapshotCanonicalProtocol(
  value: unknown,
  field: string,
): { id: string; version: number } {
  const protocol = snapshotPlainDataObject(value, ['id', 'version'], field);
  const id = ownDataProperty(protocol, 'id');
  const version = ownDataProperty(protocol, 'version');
  if (!isCanonicalProtocol(id, version)) {
    throw new Error(`${field} is not a canonical protocol identifier`);
  }
  return { id: id as string, version: version as number };
}
