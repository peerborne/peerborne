import type { DocumentAuthority } from './coordinated-document.js';
import {
  captureDocumentRoster,
  type CapturedDocumentMember,
} from './policy/authority-capture.js';
import { copyUnsharedUint8Array } from './utils.js';
import { documentBytesId } from './internal/document-binary.js';

const ownDescriptor = Object.getOwnPropertyDescriptor;
const apply = Reflect.apply;

function ownData(value: unknown, name: PropertyKey): unknown {
  if (typeof value !== 'object' || value === null)
    throw new Error('Invalid document authority');
  const field = ownDescriptor(value, name);
  if (!field || !('value' in field))
    throw new Error('Invalid document authority data property');
  return field.value;
}

/** @internal Capture provider data and one receiver-bound validity function. */
export function captureDocumentAuthorityLease(
  value: ReturnType<DocumentAuthority['capture']>,
  localId: string,
): {
  readonly headId: Uint8Array;
  readonly members: ReadonlyMap<string, CapturedDocumentMember>;
  isCurrent(): boolean;
} {
  const guard = ownData(value, 'isCurrent');
  if (typeof guard !== 'function')
    throw new Error('Invalid document authority guard');
  const source = ownData(value, 'members');
  if (!Array.isArray(source)) throw new Error('Invalid document authority');
  const count: unknown = ownData(source, 'length');
  if (
    typeof count !== 'number' ||
    !Number.isSafeInteger(count) ||
    count < 1 ||
    count > 256
  )
    throw new Error('Invalid document authority');
  const headId = copyUnsharedUint8Array(
    ownData(value, 'headId'),
    32,
    32,
    'document authority head',
  );
  const entries: CapturedDocumentMember[] = [];
  for (let index = 0; index < count; index++) {
    const member = ownData(source, index);
    const publicKey = ownData(member, 'publicKey');
    const role = ownData(member, 'role');
    if (
      typeof publicKey !== 'string' ||
      typeof role !== 'number' ||
      !Number.isSafeInteger(role)
    )
      throw new Error('Invalid document authority member');
    const id = documentBytesId(
      copyUnsharedUint8Array(
        ownData(member, 'memberId'),
        32,
        32,
        'document member',
      ),
    );
    entries.push({ id, publicKey, role });
  }
  const roster = captureDocumentRoster(entries, localId);
  if (!roster.valid) throw new Error('Invalid document authority roster');
  return {
    headId,
    members: roster.members,
    isCurrent: () => apply(guard, value, []) === true,
  };
}
