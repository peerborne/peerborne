import { describe, expect, test } from '@jest/globals';
import {
  CAP_DOC_ADMIN,
  CAP_DOC_WRITE,
  CAP_DOC_READ,
  CAP_DOC_HISTORY,
  capabilityImplies,
  isFieldCapability,
  getFieldPath,
} from './capabilities.js';

describe('capabilityImplies', () => {
  test.each([
    [CAP_DOC_ADMIN, CAP_DOC_WRITE, true, 'admin implies write'],
    [CAP_DOC_ADMIN, CAP_DOC_READ, true, 'admin implies read'],
    [CAP_DOC_ADMIN, CAP_DOC_ADMIN, true, 'admin implies admin'],
    [CAP_DOC_WRITE, CAP_DOC_READ, true, 'write implies read'],
    [CAP_DOC_WRITE, CAP_DOC_WRITE, true, 'write implies write'],
    [CAP_DOC_WRITE, CAP_DOC_ADMIN, false, 'write does not imply admin'],
    [CAP_DOC_READ, CAP_DOC_READ, true, 'read implies read'],
    [CAP_DOC_READ, CAP_DOC_WRITE, false, 'read does not imply write'],
    [CAP_DOC_READ, CAP_DOC_ADMIN, false, 'read does not imply admin'],
    [CAP_DOC_HISTORY, CAP_DOC_HISTORY, true, 'history self-implies'],
    [CAP_DOC_HISTORY, CAP_DOC_READ, false, 'history does not imply read'],
    [CAP_DOC_READ, CAP_DOC_HISTORY, false, 'read does not imply history'],
    [CAP_DOC_HISTORY, CAP_DOC_WRITE, false, 'history does not imply write'],
    [CAP_DOC_HISTORY, CAP_DOC_ADMIN, false, 'history does not imply admin'],
    [CAP_DOC_ADMIN, CAP_DOC_HISTORY, false, 'admin does not imply history'],
  ])(
    '%s held, %s required -> %s (%s)',
    (held: string, required: string, expected: boolean) => {
      expect(capabilityImplies(held, required)).toBe(expected);
    },
  );
});

describe('isFieldCapability', () => {
  test.each([
    ['/doc/write', false, 'document-level write'],
    ['/doc/read', false, 'document-level read'],
    ['/doc/admin', false, 'document-level admin'],
    ['/doc/write/field/name', true, 'field-level write'],
    ['/doc/read/field/address.city', true, 'field-level read with nested path'],
    ['/doc/write/field/items.0.title', true, 'field-level with array index path'],
  ])(
    '%s -> %s (%s)',
    (capability: string, expected: boolean) => {
      expect(isFieldCapability(capability)).toBe(expected);
    },
  );
});

describe('getFieldPath', () => {
  test.each([
    ['/doc/write/field/name', 'name', 'simple field name'],
    ['/doc/read/field/address.city', 'address.city', 'nested field path'],
    ['/doc/write/field/items.0.title', 'items.0.title', 'array index path'],
    ['/doc/write', undefined, 'no field path in document-level cap'],
    ['/doc/read', undefined, 'no field path in read cap'],
    ['/doc/admin', undefined, 'no field path in admin cap'],
  ])(
    '%s -> %s (%s)',
    (capability: string, expected: string | undefined, _description: string) => {
      expect(getFieldPath(capability)).toBe(expected);
    },
  );
});
