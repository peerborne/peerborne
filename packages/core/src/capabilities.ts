/**
 * Document-level capabilities for UCAN-based authorization.
 *
 * Capabilities are hierarchical - higher capabilities imply lower ones:
 * /doc/admin > /doc/write > /doc/read
 */

/** Full control: add/remove members, delete document, read, write */
export const CAP_DOC_ADMIN = '/doc/admin';

/** Modify document content + read */
export const CAP_DOC_WRITE = '/doc/write';

/** Decrypt and read document */
export const CAP_DOC_READ = '/doc/read';

/** Access historical epoch keys */
export const CAP_DOC_HISTORY = '/doc/history';

/**
 * All document capabilities in order of decreasing privilege.
 * Note: /doc/history is deliberately excluded because it is orthogonal to
 * the read/write/admin hierarchy. History access is independent -- a user
 * can have read+history or read without history.
 */
export const CAPABILITY_HIERARCHY = [
  CAP_DOC_ADMIN,
  CAP_DOC_WRITE,
  CAP_DOC_READ,
] as const;

/** Capabilities that are not part of the hierarchy and require exact match. */
export const NON_HIERARCHICAL_CAPABILITIES = [
  CAP_DOC_HISTORY,
] as const;

export type DocumentCapability =
  | typeof CAPABILITY_HIERARCHY[number]
  | typeof NON_HIERARCHICAL_CAPABILITIES[number];

/**
 * Check if a capability implies another capability.
 * Admin implies write, write implies read.
 */
export function capabilityImplies(held: string, required: string): boolean {
  const heldIndex = CAPABILITY_HIERARCHY.indexOf(held as any);
  const requiredIndex = CAPABILITY_HIERARCHY.indexOf(required as any);

  if (heldIndex === -1 || requiredIndex === -1) {
    // For non-hierarchical capabilities (like /doc/history), exact match required
    return held === required;
  }

  // Lower index = higher privilege
  return heldIndex <= requiredIndex;
}

/**
 * Future field-level capability pattern.
 * /doc/write/field/{fieldPath} -- Write to specific Yjs sub-document
 * /doc/read/field/{fieldPath} -- Read specific Yjs sub-document
 */
export function isFieldCapability(capability: string): boolean {
  return capability.includes('/field/');
}

export function getFieldPath(capability: string): string | undefined {
  const match = capability.match(/\/field\/(.+)$/);
  return match ? match[1] : undefined;
}
