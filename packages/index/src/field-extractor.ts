/**
 * Resolves a dot-notation path through own data properties.
 *
 * Supports numeric segments for array indexing:
 *   extractField({ a: { b: [10, 20] } }, 'a.b.1') → 20
 *
 * Inherited properties and accessors are treated as missing.
 */
export function extractField(obj: unknown, path: string): unknown {
  const segments = path.split('.');
  let current: unknown = obj;
  for (const segment of segments) {
    if (current === null || typeof current !== 'object') return undefined;
    const property = Object.getOwnPropertyDescriptor(current, segment);
    if (property === undefined || !Object.hasOwn(property, 'value')) return undefined;
    current = property.value;
  }
  return current;
}
