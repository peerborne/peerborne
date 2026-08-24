/**
 * Resolves a dot-notation path against an object, returning the value at that path.
 *
 * Supports numeric segments for array indexing:
 *   extractField({ a: { b: [10, 20] } }, 'a.b.1') → 20
 *
 * Returns `undefined` if any intermediate segment is missing or not an object/array.
 */
export function extractField(obj: unknown, path: string): unknown {
  const segments = path.split('.');
  let current: unknown = obj;
  for (const segment of segments) {
    if (current === null || current === undefined) {
      return undefined;
    }
    if (typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}
