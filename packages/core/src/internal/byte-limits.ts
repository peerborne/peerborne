/** @internal Validate configured positive byte limits before consuming input. */
export function assertPositiveSafeByteLimit(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${field} must be a positive safe integer`);
  }
  return value;
}
