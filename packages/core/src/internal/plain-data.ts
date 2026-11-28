const arrayIsArray = Array.isArray;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectPrototype = Object.prototype;
const reflectOwnKeys = Reflect.ownKeys;

/**
 * @internal Detach a plain object whose own keys are all `allowed`, include
 * every `required` key, and are enumerable data properties.
 */
export function snapshotPlainDataObject(
  value: unknown,
  allowed: ReadonlyArray<string>,
  field: string,
  required: ReadonlyArray<string> = allowed,
): Record<PropertyKey, unknown> {
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype =
      value !== null && typeof value === 'object'
        ? objectGetPrototypeOf(value)
        : null;
    keys =
      value !== null && typeof value === 'object' ? reflectOwnKeys(value) : [];
  } catch {
    throw new Error(`${field} must be a plain data object`);
  }
  if (value === null || typeof value !== 'object') {
    throw new Error(`${field} must be an object`);
  }
  if (prototype !== objectPrototype && prototype !== null) {
    throw new Error(`${field} must be a plain object`);
  }
  const snapshot = objectCreate(null) as Record<PropertyKey, unknown>;
  for (const key of keys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = objectGetOwnPropertyDescriptor(value, key);
    } catch {
      throw new Error(`${field} must contain only own data properties`);
    }
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${String(key)} must be an enumerable own data property`);
    }
    snapshot[key] = descriptor.value;
  }
  if (
    keys.some((key) => typeof key !== 'string' || !allowed.includes(key)) ||
    required.some((key) => !keys.includes(key))
  ) {
    throw new Error(`${field} has unexpected or missing fields`);
  }
  return snapshot;
}

/** @internal Detach a dense, bounded array of own data elements with no extra properties. */
export function snapshotPlainDataArray(
  value: unknown,
  field: string,
  maximumLength: number,
): unknown[] {
  let isArray: boolean;
  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    isArray = arrayIsArray(value);
    lengthDescriptor = isArray
      ? objectGetOwnPropertyDescriptor(value, 'length')
      : undefined;
  } catch {
    throw new Error(`${field} must be a bounded plain array`);
  }
  if (
    !isArray ||
    lengthDescriptor === undefined ||
    !('value' in lengthDescriptor) ||
    !numberIsSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > maximumLength
  ) {
    throw new Error(`${field} must be a bounded plain array`);
  }
  const length = lengthDescriptor.value as number;
  let keys: PropertyKey[];
  try {
    keys = reflectOwnKeys(value as object);
  } catch {
    throw new Error(`${field} must be a bounded plain array`);
  }
  if (keys.length !== length + 1 || !keys.includes('length')) {
    throw new Error(`${field} must not be sparse or contain extra properties`);
  }
  const result = new Array<unknown>(length);
  for (let index = 0; index < length; index++) {
    const descriptor = objectGetOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !('value' in descriptor)
    ) {
      throw new Error(`${field} must contain only own data properties`);
    }
    result[index] = descriptor.value;
  }
  return result;
}
