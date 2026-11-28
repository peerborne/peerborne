const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const reflectApply = Reflect.apply;

/** @internal Capture a built-in accessor so later prototype tampering cannot redirect it. */
export function requireIntrinsicGetter(
  prototype: object,
  key: PropertyKey,
  label: string,
): (this: unknown) => unknown {
  const getter = objectGetOwnPropertyDescriptor(prototype, key)?.get;
  if (getter === undefined)
    throw new Error(`${label} intrinsic is unavailable`);
  return getter;
}

/** @internal Define an own enumerable data field without invoking setters. */
export function defineEnumerableDataProperty(
  target: object,
  key: PropertyKey,
  value: unknown,
): void {
  reflectApply(objectDefineProperty, Object, [
    target,
    key,
    {
      configurable: true,
      enumerable: true,
      value,
      writable: true,
    },
  ]);
}

/** @internal Read an enumerable own data field without invoking getters. */
export function ownDataProperty(
  object: object,
  key: PropertyKey,
  field?: string,
): unknown {
  return enumerableDataValue(
    objectGetOwnPropertyDescriptor(object, key),
    key,
    field,
  );
}

/** @internal Like {@link ownDataProperty}, but an absent field reads as `undefined`. */
export function optionalOwnDataProperty(
  object: object,
  key: PropertyKey,
  field?: string,
): unknown {
  const descriptor = objectGetOwnPropertyDescriptor(object, key);
  return descriptor === undefined
    ? undefined
    : enumerableDataValue(descriptor, key, field);
}

function enumerableDataValue(
  descriptor: PropertyDescriptor | undefined,
  key: PropertyKey,
  field: string | undefined,
): unknown {
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !('value' in descriptor)
  ) {
    throw new Error(
      `${field === undefined ? '' : `${field} `}${String(key)} must be an enumerable own data property`,
    );
  }
  return descriptor.value;
}
