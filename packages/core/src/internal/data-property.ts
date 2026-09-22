const objectDefineProperty = Object.defineProperty;
const reflectApply = Reflect.apply;

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
