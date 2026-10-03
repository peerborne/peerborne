const reflectApply = Reflect.apply;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const nativeObjectConstructor = Object;
const nativeObjectPrototype = Object.prototype;
const nativeFunctionPrototype = Function.prototype;
const nativePromiseConstructor = Promise;
const promiseThen = Promise.prototype.then;
const nativePromiseSpeciesDescriptor = objectGetOwnPropertyDescriptor(
  nativePromiseConstructor,
  Symbol.species,
);
const ignorePromiseSettlement = (_value: unknown): undefined => undefined;
const ignoredPromiseSettlementArguments = [
  ignorePromiseSettlement,
  ignorePromiseSettlement,
];
// Bound hostile prototype traversal well above normal provider inheritance.
const MAX_DATA_PROPERTY_PROTOTYPE_DEPTH = 32;

/**
 * Find a property along a bounded, acyclic prototype chain without invoking
 * accessors or Proxy `get` traps.
 */
export function readDataProperty(
  target: object,
  property: PropertyKey,
  label: string,
): { readonly found: boolean; readonly value?: unknown } {
  let owner: object | null = target;
  const visited = new Set<object>();
  let depth = 0;
  while (owner !== null) {
    if (visited.has(owner) || depth++ >= MAX_DATA_PROPERTY_PROTOTYPE_DEPTH) {
      throw new TypeError(`${label} has an invalid prototype chain`);
    }
    visited.add(owner);
    const descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
      owner,
      property,
    ]) as PropertyDescriptor | undefined;
    if (descriptor !== undefined) {
      if (!('value' in descriptor)) {
        throw new TypeError(`${label} must be a data property`);
      }
      return { found: true, value: descriptor.value };
    }
    owner = reflectApply(objectGetPrototypeOf, Object, [owner]) as
      object | null;
  }
  return { found: false };
}

/**
 * Promise.prototype.then performs species construction after its internal
 * Promise brand check. Preflight that later step without invoking accessors
 * or constructors so a hostile branded Promise cannot turn a species throw
 * into a false "not a Promise" result.
 */
export function canSafelyObserveNativePromise(
  target: object,
  label: string,
): boolean {
  const constructorProperty = readDataProperty(
    target,
    'constructor',
    `${label} constructor`,
  );
  if (!constructorProperty.found || constructorProperty.value === undefined) {
    return true;
  }
  const constructor = constructorProperty.value;
  if (
    (typeof constructor !== 'object' || constructor === null) &&
    typeof constructor !== 'function'
  ) {
    return false;
  }

  if (constructor === nativePromiseConstructor) {
    const currentSpeciesDescriptor = reflectApply(
      objectGetOwnPropertyDescriptor,
      Object,
      [nativePromiseConstructor, Symbol.species],
    ) as PropertyDescriptor | undefined;
    if (
      currentSpeciesDescriptor !== undefined &&
      !('value' in currentSpeciesDescriptor)
    ) {
      return (
        nativePromiseSpeciesDescriptor !== undefined &&
        !('value' in nativePromiseSpeciesDescriptor) &&
        currentSpeciesDescriptor.get === nativePromiseSpeciesDescriptor.get &&
        currentSpeciesDescriptor.set === nativePromiseSpeciesDescriptor.set
      );
    }
    const species = currentSpeciesDescriptor?.value;
    return (
      currentSpeciesDescriptor !== undefined &&
      (species === undefined ||
        species === null ||
        species === nativePromiseConstructor)
    );
  }

  // An arbitrary object or function can be a Proxy whose descriptor trap
  // reports a harmless data property while its ordinary `get` trap throws or
  // mutates state when Promise.prototype.then performs species lookup. Only
  // trust the captured intrinsic Object constructor and its pristine
  // prototype chain. Plain claim records use exactly this path; custom class
  // instances are rejected by the stricter claim-result policies.
  if (constructor !== nativeObjectConstructor) return false;
  if (
    reflectApply(objectGetPrototypeOf, Object, [nativeObjectConstructor]) !==
      nativeFunctionPrototype ||
    reflectApply(objectGetPrototypeOf, Object, [nativeFunctionPrototype]) !==
      nativeObjectPrototype ||
    reflectApply(objectGetPrototypeOf, Object, [nativeObjectPrototype]) !== null
  ) {
    return false;
  }
  for (const owner of [
    nativeObjectConstructor,
    nativeFunctionPrototype,
    nativeObjectPrototype,
  ]) {
    const descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
      owner,
      Symbol.species,
    ]) as PropertyDescriptor | undefined;
    if (descriptor === undefined) continue;
    if (!('value' in descriptor)) return false;
    return (
      descriptor.value === undefined ||
      descriptor.value === null ||
      descriptor.value === nativePromiseConstructor
    );
  }
  return true;
}

/** Attach no-op settlement handlers when `value` is a native Promise. */
export function observeNativePromiseSettlement(value: object): boolean {
  try {
    void reflectApply(promiseThen, value, ignoredPromiseSettlementArguments);
    return true;
  } catch {
    // Non-native thenables are never assimilated.
    return false;
  }
}

/** Observe only a safely branded forbidden Promise return. */
export function observeInvalidNativePromiseReturn(
  value: object,
  label: string,
): void {
  try {
    if (canSafelyObserveNativePromise(value, label)) {
      observeNativePromiseSettlement(value);
    }
  } catch {
    // The caller rejects the result regardless; never invoke unsafe species
    // hooks merely to suppress a malicious provider's rejection.
  }
}
