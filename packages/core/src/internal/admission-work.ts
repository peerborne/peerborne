import { canSafelyObserveNativePromise } from './native-promise-observation.js';

const nativePromise = Promise;
const nativePromisePrototype = Promise.prototype;
const nativeThen = Promise.prototype.then;
const ownDescriptor = Object.getOwnPropertyDescriptor;
const prototypeOf = Object.getPrototypeOf;

export type ObservedAdmissionWork<T> =
  | {
      readonly observable: true;
      readonly result: Promise<{ readonly value: T }>;
      readonly settlement: Promise<void>;
    }
  | {
      readonly observable: false;
      readonly settlement: Promise<void>;
    };

/** No thenable assimilation. An unsafe object quarantines its work slot. */
export function observeAdmissionWork<T>(
  value: unknown,
): ObservedAdmissionWork<T> {
  let finish!: (value: { readonly value: T }) => void;
  let reject!: (error: unknown) => void;
  let settle!: () => void;
  const result = new nativePromise<{ readonly value: T }>((yes, no) => {
    finish = yes;
    reject = no;
  });
  const settlement = new nativePromise<void>((yes) => {
    settle = yes;
  });
  if (
    (typeof value !== 'object' || value === null) &&
    typeof value !== 'function'
  ) {
    settle();
    finish({ value: value as T });
    return { observable: true, result, settlement };
  }
  try {
    const constructor = ownDescriptor(value, 'constructor');
    if (constructor === undefined) {
      if (prototypeOf(value) !== nativePromisePrototype)
        return { observable: false, settlement };
      const inherited = ownDescriptor(nativePromisePrototype, 'constructor');
      if (
        inherited === undefined ||
        !('value' in inherited) ||
        inherited.value !== nativePromise
      )
        return { observable: false, settlement };
    } else if (!('value' in constructor)) {
      return { observable: false, settlement };
    }
    if (!canSafelyObserveNativePromise(value, 'admission work'))
      return { observable: false, settlement };
    Reflect.apply(nativeThen, value, [
      (resolved: T) => {
        settle();
        finish({ value: resolved });
      },
      (error: unknown) => {
        settle();
        reject(error);
      },
    ]);
    return { observable: true, result, settlement };
  } catch {
    return { observable: false, settlement };
  }
}
