export function observeNativeCrypto() {
  const prototype = Object.getPrototypeOf(crypto.subtle);
  const counts = {};
  const originals = new Map();
  for (const name of [
    'generateKey',
    'importKey',
    'sign',
    'verify',
    'digest',
    'deriveBits',
    'deriveKey',
    'encrypt',
    'decrypt',
  ]) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
    originals.set(name, descriptor);
    Object.defineProperty(prototype, name, {
      ...descriptor,
      value(...args) {
        const algorithm = args[name === 'importKey' ? 2 : 0];
        const algorithmName =
          typeof algorithm === 'string' ? algorithm : algorithm?.name;
        const label = `${name}:${algorithmName}`;
        counts[label] = (counts[label] ?? 0) + 1;
        return Reflect.apply(descriptor.value, this, args);
      },
    });
  }
  return {
    counts,
    restore() {
      for (const [name, descriptor] of originals) {
        Object.defineProperty(prototype, name, descriptor);
      }
    },
  };
}
