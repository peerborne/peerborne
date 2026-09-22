/** @internal Reject lossy UTF-16 identities before encoding them as UTF-8. */
export function assertWellFormedUtf16(value: string, context: string): void {
  for (let index = 0; index < value.length; index++) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`${context} must be well-formed UTF-16`);
      }
      index++;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError(`${context} must be well-formed UTF-16`);
    }
  }
}
