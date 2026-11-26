const P384_ORDER = BigInt(
  '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
);

/** The second valid P-384 signature `(r, n - s)` over the same message. */
export function p384SignatureTwin(signature: Uint8Array): Uint8Array {
  const half = signature.length / 2;
  const s = BigInt(`0x${Buffer.from(signature.subarray(half)).toString('hex')}`);
  const twin = signature.slice();
  twin.set(
    Buffer.from((P384_ORDER - s).toString(16).padStart(half * 2, '0'), 'hex'),
    half,
  );
  return twin;
}
