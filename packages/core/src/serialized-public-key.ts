import { Base64 } from 'js-base64';

const P384_PRIME = BigInt(
  '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
);
const P384_B = BigInt(
  '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
);

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** Decode and validate a canonical P-384 public-key encoding. */
export function decodeCanonicalP384PublicKeyEncoding(
  serialized: unknown,
  description: string,
): Uint8Array {
  if (typeof serialized !== 'string') {
    throw new TypeError(`${description} must be a string`);
  }

  if (serialized.length !== Math.ceil(97 / 3) * 4) {
    throw new Error(`${description} must be canonical base64 for a 97-byte uncompressed P-384 point`);
  }

  let raw: Uint8Array;
  try {
    raw = Base64.toUint8Array(serialized);
  } catch {
    throw new Error(`${description} must be canonical base64`);
  }
  if (Base64.fromUint8Array(raw) !== serialized) {
    throw new Error(`${description} must be canonical base64`);
  }
  if (raw.byteLength !== 97 || raw[0] !== 0x04) {
    throw new Error(
      `${description} must be a 97-byte uncompressed P-384 point`,
    );
  }

  const x = bytesToBigInt(raw.subarray(1, 49));
  const y = bytesToBigInt(raw.subarray(49));
  if (x >= P384_PRIME || y >= P384_PRIME) {
    throw new Error(`${description} is not a valid P-384 point`);
  }
  const left = (y * y) % P384_PRIME;
  const xSquared = (x * x) % P384_PRIME;
  const right =
    (xSquared * x - 3n * x + P384_B + 3n * P384_PRIME) %
    P384_PRIME;
  if (left !== right) {
    throw new Error(`${description} is not a valid P-384 point`);
  }
  return raw;
}

/** Validate the canonical ACL identity encoding without asynchronous Web Crypto. */
export function assertCanonicalP384PublicKeyEncoding(
  serialized: unknown,
): asserts serialized is string {
  void decodeCanonicalP384PublicKeyEncoding(
    serialized,
    'Serialized ACL member key',
  );
}
