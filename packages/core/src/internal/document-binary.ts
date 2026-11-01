import { boundedFieldEnd } from '../policy/frame-layout.js';
import { isWellFormedUtf16 } from './canonical-encoding.js';
import { copyUnsharedUint8Array } from '../utils.js';

export class DocumentBinaryWriter {
  private readonly parts: Uint8Array[] = [];
  private length = 0;
  constructor(private readonly maximum = 1024 * 1024) {}
  fixed(value: Uint8Array): this {
    const owned = copyUnsharedUint8Array(
      value,
      0,
      this.maximum - this.length,
      'document field',
    );
    this.length += owned.byteLength;
    this.parts.push(owned);
    return this;
  }
  integer(value: number | bigint, width: 1 | 2 | 4 | 8): this {
    if (
      (typeof value === 'number' && !Number.isSafeInteger(value)) ||
      BigInt(value) < 0n ||
      BigInt(value) >= 1n << BigInt(width * 8)
    )
      throw new TypeError('Document integer is outside bounds');
    const bytes = new Uint8Array(width);
    let remaining = BigInt(value);
    for (let index = width - 1; index >= 0; index--) {
      bytes[index] = Number(remaining & 255n);
      remaining >>= 8n;
    }
    return this.fixed(bytes);
  }
  bytes(value: Uint8Array, maximum = 512 * 1024): this {
    const owned = copyUnsharedUint8Array(value, 0, maximum, 'document bytes');
    return this.integer(owned.length, 4).fixed(owned);
  }
  text(value: string, maximum = 16 * 1024): this {
    if (
      typeof value !== 'string' ||
      value.length > maximum ||
      !isWellFormedUtf16(value)
    )
      throw new TypeError('Invalid document text');
    return this.bytes(new TextEncoder().encode(value), maximum);
  }
  finish(): Uint8Array {
    const result = new Uint8Array(this.length);
    let offset = 0;
    for (const part of this.parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }
}

export class DocumentBinaryReader {
  private readonly data: Uint8Array;
  private offset = 0;
  constructor(value: Uint8Array, maximum = 1024 * 1024) {
    this.data = copyUnsharedUint8Array(value, 0, maximum, 'document frame');
  }
  fixed(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || length > 0xffffffff)
      throw new TypeError('Invalid document field length');
    const end = boundedFieldEnd(
      this.data.length,
      this.offset,
      length,
      length,
      length,
      0,
    );
    if (end < 0) throw new TypeError('Truncated document frame');
    const result = this.data.slice(this.offset, end);
    this.offset = end;
    return result;
  }
  integer(width: 1 | 2 | 4 | 8): bigint {
    let result = 0n;
    for (const byte of this.fixed(width))
      result = (result << 8n) | BigInt(byte);
    return result;
  }
  number(width: 1 | 2 | 4 | 8): number {
    const value = this.integer(width);
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new TypeError('Unsafe document integer');
    return Number(value);
  }
  bytes(maximum = 512 * 1024): Uint8Array {
    const length = this.number(4);
    if (length > maximum)
      throw new TypeError('Document field exceeds its bound');
    return this.fixed(length);
  }
  text(maximum = 16 * 1024): string {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
      this.bytes(maximum),
    );
  }
  end(): void {
    if (this.offset !== this.data.length)
      throw new TypeError('Document frame contains trailing bytes');
  }
}

export function documentBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++)
    difference |= a[index] ^ b[index];
  return difference === 0;
}

export function documentBytesId(bytes: Uint8Array): string {
  return [...bytes]
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('');
}
