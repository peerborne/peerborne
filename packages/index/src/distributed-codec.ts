import { canonicalJsonString } from './query-ast.js';

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJsonString(value));
}

export function encodeJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

export function parseBoundedJson(input: unknown, maxBytes: number): unknown {
  let bytes: Uint8Array;
  if (typeof input === 'string') {
    bytes = new TextEncoder().encode(input);
  } else if (input instanceof Uint8Array) {
    bytes = input;
  } else {
    let json: string;
    try {
      json = JSON.stringify(input);
    } catch {
      throw new TypeError('message is not valid JSON');
    }
    if (json === undefined) throw new TypeError('message is not valid JSON');
    bytes = new TextEncoder().encode(json);
  }
  if (bytes.byteLength === 0 || bytes.byteLength > maxBytes) throw new TypeError('message size is invalid');
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new TypeError('message is not valid JSON');
  }
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

export function decodeBase64Url(value: unknown, maxBytes: number): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > maxBytes * 2) {
    throw new TypeError('invalid base64url value');
  }
  try {
    const padding = '='.repeat((4 - value.length % 4) % 4);
    const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + padding);
    if (binary.length > maxBytes) throw new Error('too large');
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new TypeError('invalid base64url value');
  }
}

export function assertExactKeys(
  value: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) throw new TypeError(`missing property: ${key}`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new TypeError(`unknown property: ${key}`);
  }
}

export function isRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function validateBoundedText(
  value: unknown,
  label: string,
  maxLength = 4096,
): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength ||
      /[\u0000-\u001f]/.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
}

export function validateUint64(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,19})$/.test(value) ||
      BigInt(value) > 18_446_744_073_709_551_615n) {
    throw new TypeError(`${label} must be a uint64 decimal string`);
  }
}
