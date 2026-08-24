import { describe, expect, test } from '@jest/globals';
import { readPathPrefixedProtocolHeader, readFirstDeserializable, readUint8Iterable } from './utils';

describe('adversarial peer simulation - protocol handler guards', () => {
  async function* source(chunks: Uint8Array[]): AsyncIterable<Uint8Array> {
    for (const chunk of chunks) yield chunk;
  }

  function buildMsg(path: string, payload: Uint8Array): Uint8Array {
    const pathBytes = new TextEncoder().encode(path);
    const hdr = new Uint8Array(4);
    const pl = pathBytes.length;
    hdr[0] = (pl >>> 24) & 0xff;
    hdr[1] = (pl >>> 16) & 0xff;
    hdr[2] = (pl >>> 8) & 0xff;
    hdr[3] = pl & 0xff;
    const result = new Uint8Array(4 + pl + payload.length);
    result.set(hdr, 0);
    result.set(pathBytes, 4);
    result.set(payload, 4 + pl);
    return result;
  }

  test('DoS: oversized request rejected', async () => {
    const r = await readPathPrefixedProtocolHeader(source([new Uint8Array(200)]), new Map(), 't', 10, 256);
    expect(r).toEqual({ kind: 'drop', reason: 'request-too-large' });
  });

  test('DoS: zero-length path header rejected', async () => {
    const r = await readPathPrefixedProtocolHeader(source([new Uint8Array([0, 0, 0, 0, 1])]), new Map(), 't', 1024, 256);
    expect(r).toEqual({ kind: 'drop', reason: 'invalid-path-length' });
  });

  test('DoS: path header claiming more bytes than message', async () => {
    const hdr = new Uint8Array([0, 0, 0, 100]);
    const msg = new Uint8Array(10);
    msg.set(hdr, 0);
    const r = await readPathPrefixedProtocolHeader(source([msg]), new Map(), 't', 1024, 256);
    expect(r).toEqual({ kind: 'drop', reason: 'invalid-path-length' });
  });

  test('DoS: path exceeding max length', async () => {
    const msg = buildMsg('a'.repeat(60), new Uint8Array([1]));
    const r = await readPathPrefixedProtocolHeader(source([msg]), new Map(), 't', 1024, 10);
    expect(r).toEqual({ kind: 'drop', reason: 'invalid-path-length' });
  });

  test('abuse: unregistered doc path dropped', async () => {
    const msg = buildMsg('/ghost/doc', new Uint8Array([1]));
    const r = await readPathPrefixedProtocolHeader(source([msg]), new Map(), 't', 1024, 256);
    expect(r).toEqual({ kind: 'drop', reason: 'no-document-registered' });
  });

  test('abuse: message too short (<4 bytes)', async () => {
    const r = await readPathPrefixedProtocolHeader(source([new Uint8Array([1, 2])]), new Map(), 't', 1024, 256);
    expect(r).toEqual({ kind: 'drop', reason: 'too-short' });
  });

  test('DoS: stream read failure caught', async () => {
    async function* broken() {
      yield new Uint8Array([0, 0, 0, 5, 47, 116, 101]);
      throw new Error('connection reset');
    }
    const r = await readPathPrefixedProtocolHeader(broken(), new Map(), 't', 1024, 256);
    expect(r.kind).toBe('drop');
  });

  test('DoS: readFirstDeserializable respects maxSize', async () => {
    const deserializer = (data: Uint8Array) => JSON.parse(new TextDecoder().decode(data));
    async function* largeSource() {
      yield new TextEncoder().encode('{"big":"');
      yield new Uint8Array(500);
    }
    await expect(readFirstDeserializable(largeSource(), deserializer, 20)).rejects.toThrow(RangeError);
  });

  test('DoS: empty source returns empty array', async () => {
    expect(await readUint8Iterable(source([]))).toEqual(new Uint8Array(0));
  });
});