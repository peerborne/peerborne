import { describe, expect, jest, test } from '@jest/globals';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { crdtDocumentChangeNode } from './crdt-change-node.js';
import {
  assertCheckpointChangeHistory,
  checkpointDecode,
  checkpointEncode,
  decodeCheckpointState,
  documentCheckpointCommitment,
  encodeCheckpointState,
  openSealedDocumentCheckpoint,
  sealDocumentCheckpoint,
  type DocumentCheckpointState,
} from './document-checkpoint.js';

jest.mock(
  'multiformats',
  () => ({
    CID: {
      parse: (value: string) => ({ toString: () => value.toLowerCase() }),
    },
  }),
  { virtual: true },
);

const LIMIT = 100_000;
const GC_CANDIDATE_LIMIT = 32_768;
const cids = (count: number, prefix = 'cid-') =>
  Array.from({ length: count }, (_, index) => `${prefix}${index}`);

function state(
  overrides: Partial<DocumentCheckpointState> = {},
): DocumentCheckpointState {
  const bytes = checkpointEncode(new Uint8Array([1]));
  return {
    format: 'peerborne/local-document-checkpoint/4',
    documentPath: '/checkpoint',
    owner: 'owner',
    document: bytes,
    readers: bytes,
    writers: bytes,
    keychain: bytes,
    actors: bytes,
    writerActors: bytes,
    readerActors: bytes,
    message: bytes,
    hashes: ['cid-root'],
    ancestors: [],
    recentTips: [['cid-root', 'document']],
    ownBlocks: [],
    gcCandidates: [],
    documentChangeCount: 1,
    changesSinceSnapshot: 1,
    historyVisibility: 'full_history',
    invitationEpoch: null,
    beekem: null,
    readerLeaves: [],
    readerKemKeys: [],
    welcomes: [],
    ...overrides,
  };
}

describe('document checkpoint state', () => {
  test('encodes a bounded state that decodes unchanged', () => {
    const value = state({
      hashes: cids(LIMIT),
      ancestors: cids(LIMIT),
      recentTips: [['cid-1', 'document']],
      ownBlocks: cids(GC_CANDIDATE_LIMIT, 'cid-pruned-'),
      gcCandidates: cids(GC_CANDIDATE_LIMIT, 'cid-pruned-'),
    });
    expect(decodeCheckpointState(encodeCheckpointState(value))).toEqual(value);
  });

  test.each([
    ['too many known hashes', { hashes: cids(LIMIT + 1) }, /collection/],
    ['too many ancestors', { ancestors: cids(LIMIT + 1) }, /collection/],
    ['a duplicate hash', { hashes: ['cid-root', 'cid-root'] }, /Duplicate/],
    ['a duplicate ancestor', { ancestors: ['cid-a', 'cid-a'] }, /Duplicate/],
    [
      'a non-canonical CID',
      { ancestors: ['cid-NotCanonical'] },
      /Invalid checkpoint CID/,
    ],
    ['no known hashes', { hashes: [], recentTips: [] }, /no document history/],
    [
      'a tip that is no longer known',
      { recentTips: [['cid-forgotten', 'document']] as [string, string][] },
      /Invalid checkpoint tip/,
    ],
    [
      'too many own blocks',
      { ownBlocks: cids(GC_CANDIDATE_LIMIT + 1) },
      /own block/,
    ],
    [
      'a duplicate own block',
      { ownBlocks: ['cid-stored', 'cid-stored'] },
      /own block/,
    ],
    [
      'a non-canonical own block',
      { ownBlocks: ['cid-NotCanonical'] },
      /Invalid checkpoint CID/,
    ],
    ['no own blocks', { ownBlocks: undefined }, /Invalid document checkpoint/],
    [
      'too many garbage collection candidates',
      {
        ownBlocks: cids(GC_CANDIDATE_LIMIT),
        gcCandidates: cids(GC_CANDIDATE_LIMIT + 1),
      },
      /garbage collection candidate/,
    ],
    [
      'a duplicate garbage collection candidate',
      {
        ownBlocks: ['cid-pruned'],
        gcCandidates: ['cid-pruned', 'cid-pruned'],
      },
      /garbage collection candidate/,
    ],
    [
      'a garbage collection candidate the document did not store',
      {
        ownBlocks: ['cid-stored'],
        gcCandidates: ['cid-stored', 'cid-foreign'],
      },
      /garbage collection candidate/,
    ],
    [
      'a non-canonical garbage collection candidate',
      { gcCandidates: ['cid-NotCanonical'] },
      /Invalid checkpoint CID/,
    ],
    [
      'a garbage collection candidate that is not a CID string',
      { gcCandidates: [7] as unknown as string[] },
      /Invalid checkpoint CID/,
    ],
    [
      'no garbage collection candidates',
      { gcCandidates: undefined },
      /Invalid document checkpoint/,
    ],
  ])('refuses to encode a state with %s', (_name, overrides, error) => {
    const value = state(overrides as Partial<DocumentCheckpointState>);
    expect(() => encodeCheckpointState(value)).toThrow(error);
    expect(() =>
      decodeCheckpointState(new TextEncoder().encode(JSON.stringify(value))),
    ).toThrow(error);
  });

  test('a restored checkpoint deletes blocks pruned before it was exported', async () => {
    await promisify(execFile)(
      process.execPath,
      ['--test', `${__dirname}/document-checkpoint-gc.fixture.mjs`],
      { timeout: 60_000 },
    );
  }, 70_000);

  test('after Automerge, Yjs and Loro restore a checkpoint with a large snapshot, edits publish small frames a replica applies', async () => {
    await promisify(execFile)(
      process.execPath,
      ['--test', `${__dirname}/restored-checkpoint-frame.fixture.mjs`],
      { timeout: 120_000 },
    );
  }, 130_000);

  test('round-trips a document field near the checkpoint size limit', () => {
    const documentBytes = new Uint8Array(4 * 1024 * 1024).map(
      (_, index) => index % 251,
    );
    const value = state({ document: checkpointEncode(documentBytes) });
    const decoded = decodeCheckpointState(encodeCheckpointState(value));
    expect(checkpointDecode(decoded.document)).toEqual(documentBytes);
  });

  test.each([
    ['a misplaced padding character', 'AA=A'],
    ['too much padding', 'A==='],
    ['a character outside the alphabet', 'AA-A'],
    ['non-canonical trailing bits', 'AB=='],
    ['a length that is not a multiple of four', 'AAAAA'],
  ])('rejects checkpoint bytes with %s', (_name, encoded) => {
    expect(() => checkpointDecode(encoded)).toThrow(
      'Invalid checkpoint byte encoding',
    );
  });
});

describe('checkpoint change history', () => {
  const message = {
    documentId: '/checkpoint',
    signatureContext: 'ordinary-sync-v1' as const,
    changeId: 'cid-head',
    changes: {
      kind: crdtDocumentChangeNode,
      change: 'head',
      children: {
        'cid-parent': {
          kind: crdtDocumentChangeNode,
          change: 'parent',
          children: { 'cid-tip': { kind: crdtDocumentChangeNode } },
        },
      },
    },
  };
  const retained = ['cid-head', 'cid-parent', 'cid-tip'];

  test.each([
    ['every node is known', retained],
    ['a node beneath the known root was forgotten', ['cid-head', 'cid-tip']],
    ['only the root is known', ['cid-head']],
  ])('accepts a retained tree when %s', (_name, known) => {
    expect(() =>
      assertCheckpointChangeHistory('/checkpoint', message, new Set(known)),
    ).not.toThrow();
  });

  test.each([
    ['a forgotten root', retained.slice(1), message, /change root/],
    [
      'another document',
      retained,
      { ...message, documentId: '/other' },
      /change root/,
    ],
    [
      'no change tree',
      retained,
      { ...message, changes: undefined },
      /change root/,
    ],
    [
      'no root CID',
      retained,
      { ...message, changeId: undefined },
      /change root/,
    ],
  ])('rejects %s', (_name, known, candidate, error) => {
    expect(() =>
      assertCheckpointChangeHistory('/checkpoint', candidate, new Set(known)),
    ).toThrow(error);
  });

  test('rejects a non-canonical node identifier', () => {
    expect(() =>
      assertCheckpointChangeHistory(
        '/checkpoint',
        {
          ...message,
          changes: {
            ...message.changes,
            children: { 'cid-NotCanonical': { kind: crdtDocumentChangeNode } },
          },
        },
        new Set(retained),
      ),
    ).toThrow(/canonical CID/);
  });

  test('rejects conflicting descriptions of one node', () => {
    expect(() =>
      assertCheckpointChangeHistory(
        '/checkpoint',
        {
          ...message,
          changes: {
            ...message.changes,
            children: {
              ...message.changes.children,
              'cid-other': {
                kind: crdtDocumentChangeNode,
                change: 'other',
                children: {
                  'cid-parent': {
                    kind: crdtDocumentChangeNode,
                    change: 'a different parent',
                  },
                },
              },
            },
          },
        },
        new Set(retained),
      ),
    ).toThrow(/conflicting descriptions/);
  });
});

describe('encrypted checkpoint', () => {
  const path = '/encrypted';
  const aesKey = (
    usages: KeyUsage[] = ['encrypt', 'decrypt'],
    length = 256,
    name = 'AES-GCM',
  ) =>
    crypto.subtle.generateKey(
      { name, length },
      false,
      usages,
    ) as Promise<CryptoKey>;
  const checkpoint = () => ({
    payload: new TextEncoder().encode(
      '{"keychain":"document key","x":"secret"}',
    ),
    signature: new Uint8Array([7, 8, 9]),
  });
  const contains = (haystack: Uint8Array, needle: Uint8Array) =>
    Buffer.from(haystack).includes(Buffer.from(needle));

  test('round-trips under its key and path without exposing the payload', async () => {
    const key = await aesKey();
    const original = checkpoint();
    const sealed = await sealDocumentCheckpoint(original, path, key);
    expect(contains(sealed, new TextEncoder().encode('secret'))).toBe(false);
    expect(contains(sealed, original.payload.subarray(0, 8))).toBe(false);
    expect(await openSealedDocumentCheckpoint(sealed, path, key)).toEqual(
      original,
    );
    const again = await sealDocumentCheckpoint(original, path, key);
    expect(Buffer.from(again).equals(Buffer.from(sealed))).toBe(false);
  });

  test('rejects another key, another path and altered bytes', async () => {
    const key = await aesKey();
    const sealed = await sealDocumentCheckpoint(checkpoint(), path, key);
    const altered = sealed.slice();
    altered[altered.length - 1] ^= 1;
    for (const [bytes, documentPath, storageKey] of [
      [sealed, path, await aesKey()],
      [sealed, '/other', key],
      [altered, path, key],
      [sealed.subarray(0, sealed.length - 1), path, key],
    ] as const)
      await expect(
        openSealedDocumentCheckpoint(bytes, documentPath, storageKey),
      ).rejects.toThrow('Encrypted checkpoint could not be authenticated');
    await expect(
      openSealedDocumentCheckpoint(sealed.subarray(0, 20), path, key),
    ).rejects.toThrow(/Encrypted checkpoint/);
  });

  test.each([
    ['an AES-CBC key', () => aesKey(['encrypt', 'decrypt'], 256, 'AES-CBC')],
    ['a 128-bit key', () => aesKey(['encrypt', 'decrypt'], 128)],
    ['a key that cannot encrypt', () => aesKey(['decrypt'])],
  ])('refuses to seal with %s', async (_name, key) => {
    await expect(
      sealDocumentCheckpoint(checkpoint(), path, await key()),
    ).rejects.toThrow('Checkpoint storage key must be a 256-bit AES-GCM key');
  });

  test('refuses to open with a key that cannot decrypt', async () => {
    const sealed = await sealDocumentCheckpoint(
      checkpoint(),
      path,
      await aesKey(),
    );
    await expect(
      openSealedDocumentCheckpoint(sealed, path, await aesKey(['encrypt'])),
    ).rejects.toThrow('that can decrypt');
  });

  test('commits to the sealed bytes', async () => {
    const key = await aesKey();
    const original = checkpoint();
    const sealed = await sealDocumentCheckpoint(original, path, key);
    expect(Buffer.from(await documentCheckpointCommitment(sealed))).toEqual(
      Buffer.from(
        await crypto.subtle.digest(
          'SHA-256',
          sealed as Uint8Array<ArrayBuffer>,
        ),
      ),
    );
    expect(Buffer.from(await documentCheckpointCommitment(original))).toEqual(
      Buffer.from(
        await crypto.subtle.digest(
          'SHA-256',
          original.payload as Uint8Array<ArrayBuffer>,
        ),
      ),
    );
  });

  test('restores only under its key, path and commitment on a real document', async () => {
    await promisify(execFile)(
      process.execPath,
      ['--test', `${__dirname}/encrypted-checkpoint.fixture.mjs`],
      { timeout: 60_000 },
    );
  }, 70_000);
});
