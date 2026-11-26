import { describe, expect, jest, test } from '@jest/globals';
import { crdtDocumentChangeNode } from './crdt-change-node.js';
import {
  assertCheckpointChangeHistory,
  checkpointDecode,
  checkpointEncode,
  decodeCheckpointState,
  encodeCheckpointState,
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
const cids = (count: number, prefix = 'cid-') =>
  Array.from({ length: count }, (_, index) => `${prefix}${index}`);

function state(
  overrides: Partial<DocumentCheckpointState> = {},
): DocumentCheckpointState {
  const bytes = checkpointEncode(new Uint8Array([1]));
  return {
    format: 'peerborne/local-document-checkpoint/2',
    documentPath: '/checkpoint',
    owner: 'owner',
    document: bytes,
    readers: bytes,
    writers: bytes,
    keychain: bytes,
    message: bytes,
    hashes: ['cid-root'],
    ancestors: [],
    recentTips: [['cid-root', 'document']],
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
  ])('refuses to encode a state with %s', (_name, overrides, error) => {
    const value = state(overrides as Partial<DocumentCheckpointState>);
    expect(() => encodeCheckpointState(value)).toThrow(error);
    expect(() =>
      decodeCheckpointState(new TextEncoder().encode(JSON.stringify(value))),
    ).toThrow(error);
  });

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
