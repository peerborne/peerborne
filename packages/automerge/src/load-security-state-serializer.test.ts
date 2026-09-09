import { describe, expect, test } from '@jest/globals';
import { CRDTChangeNode, MAX_MERKLE_DAG_DEPTH } from '@peerborne/core';
import { AutomergeJSONSerializer } from './peerborne-automerge.js';

function changeChain<ChangesType>(depth: number): CRDTChangeNode<ChangesType> {
  const root: CRDTChangeNode<ChangesType> = { kind: 'document' };
  let cursor = root;
  for (let level = 2; level <= depth; level++) {
    const child: CRDTChangeNode<ChangesType> = { kind: 'document' };
    cursor.children = { [`N${level}`]: child };
    cursor = child;
  }
  return root;
}

const commitments = {
  version: 1 as const,
  controlHead: new Uint8Array(32).fill(4),
  groupId: 'group-automerge',
  epoch: 18446744073709551615n,
  treeHash: new Uint8Array(32).fill(5),
  confirmedTranscriptHash: new Uint8Array(32).fill(6),
};

describe('AutomergeJSONSerializer load security state', () => {
  test('round-trips the strict commitment tuple without bigint loss', () => {
    const serializer = new AutomergeJSONSerializer();
    const loadChallenge = new Uint8Array(32).fill(7);
    const decoded = serializer.deserializeSyncMessage(
      serializer.serializeSyncMessage({
        documentId: '/doc',
        loadSecurityState: commitments,
        loadChallenge,
        signature: 'writer-signature',
      }),
    );
    expect(decoded.loadSecurityState).toEqual(commitments);
    expect(decoded.loadSecurityState?.treeHash).not.toBe(commitments.treeHash);
    expect(decoded.signature).toBe('writer-signature');
    expect(decoded.loadChallenge).toEqual(loadChallenge);
    expect(
      serializer.serializeSyncMessage({
        documentId: '/doc',
        loadSecurityState: commitments,
      }),
    ).not.toEqual(
      serializer.serializeSyncMessage({
        documentId: '/doc',
        loadSecurityState: {
          ...commitments,
          controlHead: new Uint8Array(32).fill(9),
        },
      }),
    );
  });

  test('round-trips a V4 load-request challenge and rejects malformed width', () => {
    const serializer = new AutomergeJSONSerializer();
    const loadChallenge = new Uint8Array(32).fill(8);
    expect(
      serializer.deserializeLoadRequest(
        serializer.serializeLoadRequest({
          documentId: '/doc',
          signature: 'request-signature',
          loadChallenge,
        }),
      ).loadChallenge,
    ).toEqual(loadChallenge);
    expect(() =>
      serializer.deserializeLoadRequest(
        new TextEncoder().encode(
          JSON.stringify({
            documentId: '/doc',
            signature: 'request-signature',
            loadChallenge: 'AQ==',
          }),
        ),
      ),
    ).toThrow(/32-byte/);
  });

  test('rejects unknown fields in security commitments', () => {
    const serializer = new AutomergeJSONSerializer();
    const digest = Buffer.from(new Uint8Array(32)).toString('base64');
    const wire = new TextEncoder().encode(
      JSON.stringify({
        documentId: '/doc',
        loadSecurityState: {
          version: 1,
          controlHead: digest,
          groupId: 'group',
          epoch: '0',
          treeHash: digest,
          confirmedTranscriptHash: digest,
          extra: true,
        },
      }),
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/exactly/);
  });

  test('accepts legacy depth 513 beyond the V4 manifest policy', () => {
    const serializer = new AutomergeJSONSerializer();
    const legacy = changeChain<Uint8Array[]>(MAX_MERKLE_DAG_DEPTH + 1);
    expect(
      serializer.deserializeSyncMessage(
        serializer.serializeSyncMessage({
          documentId: '/doc',
          changes: legacy,
        }),
      ).changes,
    ).toBeDefined();
  });

  test('preserves non-schema nested field order across re-encoding', () => {
    const serializer = new AutomergeJSONSerializer();
    const child = {} as CRDTChangeNode<Uint8Array[]>;
    child.change = [new Uint8Array([2])];
    child.kind = 'writer';
    const changes = {} as CRDTChangeNode<Uint8Array[]>;
    changes.children = { PARENT: child };
    changes.change = [new Uint8Array([1])];
    changes.keyID = 'epoch-7';
    changes.kind = 'document';

    const first = serializer.serializeSyncMessage({
      documentId: '/signed-load',
      changeId: 'ROOT',
      changes,
    });
    const second = serializer.serializeSyncMessage(
      serializer.deserializeSyncMessage(first),
    );
    expect(second).toEqual(first);
  });
});
