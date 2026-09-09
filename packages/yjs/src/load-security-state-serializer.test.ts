import { describe, expect, test } from '@jest/globals';
import {
  CRDTChangeNode,
  MAX_MERKLE_DAG_DEPTH,
} from '@peerborne/core';
import { YjsJSONSerializer } from './peerborne-yjs.js';

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
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'group-yjs',
  epoch: 9007199254740993n,
  treeHash: new Uint8Array(32).fill(2),
  confirmedTranscriptHash: new Uint8Array(32).fill(3),
};

describe('YjsJSONSerializer load security state', () => {
  test('round-trips the strict commitment tuple without bigint loss', () => {
    const serializer = new YjsJSONSerializer();
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
    expect(decoded.loadSecurityState?.controlHead).not.toBe(
      commitments.controlHead,
    );
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
        loadSecurityState: { ...commitments, epoch: commitments.epoch + 1n },
      }),
    );
  });

  test('round-trips a V4 load-request challenge and rejects malformed width', () => {
    const serializer = new YjsJSONSerializer();
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

  test('rejects malformed security commitments at the sync boundary', () => {
    const serializer = new YjsJSONSerializer();
    const wire = new TextEncoder().encode(
      JSON.stringify({
        documentId: '/doc',
        loadSecurityState: {
          version: 1,
          controlHead: 'AQ==',
          groupId: 'group',
          epoch: '01',
          treeHash: 'AQ==',
          confirmedTranscriptHash: 'AQ==',
        },
      }),
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /loadSecurityState/,
    );
  });

  test('accepts legacy depth 513 beyond the V4 manifest policy', () => {
    const serializer = new YjsJSONSerializer();
    const legacy = changeChain<Uint8Array>(MAX_MERKLE_DAG_DEPTH + 1);
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
    const serializer = new YjsJSONSerializer();
    const child = {} as CRDTChangeNode<Uint8Array>;
    child.change = new Uint8Array([2]);
    child.kind = 'writer';
    const changes = {} as CRDTChangeNode<Uint8Array>;
    changes.children = { PARENT: child };
    changes.change = new Uint8Array([1]);
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
