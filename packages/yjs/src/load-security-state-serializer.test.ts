import { describe, expect, test } from '@jest/globals';
import { Base64 } from 'js-base64';
import {
  CRDTChangeNode,
  MAX_INITIAL_LOAD_CHALLENGE_DOCUMENT_ID_BYTES,
  MAX_INITIAL_LOAD_RESPONSE_SIZE,
  MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES,
  MAX_LOAD_SECURITY_EPOCH,
  MAX_LOAD_SECURITY_GROUP_ID_BYTES,
  MAX_MERKLE_DAG_DEPTH,
  MAX_SECURITY_ADVERTISE_RESPONSE_SIZE,
  MAX_SHARED_PROTOCOL_REQUEST_SIZE,
  MAX_TIP_ADVERTISE_RESPONSE_SIZE,
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

  test('wire caps admit maximum valid V4 advertisement fields', () => {
    const serializer = new YjsJSONSerializer();
    const body = serializer.serializeSyncMessage({
      documentId: '\0'.repeat(MAX_INITIAL_LOAD_CHALLENGE_DOCUMENT_ID_BYTES),
      tipsHash: new Uint8Array(32),
      loadSecurityState: {
        version: 1,
        controlHead: new Uint8Array(32),
        groupId: '\0'.repeat(MAX_LOAD_SECURITY_GROUP_ID_BYTES),
        epoch: MAX_LOAD_SECURITY_EPOCH,
        treeHash: new Uint8Array(32),
        confirmedTranscriptHash: new Uint8Array(32),
      },
      loadChallenge: new Uint8Array(32),
      signature: Base64.fromUint8Array(new Uint8Array(4096)),
    });
    const encryptedWireLength = 32 + 12 + body.length + 16;
    expect(encryptedWireLength).toBeGreaterThan(6 * 1024);
    expect(encryptedWireLength).toBeLessThanOrEqual(
      MAX_SECURITY_ADVERTISE_RESPONSE_SIZE,
    );
  });

  test('legacy advertisement cap preserves long V3 document IDs', () => {
    const serializer = new YjsJSONSerializer();
    const documentId = 'd'.repeat(64 * 1024);
    const request = serializer.serializeLoadRequest({
      documentId,
      signature: '',
    });
    const body = serializer.serializeSyncMessage({
      documentId,
      tipsHash: new Uint8Array(32),
      signature: 'A'.repeat(128),
    });
    const encryptedWireLength = 32 + 12 + body.length + 16;

    expect(request.length).toBeLessThanOrEqual(
      MAX_SHARED_PROTOCOL_REQUEST_SIZE,
    );
    expect(encryptedWireLength).toBeGreaterThan(
      MAX_SECURITY_ADVERTISE_RESPONSE_SIZE,
    );
    expect(encryptedWireLength).toBeLessThanOrEqual(
      MAX_TIP_ADVERTISE_RESPONSE_SIZE,
    );
  });

  test('full-load wire cap admits all three maximum Yjs manifest payloads', () => {
    const serializer = new YjsJSONSerializer();
    const payload = new Uint8Array(MAX_LOAD_RESPONSE_MANIFEST_PAYLOAD_BYTES);
    const body = serializer.serializeSyncMessage({
      documentId: '/doc',
      changeId: 'ROOT',
      changes: { kind: 'document', change: payload },
      keychainChanges: payload,
      snapshot: {
        state: payload,
        lastChangeNodeCID: 'ROOT',
        compactedCount: 1,
        signature: new Uint8Array(96),
        timestamp: 1,
      },
    });
    const encryptedWireLength = 32 + 12 + body.length + 16;
    expect(encryptedWireLength).toBeGreaterThan(64 * 1024 * 1024);
    expect(encryptedWireLength).toBeLessThanOrEqual(
      MAX_INITIAL_LOAD_RESPONSE_SIZE,
    );
  });

});
