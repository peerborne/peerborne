import { describe, expect, test } from '@jest/globals';
import { CRDTSnapshotNode } from './snapshot-node.js';

describe('CRDTSnapshotNode', () => {
  test('can create a valid snapshot node', () => {
    const snapshot: CRDTSnapshotNode<Uint8Array, string> = {
      state: new Uint8Array([1, 2, 3, 4]),
      lastChangeNodeCID: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
      compactedCount: 150,
      signature: new Uint8Array([10, 20, 30]),
      publicKey: 'writer-public-key-123',
      timestamp: 1700000000000,
    };

    expect(snapshot.state).toEqual(new Uint8Array([1, 2, 3, 4]));
    expect(snapshot.lastChangeNodeCID).toBe(
      'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
    );
    expect(snapshot.compactedCount).toBe(150);
    expect(snapshot.signature).toEqual(new Uint8Array([10, 20, 30]));
    expect(snapshot.publicKey).toBe('writer-public-key-123');
    expect(snapshot.timestamp).toBe(1700000000000);
  });

  test('compactedCount comparison for choosing latest snapshot', () => {
    const older: CRDTSnapshotNode<Uint8Array, string> = {
      state: new Uint8Array([1]),
      lastChangeNodeCID: 'cid-100',
      compactedCount: 100,
      signature: new Uint8Array([1]),
      publicKey: 'key-a',
      timestamp: 1700000000000,
    };

    const newer: CRDTSnapshotNode<Uint8Array, string> = {
      state: new Uint8Array([2]),
      lastChangeNodeCID: 'cid-200',
      compactedCount: 200,
      signature: new Uint8Array([2]),
      publicKey: 'key-b',
      timestamp: 1700000001000,
    };

    // The snapshot with higher compactedCount is preferred.
    expect(newer.compactedCount).toBeGreaterThan(older.compactedCount);
  });

  test('snapshot with empty state is valid (empty document)', () => {
    const snapshot: CRDTSnapshotNode<Uint8Array, string> = {
      state: new Uint8Array([]),
      lastChangeNodeCID: '',
      compactedCount: 0,
      signature: new Uint8Array([]),
      publicKey: 'key',
      timestamp: Date.now(),
    };

    expect(snapshot.compactedCount).toBe(0);
    expect(snapshot.state.length).toBe(0);
  });
});
