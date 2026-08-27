import { describe, expect, test } from '@jest/globals';
import { crdtDocumentChangeNode } from './crdt-change-node.js';
import type { CRDTSyncMessage } from './crdt-sync-message.js';
import {
  assertInitialInvitationBeeKEMCapacity,
  assertInitialInvitationBeeKEMWelcomeShape,
  assertInitialInvitationCapacityProfile,
  assertInvitationOpaquePayloadCapacity,
  assertProjectedInitialInvitationBootstrapCapacity,
  assertProjectedInitialInvitationWelcomeCapacity,
  INITIAL_INVITATION_BOOTSTRAP_RESERVE_BYTES,
  INITIAL_INVITATION_CAPACITY_PROFILE,
  INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES,
  INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SIGNATURE_BYTES,
  projectInitialInvitationBootstrapCapacity,
} from './invitation-capacity.js';
import { MAX_INVITATION_OPAQUE_PAYLOAD_BYTES } from './invitation-wire.js';
import type { SyncMessageSerializer } from './sync-message-serializer.js';
import type { BeeKEMWelcome } from './beekem/types.js';

interface SizedChanges {
  readonly bytes: number;
}

class CountingSyncMessageSerializer
  implements SyncMessageSerializer<SizedChanges, never>
{
  serializeSyncMessage(
    message: CRDTSyncMessage<SizedChanges, never>,
  ): Uint8Array {
    const changeBytes = message.changes?.change?.bytes ?? 0;
    const keychainBytes = message.keychainChanges?.bytes ?? 0;
    const snapshotBytes = message.snapshot?.state.bytes ?? 0;
    const signatureBytes = message.signature?.length ?? 0;
    const tipsBytes = message.tips?.reduce(
      (total, tip) => total + tip.length,
      0,
    ) ?? 0;
    return new Uint8Array(
      changeBytes +
        keychainBytes +
        snapshotBytes +
        signatureBytes +
        tipsBytes,
    );
  }

  deserializeSyncMessage(): CRDTSyncMessage<SizedChanges, never> {
    throw new Error('not needed by capacity projection tests');
  }
}

const serializer = new CountingSyncMessageSerializer();

function twoMemberWelcome(
  overrides: Partial<BeeKEMWelcome> = {},
): BeeKEMWelcome {
  return {
    leafIndex: 2,
    pathKeys: [
      {
        nodeIndex: 1,
        publicKey: new Uint8Array([1]),
        encryptedPrivateKey: new Uint8Array([2]),
      },
    ],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: new Uint8Array([3]) },
    ],
    treeHash: new Uint8Array(32),
    ...overrides,
  };
}

function messageWithChanges(bytes: number): CRDTSyncMessage<SizedChanges, never> {
  return {
    documentId: '/capacity-test',
    changes: {
      kind: crdtDocumentChangeNode,
      change: { bytes },
    },
  };
}

function project(options?: {
  readonly currentBytes?: number;
  readonly keychainBytes?: number;
  readonly snapshotBytes?: number;
  readonly tips?: readonly string[];
}) {
  const snapshotBytes = options?.snapshotBytes;
  return projectInitialInvitationBootstrapCapacity({
    currentMessage: messageWithChanges(options?.currentBytes ?? 0),
    keychainChanges: { bytes: options?.keychainBytes ?? 0 },
    snapshot:
      snapshotBytes === undefined
        ? undefined
        : {
            state: { bytes: snapshotBytes },
            lastChangeNodeCID: 'snapshot-tip',
            compactedCount: 1,
            signature: new Uint8Array(INITIAL_INVITATION_MAX_SIGNATURE_BYTES),
            timestamp: 1,
          },
    tips: options?.tips ?? [],
    serializer,
  });
}

describe('initial invitation bootstrap capacity', () => {
  test('accepts only the exact founder-plus-one BeeKEM Welcome shape', () => {
    expect(() =>
      assertInitialInvitationBeeKEMWelcomeShape(twoMemberWelcome()),
    ).not.toThrow();

    const invalidWelcomes: BeeKEMWelcome[] = [
      twoMemberWelcome({ leafIndex: 4 }),
      twoMemberWelcome({ pathKeys: [] }),
      twoMemberWelcome({
        pathKeys: [
          {
            nodeIndex: 3,
            publicKey: new Uint8Array([1]),
            encryptedPrivateKey: new Uint8Array([2]),
          },
        ],
      }),
      twoMemberWelcome({ treeNodePublicKeys: [] }),
      twoMemberWelcome({
        treeNodePublicKeys: [
          { nodeIndex: 0, publicKey: new Uint8Array([3]) },
          { nodeIndex: 4, publicKey: new Uint8Array([4]) },
        ],
      }),
      twoMemberWelcome({
        treeNodePublicKeys: [{ nodeIndex: 1, publicKey: new Uint8Array([3]) }],
      }),
      twoMemberWelcome({
        treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
      }),
      twoMemberWelcome({ treeHash: new Uint8Array(31) }),
    ];
    for (const welcome of invalidWelcomes) {
      expect(() =>
        assertInitialInvitationBeeKEMWelcomeShape(welcome),
      ).toThrow('bounded founder-plus-one topology');
    }
  });

  test('limits sealed-Welcome sizing to the tested founder-plus-one tree', () => {
    expect(() =>
      assertInitialInvitationBeeKEMCapacity(undefined, false, '/new'),
    ).not.toThrow();
    expect(() =>
      assertInitialInvitationBeeKEMCapacity(1, false, '/founder'),
    ).not.toThrow();
    expect(() =>
      assertInitialInvitationBeeKEMCapacity(
        2,
        true,
        '/retry',
        true,
        true,
      ),
    ).not.toThrow();
    expect(() =>
      assertInitialInvitationBeeKEMCapacity(2, true, '/incomplete-retry'),
    ).toThrow('existing BeeKEM leaf or cached Welcome is unavailable');
    expect(() =>
      assertInitialInvitationBeeKEMCapacity(2, false, '/replacement'),
    ).toThrow('bounded initial founder-plus-one topology');
    expect(() =>
      assertInitialInvitationBeeKEMCapacity(3, true, '/large-tree'),
    ).toThrow('bounded initial founder-plus-one topology');
  });

  test('rejects combined inputs that are individually below the old headroom limit', () => {
    const individuallyAllowedBytes = 450 * 1024;
    expect(individuallyAllowedBytes).toBeLessThan(
      MAX_INVITATION_OPAQUE_PAYLOAD_BYTES -
        INITIAL_INVITATION_BOOTSTRAP_RESERVE_BYTES,
    );

    const projection = project({
      currentBytes: individuallyAllowedBytes,
      keychainBytes: individuallyAllowedBytes,
    });

    expect(() =>
      assertProjectedInitialInvitationBootstrapCapacity(
        projection,
        '/combined',
      ),
    ).toThrow('too large before onboarding');
  });

  test('includes the latest snapshot in the combined projection', () => {
    const projection = project({ snapshotBytes: 900 * 1024 });

    expect(() =>
      assertProjectedInitialInvitationBootstrapCapacity(
        projection,
        '/snapshot',
      ),
    ).toThrow('too large before onboarding');
  });

  test('accepts the exact boundary and rejects one serialized byte more', () => {
    const signatureBase64Bytes = 4 * Math.ceil(
      INITIAL_INVITATION_MAX_SIGNATURE_BYTES / 3,
    );
    const fixedBytes =
      signatureBase64Bytes +
      INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES +
      INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES +
      INITIAL_INVITATION_BOOTSTRAP_RESERVE_BYTES;
    const atLimit = project({
      currentBytes: MAX_INVITATION_OPAQUE_PAYLOAD_BYTES - fixedBytes,
    });
    const overLimit = project({
      currentBytes: MAX_INVITATION_OPAQUE_PAYLOAD_BYTES - fixedBytes + 1,
    });

    expect(atLimit.projectedEncryptedBootstrapBytes).toBe(
      MAX_INVITATION_OPAQUE_PAYLOAD_BYTES,
    );
    expect(() =>
      assertProjectedInitialInvitationBootstrapCapacity(atLimit, '/boundary'),
    ).not.toThrow();
    expect(() =>
      assertProjectedInitialInvitationBootstrapCapacity(
        overLimit,
        '/boundary',
      ),
    ).toThrow('too large before onboarding');
  });

  test('accounts for projected frontier tips and signature bytes', () => {
    const noTips = project();
    const withTips = project({ tips: ['tip-one', 'tip-two'] });

    expect(noTips.serializedBaselineBytes).toBe(128);
    expect(withTips.serializedBaselineBytes).toBe(
      noTips.serializedBaselineBytes + 'tip-one'.length + 'tip-two'.length,
    );
  });

  test('bounds the sealed Welcome before membership mutation', () => {
    const exactBaseline =
      MAX_INVITATION_OPAQUE_PAYLOAD_BYTES -
      INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES -
      INITIAL_INVITATION_BOOTSTRAP_RESERVE_BYTES;

    expect(() =>
      assertProjectedInitialInvitationWelcomeCapacity(
        exactBaseline,
        '/welcome',
      ),
    ).not.toThrow();
    expect(() =>
      assertProjectedInitialInvitationWelcomeCapacity(
        exactBaseline + 1,
        '/welcome',
      ),
    ).toThrow('too large before onboarding');
  });

  test('retains a final exact opaque-field hard cap', () => {
    expect(() =>
      assertInvitationOpaquePayloadCapacity(
        new Uint8Array(MAX_INVITATION_OPAQUE_PAYLOAD_BYTES),
        'bootstrap',
        '/exact',
      ),
    ).not.toThrow();
    expect(() =>
      assertInvitationOpaquePayloadCapacity(
        new Uint8Array(MAX_INVITATION_OPAQUE_PAYLOAD_BYTES + 1),
        'Welcome',
        '/over',
      ),
    ).toThrow('exceeds the 1048576-byte wire limit');
  });
});

describe('initial invitation capacity profile', () => {
  const declared = {
    initialInvitationCapacityProfile: INITIAL_INVITATION_CAPACITY_PROFILE,
  } as const;
  const supportedAuth = {
    ...declared,
    supportsInitialInvitationCapacity: () => true,
  };
  const components = {
    crdtProvider: declared,
    aclProvider: declared,
    keychainProvider: { ...declared, keyIDLength: 32 },
    changesSerializer: declared,
    syncMessageSerializer: declared,
    authProvider: supportedAuth,
    privateKey: 'private',
    publicKey: 'public',
  };

  test('accepts the fully declared bounded provider stack', () => {
    expect(() => assertInitialInvitationCapacityProfile(components)).not.toThrow();
  });

  test('rejects a generic provider before size projection', () => {
    expect(() =>
      assertInitialInvitationCapacityProfile({
        ...components,
        crdtProvider: {},
      }),
    ).toThrow('unsupported CRDT provider');
  });

  test('rejects an unsupported identity or encryption profile', () => {
    expect(() =>
      assertInitialInvitationCapacityProfile({
        ...components,
        authProvider: {
          ...declared,
          supportsInitialInvitationCapacity: () => false,
        },
      }),
    ).toThrow('P-384 signing keys');
  });

  test('rejects a nonstandard key-ID width', () => {
    expect(() =>
      assertInitialInvitationCapacityProfile({
        ...components,
        keychainProvider: { ...declared, keyIDLength: 16 },
      }),
    ).toThrow('32-byte key-ID profile');
  });
});
