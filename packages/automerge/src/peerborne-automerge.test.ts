import { describe, expect, test, beforeAll, jest } from '@jest/globals';
import { createECDH } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { snapshotDeepEnumerableData } from '@peerborne/core';
import {
  Change as BinaryChange,
  applyChanges as applyAutomergeChanges,
  clone as automergeClone,
  change as automergeChange,
  decodeChange as decodeAutomergeChange,
  from as automergeFrom,
  getAllChanges as getAllAutomergeChanges,
  getChanges as getAutomergeChanges,
  init as automergeInit,
  merge as automergeMerge,
} from '@automerge/automerge';
import {
  AutomergeProvider,
  AutomergeACL,
  AutomergeACLProvider,
  AutomergeKeychain,
  AutomergeKeychainProvider,
  AutomergeJSONSerializer,
  MAX_AUTOMERGE_ACL_CHANGE_BYTES,
  MAX_AUTOMERGE_ACL_CHANGES,
  MAX_AUTOMERGE_ACL_HISTORY_BYTES,
  MAX_AUTOMERGE_ACL_MEMBERS,
  MAX_AUTOMERGE_ACL_OPERATIONS,
  serializeKey,
  deserializeKey,
} from './peerborne-automerge.js';
import {
  INITIAL_INVITATION_CAPACITY_PROFILE,
  MAX_KEYCHAIN_EPOCHS,
  INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES,
  INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SIGNATURE_BYTES,
  MAX_MERKLE_DAG_DEPTH,
  BeeKEM,
  SubtleCrypto,
  UCANACL,
  eciesSeal,
  encodeWelcomeSealedPayloadV2,
  type CRDTChangeNode,
  type CRDTSyncMessage,
} from '@peerborne/core';

// ECDSA P-384 JWK test keys (public only - ACL uses raw export which requires public keys)
const publicKeyData1 = {
  key_ops: ['verify'] as KeyUsage[],
  ext: true,
  kty: 'EC',
  x: 'iV0DESMDz3fcubTpUCMK4YLWbU9gDslDgdflc5OGrQVII_wCViDdqGbMTOmQLY0F',
  y: 'CQyfju2lK2mT0TIVDI-olIqFC3m3AayX0deHkw4JPCU-GwzV9k0BT295OSQ495kK',
  crv: 'P-384',
};
const publicKeyData2 = {
  key_ops: ['verify'] as KeyUsage[],
  ext: true,
  kty: 'EC',
  x: 'oodHRfDRDsXcpe2FvwctaK1y4pt8Lhx5tmiXZ-35vzXuDUD5zWhzPxgC8FZvyY0K',
  y: 'KhgG-mU2-mNbhgdK9_8nEMwPa2_bWWl_zlqY6Q4xuXYMOjhSLGydbFIDSAGBaNaJ',
  crv: 'P-384',
};

async function importECDSAPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['verify'],
  );
}

type AutomergeACLShape = {
  users?: Record<string, true>;
};

function deterministicSerializedP384Keys(count: number): string[] {
  const ecdh = createECDH('secp384r1');
  return Array.from({ length: count }, (_, index) => {
    const scalar = Buffer.alloc(48);
    scalar.writeUInt32BE(index + 1, 44);
    ecdh.setPrivateKey(scalar);
    return ecdh.getPublicKey().toString('base64');
  });
}

// ─── AutomergeProvider ──────────────────────────────────────────────

interface TestDoc {
  title: string;
  count: number;
}

describe('AutomergeProvider', () => {
  const provider = new AutomergeProvider<TestDoc>();

  test('newDocument() returns a valid Automerge Doc', () => {
    const doc = provider.newDocument();
    expect(doc).toBeDefined();
    // Automerge init docs are frozen plain objects
    expect(typeof doc).toBe('object');
  });

  test('localChange() applies a change and returns [newDoc, changes]', () => {
    const doc = provider.newDocument();
    const [newDoc, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'hello';
      d.count = 1;
    });
    expect(newDoc.title).toBe('hello');
    expect(newDoc.count).toBe(1);
    expect(changes.length).toBeGreaterThan(0);
  });

  test('localChange() with a message passes through', () => {
    const doc = provider.newDocument();
    const [newDoc, changes] = provider.localChange(
      doc,
      'set title',
      (d) => {
        d.title = 'with message';
      },
    );
    expect(newDoc.title).toBe('with message');
    expect(changes.length).toBeGreaterThan(0);
  });

  test('remoteChange() applies binary changes from another doc', () => {
    const doc1 = provider.newDocument();
    const [updated1, changes] = provider.localChange(doc1, '', (d) => {
      d.title = 'remote';
      d.count = 42;
    });

    let doc2 = provider.newDocument();
    doc2 = provider.remoteChange(doc2, changes);
    expect(doc2.title).toBe('remote');
    expect(doc2.count).toBe(42);
  });

  test('getHistory() returns all changes', () => {
    const doc = provider.newDocument();
    const [doc2] = provider.localChange(doc, '', (d) => {
      d.title = 'a';
    });
    const [doc3] = provider.localChange(doc2, '', (d) => {
      d.count = 5;
    });
    const history = provider.getHistory(doc3);
    expect(history.length).toBe(2);
  });

  test('round-trip: localChange on doc1 -> remoteChange on doc2 -> docs match', () => {
    const doc1 = provider.newDocument();
    const [doc1a, changes1] = provider.localChange(doc1, '', (d) => {
      d.title = 'sync';
      d.count = 99;
    });

    let doc2 = provider.newDocument();
    doc2 = provider.remoteChange(doc2, changes1);

    expect(doc2.title).toBe(doc1a.title);
    expect(doc2.count).toBe(doc1a.count);
  });
});

// ─── serializeKey / deserializeKey ──────────────────────────────────

describe('serializeKey / deserializeKey', () => {
  test('round-trip serialize then deserialize an ECDSA public key', async () => {
    const key = await importECDSAPublicKey(publicKeyData1);
    const serialized = await serializeKey(key);
    expect(typeof serialized).toBe('string');
    expect(serialized.length).toBeGreaterThan(0);

    const deserialized = await deserializeKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      ['verify'],
    )(serialized);
    expect(deserialized).toBeDefined();
    expect(deserialized.type).toBe('public');

    // Re-serialize should produce the same base64 string
    const reSerialized = await serializeKey(deserialized);
    expect(reSerialized).toBe(serialized);
  });
});

// ─── AutomergeACL ───────────────────────────────────────────────────

describe('AutomergeACL', () => {
  let key1: CryptoKey;
  let key2: CryptoKey;

  beforeAll(async () => {
    key1 = await importECDSAPublicKey(publicKeyData1);
    key2 = await importECDSAPublicKey(publicKeyData2);
  });

  test('add() adds a user and check() returns true', async () => {
    const acl = new AutomergeACL();
    const changes = await acl.add(key1);
    expect(changes.length).toBeGreaterThan(0);
    expect(await acl.check(key1)).toBe(true);
  });

  test('add() rejects a non-P-384 identity before emitting changes', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const acl = new AutomergeACL();
    const before = acl.current();

    await expect(acl.add(keyPair.publicKey)).rejects.toThrow(
      /97-byte uncompressed P-384 point/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(keyPair.publicKey)).toBe(false);
  });

  test('removal rejects a non-P-384 identity without changing state', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const acl = new AutomergeACL();
    await acl.add(key1);
    const before = acl.current();

    await expect(acl.prepareRemove(keyPair.publicKey)).rejects.toThrow(
      /97-byte uncompressed P-384 point/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);

    await expect(acl.remove(keyPair.publicKey)).rejects.toThrow(
      /97-byte uncompressed P-384 point/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
  });

  test('prepareAdd() stages detached changes without changing live membership', async () => {
    const acl = new AutomergeACL();
    const before = acl.current();

    const prepared = await acl.prepareAdd(key1);

    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(false);

    const receiver = new AutomergeACL();
    receiver.merge(prepared.changes);
    expect(await receiver.check(key1)).toBe(true);

    prepared.commit();
    expect(await acl.check(key1)).toBe(true);
  });

  test('prepareAdd() claim stays invisible and finalizes prebuilt accounting once', async () => {
    const acl = new AutomergeACL();
    const internals = acl as unknown as {
      _acl: unknown;
      _revision: number;
      _retainedChanges: Map<string, unknown>;
      _retainedChangeBytes: number;
      _retainedOperations: number;
      _retainedCanonicalUsersRootSeed: boolean;
      _stagedAdditionActors: Set<string>;
      _commitChangeAccounting(records: readonly unknown[]): void;
    };
    const liveACL = internals._acl;
    const liveAccounting = internals._retainedChanges;
    const prepared = await acl.prepareAdd(key1);
    const reservations = new Set(internals._stagedAdditionActors);

    const claim = prepared.claimCommit!();

    expect(internals._acl).toBe(liveACL);
    expect(internals._revision).toBe(0);
    expect(internals._retainedChanges).toBe(liveAccounting);
    expect(internals._retainedChangeBytes).toBe(0);
    expect(internals._retainedOperations).toBe(0);
    expect(internals._retainedCanonicalUsersRootSeed).toBe(false);
    expect(internals._stagedAdditionActors).toEqual(reservations);
    expect(await acl.check(key1)).toBe(false);
    expect(() => prepared.claimCommit!()).toThrow(
      /already committed or claimed/,
    );
    expect(() => prepared.commit()).toThrow(/already committed or claimed/);

    const setAccounting = jest
      .spyOn(liveAccounting, 'set')
      .mockImplementation(() => {
        throw new Error('Finalization must not mutate live accounting');
      });
    const commitAccounting = jest
      .spyOn(internals, '_commitChangeAccounting')
      .mockImplementation(() => {
        throw new Error('Finalization must not run accounting work');
      });
    try {
      expect(() => claim.finalize()).not.toThrow();
      expect(() => claim.finalize()).not.toThrow();
    } finally {
      setAccounting.mockRestore();
      commitAccounting.mockRestore();
    }

    expect(internals._acl).not.toBe(liveACL);
    expect(internals._revision).toBe(1);
    expect(internals._retainedChanges).not.toBe(liveAccounting);
    expect(internals._retainedChanges.size).toBe(prepared.changes.length);
    expect(internals._retainedChangeBytes).toBe(
      prepared.changes.reduce(
        (total, binaryChange) => total + binaryChange.byteLength,
        0,
      ),
    );
    expect(internals._retainedOperations).toBe(
      prepared.changes.reduce(
        (total, binaryChange) =>
          total + decodeAutomergeChange(binaryChange).ops.length,
        0,
      ),
    );
    expect(internals._retainedCanonicalUsersRootSeed).toBe(true);
    expect(internals._stagedAdditionActors).toEqual(reservations);
    expect(await acl.check(key1)).toBe(true);
  });

  test('an abandoned addition claim retains its actor and permits fresh staging', async () => {
    const acl = new AutomergeACL();
    const internals = acl as unknown as {
      _revision: number;
      _retainedChanges: Map<string, unknown>;
      _stagedAdditionActors: Set<string>;
    };
    const abandoned = await acl.prepareAdd(key1);
    const firstReservations = new Set(internals._stagedAdditionActors);

    abandoned.claimCommit!();
    expect(internals._revision).toBe(0);
    expect(internals._retainedChanges.size).toBe(0);
    expect(await acl.check(key1)).toBe(false);

    const retry = await acl.prepareAdd(key1);
    expect(internals._stagedAdditionActors.size).toBe(
      firstReservations.size + 1,
    );
    for (const actor of firstReservations) {
      expect(internals._stagedAdditionActors.has(actor)).toBe(true);
    }

    const reservationsBeforeFinalize = new Set(
      internals._stagedAdditionActors,
    );
    retry.claimCommit!().finalize();
    expect(internals._stagedAdditionActors).toEqual(
      reservationsBeforeFinalize,
    );
    expect(await acl.check(key1)).toBe(true);
  });

  test('prepared commits do not look up replaceable claim methods', async () => {
    const acl = new AutomergeACL();
    const addition = await acl.prepareAdd(key1);
    Object.defineProperty(addition, 'claimCommit', {
      get: () => {
        throw new Error('replaceable addition claim was read');
      },
    });

    expect(() => addition.commit()).not.toThrow();
    expect(await acl.check(key1)).toBe(true);

    const removal = await acl.prepareRemove(key1);
    Object.defineProperty(removal, 'claimCommit', {
      get: () => {
        throw new Error('replaceable removal claim was read');
      },
    });

    expect(() => removal.commit()).not.toThrow();
    expect(await acl.check(key1)).toBe(false);
  });

  test('UCAN-wrapped Automerge claim commits backing membership and local authorization together', async () => {
    const backing = new AutomergeACL();
    const acl = new UCANACL(
      backing,
      serializeKey,
      deserializeKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        ['verify'],
      ),
    );
    await acl.add(key1);
    await acl.remove(key1);
    const prepared = await acl.prepareAdd(key1);

    const claim = prepared.claimCommit!();

    expect(await backing.check(key1)).toBe(false);
    expect(await acl.check(key1)).toBe(false);
    expect(await acl.users()).toEqual([]);

    claim.finalize();

    expect(await backing.check(key1)).toBe(true);
    expect(await acl.check(key1)).toBe(true);
    expect(
      await Promise.all((await acl.users()).map(serializeKey)),
    ).toEqual([await serializeKey(key1)]);
  });

  test('prepareAdd() releases actors after post-reservation validation failures', async () => {
    const acl = new AutomergeACL();
    const internals = acl as unknown as {
      _retainedChanges: Map<string, unknown>;
      _stagedAdditionActors: Set<string>;
    };
    for (let index = 0; index < MAX_AUTOMERGE_ACL_CHANGES; index++) {
      internals._retainedChanges.set(`retained-${index}`, {});
      if (index < MAX_AUTOMERGE_ACL_CHANGES - 1) {
        internals._stagedAdditionActors.add(`reserved-${index}`);
      }
    }
    const retainedActors = new Set(internals._stagedAdditionActors);

    for (let attempt = 0; attempt < 3; attempt++) {
      await expect(acl.prepareAdd(key1)).rejects.toThrow(
        `Automerge ACL retained history exceeds the ${MAX_AUTOMERGE_ACL_CHANGES}-change limit`,
      );
      expect(internals._stagedAdditionActors).toEqual(retainedActors);
    }

    internals._retainedChanges.clear();
    const prepared = await acl.prepareAdd(key1);
    expect(prepared.changes.length).toBeGreaterThan(0);
    expect(internals._stagedAdditionActors.size).toBe(
      MAX_AUTOMERGE_ACL_CHANGES,
    );
  });

  test('prepareAdd() commit is single-use', async () => {
    const acl = new AutomergeACL();
    const prepared = await acl.prepareAdd(key1);

    prepared.commit();

    expect(() => prepared.commit()).toThrow(
      'Prepared ACL addition was already committed',
    );
    expect(await acl.check(key1)).toBe(true);
  });

  test('prepareAdd() rejects competing and merge-staled commits before mutation', async () => {
    const acl = new AutomergeACL();
    const first = await acl.prepareAdd(key1);
    const competing = await acl.prepareAdd(key2);

    first.commit();
    expect(() => competing.commit()).toThrow(
      'ACL changed while addition was staged',
    );
    expect(await acl.check(key2)).toBe(false);

    const mergeStaled = await acl.prepareAdd(key2);
    const remote = new AutomergeACL();
    remote.merge(acl.current());
    const remoteChanges = await remote.remove(key1);
    acl.merge(remoteChanges);

    expect(() => mergeStaled.commit()).toThrow(
      'ACL changed while addition was staged',
    );
    expect(await acl.check(key2)).toBe(false);
  });

  test('addition and removal claims reject stale local and remote bases', async () => {
    const acl = new AutomergeACL();
    const staleAddition = await acl.prepareAdd(key2);
    await acl.add(key1);
    const afterLocalMutation = acl.current();

    expect(() => staleAddition.claimCommit!()).toThrow(
      'ACL changed while addition was staged',
    );
    expect(acl.current()).toEqual(afterLocalMutation);
    expect(await acl.check(key2)).toBe(false);

    const staleRemoval = await acl.prepareRemove(key1);
    const remote = new AutomergeACL();
    remote.merge(acl.current());
    const remoteChanges = await remote.add(key2);
    acl.merge(remoteChanges);
    const afterRemoteMutation = acl.current();

    expect(() => staleRemoval.claimCommit!()).toThrow(
      'ACL changed while removal was staged',
    );
    expect(acl.current()).toEqual(afterRemoteMutation);
    expect(await acl.check(key1)).toBe(true);
    expect(await acl.check(key2)).toBe(true);
  });

  test('blank-base prepared additions remain mergeable in either order', async () => {
    const first = await new AutomergeACL().prepareAdd(key1);
    const second = await new AutomergeACL().prepareAdd(key2);

    expect(first.changes[0]).toEqual(second.changes[0]);
    for (const changes of [
      [first.changes, second.changes],
      [second.changes, first.changes],
    ]) {
      const receiver = new AutomergeACL();
      receiver.merge(changes[0]);
      receiver.merge(changes[1]);
      expect(await receiver.check(key1)).toBe(true);
      expect(await receiver.check(key2)).toBe(true);
    }
  });

  test(
    'canonical root seed preserves the 4,096-member change capacity',
    async () => {
      const serializedMembers = deterministicSerializedP384Keys(
        MAX_AUTOMERGE_ACL_MEMBERS - 1,
      );
      const [lastMember, rejectedMember] = await Promise.all([
        serializeKey(key1),
        serializeKey(key2),
      ]);
      expect(
        new Set([...serializedMembers, lastMember, rejectedMember]).size,
      ).toBe(MAX_AUTOMERGE_ACL_MEMBERS + 1);

      const bootstrapKey = await deserializeKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        ['verify'],
      )(serializedMembers[0]!);
      const bootstrap = new AutomergeACL();
      await bootstrap.add(bootstrapKey);
      const [bootstrapDocument] = applyAutomergeChanges(
        automergeInit<AutomergeACLShape>(),
        bootstrap.current(),
      );
      let source = automergeClone(bootstrapDocument);
      for (const serialized of serializedMembers.slice(1)) {
        source = automergeChange(source, (doc) => {
          doc.users![serialized] = true;
        });
      }
      const beforeLastMember = getAllAutomergeChanges(source);
      expect(beforeLastMember).toHaveLength(MAX_AUTOMERGE_ACL_CHANGES);

      const acl = new AutomergeACL();
      expect(() => acl.merge(beforeLastMember)).not.toThrow();
      const prepared = await acl.prepareAdd(key1);
      expect(prepared.changes).toHaveLength(1);
      prepared.commit();

      const atMemberLimit = acl.current();
      expect(atMemberLimit).toHaveLength(MAX_AUTOMERGE_ACL_CHANGES + 1);
      expect(
        atMemberLimit.reduce(
          (total, binaryChange) => total + binaryChange.byteLength,
          0,
        ),
      ).toBeLessThanOrEqual(MAX_AUTOMERGE_ACL_HISTORY_BYTES);
      expect(
        atMemberLimit.reduce(
          (total, binaryChange) =>
            total + decodeAutomergeChange(binaryChange).ops.length,
          0,
        ),
      ).toBeLessThanOrEqual(MAX_AUTOMERGE_ACL_OPERATIONS);
      expect(await acl.check(key1)).toBe(true);

      const receiver = new AutomergeACL();
      expect(() => receiver.merge(atMemberLimit)).not.toThrow();
      expect(await receiver.check(key1)).toBe(true);

      const beforeRejectedMember = acl.current();
      await expect(acl.prepareAdd(key2)).rejects.toThrow(
        `Automerge ACL retained history exceeds the ${MAX_AUTOMERGE_ACL_CHANGES}-change limit`,
      );
      expect(acl.current()).toEqual(beforeRejectedMember);

      const seedIndex = atMemberLimit.findIndex((binaryChange) => {
        const decoded = decodeAutomergeChange(binaryChange);
        return decoded.ops.some(
          (operation) =>
            operation.obj === '_root' && operation.key === 'users',
        );
      });
      expect(seedIndex).toBeGreaterThanOrEqual(0);
      const seed = decodeAutomergeChange(atMemberLimit[seedIndex]!);
      const malformedSeed = automergeChange(
        automergeInit<AutomergeACLShape & { padding?: boolean }>({
          actor: seed.actor,
        }),
        { time: seed.time },
        (doc) => {
          doc.users = {};
          doc.padding = true;
        },
      );
      const dependency = automergeChange(
        automergeInit<{ padding?: boolean }>(),
        (doc) => {
          doc.padding = true;
        },
      );
      const dependentSeed = automergeChange(
        automergeClone(dependency, { actor: seed.actor }),
        { time: seed.time },
        (doc: AutomergeACLShape & { padding?: boolean }) => {
          doc.users = {};
        },
      );
      const dependentSeedChange = getAllAutomergeChanges(dependentSeed).find(
        (binaryChange) =>
          decodeAutomergeChange(binaryChange).actor === seed.actor,
      )!;

      for (const nearSeed of [
        getAllAutomergeChanges(malformedSeed)[0]!,
        dependentSeedChange,
      ]) {
        const oversizedNearSeedHistory = [
          nearSeed,
          ...atMemberLimit.filter((_, index) => index !== seedIndex),
        ];
        expect(oversizedNearSeedHistory).toHaveLength(
          MAX_AUTOMERGE_ACL_CHANGES + 1,
        );
        const hostileReceiver = new AutomergeACL();
        expect(() => hostileReceiver.merge(oversizedNearSeedHistory)).toThrow(
          `Automerge ACL changes exceed the ${MAX_AUTOMERGE_ACL_CHANGES}-change limit`,
        );
        expect(hostileReceiver.current()).toEqual([]);
      }
    },
    120_000,
  );

  test('blank-base prepared additions share a seed across creation times', async () => {
    const now = jest.spyOn(Date, 'now');
    try {
      now.mockReturnValue(1_000);
      const first = await new AutomergeACL().prepareAdd(key1);

      now.mockReturnValue(3_000);
      const second = await new AutomergeACL().prepareAdd(key2);

      expect(first.changes[0]).toEqual(second.changes[0]);
    } finally {
      now.mockRestore();
    }
  });

  test('same-member prepared additions remain mergeable in either order', async () => {
    const founder = new AutomergeACL();
    await founder.add(key1);
    const base = founder.current();
    const firstSource = new AutomergeACL();
    const secondSource = new AutomergeACL();
    firstSource.merge(base);
    secondSource.merge(base);
    const first = await firstSource.prepareAdd(key2);
    const second = await secondSource.prepareAdd(key2);

    for (const changes of [
      [first.changes, second.changes],
      [second.changes, first.changes],
    ]) {
      const receiver = new AutomergeACL();
      receiver.merge(base);
      receiver.merge(changes[0]);
      receiver.merge(changes[1]);
      expect(await receiver.check(key1)).toBe(true);
      expect(await receiver.check(key2)).toBe(true);
    }
  });

  test('prepareAdd() no-op commit preserves other staged work', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const noOp = await acl.prepareAdd(key1);
    const addition = await acl.prepareAdd(key2);

    expect(noOp.changes).toEqual([]);
    noOp.commit();
    addition.commit();

    expect(await acl.check(key1)).toBe(true);
    expect(await acl.check(key2)).toBe(true);
    expect(() => noOp.commit()).toThrow(
      'Prepared ACL addition was already committed',
    );
  });

  test('no-op claims preserve revision, accounting, and compatible staged work', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const addition = await acl.prepareAdd(key2);
    const noOpAddition = await acl.prepareAdd(key1);
    const noOpRemoval = await acl.prepareRemove(key2);
    const internals = acl as unknown as {
      _acl: unknown;
      _revision: number;
      _retainedChanges: Map<string, unknown>;
      _retainedChangeBytes: number;
      _retainedOperations: number;
      _retainedCanonicalUsersRootSeed: boolean;
      _stagedAdditionActors: Set<string>;
    };
    const liveACL = internals._acl;
    const revision = internals._revision;
    const retainedChanges = internals._retainedChanges;
    const retainedChangeBytes = internals._retainedChangeBytes;
    const retainedOperations = internals._retainedOperations;
    const retainedCanonicalUsersRootSeed =
      internals._retainedCanonicalUsersRootSeed;
    const reservations = new Set(internals._stagedAdditionActors);

    noOpAddition.claimCommit!().finalize();
    noOpRemoval.claimCommit!().finalize();

    expect(internals._acl).toBe(liveACL);
    expect(internals._revision).toBe(revision);
    expect(internals._retainedChanges).toBe(retainedChanges);
    expect(internals._retainedChangeBytes).toBe(retainedChangeBytes);
    expect(internals._retainedOperations).toBe(retainedOperations);
    expect(internals._retainedCanonicalUsersRootSeed).toBe(
      retainedCanonicalUsersRootSeed,
    );
    expect(internals._stagedAdditionActors).toEqual(reservations);

    addition.claimCommit!().finalize();
    expect(await acl.check(key1)).toBe(true);
    expect(await acl.check(key2)).toBe(true);
  });

  test('prepareAdd() commits private state after returned changes are mutated', async () => {
    const acl = new AutomergeACL();
    const prepared = await acl.prepareAdd(key1);

    for (const change of prepared.changes) change.fill(0);
    prepared.changes.length = 0;
    prepared.commit();

    expect(await acl.check(key1)).toBe(true);
  });

  test('ordinary additions stage and commit in invocation order', async () => {
    const acl = new AutomergeACL();
    const external = await acl.prepareAdd(key2);
    const prepareAdd = acl.prepareAdd.bind(acl);
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });
    let preparation = 0;
    acl.prepareAdd = jest.fn(async (publicKey: CryptoKey) => {
      preparation++;
      if (preparation === 1) {
        firstStarted();
        await firstGate;
      }
      return prepareAdd(publicKey);
    });

    const first = acl.add(key1);
    await started;
    const second = acl.add(key2);
    await Promise.resolve();

    expect(acl.prepareAdd).toHaveBeenCalledTimes(1);
    expect(() => external.claimCommit!()).toThrow(
      'Prepared ACL addition cannot commit during a local ACL mutation',
    );
    expect(() => external.commit()).toThrow(
      'Prepared ACL addition cannot commit during a local ACL mutation',
    );
    releaseFirst();
    await expect(first).resolves.toBeDefined();
    await expect(second).resolves.toBeDefined();
    expect(acl.prepareAdd).toHaveBeenCalledTimes(2);
    expect(await acl.check(key1)).toBe(true);
    expect(await acl.check(key2)).toBe(true);
    expect(() => external.commit()).toThrow(
      'ACL changed while addition was staged',
    );
  });

  test('prepareAdd() commit cannot overtake an admitted removal', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const external = await acl.prepareAdd(key2);
    const prepareRemove = acl.prepareRemove.bind(acl);
    let releaseRemoval!: () => void;
    const removalGate = new Promise<void>((resolve) => {
      releaseRemoval = resolve;
    });
    let removalStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      removalStarted = resolve;
    });
    acl.prepareRemove = jest.fn(async (publicKey: CryptoKey) => {
      removalStarted();
      await removalGate;
      return prepareRemove(publicKey);
    });

    const removal = acl.remove(key1);
    await started;

    expect(() => external.claimCommit!()).toThrow(
      'Prepared ACL addition cannot commit during a local ACL mutation',
    );
    expect(() => external.commit()).toThrow(
      'Prepared ACL addition cannot commit during a local ACL mutation',
    );
    expect(await acl.check(key2)).toBe(false);

    releaseRemoval();
    await expect(removal).resolves.toBeDefined();
    expect(await acl.check(key1)).toBe(false);
    expect(() => external.commit()).toThrow(
      'ACL changed while addition was staged',
    );
  });

  test('remove() removes a user and check() returns false', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    expect(await acl.check(key1)).toBe(true);

    const removeChanges = await acl.remove(key1);
    expect(removeChanges.length).toBeGreaterThan(0);
    expect(await acl.check(key1)).toBe(false);
  });

  test('ordinary mutations are FIFO and reject a racing merge', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const externalRemoval = await acl.prepareRemove(key1);
    const remote = new AutomergeACL();
    const remoteChanges = await remote.add(key2);
    const originalPrepareRemove = acl.prepareRemove.bind(acl);
    let releasePreparation!: () => void;
    const preparationGate = new Promise<void>((resolve) => {
      releasePreparation = resolve;
    });
    let preparationStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      preparationStarted = resolve;
    });
    acl.prepareRemove = jest.fn(async (publicKey: CryptoKey) => {
      preparationStarted();
      await preparationGate;
      return originalPrepareRemove(publicKey);
    });

    const removal = acl.remove(key1);
    await started;
    const addition = acl.add(key2);
    await Promise.resolve();

    expect(await acl.check(key2)).toBe(false);
    expect(() => acl.merge(remoteChanges)).toThrow(
      'Cannot merge during a local ACL mutation',
    );
    expect(() => externalRemoval.claimCommit!()).toThrow(
      'Prepared ACL removal cannot commit during a local ACL mutation',
    );
    expect(() => externalRemoval.commit()).toThrow(
      'Prepared ACL removal cannot commit during a local ACL mutation',
    );

    releasePreparation();
    await expect(removal).resolves.toBeDefined();
    await expect(addition).resolves.toBeDefined();
    expect(await acl.check(key1)).toBe(false);
    expect(await acl.check(key2)).toBe(true);
    expect(() => externalRemoval.commit()).toThrow(
      'ACL changed while removal was staged',
    );
  });

  test('prepareRemove() stages detached changes without changing live membership', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    await acl.add(key2);
    const before = acl.current();

    const prepared = await acl.prepareRemove(key1);

    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
    expect(await acl.users()).toHaveLength(2);

    const receiver = new AutomergeACL();
    receiver.merge(before);
    receiver.merge(prepared.changes);
    expect(await receiver.check(key1)).toBe(false);
    expect(await receiver.check(key2)).toBe(true);

    prepared.commit();
    expect(await acl.check(key1)).toBe(false);
    expect(await acl.check(key2)).toBe(true);
  });

  test('prepareRemove() claim stays invisible until an idempotent finalize', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const internals = acl as unknown as {
      _acl: unknown;
      _revision: number;
      _retainedChanges: Map<string, unknown>;
    };
    const prepared = await acl.prepareRemove(key1);
    const liveACL = internals._acl;
    const revision = internals._revision;
    const retainedChanges = internals._retainedChanges;

    const claim = prepared.claimCommit!();

    expect(internals._acl).toBe(liveACL);
    expect(internals._revision).toBe(revision);
    expect(internals._retainedChanges).toBe(retainedChanges);
    expect(await acl.check(key1)).toBe(true);
    expect(() => prepared.claimCommit!()).toThrow(/already committed or claimed/);
    expect(() => prepared.commit()).toThrow(/already committed or claimed/);

    claim.finalize();
    claim.finalize();
    expect(internals._acl).not.toBe(liveACL);
    expect(internals._revision).toBe(revision + 1);
    expect(internals._retainedChanges).not.toBe(retainedChanges);
    expect(await acl.check(key1)).toBe(false);
  });

  test('prepareRemove() commit is single-use', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const prepared = await acl.prepareRemove(key1);

    prepared.commit();

    expect(() => prepared.commit()).toThrow(
      'Prepared ACL removal was already committed',
    );
    expect(await acl.check(key1)).toBe(false);
  });

  test('no-op merge replays do not stale a prepared removal', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const replay = acl.current();
    const prepared = await acl.prepareRemove(key1);

    acl.merge([]);
    acl.merge(replay);

    expect(() => prepared.commit()).not.toThrow();
    expect(await acl.check(key1)).toBe(false);
  });

  test('prepareRemove() rejects a stale commit before changing membership', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const before = acl.current();
    const prepared = await acl.prepareRemove(key1);
    const concurrentChanges = await acl.add(key2);

    expect(() => prepared.commit()).toThrow(
      'ACL changed while removal was staged',
    );
    expect(await acl.check(key1)).toBe(true);
    expect(await acl.check(key2)).toBe(true);

    const receiver = new AutomergeACL();
    receiver.merge(before);
    receiver.merge(prepared.changes);
    receiver.merge(concurrentChanges);
    expect(await receiver.check(key1)).toBe(false);
    expect(await receiver.check(key2)).toBe(true);
  });

  test('merge preserves a removal committed by a caller accessor', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const removal = await acl.prepareRemove(key1);
    const remote = new AutomergeACL();
    remote.merge(acl.current());
    const remoteChanges = await remote.add(key2);
    let committed = false;
    const reentrantChanges = new Proxy(remoteChanges, {
      get(target, property, receiver) {
        if (property === '0' && !committed) {
          committed = true;
          removal.commit();
        }
        return Reflect.get(target, property, receiver);
      },
    });

    expect(() => acl.merge(reentrantChanges)).not.toThrow();

    expect(committed).toBe(true);
    expect(await acl.check(key1)).toBe(false);
    expect(await acl.check(key2)).toBe(true);
  });

  test('merge accepts detached cross-realm changes and rejects byte lookalikes and shared backing', async () => {
    const source = new AutomergeACL();
    await source.add(key1);
    const crossRealm = source
      .current()
      .map(
        (binaryChange) =>
          runInNewContext(
            `new Uint8Array([${Array.from(binaryChange).join(',')}])`,
          ) as Uint8Array,
      );
    expect(crossRealm[0]).not.toBeInstanceOf(Uint8Array);
    const receiver = new AutomergeACL();

    expect(() => receiver.merge(crossRealm)).not.toThrow();
    expect(await receiver.check(key1)).toBe(true);
    const before = receiver.current();
    expect(() =>
      receiver.merge([
        { 0: 0, length: 1 } as unknown as BinaryChange,
      ]),
    ).toThrow('Automerge ACL change must be a genuine Uint8Array');
    expect(receiver.current()).toEqual(before);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(new SharedArrayBuffer(1));
      expect(() => receiver.merge([shared as BinaryChange])).toThrow(
        'Automerge ACL change has an invalid length or backing buffer',
      );
      expect(receiver.current()).toEqual(before);
    }
  });

  test('merge bounds change count and bytes before Automerge parsing', async () => {
    const acl = new AutomergeACL();
    const before = acl.current();

    expect(() =>
      acl.merge(
        new Array(MAX_AUTOMERGE_ACL_CHANGES + 2) as BinaryChange[],
      ),
    ).toThrow(/change limit/);
    expect(() =>
      acl.merge([
        new Uint8Array(MAX_AUTOMERGE_ACL_CHANGE_BYTES + 1) as BinaryChange,
      ]),
    ).toThrow(/invalid length/);
    expect(() =>
      acl.merge([
        ...Array.from(
          {
            length:
              MAX_AUTOMERGE_ACL_HISTORY_BYTES /
              MAX_AUTOMERGE_ACL_CHANGE_BYTES,
          },
          () =>
            new Uint8Array(
              MAX_AUTOMERGE_ACL_CHANGE_BYTES,
            ) as BinaryChange,
        ),
        new Uint8Array(1) as BinaryChange,
      ]),
    ).toThrow(/aggregate limit/);
    const operationBombBase = automergeInit<{ padding?: number[] }>();
    const operationBomb = automergeChange(operationBombBase, (doc) => {
      doc.padding = [];
      for (let index = 0; index <= MAX_AUTOMERGE_ACL_OPERATIONS; index++) {
        doc.padding.push(index);
      }
    });
    const operationBombChanges = getAutomergeChanges(
      operationBombBase,
      operationBomb,
    );
    expect(operationBombChanges).toHaveLength(1);
    expect(operationBombChanges[0]!.byteLength).toBeLessThan(
      MAX_AUTOMERGE_ACL_CHANGE_BYTES,
    );
    expect(
      decodeAutomergeChange(operationBombChanges[0]!).ops.length,
    ).toBeGreaterThan(MAX_AUTOMERGE_ACL_OPERATIONS);
    expect(() => acl.merge(operationBombChanges)).toThrow(/operation limit/);

    expect(acl.current()).toEqual(before);
  });

  test('merge rejects retained Automerge ACL history growth atomically', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    let padding = automergeInit<Record<string, Uint8Array>>();
    const chunks: BinaryChange[][] = [];
    for (let index = 0; index < 5; index++) {
      const previous = padding;
      padding = automergeChange(padding, (doc) => {
        doc[`padding-${index}`] = new Uint8Array(900_000).fill(index + 1);
      });
      const chunk = getAutomergeChanges(previous, padding);
      expect(chunk).toHaveLength(1);
      expect(chunk[0]!.byteLength).toBeLessThanOrEqual(
        MAX_AUTOMERGE_ACL_CHANGE_BYTES,
      );
      chunks.push(chunk);
    }

    for (const chunk of chunks.slice(0, 4)) {
      expect(() => acl.merge(chunk)).not.toThrow();
    }
    const before = acl.current();
    expect(
      before.reduce((total, change) => total + change.byteLength, 0),
    ).toBeLessThanOrEqual(MAX_AUTOMERGE_ACL_HISTORY_BYTES);

    expect(() => acl.merge(chunks[4]!)).toThrow(/history exceeds.*byte limit/);
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
  });

  test('rejects conflicting independent ACL roots without changing membership', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const before = acl.current();
    const serialized = await serializeKey(key2);
    const independent = automergeChange(
      automergeInit<AutomergeACLShape>({
        actor: 'ffffffffffffffffffffffffffffffff',
      }),
      (doc) => {
        doc.users = { [serialized]: true };
      },
    );
    const independentChanges = getAllAutomergeChanges(independent);

    expect(() => acl.merge(independentChanges)).toThrow(
      /conflicting users roots/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
    expect(await acl.check(key2)).toBe(false);

    const fresh = new AutomergeACL();
    expect(() => fresh.merge(independentChanges)).not.toThrow();
    expect(await fresh.check(key2)).toBe(true);
  });

  test('rejects a concurrent membership assignment and deletion atomically', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const before = acl.current();
    const serialized = await serializeKey(key1);
    const deleteBase = automergeInit<AutomergeACLShape>({
      actor: 'ffffffffffffffffffffffffffffffff',
    });
    const assignBase = automergeInit<AutomergeACLShape>({
      actor: '11111111111111111111111111111111',
    });
    const [deleteDocument] = applyAutomergeChanges(deleteBase, before);
    const [assignDocument] = applyAutomergeChanges(assignBase, before);
    const deletion = automergeChange(deleteDocument, (doc) => {
      delete doc.users![serialized];
    });
    const assignment = automergeChange(assignDocument, (doc) => {
      delete doc.users![serialized];
      doc.users![serialized] = true;
    });
    const conflicted = automergeMerge(deletion, assignment);

    expect(() => acl.merge(getAllAutomergeChanges(conflicted))).toThrow(
      /conflicting membership/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
  });

  test('rejects a users-root deletion racing a nested assignment', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const before = acl.current();
    const serialized = await serializeKey(key2);
    const deleteBase = automergeInit<AutomergeACLShape>({
      actor: 'ffffffffffffffffffffffffffffffff',
    });
    const assignBase = automergeInit<AutomergeACLShape>({
      actor: '11111111111111111111111111111111',
    });
    const [deleteDocument] = applyAutomergeChanges(deleteBase, before);
    const [assignDocument] = applyAutomergeChanges(assignBase, before);
    const deletion = automergeChange(deleteDocument, (doc) => {
      delete doc.users;
    });
    const assignment = automergeChange(assignDocument, (doc) => {
      doc.users![serialized] = true;
    });
    const conflicted = automergeMerge(deletion, assignment);
    expect(conflicted.users).toBeUndefined();

    expect(() => acl.merge(getAllAutomergeChanges(conflicted))).toThrow(
      /mutates the users root/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
    expect(await acl.check(key2)).toBe(false);
  });

  test('rejects a malformed serialized membership key atomically', async () => {
    const invalidPoint = new Uint8Array(97);
    invalidPoint[0] = 0x04;
    const invalidSerializedPoint = Buffer.from(invalidPoint).toString('base64');
    let source = automergeInit<AutomergeACLShape>();
    source = automergeChange(source, (doc) => {
      doc.users = { [invalidSerializedPoint]: true };
    });
    const acl = new AutomergeACL();
    const before = acl.current();

    expect(() => acl.merge(getAllAutomergeChanges(source))).toThrow(
      /valid P-384 point/,
    );
    expect(acl.current()).toEqual(before);
    await expect(acl.users()).resolves.toEqual([]);
  });

  test('rejects a tombstoned non-P-384 membership key atomically', async () => {
    const nonP384Point = new Uint8Array(65);
    nonP384Point[0] = 0x04;
    const nonP384Key = Buffer.from(nonP384Point).toString('base64');
    const acl = new AutomergeACL();
    await acl.add(key1);
    const before = acl.current();
    const sourceSeed = automergeInit<AutomergeACLShape>();
    const [sourceBase] = applyAutomergeChanges(sourceSeed, before);
    let source = automergeChange(sourceBase, (doc) => {
      doc.users![nonP384Key] = true;
    });
    source = automergeChange(source, (doc) => {
      delete doc.users![nonP384Key];
    });
    const remoteHistory = getAutomergeChanges(sourceBase, source);
    expect(source.users?.[nonP384Key]).toBeUndefined();

    expect(() => acl.merge(remoteHistory)).toThrow(
      /97-byte uncompressed P-384 point/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
  });

  test('rejects a tombstoned invalid membership value atomically', async () => {
    const serialized = await serializeKey(key2);
    const acl = new AutomergeACL();
    await acl.add(key1);
    const before = acl.current();
    const sourceSeed = automergeInit<{
      users?: Record<string, unknown>;
    }>();
    const [sourceBase] = applyAutomergeChanges(sourceSeed, before);
    let source = automergeChange(sourceBase, (doc) => {
      doc.users![serialized] = false;
    });
    source = automergeChange(source, (doc) => {
      delete doc.users![serialized];
    });
    const remoteHistory = getAutomergeChanges(sourceBase, source);
    expect(source.users?.[serialized]).toBeUndefined();

    expect(() => acl.merge(remoteHistory)).toThrow(
      /membership values must be true/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
  });

  test('rejects a tombstoned structured membership value atomically', async () => {
    const serialized = await serializeKey(key2);
    const acl = new AutomergeACL();
    await acl.add(key1);
    const before = acl.current();
    const sourceSeed = automergeInit<{
      users?: Record<string, unknown>;
    }>();
    const [sourceBase] = applyAutomergeChanges(sourceSeed, before);
    let source = automergeChange(sourceBase, (doc) => {
      doc.users![serialized] = {};
    });
    source = automergeChange(source, (doc) => {
      delete doc.users![serialized];
    });
    const remoteHistory = getAutomergeChanges(sourceBase, source);
    expect(source.users?.[serialized]).toBeUndefined();

    expect(() => acl.merge(remoteHistory)).toThrow(
      /membership values must be true/,
    );
    expect(acl.current()).toEqual(before);
    expect(await acl.check(key1)).toBe(true);
  });

  test('prepareRemove() rejects a commit staled by a remote merge', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const prepared = await acl.prepareRemove(key1);
    const remote = new AutomergeACL();
    remote.merge(acl.current());
    const remoteChanges = await remote.add(key2);

    acl.merge(remoteChanges);

    expect(() => prepared.commit()).toThrow(
      'ACL changed while removal was staged',
    );
    expect(await acl.check(key1)).toBe(true);
    expect(await acl.check(key2)).toBe(true);
  });

  test('prepareRemove() commits private state after returned changes are mutated', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    const prepared = await acl.prepareRemove(key1);

    for (const change of prepared.changes) change.fill(0);
    prepared.changes.length = 0;
    prepared.commit();

    expect(await acl.check(key1)).toBe(false);
  });

  test('remove() is a no-op for a blank ACL', async () => {
    const acl = new AutomergeACL();

    await expect(acl.remove(key1)).resolves.toEqual([]);
    expect(acl.current()).toEqual([]);
  });

  test('staged additions and removals converge after child-before-parent delivery', async () => {
    const additionSender = new AutomergeACL();
    const additionParent = await additionSender.add(key1);
    const additionChild = await additionSender.prepareAdd(key2);
    const additionReceiver = new AutomergeACL();

    additionReceiver.merge(additionChild.changes);
    await expect(additionReceiver.check(key2)).rejects.toThrow(
      /unresolved change dependencies/i,
    );
    additionReceiver.merge(additionParent);
    expect(await additionReceiver.check(key1)).toBe(true);
    expect(await additionReceiver.check(key2)).toBe(true);

    const removalSender = new AutomergeACL();
    const removalParent = await removalSender.add(key1);
    const removalChild = await removalSender.prepareRemove(key1);
    const removalReceiver = new AutomergeACL();

    removalReceiver.merge(removalChild.changes);
    await expect(removalReceiver.check(key1)).rejects.toThrow(
      /unresolved change dependencies/i,
    );
    removalReceiver.merge(removalParent);
    expect(await removalReceiver.check(key1)).toBe(false);
  });

  test('check() returns false for an unknown key', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    expect(await acl.check(key2)).toBe(false);
  });

  test('users() returns all added keys', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    await acl.add(key2);

    const users = await acl.users();
    expect(users).toHaveLength(2);

    // Verify by serializing the returned keys and comparing
    const serialized1 = await serializeKey(key1);
    const serialized2 = await serializeKey(key2);
    const returnedSerialized = await Promise.all(users.map(serializeKey));
    expect(returnedSerialized).toContain(serialized1);
    expect(returnedSerialized).toContain(serialized2);
  });

  test('current() / merge() - export changes and verify merge', async () => {
    const acl1 = new AutomergeACL();
    await acl1.add(key1);
    await acl1.add(key2);

    const exported = acl1.current();
    expect(exported.length).toBeGreaterThan(0);

    // Merge back into the same ACL (self-merge is idempotent)
    acl1.merge(exported);
    expect(await acl1.check(key1)).toBe(true);
    expect(await acl1.check(key2)).toBe(true);
  });

  test('founder changes authorize its signing key in a fresh ACL', async () => {
    const signingPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const founder = new AutomergeACL();
    const founderChanges = await founder.add(signingPair.publicKey);
    const receiver = new AutomergeACL();

    receiver.merge(founderChanges);

    expect(await receiver.check(signingPair.publicKey)).toBe(true);
    const writerKeys = await receiver.users();
    expect(writerKeys).toHaveLength(1);
    const [verifyingKey] = writerKeys;
    const payload = new Uint8Array([9, 8, 7, 6]);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      signingPair.privateKey,
      payload,
    );

    expect(
      await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' },
        verifyingKey,
        signature,
        payload,
      ),
    ).toBe(true);
  });

  test('fresh ACLs start from the same blank history', () => {
    const first = new AutomergeACL();
    const second = new AutomergeACL();

    expect(first.current()).toEqual([]);
    expect(second.current()).toEqual(first.current());
  });

  test('loads a complete ACL history from the legacy random-seed format', async () => {
    const serialized = await serializeKey(key1);
    const legacyBase = automergeFrom<{ users: Record<string, true> }>({
      users: {},
    });
    const legacyWithMember = automergeChange(legacyBase, (doc) => {
      doc.users[serialized] = true;
    });
    const receiver = new AutomergeACL();

    receiver.merge(getAllAutomergeChanges(legacyWithMember));

    expect(await receiver.check(key1)).toBe(true);
    expect(await receiver.users()).toHaveLength(1);
  });

  test('fails closed for a legacy incremental change that omitted its seed', async () => {
    const serialized = await serializeKey(key1);
    const legacyBase = automergeFrom<{ users: Record<string, true> }>({
      users: {},
    });
    const legacyWithMember = automergeChange(legacyBase, (doc) => {
      doc.users[serialized] = true;
    });
    const receiver = new AutomergeACL();

    receiver.merge(getAutomergeChanges(legacyBase, legacyWithMember));

    await expect(receiver.check(key1)).rejects.toThrow(
      /unresolved change dependencies.*complete ACL history/i,
    );
    expect(() => receiver.current()).toThrow(/cannot be migrated safely/i);
  });

  test('allows valid child-before-parent delivery once dependencies arrive', async () => {
    const sender = new AutomergeACL();
    const founderChanges = await sender.add(key1);
    const collaboratorChanges = await sender.add(key2);
    const receiver = new AutomergeACL();

    receiver.merge(collaboratorChanges);
    await expect(receiver.users()).rejects.toThrow(
      /unresolved change dependencies/i,
    );

    receiver.merge(founderChanges);
    expect(await receiver.check(key1)).toBe(true);
    expect(await receiver.check(key2)).toBe(true);
  });

  test('a new dependency-incomplete change still stales prepared removal', async () => {
    const receiver = new AutomergeACL();
    await receiver.add(key1);
    const prepared = await receiver.prepareRemove(key1);
    const sender = new AutomergeACL();
    await sender.add(key2);
    const dependent = await sender.add(key1);

    receiver.merge(dependent);

    expect(() => prepared.commit()).toThrow(
      'ACL changed while removal was staged',
    );
    expect(() => receiver.current()).toThrow(
      /unresolved change dependencies/,
    );
  });

  test('does not authorize across a merge that introduces missing dependencies', async () => {
    const receiver = new AutomergeACL();
    await receiver.add(key1);
    const sender = new AutomergeACL();
    await sender.add(key2);
    const dependentChanges = await sender.add(key1);
    let exportStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      exportStarted = resolve;
    });
    let releaseExport!: () => void;
    const release = new Promise<void>((resolve) => {
      releaseExport = resolve;
    });
    const originalExportKey = crypto.subtle.exportKey.bind(crypto.subtle);
    const exportSpy = jest
      .spyOn(crypto.subtle, 'exportKey')
      .mockImplementationOnce(async (format, key) => {
        exportStarted();
        await release;
        return originalExportKey(format, key);
      });

    try {
      const authorization = receiver.check(key1);
      await started;
      receiver.merge(dependentChanges);
      releaseExport();

      await expect(authorization).rejects.toThrow(
        /unresolved change dependencies/,
      );
    } finally {
      exportSpy.mockRestore();
    }
  });
});

describe('AutomergeACLProvider', () => {
  test('initialize() returns a new AutomergeACL', () => {
    const provider = new AutomergeACLProvider();
    const acl = provider.initialize();
    expect(acl).toBeInstanceOf(AutomergeACL);
  });
});

// ─── AutomergeKeychain ──────────────────────────────────────────────

type TestKeychainDoc = {
  keys: [string, string][];
  unrelated?: string;
};

function newTestKeychainDoc() {
  const seeded = automergeChange(
    automergeInit<TestKeychainDoc>(
      'ababababababababababababababababababababab',
    ),
    { time: 0 },
    (doc) => {
      doc.keys = [];
    },
  );
  return automergeClone(seeded);
}

function appendTestKeychainEntry(
  doc: ReturnType<typeof newTestKeychainDoc>,
  entry: [string, string],
) {
  return automergeChange(doc, (next) => {
    next.keys.push(entry);
  });
}

const KEYCHAIN_COMMITMENT_GOLDENS = [
  'afa90588687d49cacdf36100e04468733207c5544dabe98108d6b572a2fa4d1f',
  'bd87e8f14d8d98a4862512d74e47b1406b7f57773dc1f619551b7f47c49ce50f',
  '52fba32ca5e4a5f95c53a5dd845a138e0f9e6b79cf4071131a5c581839255ce6',
] as const;

const commitmentHex = (commitment: Uint8Array): string =>
  Array.from(commitment, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );

describe('AutomergeKeychain', () => {
  test('state commitment matches the cross-adapter golden vectors', async () => {
    const keychain = new AutomergeKeychain();
    expect(commitmentHex(await keychain.stateCommitment())).toBe(
      KEYCHAIN_COMMITMENT_GOLDENS[0],
    );
    const entries = [
      [0x11, 0xaa],
      [0x22, 0xbb],
    ] as const;
    for (let index = 0; index < entries.length; index++) {
      const [idFill, keyFill] = entries[index];
      const id = new Uint8Array(32).fill(idFill);
      const key = await crypto.subtle.importKey(
        'raw',
        new Uint8Array(32).fill(keyFill),
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      );
      await keychain.addEpochKey(id, key);
      expect(commitmentHex(await keychain.stateCommitment())).toBe(
        KEYCHAIN_COMMITMENT_GOLDENS[index + 1],
      );
    }
  });

  test('add() returns [keyIDBytes, CryptoKey, changes]', async () => {
    const keychain = new AutomergeKeychain();
    const [keyIDBytes, key, changes] = await keychain.add();

    expect(keyIDBytes).toBeInstanceOf(Uint8Array);
    // 32 bytes -- matches `keyIDLength` and the BeeKEM-derived epoch
    // ID width from `deriveEpochIdFromRootSecret`. A single fixed
    // width across both provisioning paths means the wire-format
    // key-ID prefix never needs to be truncated.
    expect(keyIDBytes.length).toBe(32);
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(changes.length).toBeGreaterThan(0);
  });

  test('prepareKey() stages a bounded random key without live mutation', async () => {
    const keychain = new AutomergeKeychain();
    const before = keychain.history();
    const prepared = await keychain.prepareKey();
    const stableId = new Uint8Array(prepared.keyId);
    expect(stableId).toHaveLength(32);
    expect(prepared.key.algorithm).toMatchObject({
      name: 'AES-GCM',
      length: 256,
    });
    expect(keychain.history()).toEqual(before);
    expect(await keychain.keys()).toHaveLength(0);

    const independent = new AutomergeKeychain();
    await independent.addEpochKey(stableId, prepared.key);
    independent.merge(prepared.currentKeyChange!);
    expect((await independent.keys()).map(([id]) => id)).toEqual([stableId]);

    prepared.keyId.fill(0xff);
    prepared.commit();
    expect((await keychain.current())[0]).toEqual(stableId);
    expect(keychain.getKey(stableId)).toBe(prepared.key);
    expect(() => prepared.commit()).toThrow(
      'Prepared epoch key was already committed',
    );
  });

  test('prepareKey() commit rejects a stale live base', async () => {
    const keychain = new AutomergeKeychain();
    const prepared = await keychain.prepareKey();
    await keychain.add();

    expect(() => prepared.commit()).toThrow(
      'Keychain changed while epoch key was staged',
    );
    expect(await keychain.keys()).toHaveLength(1);
  });

  test('keys() returns all added keys', async () => {
    const keychain = new AutomergeKeychain();
    await keychain.add();
    await keychain.add();

    const keys = await keychain.keys();
    expect(keys).toHaveLength(2);
    for (const [idBytes, key] of keys) {
      expect(idBytes).toBeInstanceOf(Uint8Array);
      expect(idBytes.length).toBe(32);
      expect(key).toBeDefined();
    }
  });

  test('history() / merge() - export changes and merge into a fresh keychain', async () => {
    const kc1 = new AutomergeKeychain();
    const [id1] = await kc1.add();
    const [id2] = await kc1.add();

    const exported = kc1.history();
    expect(exported.length).toBeGreaterThan(0);

    // Every AutomergeKeychain seeds its empty `keys: []` array under a
    // shared deterministic actor (KEYCHAIN_SEED_ACTOR) and then clones to
    // a per-instance random actor for subsequent writes. That makes the
    // initial empty-array op identical across instances, so full-history
    // merge into a fresh keychain is deterministic and preserves entries.
    const kc2 = new AutomergeKeychain();
    kc2.merge(exported);
    const ids = (await kc2.keys()).map(([id]) => Array.from(id));
    expect(ids).toContainEqual(Array.from(id1));
    expect(ids).toContainEqual(Array.from(id2));
  });

  test('prepareMerge detaches caller changes and commits independently of returned buffers', async () => {
    const source = new AutomergeKeychain();
    const [keyId] = await source.add();
    const callerChanges = source.history().map(
      (change) => new Uint8Array(change),
    );
    const receiver = new AutomergeKeychain();
    const prepared = receiver.prepareMerge(callerChanges);

    expect(prepared.changes).not.toBe(callerChanges);
    expect(prepared.changes[0]).not.toBe(callerChanges[0]);
    const stagedFirstByte = prepared.changes[0][0];
    callerChanges[0].fill(stagedFirstByte ^ 0xff);
    callerChanges.length = 0;
    expect(prepared.changes.length).toBeGreaterThan(0);
    expect(prepared.changes[0][0]).toBe(stagedFirstByte);

    prepared.changes[0].fill(stagedFirstByte ^ 0xff);
    prepared.changes.length = 0;
    prepared.commit();
    expect((await receiver.keys()).map(([id]) => Array.from(id))).toContainEqual(
      Array.from(keyId),
    );
  });

  test('seed history is deterministic across creation times', () => {
    const now = jest.spyOn(Date, 'now');
    try {
      now.mockReturnValue(1_000);
      const source = new AutomergeKeychain();

      now.mockReturnValue(3_000);
      const receiver = new AutomergeKeychain();

      const sourceHistory = source.history();
      const receiverHistory = receiver.history();
      expect(sourceHistory.length).toBeGreaterThan(0);
      expect(receiverHistory).toEqual(sourceHistory);
      expect(() => receiver.merge(sourceHistory)).not.toThrow();
    } finally {
      now.mockRestore();
    }
  });

  test('getKey() retrieves a cached key by ID', async () => {
    const keychain = new AutomergeKeychain();
    const [keyIDBytes, originalKey] = await keychain.add();

    const retrieved = keychain.getKey(keyIDBytes);
    expect(retrieved).toBeDefined();
    expect(retrieved).toBe(originalKey); // Same reference from cache
  });

  test('getKey() returns undefined for unknown ID', () => {
    const keychain = new AutomergeKeychain();
    const unknownID = new Uint8Array(32);
    unknownID.fill(0xff);
    const result = keychain.getKey(unknownID);
    expect(result).toBeUndefined();
  });

  test('currentKeyChange() reuses replay-safe history for a one-key keychain', async () => {
    const source = new AutomergeKeychain();
    const [id] = await source.add();

    const first = await source.currentKeyChange();
    const repeated = await source.currentKeyChange();
    expect(repeated).toEqual(first);
    const restored = new AutomergeKeychain();
    restored.merge(source.history());
    expect(await restored.currentKeyChange()).toEqual(first);

    const receiver = new AutomergeKeychain();
    receiver.merge(first);
    receiver.merge(repeated);
    expect(await receiver.currentKeyChange()).toEqual(first);
    expect((await receiver.keys()).map(([keyID]) => keyID)).toEqual([id]);
  });

  test('currentKeyChange() rejects a later key rather than synthesizing a fresh actor', async () => {
    const source = new AutomergeKeychain();
    await source.add();
    await source.add();
    const before = source.history().map((entry) => Array.from(entry));

    await expect(source.currentKeyChange()).rejects.toThrow(
      'Automerge cannot export the current key replay-safely',
    );
    expect(source.history().map((entry) => Array.from(entry))).toEqual(before);
  });

  test('historySince() reuses replay-safe history at the first key', async () => {
    const source = new AutomergeKeychain();
    const [id1] = await source.add();
    const [id2] = await source.add();
    const [id3] = await source.add();

    const first = await source.historySince(id1);
    const repeated = await source.historySince(id1);
    expect(repeated).toEqual(first);
    const restored = new AutomergeKeychain();
    restored.merge(source.history());
    const restoredHistory = await restored.historySince(id1);
    expect(restoredHistory).toEqual(first);

    const receiver = new AutomergeKeychain();
    receiver.merge(first);
    receiver.merge(repeated);
    receiver.merge(restoredHistory);
    const keys = await receiver.keys();
    expect(keys).toHaveLength(3);
    const ids = keys.map(([id]) => Array.from(id));
    expect(ids).toContainEqual(Array.from(id1));
    expect(ids).toContainEqual(Array.from(id2));
    expect(ids).toContainEqual(Array.from(id3));
  });

  test('historySince() repeatedly rejects an unknown boundary without mutation', async () => {
    const source = new AutomergeKeychain();
    await source.add();
    await source.add();
    const before = source.history().map((entry) => Array.from(entry));

    const unknownID = new Uint8Array(32).fill(0xff);
    await expect(source.historySince(unknownID)).rejects.toThrow(
      'Unknown keychain history boundary',
    );
    await expect(source.historySince(unknownID)).rejects.toThrow(
      'Unknown keychain history boundary',
    );
    expect(source.history().map((entry) => Array.from(entry))).toEqual(before);
  });

  test('historySince() rejects a later boundary rather than synthesizing fresh actors', async () => {
    const source = new AutomergeKeychain();
    await source.add();
    const [laterID] = await source.add();

    await expect(source.historySince(laterID)).rejects.toThrow(
      'Automerge cannot export this keychain suffix replay-safely',
    );
  });

  test('addEpochKey() rejects a duplicate ID without poisoning its cache', async () => {
    const source = new AutomergeKeychain();
    const [id, key] = await source.add();
    const replacement = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    await expect(source.addEpochKey(id, replacement)).rejects.toThrow(
      'Duplicate keychain key ID',
    );
    expect(source.getKey(id)).toBe(key);
    expect(await source.keys()).toHaveLength(1);
  });

  // ───────────────────────────────────────────────────────────────────
  // BeeKEM PathUpdateV2 compatibility: the flow installs
  // epoch keys via addEpochKey(...) using the FULL 32-byte HKDF output
  // (no truncation). The keychain MUST store the key under a cache-key
  // form that round-trips with getKey() on the exact same 32 bytes.
  // Earlier revisions stored 32-byte epoch IDs under hex but, for
  // 16-byte inputs (the result of truncating to the old `keyIDLength`),
  // looked up under UUID format -- a deterministic cache miss on every
  // post-rotation lookup. These tests pin the round-trip behaviour.
  // ───────────────────────────────────────────────────────────────────

  test('addEpochKey() round-trips through getKey() for a 32-byte epoch ID', async () => {
    const keychain = new AutomergeKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    await keychain.addEpochKey(epochId, key);

    // The exact 32-byte ID that went in must come back out of getKey.
    // A failure here means the epoch ID bytes did not round-trip through
    // the hexadecimal cache-key encoding.
    const retrieved = keychain.getKey(epochId);
    expect(retrieved).toBe(key);

    // current() must report the same 32-byte ID (and key) so
    // `_makeChange` writes the correct wire-format key-ID prefix.
    const [currentID, currentKey] = await keychain.current();
    expect(currentID.length).toBe(32);
    expect(Array.from(currentID)).toEqual(Array.from(epochId));
    expect(currentKey).toBe(key);
  });

  test.each([31, 33])(
    'prepareEpochKey() rejects a %i-byte epoch ID without mutating state',
    async (byteLength) => {
      const keychain = new AutomergeKeychain();
      const historyBefore = keychain
        .history()
        .map((binaryChange) => new Uint8Array(binaryChange));
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      );

      await expect(
        keychain.prepareEpochKey(new Uint8Array(byteLength), key),
      ).rejects.toThrow('Epoch ID has an invalid length or backing buffer');
      expect(keychain.history()).toEqual(historyBefore);
      expect(await keychain.keys()).toHaveLength(0);
    },
  );

  test('addEpochKey() rejects non-AES document keys without mutation', async () => {
    const keychain = new AutomergeKeychain();
    const before = keychain.history();
    const hmacKey = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign', 'verify'],
    );

    await expect(
      keychain.addEpochKey(new Uint8Array(32).fill(3), hmacKey),
    ).rejects.toThrow('Document key must be a 256-bit AES-GCM key');
    expect(keychain.history()).toEqual(before);
    expect(await keychain.keys()).toHaveLength(0);
  });

  test.each([31, 33])(
    'addEpochKey() rejects a %i-byte epoch ID without mutating state',
    async (byteLength) => {
      const keychain = new AutomergeKeychain();
      const historyBefore = keychain
        .history()
        .map((binaryChange) => new Uint8Array(binaryChange));
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      );

      await expect(
        keychain.addEpochKey(new Uint8Array(byteLength), key),
      ).rejects.toThrow('Epoch ID has an invalid length or backing buffer');
      expect(keychain.history()).toEqual(historyBefore);
      expect(await keychain.keys()).toHaveLength(0);
    },
  );

  test('prepareEpochKey() accepts cross-realm bytes and snapshots them before awaiting', async () => {
    const keychain = new AutomergeKeychain();
    const epochId = runInNewContext(
      'new Uint8Array(32).fill(7)',
    ) as Uint8Array;
    const expectedEpochId = new Uint8Array(32).fill(7);
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    expect(epochId).not.toBeInstanceOf(Uint8Array);
    const preparing = keychain.prepareEpochKey(epochId, key);
    epochId.fill(9);
    const prepared = await preparing;
    prepared.commit();

    const [currentId, currentKey] = await keychain.current();
    expect(currentId).toEqual(expectedEpochId);
    expect(currentKey).toBe(key);
    expect(keychain.getKey(expectedEpochId)).toBe(key);
  });

  test('legacy keychain commit uses its captured claim method', async () => {
    const keychain = new AutomergeKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const prepared = await keychain.prepareEpochKey(epochId, key);
    Object.defineProperty(prepared, 'claimCommit', {
      get: () => {
        throw new Error('replaceable keychain claim was read');
      },
    });

    expect(() => prepared.commit()).not.toThrow();
    expect(keychain.getKey(epochId)).toBe(key);
    expect((await keychain.current())[0]).toEqual(epochId);
  });

  test('prepareEpochKey() claim keeps history and cache hidden until constant-time finalize', async () => {
    const keychain = new AutomergeKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const historyBefore = keychain.history();
    const prepared = await keychain.prepareEpochKey(epochId, key);

    const claim = prepared.claimCommit!();
    expect(keychain.history()).toEqual(historyBefore);
    expect(keychain.getKey(epochId)).toBeUndefined();
    expect(() => prepared.claimCommit!()).toThrow(/already committed or claimed/);
    expect(() => prepared.commit()).toThrow(/already committed or claimed/);

    const cache = (
      keychain as unknown as {
        _keyCache: { set(key: string, value: CryptoKey): void };
      }
    )._keyCache;
    const set = jest.spyOn(cache, 'set').mockImplementation(() => {
      throw new Error('Live cache insertion must not run during finalization');
    });
    try {
      expect(() => claim.finalize()).not.toThrow();
      expect(() => claim.finalize()).not.toThrow();
      expect(set).not.toHaveBeenCalled();
    } finally {
      set.mockRestore();
    }

    expect((await keychain.keys()).map(([id]) => id)).toEqual([epochId]);
    expect(keychain.getKey(epochId)).toBe(key);
  });

  test('an abandoned epoch claim permits same-ID restaging without exposing its key', async () => {
    const keychain = new AutomergeKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const abandonedKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const committedKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const abandoned = await keychain.prepareEpochKey(epochId, abandonedKey);

    abandoned.claimCommit!();
    expect(keychain.getKey(epochId)).toBeUndefined();
    const retry = await keychain.prepareEpochKey(epochId, committedKey);
    retry.claimCommit!().finalize();

    expect((await keychain.keys()).map(([id]) => id)).toEqual([epochId]);
    expect(keychain.getKey(epochId)).toBe(committedKey);
    expect(keychain.getKey(epochId)).not.toBe(abandonedKey);
  });

  test('epoch claims reject revision-changing merge commits and retain intervening hydration', async () => {
    const source = new AutomergeKeychain();
    const baseEpochId = crypto.getRandomValues(new Uint8Array(32));
    const baseKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    await source.addEpochKey(baseEpochId, baseKey);
    const receiver = new AutomergeKeychain();
    receiver.merge(source.history());

    const stagedEpochId = crypto.getRandomValues(new Uint8Array(32));
    const stagedKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const claimed = await receiver.prepareEpochKey(stagedEpochId, stagedKey);
    const claim = claimed.claimCommit!();
    const [, hydratedBaseKey] = await receiver.current();

    claim.finalize();
    expect(receiver.getKey(baseEpochId)).toBe(hydratedBaseKey);
    expect(receiver.getKey(stagedEpochId)).toBe(stagedKey);

    const staleEpochId = crypto.getRandomValues(new Uint8Array(32));
    const staleKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const stale = await receiver.prepareEpochKey(staleEpochId, staleKey);
    const remote = new AutomergeKeychain();
    remote.merge(receiver.history());
    await remote.add();
    receiver.prepareMerge(remote.history()).commit();

    expect(() => stale.claimCommit!()).toThrow(
      'Keychain changed while epoch key was staged',
    );
    expect(receiver.getKey(staleEpochId)).toBeUndefined();
  });

  test('epoch claims reject a revision-changing direct merge', async () => {
    const receiver = new AutomergeKeychain();
    await receiver.add();
    const stagedEpochId = crypto.getRandomValues(new Uint8Array(32));
    const stagedKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const staged = await receiver.prepareEpochKey(stagedEpochId, stagedKey);
    const remote = new AutomergeKeychain();
    remote.merge(receiver.history());
    await remote.add();

    receiver.merge(remote.history());

    expect(() => staged.claimCommit!()).toThrow(
      'Keychain changed while epoch key was staged',
    );
    expect(receiver.getKey(stagedEpochId)).toBeUndefined();
  });

  test('epoch claim finalization leaves unrelated historical keys uncached', async () => {
    const source = new AutomergeKeychain();
    const [historicalEpochId] = await source.add();
    const receiver = new AutomergeKeychain();
    receiver.merge(source.history());
    const stagedEpochId = crypto.getRandomValues(new Uint8Array(32));
    const stagedKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const staged = await receiver.prepareEpochKey(stagedEpochId, stagedKey);

    staged.claimCommit!().finalize();

    expect(receiver.getKey(historicalEpochId)).toBeUndefined();
    expect(receiver.getKey(stagedEpochId)).toBe(stagedKey);
  });

  test.each([
    ['another typed-array kind', new Uint16Array(16)],
    [
      'a Uint8Array lookalike',
      {
        byteLength: 32,
        length: 32,
        [Symbol.toStringTag]: 'Uint8Array',
      },
    ],
  ])('prepareEpochKey() rejects %s', async (_label, epochId) => {
    const keychain = new AutomergeKeychain();
    const historyBefore = keychain
      .history()
      .map((binaryChange) => new Uint8Array(binaryChange));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    await expect(
      keychain.prepareEpochKey(epochId as unknown as Uint8Array, key),
    ).rejects.toThrow(/Epoch ID/);
    expect(keychain.history()).toEqual(historyBefore);
    expect(await keychain.keys()).toHaveLength(0);
  });

  test('prepareEpochKey() rejects SharedArrayBuffer-backed bytes', async () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    const keychain = new AutomergeKeychain();
    const historyBefore = keychain
      .history()
      .map((binaryChange) => new Uint8Array(binaryChange));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    await expect(
      keychain.prepareEpochKey(
        new Uint8Array(new SharedArrayBuffer(32)),
        key,
      ),
    ).rejects.toThrow('Epoch ID has an invalid length or backing buffer');
    expect(keychain.history()).toEqual(historyBefore);
    expect(await keychain.keys()).toHaveLength(0);
  });

  test('prepareEpochKey() exposes an exact replay-safe current projection', async () => {
    const keychain = new AutomergeKeychain();
    const firstId = crypto.getRandomValues(new Uint8Array(32));
    const firstKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const first = await keychain.prepareEpochKey(firstId, firstKey);
    expect(first.currentKeyChange).toBeDefined();
    const receiver = new AutomergeKeychain();
    receiver.merge(first.currentKeyChange!);
    receiver.merge(first.currentKeyChange!);
    expect((await receiver.keys()).map(([id]) => id)).toEqual([firstId]);
    first.commit();

    const nextKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const nextId = crypto.getRandomValues(new Uint8Array(32));
    const next = await keychain.prepareEpochKey(nextId, nextKey);
    expect(next.currentKeyChange).toBeDefined();
    const narrowReceiver = new AutomergeKeychain();
    narrowReceiver.merge(next.currentKeyChange!);
    narrowReceiver.merge(next.currentKeyChange!);
    expect((await narrowReceiver.keys()).map(([id]) => id)).toEqual([nextId]);
  });

  test('prepareMerge() rejects non-canonical entries before live state or cache mutation', async () => {
    const validKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const serialized = await serializeKey(validKey);
    const invalidEntries: unknown[] = [
      ['aa'.repeat(16), serialized],
      ['AB'.repeat(32), serialized],
      ['ab'.repeat(32), 'not-a-key'],
      ['ab'.repeat(32), `${'A'.repeat(42)}B=`],
      ['ab'.repeat(32), serialized, 'extra'],
      ['ab'.repeat(32), 7],
    ];

    for (const entry of invalidEntries) {
      const malformed = appendTestKeychainEntry(
        newTestKeychainDoc(),
        entry as [string, string],
      );
      const receiver = new AutomergeKeychain();
      expect(() =>
        receiver.prepareMerge(getAllAutomergeChanges(malformed)),
      ).toThrow(/Invalid (keychain entry|serialized keychain key)/);
      expect(await receiver.keys()).toHaveLength(0);
      expect(receiver.getKey(new Uint8Array(32))).toBeUndefined();
    }
  });

  test('prepareMerge() rejects duplicate IDs before they can poison cached key material', async () => {
    const firstKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const secondKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const id = new Uint8Array(32).fill(5);
    const idHex = Array.from(id, (byte) =>
      byte.toString(16).padStart(2, '0'),
    ).join('');
    let duplicate = appendTestKeychainEntry(newTestKeychainDoc(), [
      idHex,
      await serializeKey(firstKey),
    ]);
    duplicate = appendTestKeychainEntry(duplicate, [
      idHex,
      await serializeKey(secondKey),
    ]);
    const receiver = new AutomergeKeychain();

    expect(() =>
      receiver.prepareMerge(getAllAutomergeChanges(duplicate)),
    ).toThrow('Duplicate keychain key ID');
    expect(await receiver.keys()).toHaveLength(0);
    expect(receiver.getKey(id)).toBeUndefined();
  });

  test('prepareMerge() rejects delete, rewrite, reorder, and unrelated operations', async () => {
    const firstKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const secondKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const firstEntry: [string, string] = [
      '11'.repeat(32),
      await serializeKey(firstKey),
    ];
    const secondEntry: [string, string] = [
      '22'.repeat(32),
      await serializeKey(secondKey),
    ];
    const firstDoc = appendTestKeychainEntry(newTestKeychainDoc(), firstEntry);
    const twoKeyDoc = appendTestKeychainEntry(firstDoc, secondEntry);

    const deleted = automergeChange(twoKeyDoc, (doc) => {
      doc.keys.splice(0, 1);
    });
    expect(() =>
      new AutomergeKeychain().prepareMerge(getAllAutomergeChanges(deleted)),
    ).toThrow(/non-append|unrelated metadata or operations/);

    const rewritten = automergeChange(automergeClone(firstDoc), (doc) => {
      doc.keys[0][1] = secondEntry[1];
    });
    expect(() =>
      new AutomergeKeychain().prepareMerge(getAllAutomergeChanges(rewritten)),
    ).toThrow(/non-append|rewrite|unrelated metadata or operations/);

    const reorderBase = appendTestKeychainEntry(
      newTestKeychainDoc(),
      firstEntry,
    );
    const receiver = new AutomergeKeychain();
    receiver.merge(getAllAutomergeChanges(reorderBase));
    const reordered = automergeChange(automergeClone(reorderBase), (doc) => {
      doc.keys.splice(0, 0, secondEntry);
    });
    expect(() =>
      receiver.prepareMerge(getAutomergeChanges(reorderBase, reordered)),
    ).toThrow(/non-append|append without rewriting entries/);

    const unrelatedBase = appendTestKeychainEntry(
      newTestKeychainDoc(),
      firstEntry,
    );
    const unrelated = automergeChange(automergeClone(unrelatedBase), (doc) => {
      doc.unrelated = 'not keychain state';
    });
    expect(() =>
      new AutomergeKeychain().prepareMerge(getAllAutomergeChanges(unrelated)),
    ).toThrow(/Invalid Automerge keychain document|unrelated operation/);

    const metadata = automergeChange(
      newTestKeychainDoc(),
      'unrelated retained metadata',
      (doc) => {
        doc.keys.push(firstEntry);
      },
    );
    expect(() =>
      new AutomergeKeychain().prepareMerge(getAllAutomergeChanges(metadata)),
    ).toThrow('Keychain history contains unrelated metadata');

    const concurrent = automergeMerge(
      appendTestKeychainEntry(newTestKeychainDoc(), firstEntry),
      appendTestKeychainEntry(newTestKeychainDoc(), secondEntry),
    );
    expect(() =>
      new AutomergeKeychain().prepareMerge(
        getAllAutomergeChanges(concurrent),
      ),
    ).toThrow('Keychain history is not a linear append sequence');
  });

  test('history projections reject tombstoned historical key material', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const serialized = await serializeKey(key);
    let tombstoned = appendTestKeychainEntry(newTestKeychainDoc(), [
      '11'.repeat(32),
      serialized,
    ]);
    tombstoned = automergeChange(tombstoned, (doc) => {
      doc.keys.splice(0, 1);
    });
    tombstoned = appendTestKeychainEntry(tombstoned, [
      '22'.repeat(32),
      serialized,
    ]);
    const compromised = new AutomergeKeychain();
    Object.defineProperty(compromised, '_keychain', {
      value: tombstoned,
      writable: true,
    });

    expect(() => compromised.history()).toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(compromised.stateCommitment()).rejects.toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(compromised.keys()).rejects.toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(compromised.current()).rejects.toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(compromised.currentKeyChange()).rejects.toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(
      compromised.historySince(new Uint8Array(32).fill(0x22)),
    ).rejects.toThrow(/non-append|unrelated metadata or operations/);
  });

  test('prepareMerge() hydrates detached staged keys and transfers them only on commit', async () => {
    const source = new AutomergeKeychain();
    const [firstId] = await source.add();
    const [currentId] = await source.add();
    const receiver = new AutomergeKeychain();
    const prepared = receiver.prepareMerge(source.history());

    expect(prepared.currentKeyId).toEqual(currentId);
    prepared.keyIds[0].fill(0xff);
    prepared.currentKeyId!.fill(0xee);
    expect(await prepared.stateCommitment!()).toEqual(
      await source.stateCommitment(),
    );
    const hydrated = await prepared.hydrateKeys();
    expect(hydrated.map(([id]) => id)).toEqual([firstId, currentId]);
    expect(prepared.getKey(firstId)).toBe(hydrated[0][1]);
    expect(prepared.getKey(currentId)).toBe(hydrated[1][1]);
    expect(await receiver.keys()).toHaveLength(0);
    expect(receiver.getKey(currentId)).toBeUndefined();

    const historyBefore = receiver.history();
    const claim = prepared.claimCommit!();
    expect(receiver.history()).toEqual(historyBefore);
    expect(receiver.getKey(firstId)).toBeUndefined();
    expect(receiver.getKey(currentId)).toBeUndefined();
    expect(() => prepared.claimCommit!()).toThrow(
      /already committed or claimed/,
    );
    expect(() => prepared.commit()).toThrow(/already committed or claimed/);
    const cache = (
      receiver as unknown as {
        _keyCache: {
          _setMapEntry(key: string, value: CryptoKey): void;
        };
      }
    )._keyCache;
    const setMapEntry = jest
      .spyOn(cache, '_setMapEntry')
      .mockImplementation(() => {
        throw new Error('Merge finalization must not perform Map work');
      });
    try {
      expect(claim.finalize()).toBeUndefined();
      expect(claim.finalize()).toBeUndefined();
      expect(setMapEntry).not.toHaveBeenCalled();
    } finally {
      setMapEntry.mockRestore();
    }
    expect(receiver.getKey(firstId)).toBe(hydrated[0][1]);
    expect(receiver.getKey(currentId)).toBe(hydrated[1][1]);
    expect((await receiver.current())[0]).toEqual(currentId);
    expect(await receiver.stateCommitment()).toEqual(
      await source.stateCommitment(),
    );
  });

  test('legacy merge commit ignores an accessor replacing the returned claim method', async () => {
    const source = new AutomergeKeychain();
    const [epochId] = await source.add();
    const receiver = new AutomergeKeychain();
    const prepared = receiver.prepareMerge(source.history());
    const hydratedKey = (await prepared.hydrateKeys())[0][1];
    const replacement = jest.fn(() => {
      throw new Error('replaceable merge claim was invoked');
    });
    Object.defineProperty(prepared, 'claimCommit', {
      get: replacement,
    });

    expect(() => prepared.commit()).not.toThrow();

    expect(replacement).not.toHaveBeenCalled();
    expect((await receiver.current())[0]).toEqual(epochId);
    expect(receiver.getKey(epochId)).toBe(hydratedKey);
  });

  test('merge claim rejects in-flight and post-claim hydration', async () => {
    const source = new AutomergeKeychain();
    const [epochId] = await source.add();
    const receiver = new AutomergeKeychain();
    const prepared = receiver.prepareMerge(source.history());
    const firstHydration = prepared.hydrateKeys();
    const concurrentHydration = prepared.hydrateKeys();

    expect(() => prepared.claimCommit!()).toThrow(
      'key hydration is in progress',
    );
    const [first, concurrent] = await Promise.all([
      firstHydration,
      concurrentHydration,
    ]);
    expect(concurrent[0][1]).toBe(first[0][1]);

    const claim = prepared.claimCommit!();
    await expect(prepared.hydrateKeys()).rejects.toThrow(
      /already committed or claimed/,
    );
    claim.finalize();

    expect(receiver.getKey(epochId)).toBe(first[0][1]);
  });

  test('an abandoned merge claim permits replay without exposing its hydrated keys', async () => {
    const source = new AutomergeKeychain();
    const [epochId] = await source.add();
    const receiver = new AutomergeKeychain();
    const abandoned = receiver.prepareMerge(source.history());
    const abandonedKey = (await abandoned.hydrateKeys())[0][1];

    abandoned.claimCommit!();
    expect(receiver.getKey(epochId)).toBeUndefined();
    expect(await receiver.keys()).toHaveLength(0);

    const replay = receiver.prepareMerge(source.history());
    const replayKey = (await replay.hydrateKeys())[0][1];
    replay.claimCommit!().finalize();

    expect(replayKey).not.toBe(abandonedKey);
    expect(receiver.getKey(epochId)).toBe(replayKey);
    expect((await receiver.current())[0]).toEqual(epochId);
  });

  test('merge claim preparation failure leaves staged state retryable', async () => {
    const source = new AutomergeKeychain();
    const [epochId] = await source.add();
    const receiver = new AutomergeKeychain();
    const prepared = receiver.prepareMerge(source.history());
    const hydratedKey = (await prepared.hydrateKeys())[0][1];
    const historyBefore = receiver.history();
    const cache = (
      receiver as unknown as {
        _keyCache: {
          prepareSetMany(entries: ReadonlyMap<string, CryptoKey>): () => void;
        };
      }
    )._keyCache;
    const prepareSetMany = jest
      .spyOn(cache, 'prepareSetMany')
      .mockImplementationOnce(() => {
        throw new Error('cache batch preparation failed');
      });

    expect(() => prepared.claimCommit!()).toThrow(
      'cache batch preparation failed',
    );
    expect(receiver.history()).toEqual(historyBefore);
    expect(receiver.getKey(epochId)).toBeUndefined();

    prepareSetMany.mockRestore();
    prepared.claimCommit!().finalize();
    expect(receiver.getKey(epochId)).toBe(hydratedKey);
  });

  test('merge claims reject replay revision changes and same-revision base replacement', async () => {
    const source = new AutomergeKeychain();
    const [epochId] = await source.add();
    const receiver = new AutomergeKeychain();
    const staleRevision = receiver.prepareMerge(source.history());

    receiver.prepareMerge(receiver.history()).claimCommit!().finalize();

    expect(() => staleRevision.claimCommit!()).toThrow(
      'Keychain changed while merge was staged',
    );

    const replaced = new AutomergeKeychain();
    const staleIdentity = replaced.prepareMerge(source.history());
    await staleIdentity.hydrateKeys();
    const replacementOwner = new AutomergeKeychain();
    const replacement = (
      replacementOwner as unknown as { _keychain: unknown }
    )._keychain;
    Object.defineProperty(replaced, '_keychain', {
      value: replacement,
      writable: true,
    });

    expect(() => staleIdentity.claimCommit!()).toThrow(
      'Keychain changed while merge was staged',
    );
    expect(replaced.getKey(epochId)).toBeUndefined();
  });

  test('prepareMerge() accepts cross-realm bytes and rejects shared backing', async () => {
    const source = new AutomergeKeychain();
    const [id] = await source.add();
    const history = source.history();
    const crossRealm = history.map(
      (binaryChange) =>
        runInNewContext(
          `new Uint8Array([${Array.from(binaryChange).join(',')}])`,
        ) as Uint8Array,
    );
    expect(crossRealm[0]).not.toBeInstanceOf(Uint8Array);
    const receiver = new AutomergeKeychain();
    receiver.prepareMerge(crossRealm).commit();
    expect((await receiver.keys()).map(([keyID]) => keyID)).toEqual([id]);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(
        new SharedArrayBuffer(history[0].byteLength),
      );
      shared.set(history[0]);
      expect(() => new AutomergeKeychain().prepareMerge([shared])).toThrow(
        'Automerge keychain change has an invalid length or backing buffer',
      );
    }
  });

  test('merge coalesces independently authored identical histories and rejects material conflicts', async () => {
    const epochId = new Uint8Array(32).fill(0x44);
    const epochKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const left = new AutomergeKeychain();
    const right = new AutomergeKeychain();
    await left.addEpochKey(epochId, epochKey);
    await right.addEpochKey(epochId, epochKey);
    const originalLeftHistory = left.history();
    const originalRightHistory = right.history();
    expect(originalLeftHistory).not.toEqual(originalRightHistory);
    expect(await left.stateCommitment()).toEqual(
      await right.stateCommitment(),
    );
    left.merge(originalRightHistory);
    right.merge(originalLeftHistory);
    expect(await left.keys()).toHaveLength(1);
    expect(await right.keys()).toHaveLength(1);
    expect(left.history()).toEqual(right.history());
    const nextId = new Uint8Array(32).fill(0x55);
    await right.addEpochKey(nextId, epochKey);

    left.merge(right.history());
    expect((await left.keys()).map(([id]) => id)).toEqual([epochId, nextId]);

    const conflicting = new AutomergeKeychain();
    const conflictingKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    await conflicting.addEpochKey(epochId, conflictingKey);
    expect(() => left.prepareMerge(conflicting.history())).toThrow(
      /Duplicate keychain key ID|append/,
    );
    expect((await left.keys()).map(([id]) => id)).toEqual([epochId, nextId]);
  });

  test('requires full history after independently authored epoch operations diverge', async () => {
    const founder = new AutomergeKeychain();
    await founder.add();
    const sender = new AutomergeKeychain();
    const receiver = new AutomergeKeychain();
    sender.merge(founder.history());
    receiver.merge(founder.history());
    const epochId = new Uint8Array(32).fill(0x66);
    const epochKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    await sender.addEpochKey(epochId, epochKey);
    await receiver.addEpochKey(epochId, epochKey);
    expect(sender.history()).not.toEqual(receiver.history());
    expect(await sender.stateCommitment()).toEqual(
      await receiver.stateCommitment(),
    );
    const [, , incremental] = await sender.add();

    expect(() => receiver.prepareMerge(incremental)).toThrow(
      /unresolved|Invalid Automerge keychain (?:operation history|document)/,
    );
    receiver.merge(sender.history());
    expect(await receiver.keys()).toHaveLength(3);
  });

  test('context-gated standalone append rejects rollback and binds predecessor and new ID', async () => {
    const keyA = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const keyB = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const keyC = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const idA = new Uint8Array(32).fill(0xa1);
    const idB = new Uint8Array(32).fill(0xb2);
    const idC = new Uint8Array(32).fill(0xc3);
    const receiver = new AutomergeKeychain();
    await receiver.addEpochKey(idA, keyA);
    const projectionSource = new AutomergeKeychain();
    const stagedB = await projectionSource.prepareEpochKey(idB, keyB);
    const projectionB = stagedB.currentKeyChange!;

    expect(() => receiver.prepareMerge(projectionB)).toThrow(
      'Standalone keychain history is not an append-only view',
    );
    expect(() =>
      receiver.prepareAppend([projectionB[1]], {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('canonical standalone single-key projection');
    expect(() =>
      receiver.prepareAppend([...projectionB].reverse(), {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('canonical standalone single-key projection');
    expect(() =>
      receiver.prepareAppend([...projectionB, projectionB[1]], {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('canonical standalone single-key projection');
    expect(() =>
      (receiver.prepareMerge as (...args: unknown[]) => unknown)(projectionB, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Standalone keychain history is not an append-only view');
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: idC,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Keychain append predecessor does not match current key');
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idC,
      }),
    ).toThrow('Keychain projection does not match expected new key');
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: new Uint8Array(31),
        expectedNewKeyId: idB,
      }),
    ).toThrow('Key ID has an invalid length or backing buffer');
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: {
          byteLength: 32,
          buffer: new ArrayBuffer(32),
        } as Uint8Array,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Key ID must be a genuine Uint8Array');

    const stale = receiver.prepareAppend(projectionB, {
      expectedPreviousKeyId: idA,
      expectedNewKeyId: idB,
    });
    receiver.prepareMerge(receiver.history()).commit();
    expect(() => stale.commit()).toThrow(
      'Keychain changed while merge was staged',
    );

    const previousIntent = runInNewContext(
      `new Uint8Array(32).fill(${idA[0]})`,
    ) as Uint8Array;
    const newIntent = runInNewContext(
      `new Uint8Array(32).fill(${idB[0]})`,
    ) as Uint8Array;
    expect(previousIntent).not.toBeInstanceOf(Uint8Array);
    expect(newIntent).not.toBeInstanceOf(Uint8Array);
    const valid = receiver.prepareAppend(projectionB, {
      expectedPreviousKeyId: previousIntent,
      expectedNewKeyId: newIntent,
    });
    const appendCommitment = await valid.stateCommitment!();
    previousIntent.fill(0);
    newIntent.fill(0);
    valid.claimCommit!().finalize();
    expect((await receiver.keys()).map(([id]) => id)).toEqual([idA, idB]);
    expect(await receiver.stateCommitment()).toEqual(appendCommitment);

    receiver.prepareMerge(projectionB).commit();
    const replayedCommitment = await receiver.stateCommitment();
    const replay = receiver.prepareAppend(projectionB, {
      expectedPreviousKeyId: idA,
      expectedNewKeyId: idB,
    });
    expect(replay.keyIds).toEqual([idA, idB]);
    expect(replay.currentKeyId).toEqual(idB);
    expect(await replay.stateCommitment!()).toEqual(replayedCommitment);
    replay.commit();
    expect((await receiver.keys()).map(([id]) => id)).toEqual([idA, idB]);

    const conflictingB = await new AutomergeKeychain().prepareEpochKey(
      idB,
      keyC,
    );
    expect(() =>
      receiver.prepareAppend(conflictingB.currentKeyChange!, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Keychain append replay does not match live history');

    const stagedC = await new AutomergeKeychain().prepareEpochKey(idC, keyC);
    receiver
      .prepareAppend(stagedC.currentKeyChange!, {
        expectedPreviousKeyId: idB,
        expectedNewKeyId: idC,
      })
      .commit();
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Keychain append predecessor does not match current key');
    expect((await receiver.current())[0]).toEqual(idC);
  });

  test('enforces the keychain epoch limit before over-limit mutations', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const serialized = await serializeKey(key);
    let source = newTestKeychainDoc();
    for (let index = 0; index < MAX_KEYCHAIN_EPOCHS; index++) {
      source = appendTestKeychainEntry(source, [
        index.toString(16).padStart(64, '0'),
        serialized,
      ]);
    }
    const receiver = new AutomergeKeychain();
    const atLimit = receiver.prepareMerge(getAllAutomergeChanges(source));
    expect(atLimit.keyIds).toHaveLength(MAX_KEYCHAIN_EPOCHS);
    atLimit.commit();
    const before = receiver.history();

    const overflow = appendTestKeychainEntry(automergeClone(source), [
      MAX_KEYCHAIN_EPOCHS.toString(16).padStart(64, '0'),
      serialized,
    ]);
    expect(() =>
      receiver.prepareMerge(getAutomergeChanges(source, overflow)),
    ).toThrow('Keychain exceeds the supported epoch limit');
    await expect(
      receiver.addEpochKey(new Uint8Array(32).fill(0xff), key),
    ).rejects.toThrow('Keychain exceeds the supported epoch limit');
    await expect(receiver.prepareKey()).rejects.toThrow(
      'Keychain exceeds the supported epoch limit',
    );
    const previousId = new Uint8Array(32);
    const overflowId = new Uint8Array(32);
    new DataView(previousId.buffer).setUint32(
      28,
      MAX_KEYCHAIN_EPOCHS - 1,
    );
    new DataView(overflowId.buffer).setUint32(28, MAX_KEYCHAIN_EPOCHS);
    const overflowProjection = await new AutomergeKeychain().prepareEpochKey(
      overflowId,
      key,
    );
    expect(() =>
      receiver.prepareAppend(overflowProjection.currentKeyChange!, {
        expectedPreviousKeyId: previousId,
        expectedNewKeyId: overflowId,
      }),
    ).toThrow('Keychain exceeds the supported epoch limit');
    expect(receiver.history()).toEqual(before);
  });

  test('addEpochKey() output merges into a fresh keychain and getKey() works there too', async () => {
    // Models the surviving-reader case: writer installs the new
    // key via addEpochKey on their local keychain AND propagates
    // the keychain CRDT changes to peers. After a peer merges the
    // change, `getKey()` for the same 32-byte epoch ID must succeed
    // -- this is what unblocks post-rotation decrypt on the
    // surviving-reader side.
    const sender = new AutomergeKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const changes = await sender.addEpochKey(epochId, key);

    const receiver = new AutomergeKeychain();
    receiver.merge(changes);

    // Touch keys() so the deserialized AES-GCM key is imported and
    // cached -- getKey() is a pure cache lookup (see jsdoc).
    const receiverKeys = await receiver.keys();
    expect(receiverKeys).toHaveLength(1);
    expect(Array.from(receiverKeys[0][0])).toEqual(Array.from(epochId));

    const retrieved = receiver.getKey(epochId);
    expect(retrieved).toBeDefined();

    // Same raw key material on both sides: this is the BeeKEM-rotation
    // invariant the test is here to defend.
    const rawSender = new Uint8Array(
      await crypto.subtle.exportKey('raw', key),
    );
    const rawReceiver = new Uint8Array(
      await crypto.subtle.exportKey('raw', retrieved!),
    );
    expect(rawReceiver).toEqual(rawSender);
  });
});

describe('AutomergeKeychainProvider', () => {
  test('initialize() returns a new AutomergeKeychain with keyIDLength=32', () => {
    const provider = new AutomergeKeychainProvider();
    const keychain = provider.initialize();
    expect(keychain).toBeInstanceOf(AutomergeKeychain);
    expect(provider.keyIDLength).toBe(32);
  });
});

// ─── AutomergeJSONSerializer ────────────────────────────────────────

describe('AutomergeJSONSerializer', () => {
  const serializer = new AutomergeJSONSerializer();
  const SHALLOW_HISTORY_NODE_COUNT = 4_096;

  function nestedTree(depth: number): CRDTChangeNode<BinaryChange[]> {
    const root: CRDTChangeNode<BinaryChange[]> = { kind: 'document' };
    let cursor = root;
    for (let index = 1; index < depth; index++) {
      const child: CRDTChangeNode<BinaryChange[]> = { kind: 'document' };
      cursor.children = { [`cid-${index}`]: child };
      cursor = child;
    }
    return root;
  }

  function shallowTree(nodeCount: number): CRDTChangeNode<BinaryChange[]> {
    const root: CRDTChangeNode<BinaryChange[]> = { kind: 'document' };
    const children: Record<string, CRDTChangeNode<BinaryChange[]>> = {};
    for (let index = 1; index < nodeCount; index++) {
      children[`cid-${index}`] = { kind: 'document' };
    }
    root.children = children;
    return root;
  }

  test('preserves nested sync-message signing bytes across the wire', () => {
    const unsignedMessage = {
      documentId: 'signed-doc',
      changeId: 'root-cid',
      changes: {
        kind: 'document' as const,
        change: [new Uint8Array([1, 2, 3])],
        children: {
          'parent-cid': {
            kind: 'writer' as const,
            change: [new Uint8Array([4, 5, 6])],
          },
        },
      },
    };
    const senderSigningBytes = serializer.serializeSyncMessage(unsignedMessage);
    const wire = serializer.serializeSyncMessage({
      ...unsignedMessage,
      signature: 'test-signature',
    });
    const received = serializer.deserializeSyncMessage(wire);
    const { signature: _signature, ...receivedUnsignedMessage } = received;
    const receiverVerificationBytes = serializer.serializeSyncMessage(
      receivedUnsignedMessage,
    );

    expect(receiverVerificationBytes).toEqual(senderSigningBytes);
  });

  test('round-trips the maximum accepted nesting without overflowing JSON serialization', () => {
    const genericSerialize = jest.spyOn(serializer, 'serialize');
    const wire = serializer.serializeSyncMessage({
      documentId: 'maximum-depth',
      changes: nestedTree(MAX_MERKLE_DAG_DEPTH),
    });
    const restored = serializer.deserializeSyncMessage(wire);

    expect(serializer.serializeSyncMessage(restored)).toEqual(wire);
    expect(genericSerialize).not.toHaveBeenCalled();
    genericSerialize.mockRestore();
    expect(() =>
      serializer.serializeSyncMessage({
        documentId: 'over-maximum-depth',
        changes: nestedTree(MAX_MERKLE_DAG_DEPTH + 1),
      }),
    ).toThrow(/maximum depth/);
  });

  test('round-trips 4096 shallow history nodes with stable wire bytes', () => {
    const wire = serializer.serializeSyncMessage({
      documentId: 'wide-history',
      changes: shallowTree(SHALLOW_HISTORY_NODE_COUNT),
    });
    const restored = serializer.deserializeSyncMessage(wire);

    expect(serializer.serializeSyncMessage(restored)).toEqual(wire);
    expect(
      Object.keys(
        restored.changes!.children as Record<
          string,
          CRDTChangeNode<BinaryChange[]>
        >,
      ),
    ).toHaveLength(SHALLOW_HISTORY_NODE_COUNT - 1);
  });

  test('preserves the existing sync-message wire bytes', () => {
    const wire = serializer.serializeSyncMessage({
      documentId: 'wire-compatibility',
      changes: {
        kind: 'document',
        change: [new Uint8Array([1, 2])],
        children: { cid: { kind: 'writer' } },
      },
    });

    expect(new TextDecoder().decode(wire)).toBe(
      '{"documentId":"wire-compatibility","changes":{"kind":"document","change":["AQI="],"children":{"cid":{"kind":"writer"}}}}',
    );
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip with keyID', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    const block = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
      keyID: 'epoch-key-abc-123',
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.keyID).toBe('epoch-key-abc-123');
    expect(deserialized.nonce).toEqual(block.nonce);
    expect(deserialized.changes).toHaveLength(changes.length);
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip with blindIndexTokens', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    const block = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
      blindIndexTokens: { 'field.name': 'hmac-token-abc', 'field.email': 'hmac-token-def' },
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.blindIndexTokens).toEqual({
      'field.name': 'hmac-token-abc',
      'field.email': 'hmac-token-def',
    });
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip with empty blindIndexTokens', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    const block = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
      blindIndexTokens: {},
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.blindIndexTokens).toEqual({});
  });

  test('deserializeChangeBlock sanitizes dangerous keys in blindIndexTokens', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    // Serialize normally first to get valid changes encoding
    const validBlock = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
    };
    const validSerialized = serializer.serializeChangeBlock(validBlock);
    // Parse, inject dangerous blindIndexTokens, re-serialize
    const parsed = JSON.parse(validSerialized);
    parsed.blindIndexTokens = {
      '__proto__': 'evil',
      'constructor': 'evil',
      'prototype': 'evil',
      'safe-key': 'safe-value',
    };
    const malicious = JSON.stringify(parsed);
    const deserialized = serializer.deserializeChangeBlock(malicious);
    expect(deserialized.blindIndexTokens).toEqual({ 'safe-key': 'safe-value' });
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, '__proto__')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, 'constructor')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, 'prototype')).toBe(false);
  });

  test('deserializeChangeBlock without keyID or blindIndexTokens omits them', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    const block = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.keyID).toBeUndefined();
    expect(deserialized.blindIndexTokens).toBeUndefined();
  });

  // Build a sync-message Uint8Array wire payload directly from a JS object,
  // bypassing `serializeSyncMessage`'s type-safety so we can test that
  // `deserializeSyncMessage` rejects every defined-but-malformed shape of
  // `changes` rather than silently passing the falsy value through.
  function buildWire(obj: unknown): Uint8Array {
    return new TextEncoder().encode(JSON.stringify(obj));
  }

  test('deserializeSyncMessage rejects "changes: null" (validation bypass regression)', () => {
    const wire = buildWire({ documentId: 'doc', changes: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got null/,
    );
  });

  test('deserializeSyncMessage rejects "changes: 0"', () => {
    const wire = buildWire({ documentId: 'doc', changes: 0 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got number/,
    );
  });

  test('deserializeSyncMessage rejects "changes: \\"\\"" (empty string)', () => {
    const wire = buildWire({ documentId: 'doc', changes: '' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got string/,
    );
  });

  test('deserializeSyncMessage accepts omitted "changes" field', () => {
    const wire = buildWire({ documentId: 'doc' });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.changes).toBeUndefined();
  });

  test('preserves signed V4 full-load bytes across deserialize and reserialize', () => {
    // Mirror the intended V4 response construction order: signature already
    // has an insertion slot from the cached sync message, while
    // keychainChanges is appended after the V4 challenge.
    const message: any = {
      documentId: '/signed-load',
      changeId: 'ROOT',
      changes: {
        kind: 'document' as const,
        keyID: 'epoch-7',
        change: [new Uint8Array([1])],
        children: {
          PARENT: {
            kind: 'writer' as const,
            change: [new Uint8Array([2])],
          },
        },
      },
      signature: undefined,
    };
    message.tips = ['ROOT'];
    message.loadSecurityState = {
      version: 1 as const,
      controlHead: new Uint8Array(32),
      groupId: 'group',
      epoch: 1n,
      treeHash: new Uint8Array(32),
      confirmedTranscriptHash: new Uint8Array(32),
    };
    message.loadChallenge = new Uint8Array(32);
    message.keychainChanges = [new Uint8Array([3])];

    const { signature: _unsigned, ...signedPayload } = message;
    const expectedSignedBytes = serializer.serializeSyncMessage(signedPayload);
    message.signature = 'signature';
    const decoded = serializer.deserializeSyncMessage(
      serializer.serializeSyncMessage(message),
    );
    const { signature: _received, ...verificationPayload } = decoded;
    const detachedVerificationPayload =
      snapshotDeepEnumerableData(verificationPayload);

    expect(
      serializer.serializeSyncMessage(detachedVerificationPayload),
    ).toEqual(expectedSignedBytes);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves welcomeEpochId for BeeKEM Welcome', () => {
    const epochId = new Uint8Array(32);
    for (let i = 0; i < epochId.length; i++) epochId[i] = (i * 11) & 0xff;
    const message = {
      documentId: 'welcome-doc',
      welcomeEpochId: epochId,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeEpochId).toEqual(epochId);
  });

  test('deserializeSyncMessage omits welcomeEpochId when absent on wire', () => {
    const message = { documentId: 'no-welcome-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeEpochId).toBeUndefined();
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves welcomeRecipient', () => {
    const message = {
      documentId: 'welcome-doc',
      welcomeRecipient: 'recipient-serialized-pubkey-base64',
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeRecipient).toBe(
      'recipient-serialized-pubkey-base64',
    );
  });

  test('deserializeSyncMessage omits welcomeRecipient when absent on wire', () => {
    const message = { documentId: 'no-welcome-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeRecipient).toBeUndefined();
  });

  test('deserializeSyncMessage rejects non-string welcomeRecipient', () => {
    const wire = buildWire({
      documentId: 'doc',
      welcomeRecipient: 42,
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /welcomeRecipient/,
    );
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves welcomeRecipientKemPublicKey', () => {
    const kemPub = new Uint8Array(65);
    for (let i = 0; i < kemPub.length; i++) kemPub[i] = (i * 11) & 0xff;
    const message = {
      documentId: 'welcome-doc',
      welcomeRecipientKemPublicKey: kemPub,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeRecipientKemPublicKey).toEqual(kemPub);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves eciesSealed', () => {
    const sealed = new Uint8Array(160);
    for (let i = 0; i < sealed.length; i++) sealed[i] = (i * 17) & 0xff;
    const message = {
      documentId: 'welcome-doc',
      eciesSealed: sealed,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.eciesSealed).toEqual(sealed);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves all current PathUpdate fields', () => {
    const pathUpdate = {
      version: 2 as const,
      generation: 7,
      parentTreeHash: "AQID",
      numLeaves: 2,
      senderLeafIndex: 0,
      senderLeafPublicKey: 'AAAA',
      nodes: [{
        nodeIndex: 1,
        publicKey: 'AQID',
        encryptedPathKeyBundles: [
          { recipientNodeIndex: 2, ciphertext: 'BwgJ' },
        ],
      }],
      treeNodePublicKeys: [
        { nodeIndex: 0, publicKey: 'AAAA' },
        { nodeIndex: 1, publicKey: 'AQID' },
        { nodeIndex: 2, publicKey: 'CgsM' },
      ],
      treeHash: 'DQ4P',
    };
    const wire = serializer.serializeSyncMessage({
      documentId: 'pathupdate-v2-doc',
      pathUpdate,
    });
    expect(serializer.deserializeSyncMessage(wire).pathUpdate).toEqual(
      pathUpdate,
    );
  });

  test('deserializeSyncMessage omits pathUpdate when absent on wire', () => {
    const message = { documentId: 'no-pathupdate-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.pathUpdate).toBeUndefined();
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves pathUpdateEpochId', () => {
    const epochId = new Uint8Array(32);
    for (let i = 0; i < epochId.length; i++) epochId[i] = (i * 7) & 0xff;
    const message = {
      documentId: 'pathupdate-doc',
      pathUpdateEpochId: epochId,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.pathUpdateEpochId).toEqual(epochId);
  });

  test('deserializeSyncMessage rejects pathUpdate that is not an object', () => {
    const wire = buildWire({
      documentId: 'doc',
      pathUpdate: 'not-an-object',
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /pathUpdate/,
    );
  });

  test('deserializeSyncMessage rejects pathUpdate that is null', () => {
    const wire = buildWire({
      documentId: 'doc',
      pathUpdate: null,
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /pathUpdate/,
    );
  });

  test('deserializeSyncMessage rejects non-string pathUpdateEpochId', () => {
    const wire = buildWire({
      documentId: 'doc',
      pathUpdateEpochId: 42,
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /pathUpdateEpochId/,
    );
  });

  // Round-trip for the initial-load quorum tip-set hash (#189 §5.4.2).
  // Table-driven: covers a deterministic-pattern hash and the all-zeros
  // boundary (base64 leading-zero handling is a common regression source).
  test.each([
    [
      'deterministic-pattern',
      (() => {
        const h = new Uint8Array(32);
        for (let i = 0; i < h.length; i++) h[i] = (i * 7 + 3) & 0xff;
        return h;
      })(),
    ],
    ['all-zeros', new Uint8Array(32)],
  ])(
    'serializeSyncMessage/deserializeSyncMessage preserves tipsHash (quorum, %s)',
    (_label, hash) => {
      const wire = serializer.serializeSyncMessage({
        documentId: 'quorum-doc',
        tipsHash: hash,
      });
      const deserialized = serializer.deserializeSyncMessage(wire);
      expect(deserialized.tipsHash).toEqual(hash);
    },
  );

  test('deserializeSyncMessage omits tipsHash when absent on wire', () => {
    const message = { documentId: 'no-quorum-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.tipsHash).toBeUndefined();
  });

  // Left as a standalone `test` (not folded into the round-trip table) because
  // it builds a malformed wire payload via `buildWire` to exercise the
  // deserialize-side validator -- different setup from the round-trip cases.
  test('deserializeSyncMessage rejects non-string tipsHash', () => {
    const wire = buildWire({
      documentId: 'doc',
      tipsHash: 42,
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /tipsHash/,
    );
  });

  // `tipsHash` is defined as a fixed 32-byte
  // SHA-256 digest; the deserializer previously accepted any base64-decoded
  // length and let downstream quorum logic mis-bucket the value. Reject
  // wrong-length payloads at the wire boundary.
  test.each([
    ['empty', new Uint8Array(0)],
    ['short (16 bytes)', new Uint8Array(16)],
    ['long (64 bytes)', new Uint8Array(64)],
  ])(
    'deserializeSyncMessage rejects tipsHash that is not exactly 32 bytes (%s)',
    (_label, malformedHash) => {
      const b64 = Buffer.from(malformedHash).toString('base64');
      const wire = buildWire({ documentId: 'doc', tipsHash: b64 });
      expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
        /tipsHash.*32 bytes/,
      );
    },
  );

  // Quorum frontier binding wire-encoding (#186 / #189 §5.4.2). The `tips`
  // field carries an explicit string[] of CIDs on load responses so the
  // loader can bind the served state to the responder's frontier hash.
  test.each([
    ['typical', ['bafy1', 'bafy2', 'bafy3']],
    ['single-tip', ['bafyOnly']],
    ['empty-frontier', [] as string[]],
  ])(
    'serializeSyncMessage/deserializeSyncMessage preserves tips (%s)',
    (_label, tips) => {
      const wire = serializer.serializeSyncMessage({
        documentId: 'frontier-doc',
        tips,
      });
      const deserialized = serializer.deserializeSyncMessage(wire);
      expect(deserialized.tips).toEqual(tips);
    },
  );

  test('deserializeSyncMessage omits tips when absent on wire', () => {
    const wire = serializer.serializeSyncMessage({
      documentId: 'no-frontier-doc',
    });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.tips).toBeUndefined();
  });

  test('deserializeSyncMessage rejects non-array tips', () => {
    const wire = buildWire({ documentId: 'doc', tips: 'not-an-array' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/tips/);
  });

  test('deserializeSyncMessage rejects non-string tips entries', () => {
    const wire = buildWire({ documentId: 'doc', tips: ['ok', 42] });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/tips/);
  });

  // Regression: prior to the upfront object guard, a malformed peer payload
  // like JSON `null` flowed straight to `raw.snapshot` access and threw a
  // bare `TypeError: Cannot read properties of null`. The guard mirrors
  // `YjsJSONSerializer.deserializeSyncMessage` and produces a descriptive
  // `Error` so the malformed payload can be attributed back to the peer
  // instead of crashing the deserializer (a trivial DoS vector).
  test('deserializeSyncMessage rejects a top-level JSON null payload', () => {
    const wire = buildWire(null);
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(Error);
    expect(() => serializer.deserializeSyncMessage(wire)).not.toThrow(
      TypeError,
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got null/,
    );
  });

  test('deserializeSyncMessage rejects a top-level JSON array payload', () => {
    const wire = buildWire([1, 2, 3]);
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got array/,
    );
  });

  test('deserializeSyncMessage rejects a top-level JSON number payload', () => {
    const wire = buildWire(42);
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got number/,
    );
  });

  test('deserializeSyncMessage rejects a top-level JSON string payload', () => {
    const wire = buildWire('not-an-object');
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got string/,
    );
  });

  // Regression: prior to validating `documentId`, a malformed peer payload
  // missing the field (or sending a non-string value) would propagate
  // `documentId: undefined`/non-string downstream and violate the required
  // field contract of `CRDTSyncMessage`. The fix rejects the payload with a
  // descriptive error attributable back to the peer.
  test('deserializeSyncMessage rejects payload missing documentId', () => {
    const wire = buildWire({ changeId: 'c1' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got undefined/,
    );
  });

  test('deserializeSyncMessage rejects payload with non-string documentId (number)', () => {
    const wire = buildWire({ documentId: 42 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got number/,
    );
  });

  test('deserializeSyncMessage rejects payload with null documentId', () => {
    const wire = buildWire({ documentId: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got null/,
    );
  });

  test('deserializeSyncMessage rejects payload with object documentId', () => {
    const wire = buildWire({ documentId: { id: 'doc' } });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got object/,
    );
  });

  test('deserializeSyncMessage rejects non-string changeId', () => {
    const wire = buildWire({ documentId: 'doc', changeId: 7 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'changeId' must be a string when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects non-string signature', () => {
    const wire = buildWire({ documentId: 'doc', signature: 7 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'signature' must be a string when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects non-array keychainChanges', () => {
    const wire = buildWire({ documentId: 'doc', keychainChanges: 'not-an-array' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'keychainChanges' must be an array when present.*got string/,
    );
  });

  test('deserializeSyncMessage rejects array snapshot', () => {
    const wire = buildWire({ documentId: 'doc', snapshot: [1, 2, 3] });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got array/,
    );
  });

  // Regression: a truthy guard (`if (raw.snapshot)`) silently dropped
  // defined-but-falsy snapshot values rather than rejecting the malformed
  // payload. The fix routes any non-`undefined` value through the validator
  // so peers can't bypass it by sending `snapshot: null/0/""`.
  test('deserializeSyncMessage rejects "snapshot: null" (validation bypass regression)', () => {
    const wire = buildWire({ documentId: 'doc', snapshot: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got null/,
    );
  });

  test('deserializeSyncMessage rejects "snapshot: 0"', () => {
    const wire = buildWire({ documentId: 'doc', snapshot: 0 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects "snapshot: \\"\\"" (empty string)', () => {
    const wire = buildWire({ documentId: 'doc', snapshot: '' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got string/,
    );
  });

  test('deserializeSyncMessage accepts omitted "snapshot" field', () => {
    const wire = buildWire({ documentId: 'doc' });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.snapshot).toBeUndefined();
  });

  // Regression: prior to building the returned object explicitly, the
  // deserializer spread `...raw` straight onto the result. A malicious peer
  // could append junk keys (or attempt prototype-pollution-style keys) and
  // they would leak through to downstream consumers. The fix only propagates
  // fields declared on `CRDTSyncMessage`.
  test('deserializeSyncMessage strips peer-supplied junk keys', () => {
    const wire = buildWire({
      documentId: 'doc',
      changeId: 'cid',
      somethingExtra: 'evil',
      anotherJunkField: { nested: true },
      __evilNonProtoKey: 'still-junk',
    });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.documentId).toBe('doc');
    expect(deserialized.changeId).toBe('cid');
    expect((deserialized as Record<string, unknown>).somethingExtra).toBeUndefined();
    expect((deserialized as Record<string, unknown>).anotherJunkField).toBeUndefined();
    expect((deserialized as Record<string, unknown>).__evilNonProtoKey).toBeUndefined();
  });

  test('deserializeSyncMessage round-trips a minimal valid payload', () => {
    const wire = buildWire({ documentId: 'doc' });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.documentId).toBe('doc');
    expect(deserialized.changes).toBeUndefined();
    expect(deserialized.changeId).toBeUndefined();
    expect(deserialized.signature).toBeUndefined();
    expect(deserialized.keychainChanges).toBeUndefined();
    expect(deserialized.snapshot).toBeUndefined();
  });
});

describe('bounded initial invitation profile', () => {
  test('all bundled Automerge components declare the same profile', () => {
    expect(new AutomergeProvider().initialInvitationCapacityProfile).toBe(
      INITIAL_INVITATION_CAPACITY_PROFILE,
    );
    expect(new AutomergeACLProvider().initialInvitationCapacityProfile).toBe(
      INITIAL_INVITATION_CAPACITY_PROFILE,
    );
    expect(
      new AutomergeKeychainProvider().initialInvitationCapacityProfile,
    ).toBe(INITIAL_INVITATION_CAPACITY_PROFILE);
    expect(
      new AutomergeJSONSerializer().initialInvitationCapacityProfile,
    ).toBe(INITIAL_INVITATION_CAPACITY_PROFILE);
  });

  test('founder-plus-editor ACL publication stays within the serialized growth bound', async () => {
    const founderPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const recipientPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const readers = new AutomergeACL();
    const writers = new AutomergeACL();
    const founderChanges = await writers.add(founderPair.publicKey);
    const membershipChanges: Array<
      readonly ['reader' | 'writer', Uint8Array[]]
    > = [
      ['reader', await readers.add(recipientPair.publicKey)],
      ['writer', await writers.add(recipientPair.publicKey)],
      ['reader', readers.current()],
      ['writer', writers.current()],
    ];
    const serializer = new AutomergeJSONSerializer();
    const cid = (label: string) => `bafy${label.repeat(55).slice(0, 55)}`;
    const founderCid = cid('f');
    const signature = 'A'.repeat(128);
    const baseline: CRDTSyncMessage<Uint8Array[], CryptoKey> = {
      documentId: '/capacity-growth',
      changeId: founderCid,
      changes: { kind: 'writer', change: founderChanges },
      tips: [founderCid],
      signature,
    };
    const baselineBytes =
      serializer.serializeSyncMessage(baseline).byteLength;
    let previousCid = founderCid;
    let previousNode = baseline.changes!;
    const deferredTips: string[] = [];

    for (let index = 0; index < membershipChanges.length; index++) {
      const [kind, change] = membershipChanges[index]!;
      const nextCid = cid(String(index));
      const children: Record<string, CRDTChangeNode<Uint8Array[]>> = {
        [previousCid]: previousNode,
      };
      const nextNode: CRDTChangeNode<Uint8Array[]> = {
        kind,
        change,
        children,
      };
      for (let crossLink = 0; crossLink < 3; crossLink++) {
        const crossLinkCid = cid(`${index}${crossLink}`);
        children[crossLinkCid] = { kind: 'document' };
        deferredTips.push(crossLinkCid);
      }
      previousCid = nextCid;
      previousNode = nextNode;
    }

    const afterMembership: CRDTSyncMessage<Uint8Array[], CryptoKey> = {
      documentId: baseline.documentId,
      changeId: previousCid,
      changes: previousNode,
      tips: [previousCid, ...deferredTips],
      signature,
    };
    const membershipGrowth =
      serializer.serializeSyncMessage(afterMembership).byteLength -
      baselineBytes;

    expect(membershipGrowth).toBeGreaterThan(0);
    expect(membershipGrowth).toBeLessThanOrEqual(4 * 1024);
    expect(membershipGrowth).toBeLessThanOrEqual(
      INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES,
    );
  });

  test('real bundled signature, encryption, and sealed Welcome overheads stay bounded', async () => {
    const signingPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const serializer = new AutomergeJSONSerializer();
    const crdt = new AutomergeProvider<{ value: string }>();
    const [document, changes] = crdt.localChange(
      crdt.newDocument(),
      'capacity payload',
      (draft) => {
        draft.value = 'founder plus one';
      },
    );
    expect(document.value).toBe('founder plus one');
    const plaintext = serializer.serializeSyncMessage({
      documentId: '/real-overheads',
      changes: { kind: 'document', change: changes },
    });
    const signature = await new SubtleCrypto().sign(
      plaintext,
      signingPair.privateKey,
    );
    expect(signature.byteLength).toBe(96);
    expect(signature.byteLength).toBeLessThanOrEqual(
      INITIAL_INVITATION_MAX_SIGNATURE_BYTES,
    );

    const auth = new SubtleCrypto();
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const measuredOverheads: number[] = [];
    for (const sample of [plaintext, new Uint8Array(16)]) {
      const encrypted = await auth.encrypt(sample, key);
      const framedBytes =
        32 + encrypted.nonce.byteLength + encrypted.data.byteLength;
      measuredOverheads.push(framedBytes - sample.byteLength);
    }
    expect(Math.max(...measuredOverheads)).toBe(60);
    expect(Math.max(...measuredOverheads)).toBeLessThanOrEqual(
      INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES,
    );

    const founderKemPair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
    const recipientKemPair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
    const beekem = new BeeKEM();
    await beekem.initialize(
      founderKemPair.privateKey,
      founderKemPair.publicKey,
    );
    const { welcome } = await beekem.addMember(recipientKemPair.publicKey);
    const keychain = new AutomergeKeychain();
    await keychain.add();
    const keychainBytes = serializer.serializeChanges(keychain.history());
    const withoutBeeKEMBytes = '{"k":"","bk":}'.length +
      Math.ceil(keychainBytes.byteLength / 3) * 4;
    const sealedWelcome = await eciesSeal(
      encodeWelcomeSealedPayloadV2({
        keychainChanges: keychainBytes,
        beekemWelcome: welcome,
      }),
      recipientKemPair.publicKey,
    );

    const sealedWelcomeGrowth =
      sealedWelcome.byteLength - withoutBeeKEMBytes;
    expect(sealedWelcomeGrowth).toBeLessThanOrEqual(
      INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES,
    );
  });
});
