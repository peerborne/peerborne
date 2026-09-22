import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';
import { PeerborneDocument } from './peerborne-document.js';
import { eciesOpen } from './ecies.js';
import { decodeWelcomeSealedPayloadV2 } from './welcome-sealed-payload.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import { deserializePathUpdateV2FromWire } from './path-update-wire.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Reject: 'reject' } }),
  { virtual: true },
);
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne.js', () => ({
  MAX_DOCUMENT_PATH_LENGTH: 4096,
  Peerborne: class {},
}));

jest.mock('./ecies.js', () => ({
  ECIES_P256_PUBLIC_KEY_LENGTH: 65,
  eciesOpen: jest.fn(),
  eciesSeal: jest.fn(),
  importEciesPublicKey: jest.fn(),
}));

jest.mock('./welcome-sealed-payload.js', () => ({
  decodeWelcomeSealedPayloadV2: jest.fn(),
  encodeWelcomeSealedPayloadV2: jest.fn(),
}));

jest.mock('./derive-doc-key.js', () => ({
  deriveDocumentKeyFromRootSecret: jest.fn(),
  deriveEpochIdFromRootSecret: jest.fn(),
}));

jest.mock('./path-update-wire.js', () => ({
  deserializePathUpdateV2FromWire: jest.fn(),
  serializePathUpdateV2ForWire: jest.fn(),
}));

jest.mock('./beekem/beekem.js', () => {
  class MockBeeKEM {
    readonly processWelcome = jest.fn(async () => undefined);
  }
  return { BeeKEM: MockBeeKEM };
});

type EpochPlan = {
  readonly ids: readonly Uint8Array[];
  readonly currentId: Uint8Array;
};

const localUser = { id: 'local' };
const localKemPublicKey = new Uint8Array(65).fill(4);
const oldEpoch = new Uint8Array(32).fill(1);
const currentEpoch = new Uint8Array(32).fill(2);
const nextEpoch = new Uint8Array(32).fill(3);
const derivedDocumentKey = { algorithm: { name: 'AES-GCM' } } as CryptoKey;
const rootSecret = new Uint8Array(32).fill(9);

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index])
  );
}

function fakeDocument(fields: Record<string, unknown>): any {
  return Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath: '/inbound-transitions',
    _bootstrapLoadApplicationState: 'complete',
    _bootstrapLoadApplicationRevision: 0,
    _userPublicKey: localUser,
    _kemKeyPair: { privateKey: {}, publicKey: {} },
    _kemPublicKeyRaw: localKemPublicKey,
    _authProvider: {
      serializePublicKey: async (key: { id: string }) => key.id,
    },
    _readers: { check: async () => true },
    _verifyWelcomeWriterSignature: async () => true,
    ...fields,
  });
}

function syncMessageSerializer() {
  let snapshot: Record<string, unknown> | undefined;
  return {
    serializeSyncMessage: jest.fn((message: Record<string, unknown>) => {
      snapshot = { ...message };
      return new Uint8Array([1]);
    }),
    deserializeSyncMessage: jest.fn(() => ({ ...snapshot })),
  };
}

function welcomeMessage(epochId: Uint8Array, token: number) {
  return {
    documentId: '/inbound-transitions',
    welcomeEpochId: new Uint8Array(epochId),
    welcomeRecipient: 'local',
    welcomeRecipientKemPublicKey: new Uint8Array(localKemPublicKey),
    eciesSealed: new Uint8Array([token]),
    signature: 'signed-by-writer',
  };
}

function welcomeHarness(
  options: {
    readonly claimFactory?: (applyStagedState: () => void) => unknown;
    readonly claimProperty?: 'data' | 'missing' | 'accessor';
    readonly initialIds?: readonly Uint8Array[];
    readonly invitationEpoch?: Uint8Array;
    readonly keyIdsShape?: 'duplicate' | 'sparse';
    readonly malformedPreparedId?: 'currentKeyId' | 'keyIds';
    readonly omitHydratedCurrent?: boolean;
    readonly hydratedShape?: 'missing-old' | 'undefined-old' | 'duplicate-old' | 'sparse' | 'unexpected' | 'reordered';
    readonly omitOldLookup?: boolean;
    readonly onGetKey?: (keyId: Uint8Array) => void;
    readonly onHydrate?: (
      prepared: Record<string, unknown>,
    ) => void | Promise<void>;
  } = {},
) {
  let liveIds: Uint8Array[] =
    options.initialIds?.map((id) => new Uint8Array(id)) ?? [];
  let liveRevision = 0;
  const plans = new Map<number, EpochPlan>();
  const envelopes = new Map<
    number,
    { keychainChanges: Uint8Array; beekemWelcome: object | null }
  >();
  const claims: jest.Mock[] = [];
  const finalizers: jest.Mock[] = [];
  const hydrators: jest.Mock[] = [];
  const preparedIdAccessor = jest.fn(() => {
    throw new Error('prepared ID accessor must not run');
  });
  const claimAccessor = jest.fn(() => {
    throw new Error('prepared claim accessor must not run');
  });

  const prepareMerge = jest.fn((changeToken: number) => {
    const plan = plans.get(changeToken);
    if (!plan) throw new Error('missing keychain plan');
    const stagedIds = plan.ids.map((id) => new Uint8Array(id));
    const exposedIds = stagedIds.map((id) => new Uint8Array(id));
    const prepared: Record<string, unknown> = {
      changes: changeToken,
      getKey: jest.fn((id: Uint8Array) => {
        if (options.omitOldLookup && sameBytes(id, oldEpoch)) return undefined;
        const key = stagedIds.some((candidate) => sameBytes(candidate, id))
          ? derivedDocumentKey
          : undefined;
        options.onGetKey?.(id);
        return key;
      }),
      commit: jest.fn(() => {
        throw new Error('legacy prepared merge commit must not be used');
      }),
    };
    const hydrateKeys = jest.fn(async () => {
      await options.onHydrate?.(prepared);
      const hydrated: unknown[] = stagedIds
        .filter(
          (id) =>
            !options.omitHydratedCurrent ||
            !sameBytes(id, plan.currentId),
        )
        .map((id) => [new Uint8Array(id), derivedDocumentKey] as const);
      switch (options.hydratedShape) {
        case 'missing-old': hydrated.shift(); break;
        case 'undefined-old': hydrated[0] = [new Uint8Array(oldEpoch), undefined]; break;
        case 'duplicate-old': hydrated.splice(1, 0, hydrated[0]); break;
        case 'sparse': delete hydrated[0]; break;
        case 'unexpected': hydrated[0] = [new Uint8Array(nextEpoch), derivedDocumentKey]; break;
        case 'reordered': hydrated.reverse(); break;
      }
      return hydrated;
    });
    prepared.hydrateKeys = hydrateKeys;
    hydrators.push(hydrateKeys);
    if (options.malformedPreparedId === 'keyIds') {
      Object.defineProperty(prepared, 'keyIds', {
        configurable: true,
        get: preparedIdAccessor,
      });
    } else {
      if (options.keyIdsShape === 'duplicate') {
        prepared.keyIds = [
          ...exposedIds,
          new Uint8Array(exposedIds[exposedIds.length - 1]),
        ];
      } else if (options.keyIdsShape === 'sparse') {
        const sparseIds = new Array<Uint8Array>(exposedIds.length + 1);
        for (let index = 0; index < exposedIds.length; index++) {
          sparseIds[index] = exposedIds[index];
        }
        prepared.keyIds = sparseIds;
      } else {
        prepared.keyIds = exposedIds;
      }
    }
    if (options.malformedPreparedId === 'currentKeyId') {
      Object.defineProperty(prepared, 'currentKeyId', {
        configurable: true,
        get: preparedIdAccessor,
      });
    } else {
      prepared.currentKeyId = new Uint8Array(plan.currentId);
    }
    const applyStagedState = () => {
      liveIds = stagedIds.map((id) => new Uint8Array(id));
      liveRevision += 1;
    };
    const claimCommit = jest.fn(function (this: unknown) {
      expect(this).toBe(prepared);
      const customClaim = options.claimFactory?.(applyStagedState);
      if (customClaim !== undefined) return customClaim;
      const claim: Record<string, unknown> = {};
      const finalize = jest.fn(function (this: unknown) {
        expect(this).toBe(claim);
        applyStagedState();
      });
      claim.finalize = finalize;
      finalizers.push(finalize);
      return claim;
    });
    if (options.claimProperty === 'accessor') {
      Object.defineProperty(prepared, 'claimCommit', {
        configurable: true,
        get: claimAccessor,
      });
    } else if (options.claimProperty !== 'missing') {
      prepared.claimCommit = claimCommit;
    }
    claims.push(claimCommit);
    return prepared;
  });

  const document = fakeDocument({
    _invitationEpoch:
      options.invitationEpoch === undefined
        ? undefined
        : new Uint8Array(options.invitationEpoch),
    _beekem: null,
    _beekemInitialized: false,
    _pendingWelcomes: new Map(),
    _changesSerializer: {
      deserializeChanges: jest.fn((bytes: Uint8Array) => bytes[0]),
    },
    _syncMessageSerializer: syncMessageSerializer(),
    _keychain: {
      prepareMerge,
      merge: jest.fn(() => {
        throw new Error('live keychain merge must not be used');
      }),
      keys: jest.fn(async () =>
        liveIds.map((id) => [new Uint8Array(id), derivedDocumentKey]),
      ),
    },
  });

  const register = (
    token: number,
    plan: EpochPlan,
    beekemWelcome: object | null = { token },
  ) => {
    plans.set(token, plan);
    envelopes.set(token, {
      keychainChanges: new Uint8Array([token]),
      beekemWelcome,
    });
  };

  jest.mocked(eciesOpen).mockImplementation(async (sealed) =>
    new Uint8Array([(sealed as Uint8Array)[0]]),
  );
  jest.mocked(decodeWelcomeSealedPayloadV2).mockImplementation((plaintext) => {
    const envelope = envelopes.get((plaintext as Uint8Array)[0]);
    if (!envelope) throw new Error('missing Welcome envelope');
    return envelope as never;
  });

  return {
    claimAccessor,
    claims,
    document,
    finalizers,
    hydrators,
    liveIds: () => liveIds.map((id) => new Uint8Array(id)),
    liveRevision: () => liveRevision,
    preparedIdAccessor,
    prepareMerge,
    register,
  };
}

function pathUpdateHarness(
  options: {
    readonly claimFactory?: (applyStagedState: () => void) => unknown;
    readonly claimProperty?: 'data' | 'missing' | 'accessor';
    readonly finalizer?: (applyStagedState: () => void) => unknown;
    readonly initialEpoch?: Uint8Array;
    readonly message?: Partial<Record<string, unknown>>;
    readonly onPrepare?: () => void;
    readonly onProcess?: () => void;
  } = {},
) {
  const order: string[] = [];
  let liveEpoch =
    options.initialEpoch === undefined
      ? undefined
      : new Uint8Array(options.initialEpoch);
  const liveBeeKEM = { name: 'live-tree' } as Record<string, unknown>;
  const stagedBeeKEM = {
    name: 'staged-tree',
    processPathUpdate: jest.fn(async () => {
      options.onProcess?.();
      return rootSecret;
    }),
  };
  liveBeeKEM.clone = jest.fn(() => stagedBeeKEM);
  const claimAccessor = jest.fn(() => {
    throw new Error('prepared epoch claim accessor must not run');
  });
  const claimCommit = jest.fn(function (this: unknown) {
    expect(this).toBe(preparedEpoch);
    order.push('claim');
    const applyStagedState = () => {
      liveEpoch = new Uint8Array(nextEpoch);
    };
    const customClaim = options.claimFactory?.(applyStagedState);
    if (customClaim !== undefined) return customClaim;
    const claim: Record<string, unknown> = {};
    const finalize = jest.fn(function (this: unknown) {
      expect(this).toBe(claim);
      order.push('finalize');
      if (options.finalizer) return options.finalizer(applyStagedState);
      applyStagedState();
    });
    claim.finalize = finalize;
    return claim;
  });
  const preparedEpoch: Record<string, unknown> = {
    changes: new Uint8Array([8]),
    history: new Uint8Array([8]),
    commit: jest.fn(() => {
      throw new Error('legacy epoch commit must not be used');
    }),
  };
  if (options.claimProperty === 'accessor') {
    Object.defineProperty(preparedEpoch, 'claimCommit', {
      configurable: true,
      get: claimAccessor,
    });
  } else if (options.claimProperty !== 'missing') {
    preparedEpoch.claimCommit = claimCommit;
  }
  const prepareEpochKey = jest.fn(
    async (epochId: Uint8Array, key: CryptoKey) => {
      order.push('prepare');
      expect(epochId).toEqual(nextEpoch);
      expect(key).toBe(derivedDocumentKey);
      options.onPrepare?.();
      return preparedEpoch;
    },
  );
  const addEpochKey = jest.fn(async (epochId: Uint8Array) => {
    liveEpoch = new Uint8Array(epochId);
    order.push('legacy-add');
    return new Uint8Array([7]);
  });
  const message: Record<string, unknown> = {
    documentId: '/inbound-transitions',
    signature: 'signed-by-writer',
    pathUpdate: { senderLeafIndex: 4, nodes: [] },
    pathUpdateEpochId: new Uint8Array(nextEpoch),
    ...options.message,
  };
  const document = fakeDocument({
    _beekemInitialized: true,
    _syncMessageSerializer: {
      deserializeSyncMessage: jest.fn(() => message),
      serializeSyncMessage: jest.fn(() => new Uint8Array([6])),
    },
    _keychain: { addEpochKey, prepareEpochKey },
  });
  let installedBeeKEM: unknown = liveBeeKEM;
  Object.defineProperty(document, '_beekem', {
    configurable: true,
    get: () => installedBeeKEM,
    set: (value) => {
      order.push('beekem-swap');
      installedBeeKEM = value;
    },
  });

  return {
    addEpochKey,
    claimAccessor,
    claimCommit,
    document,
    installedBeeKEM: () => installedBeeKEM,
    liveBeeKEM,
    liveEpoch: () => liveEpoch,
    message,
    order,
    prepareEpochKey,
    preparedEpoch,
    stagedBeeKEM,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  jest.mocked(deriveEpochIdFromRootSecret).mockResolvedValue(nextEpoch);
  jest.mocked(deriveDocumentKeyFromRootSecret).mockResolvedValue(
    derivedDocumentKey,
  );
  jest.mocked(deserializePathUpdateV2FromWire).mockReturnValue({
    senderLeafIndex: 4,
    senderLeafPublicKey: new Uint8Array(65).fill(7),
    nodes: [],
  });
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
  jest.spyOn(console, 'debug').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('inbound BeeKEM V2 Welcome transaction', () => {
  test.each([
    { hydratedShape: 'missing-old' as const },
    { hydratedShape: 'undefined-old' as const },
    { hydratedShape: 'duplicate-old' as const },
    { hydratedShape: 'sparse' as const },
    { hydratedShape: 'unexpected' as const },
    { hydratedShape: 'reordered' as const },
    { omitOldLookup: true },
  ])('rejects an incomplete full-history projection: %j', async (options) => {
    const harness = welcomeHarness(options);
    harness.register(19, { ids: [oldEpoch, currentEpoch], currentId: currentEpoch });
    await expect(harness.document._evaluateAndApplyBeeKEMWelcome(
      welcomeMessage(currentEpoch, 19), { fromBuffer: false },
    )).resolves.toBe('retry');
    expect(harness.claims[0]).not.toHaveBeenCalled();
    expect(harness.liveIds()).toEqual([]);
    expect(harness.document._invitationEpoch).toBeUndefined();
    expect(harness.document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('does not let duplicate or older signed Welcomes regress the keychain or replace the live tree', async () => {
    const harness = welcomeHarness();
    harness.register(1, {
      ids: [oldEpoch, currentEpoch],
      currentId: currentEpoch,
    });
    harness.register(2, {
      ids: [oldEpoch, currentEpoch],
      currentId: currentEpoch,
    });
    harness.register(3, {
      ids: [oldEpoch, currentEpoch],
      currentId: currentEpoch,
    });

    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(currentEpoch, 1),
        { fromBuffer: false },
      ),
    ).resolves.toBe('applied');

    const installedBeeKEM = harness.document._beekem;
    const installedRevision = harness.liveRevision();
    expect(installedBeeKEM).not.toBeNull();
    expect(harness.liveIds()).toEqual([oldEpoch, currentEpoch]);

    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(currentEpoch, 2),
        { fromBuffer: false },
      ),
    ).resolves.toBe('terminal');
    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(oldEpoch, 3),
        { fromBuffer: false },
      ),
    ).resolves.toBe('terminal');

    expect(harness.liveIds()).toEqual([oldEpoch, currentEpoch]);
    expect(harness.liveRevision()).toBe(installedRevision);
    expect(harness.document._invitationEpoch).toEqual(currentEpoch);
    expect(harness.document._beekem).toBe(installedBeeKEM);
    expect(harness.prepareMerge).toHaveBeenCalledTimes(2);
    expect(harness.claims).toHaveLength(2);
    expect(harness.claims[1]).not.toHaveBeenCalled();
  });

  test('rejects a key-only Welcome before staging or committing state', async () => {
    const harness = welcomeHarness();
    harness.register(15, { ids: [currentEpoch], currentId: currentEpoch }, null);
    await expect(harness.document._evaluateAndApplyBeeKEMWelcome(
      welcomeMessage(currentEpoch, 15), { fromBuffer: false },
    )).resolves.toBe('terminal');
    expect(harness.prepareMerge).not.toHaveBeenCalled();
    expect(harness.liveIds()).toEqual([]);
    expect(harness.liveRevision()).toBe(0);
    expect(harness.document._invitationEpoch).toBeUndefined();
    expect(harness.document._beekem).toBeNull();
    expect(harness.document._beekemInitialized).toBe(false);
  });

  test('rejects a staged keychain whose current ID is not the signed welcomeEpochId', async () => {
    const harness = welcomeHarness();
    harness.register(4, {
      ids: [oldEpoch, currentEpoch],
      currentId: currentEpoch,
    });

    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(nextEpoch, 4),
        { fromBuffer: false },
      ),
    ).resolves.toBe('terminal');

    expect(harness.liveIds()).toEqual([]);
    expect(harness.liveRevision()).toBe(0);
    expect(harness.document._invitationEpoch).toBeUndefined();
    expect(harness.document._beekem).toBeNull();
    expect(harness.prepareMerge).toHaveBeenCalledTimes(1);
    expect(harness.claims).toHaveLength(1);
    expect(harness.claims[0]).not.toHaveBeenCalled();
  });

  test.each(['missing', 'accessor'] as const)(
    'fails closed without poisoning when the prepared merge claim is %s',
    async (claimProperty) => {
      const harness = welcomeHarness({
        claimProperty,
        initialIds: [oldEpoch],
        invitationEpoch: oldEpoch,
      });
      const oldTree = { name: 'old-tree' };
      harness.document._beekem = oldTree;
      harness.document._beekemInitialized = true;
      harness.register(5, {
        ids: [oldEpoch, currentEpoch],
        currentId: currentEpoch,
      });

      await expect(
        harness.document._evaluateAndApplyBeeKEMWelcome(
          welcomeMessage(currentEpoch, 5),
          { fromBuffer: false },
        ),
      ).resolves.toBe('retry');

      expect(harness.claims[0]).not.toHaveBeenCalled();
      expect(harness.claimAccessor).not.toHaveBeenCalled();
      expect(harness.liveIds()).toEqual([oldEpoch]);
      expect(harness.document._invitationEpoch).toEqual(oldEpoch);
      expect(harness.document._beekem).toBe(oldTree);
      expect(harness.document._bootstrapLoadApplicationState).toBe('complete');
    },
  );

  test.each(['currentKeyId', 'keyIds'] as const)(
    'rejects an accessor-backed prepared %s without invoking it or poisoning',
    async (malformedPreparedId) => {
      const harness = welcomeHarness({
        initialIds: [oldEpoch],
        invitationEpoch: oldEpoch,
        malformedPreparedId,
      });
      harness.register(6, {
        ids: [oldEpoch, currentEpoch],
        currentId: currentEpoch,
      });

      await expect(
        harness.document._evaluateAndApplyBeeKEMWelcome(
          welcomeMessage(currentEpoch, 6),
          { fromBuffer: false },
        ),
      ).resolves.toBe('retry');

      expect(harness.preparedIdAccessor).not.toHaveBeenCalled();
      expect(harness.claims[0]).not.toHaveBeenCalled();
      expect(harness.liveIds()).toEqual([oldEpoch]);
      expect(harness.document._bootstrapLoadApplicationState).toBe('complete');
    },
  );

  test.each([
    [
      'duplicate prepared key IDs',
      { keyIdsShape: 'duplicate' as const },
      { ids: [currentEpoch], currentId: currentEpoch },
    ],
    [
      'a sparse prepared key-ID array',
      { keyIdsShape: 'sparse' as const },
      { ids: [currentEpoch], currentId: currentEpoch },
    ],
    [
      'a prepared current ID that is not final',
      {},
      { ids: [oldEpoch, currentEpoch], currentId: oldEpoch },
    ],
    [
      'hydration that omits the advertised epoch',
      { omitHydratedCurrent: true },
      { ids: [oldEpoch, currentEpoch], currentId: currentEpoch },
    ],
  ] as const)(
    'rejects %s before claiming without poisoning',
    async (_label, options, plan) => {
      const harness = welcomeHarness(options);
      harness.register(17, plan);

      await expect(
        harness.document._evaluateAndApplyBeeKEMWelcome(
          welcomeMessage(currentEpoch, 17),
          { fromBuffer: false },
        ),
      ).resolves.toBe('retry');

      expect(harness.claims).toHaveLength(1);
      expect(harness.claims[0]).not.toHaveBeenCalled();
      expect(harness.liveIds()).toEqual([]);
      expect(harness.document._invitationEpoch).toBeUndefined();
      expect(harness.document._bootstrapLoadApplicationState).toBe('complete');
    },
  );

  test('uses detached prepared-ID snapshots when hydration mutates the exposed IDs', async () => {
    const harness = welcomeHarness({
      initialIds: [oldEpoch],
      invitationEpoch: oldEpoch,
      onHydrate: (prepared) => {
        (prepared.currentKeyId as Uint8Array).fill(0xee);
        for (const id of prepared.keyIds as Uint8Array[]) id.fill(0xdd);
      },
    });
    harness.register(7, {
      ids: [oldEpoch, currentEpoch],
      currentId: currentEpoch,
    });

    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(currentEpoch, 7),
        { fromBuffer: false },
      ),
    ).resolves.toBe('applied');

    expect(harness.claims[0]).toHaveBeenCalledTimes(1);
    expect(harness.liveIds()).toEqual([oldEpoch, currentEpoch]);
    expect(harness.document._invitationEpoch).toEqual(currentEpoch);
  });

  test('passes a disposable epoch ID to the prepared key lookup', async () => {
    let lookupEpoch: Uint8Array | undefined;
    const harness = welcomeHarness({
      onGetKey: (epochId) => {
        lookupEpoch = epochId;
        epochId.fill(0xee);
      },
    });
    harness.register(20, {
      ids: [currentEpoch],
      currentId: currentEpoch,
    });

    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(currentEpoch, 20),
        { fromBuffer: false },
      ),
    ).resolves.toBe('applied');

    expect(lookupEpoch).toEqual(new Uint8Array(32).fill(0xee));
    expect(harness.liveIds()).toEqual([currentEpoch]);
    expect(harness.document._invitationEpoch).toEqual(currentEpoch);
    expect(harness.document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('cannot redirect a prepared merge claim by replacing the method during hydration', async () => {
    const replacement = jest.fn(() => {
      throw new Error('replacement claim must not run');
    });
    const harness = welcomeHarness({
      initialIds: [oldEpoch],
      invitationEpoch: oldEpoch,
      onHydrate: (prepared) => {
        prepared.claimCommit = replacement;
      },
    });
    harness.register(8, {
      ids: [oldEpoch, currentEpoch],
      currentId: currentEpoch,
    });

    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(currentEpoch, 8),
        { fromBuffer: false },
      ),
    ).resolves.toBe('applied');

    expect(replacement).not.toHaveBeenCalled();
    expect(harness.claims[0]).toHaveBeenCalledTimes(1);
    expect(harness.liveIds()).toEqual([oldEpoch, currentEpoch]);
  });

  test('abandons a hydrated Welcome transition when mutation admission expires', async () => {
    let active = true;
    const harness = welcomeHarness({
      onHydrate: () => {
        active = false;
      },
    });
    harness.register(9, {
      ids: [currentEpoch],
      currentId: currentEpoch,
    });
    const admission = {
      isActive: jest.fn(() => active),
      runMutation: jest.fn(),
    };

    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(currentEpoch, 9),
        { fromBuffer: false },
        admission,
      ),
    ).resolves.toBe('retry');

    expect(harness.hydrators[0]).toHaveBeenCalledTimes(1);
    expect(admission.runMutation).not.toHaveBeenCalled();
    expect(harness.claims[0]).not.toHaveBeenCalled();
    expect(harness.liveIds()).toEqual([]);
    expect(harness.document._invitationEpoch).toBeUndefined();
    expect(harness.document._beekem).toBeNull();
    expect(harness.document._bootstrapLoadApplicationState).toBe('complete');
  });

  test.each([
    [
      'a throwing claim',
      () => {
        throw new Error('indeterminate merge claim');
      },
    ],
    [
      'a native Promise claim',
      () => Promise.resolve({ finalize: () => undefined }),
    ],
    [
      'a hostile thenable claim',
      (apply: () => void) => ({
        finalize: () => undefined,
        then: () => {
          apply();
          throw new Error('then must not run');
        },
      }),
    ],
    [
      'an exotic claim record',
      (apply: () => void) =>
        Object.assign(Object.create({ hostile: true }), {
          finalize: apply,
        }),
    ],
  ])('poisons after the provider exposes %s', async (_label, claimFactory) => {
    const harness = welcomeHarness({ claimFactory });
    const oldTree = { name: 'old-tree' };
    harness.document._beekem = oldTree;
    harness.document._beekemInitialized = true;
    harness.register(10, {
      ids: [currentEpoch],
      currentId: currentEpoch,
    });

    await expect(
      harness.document._evaluateAndApplyBeeKEMWelcome(
        welcomeMessage(currentEpoch, 10),
        { fromBuffer: false },
      ),
    ).resolves.toBe('retry');
    await Promise.resolve();

    expect(harness.claims[0]).toHaveBeenCalledTimes(1);
    expect(harness.liveIds()).toEqual([]);
    expect(harness.document._invitationEpoch).toBeUndefined();
    expect(harness.document._beekem).toBe(oldTree);
    expect(harness.document._bootstrapLoadApplicationState).toBe('poisoned');
  });

  test.each([
    [
      'an asynchronous finalizer',
      (apply: () => void) => ({
        finalize: async () => {
          await Promise.resolve();
          apply();
        },
      }),
    ],
    [
      'a non-void finalizer',
      (apply: () => void) => ({
        finalize: () => {
          apply();
          return true;
        },
      }),
    ],
    [
      'a throwing finalizer',
      (apply: () => void) => ({
        finalize: () => {
          apply();
          throw new Error('indeterminate keychain commit');
        },
      }),
    ],
  ])(
    'poisons after a custom prepared merge exposes %s',
    async (_label, claimFactory) => {
      const harness = welcomeHarness({ claimFactory });
      harness.register(5, {
        ids: [currentEpoch],
        currentId: currentEpoch,
      });

      await expect(
        harness.document._evaluateAndApplyBeeKEMWelcome(
          welcomeMessage(currentEpoch, 5),
          { fromBuffer: false },
        ),
      ).resolves.toBe('retry');
      await Promise.resolve();

      expect(harness.document._bootstrapLoadApplicationState).toBe('poisoned');
      expect(harness.document._beekem).toBeNull();
      expect(() => harness.document.invitationEpoch).toThrow(
        /indeterminate authorization state/,
      );
    },
  );

  test('draining removes terminal authenticated Welcomes', async () => {
    const harness = welcomeHarness({
      initialIds: [oldEpoch, currentEpoch],
      invitationEpoch: currentEpoch,
    });
    harness.document._beekem = { name: 'installed-tree' };
    harness.document._beekemInitialized = true;
    harness.register(11, {
      ids: [oldEpoch, currentEpoch],
      currentId: currentEpoch,
    });
    harness.register(12, {
      ids: [oldEpoch, currentEpoch],
      currentId: currentEpoch,
    });
    harness.register(15, {
      ids: [nextEpoch],
      currentId: nextEpoch,
    });
    harness.register(16, {
      ids: [
        oldEpoch,
        currentEpoch,
        nextEpoch,
        new Uint8Array(32).fill(4),
      ],
      currentId: new Uint8Array(32).fill(4),
    });
    harness.document._pendingWelcomes.set('duplicate', {
      message: welcomeMessage(currentEpoch, 11),
      bufferedAtMs: Date.now(),
    });
    harness.document._pendingWelcomes.set('older', {
      message: welcomeMessage(oldEpoch, 12),
      bufferedAtMs: Date.now(),
    });
    harness.document._pendingWelcomes.set('divergent', {
      message: welcomeMessage(nextEpoch, 15),
      bufferedAtMs: Date.now(),
    });
    harness.document._pendingWelcomes.set('mismatched-current', {
      message: welcomeMessage(nextEpoch, 16),
      bufferedAtMs: Date.now(),
    });

    await expect(
      harness.document._drainPendingWelcomesUnlocked(true),
    ).resolves.toBeUndefined();

    expect(harness.document._pendingWelcomes.size).toBe(0);
    expect(harness.prepareMerge).toHaveBeenCalledTimes(3);
    expect(harness.claims).toHaveLength(3);
    for (const claim of harness.claims) {
      expect(claim).not.toHaveBeenCalled();
    }
    expect(harness.liveIds()).toEqual([oldEpoch, currentEpoch]);
    expect(harness.document._invitationEpoch).toEqual(currentEpoch);
  });

  test('stops draining buffered Welcomes after an invoked claim poisons state', async () => {
    const harness = welcomeHarness({
      claimFactory: () => {
        throw new Error('indeterminate buffered merge claim');
      },
    });
    harness.register(13, {
      ids: [currentEpoch],
      currentId: currentEpoch,
    });
    harness.register(14, {
      ids: [nextEpoch],
      currentId: nextEpoch,
    });
    harness.document._pendingWelcomes.set('first', {
      message: welcomeMessage(currentEpoch, 13),
      bufferedAtMs: Date.now(),
    });
    harness.document._pendingWelcomes.set('second', {
      message: welcomeMessage(nextEpoch, 14),
      bufferedAtMs: Date.now(),
    });

    await expect(
      harness.document._drainPendingWelcomesUnlocked(true),
    ).rejects.toThrow(/indeterminate buffered merge claim/);

    expect(harness.document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(harness.prepareMerge).toHaveBeenCalledTimes(1);
    expect(harness.claims).toHaveLength(1);
    expect(harness.document._pendingWelcomes.size).toBe(2);
  });

  test('default buffered drain stops after a swallowed claim failure poisons state', async () => {
    const harness = welcomeHarness({
      claimFactory: () => {
        throw new Error('indeterminate scheduled merge claim');
      },
    });
    harness.register(18, {
      ids: [currentEpoch],
      currentId: currentEpoch,
    });
    harness.register(19, {
      ids: [nextEpoch],
      currentId: nextEpoch,
    });
    harness.document._pendingWelcomes.set('first', {
      message: welcomeMessage(currentEpoch, 18),
      bufferedAtMs: Date.now(),
    });
    harness.document._pendingWelcomes.set('second', {
      message: welcomeMessage(nextEpoch, 19),
      bufferedAtMs: Date.now(),
    });

    await expect(
      harness.document._drainPendingWelcomesUnlocked(),
    ).resolves.toBeUndefined();

    expect(harness.document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(harness.prepareMerge).toHaveBeenCalledTimes(1);
    expect(harness.claims).toHaveLength(1);
    expect(harness.document._pendingWelcomes.size).toBe(2);
  });
});

describe('inbound BeeKEM PathUpdateV2 transaction', () => {
  test.each(['documentId', 'signature', 'pathUpdate', 'pathUpdateEpochId'])(
    'rejects an accessor-backed %s before routing or authentication', async (field) => {
      const harness = pathUpdateHarness();
      const original = harness.message[field];
      const getter = jest.fn(() => original);
      Object.defineProperty(harness.message, field, { enumerable: true, get: getter });
      harness.document._verifyWelcomeWriterSignature = jest.fn(async () => true);
      await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(new Uint8Array([1]));
      expect(getter).not.toHaveBeenCalled();
      expect(harness.document._verifyWelcomeWriterSignature).not.toHaveBeenCalled();
      expect(harness.document._syncMessageSerializer.serializeSyncMessage).not.toHaveBeenCalled();
      expect(harness.liveBeeKEM.clone).not.toHaveBeenCalled();
    },
  );

  test('rejects nested PathUpdateV2 accessors before calling the serializer', async () => {
    const harness = pathUpdateHarness();
    const getter = jest.fn(() => []);
    Object.defineProperty(harness.message.pathUpdate, 'nodes', { enumerable: true, get: getter });
    harness.document._verifyWelcomeWriterSignature = jest.fn(async () => true);
    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(new Uint8Array([1]));
    expect(getter).not.toHaveBeenCalled();
    expect(harness.document._verifyWelcomeWriterSignature).not.toHaveBeenCalled();
    expect(harness.document._syncMessageSerializer.serializeSyncMessage).not.toHaveBeenCalled();
    expect(harness.liveBeeKEM.clone).not.toHaveBeenCalled();
  });

  test('isolates verification bytes for every candidate writer', async () => {
    const firstWriter = { id: 'first-writer' };
    const secondWriter = { id: 'second-writer' };
    const observations: Array<{
      readonly data: Uint8Array;
      readonly signature: Uint8Array;
    }> = [];
    const document = fakeDocument({
      _getWriterKeys: jest.fn(async () => [firstWriter, secondWriter]),
      _deserializeSignature: jest.fn(() => new Uint8Array([7, 8])),
      _authProvider: {
        verify: jest.fn(
          async (
            data: Uint8Array,
            writer: { id: string },
            signature: Uint8Array,
          ) => {
            observations.push({
              data: new Uint8Array(data),
              signature: new Uint8Array(signature),
            });
            data.fill(0);
            signature.fill(0);
            return writer === secondWriter;
          },
        ),
      },
    });
    const signedBytes = new Uint8Array([1, 2, 3]);
    const verifyWelcomeWriterSignature = (
      PeerborneDocument.prototype as unknown as Record<string, unknown>
    )._verifyWelcomeWriterSignature as (
      raw: Uint8Array,
      signature: string,
    ) => Promise<boolean>;

    await expect(
      verifyWelcomeWriterSignature.call(document, signedBytes, 'signature'),
    ).resolves.toBe(true);

    expect(observations).toEqual([
      { data: new Uint8Array([1, 2, 3]), signature: new Uint8Array([7, 8]) },
      { data: new Uint8Array([1, 2, 3]), signature: new Uint8Array([7, 8]) },
    ]);
    expect(signedBytes).toEqual(new Uint8Array([1, 2, 3]));
  });

  test.each([
    ['the wrong document', { documentId: '/wrong-document' }],
    ['an empty document ID', { documentId: '' }],
    ['a missing document ID', { documentId: undefined }],
    ['a missing epoch ID', { pathUpdateEpochId: undefined }],
    ['a non-32-byte epoch ID', { pathUpdateEpochId: new Uint8Array(31) }],
  ])(
    'rejects %s before cloning or processing the live tree',
    async (_label, message) => {
      const harness = pathUpdateHarness({ message });

      await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
        new Uint8Array([1]),
      );

      expect(deserializePathUpdateV2FromWire).not.toHaveBeenCalled();
      expect(harness.liveBeeKEM.clone).not.toHaveBeenCalled();
      expect(harness.stagedBeeKEM.processPathUpdate).not.toHaveBeenCalled();
      expect(harness.prepareEpochKey).not.toHaveBeenCalled();
      expect(harness.installedBeeKEM()).toBe(harness.liveBeeKEM);
    },
  );

  test('authenticates before decoding the PathUpdateV2 payload', async () => {
    const harness = pathUpdateHarness();
    harness.document._verifyWelcomeWriterSignature = jest.fn(async () => false);

    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
      new Uint8Array([1]),
    );

    expect(deserializePathUpdateV2FromWire).not.toHaveBeenCalled();
    expect(harness.liveBeeKEM.clone).not.toHaveBeenCalled();
    expect(harness.prepareEpochKey).not.toHaveBeenCalled();
    expect(harness.installedBeeKEM()).toBe(harness.liveBeeKEM);
  });

  test('decodes only the canonical message reconstructed from authenticated bytes', async () => {
    const harness = pathUpdateHarness();
    const originalEpoch = harness.message.pathUpdateEpochId as Uint8Array;
    const canonicalPathUpdate = { senderLeafIndex: 9, nodes: [] };
    const canonicalMessage = {
      documentId: '/inbound-transitions',
      pathUpdate: canonicalPathUpdate,
      pathUpdateEpochId: new Uint8Array(nextEpoch),
    };
    harness.document._syncMessageSerializer.deserializeSyncMessage
      .mockReset()
      .mockReturnValueOnce(harness.message)
      .mockReturnValueOnce(canonicalMessage);
    harness.document._verifyWelcomeWriterSignature = jest.fn(
      async (verificationBytes: Uint8Array) => {
        verificationBytes.fill(0);
        originalEpoch.fill(0xee);
        harness.message.pathUpdate = { senderLeafIndex: 99, nodes: [] };
        return true;
      },
    );

    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
      new Uint8Array([1]),
    );

    expect(originalEpoch).toEqual(new Uint8Array(32).fill(0xee));
    expect(
      harness.document._syncMessageSerializer.deserializeSyncMessage.mock
        .calls[1][0],
    ).toEqual(new Uint8Array([6]));
    expect(deserializePathUpdateV2FromWire).toHaveBeenCalledTimes(1);
    expect(deserializePathUpdateV2FromWire).toHaveBeenCalledWith(
      canonicalPathUpdate,
    );
    expect(harness.prepareEpochKey).toHaveBeenCalledWith(
      nextEpoch,
      derivedDocumentKey,
    );
    expect(harness.liveEpoch()).toEqual(nextEpoch);
    expect(harness.installedBeeKEM()).toBe(harness.stagedBeeKEM);
  });

  test('claims the staged epoch and synchronously finalizes it before swapping the live tree', async () => {
    const harness = pathUpdateHarness();
    const admission = {
      isActive: jest.fn(() => true),
      runMutation: jest.fn(async (operation: () => unknown) => {
        harness.order.push('admission');
        const value = operation();
        if (value instanceof Promise) await value;
        expect(value).toBeUndefined();
        return { admitted: true as const, value };
      }),
    };

    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
      new Uint8Array([1]),
      admission,
    );

    expect(harness.prepareEpochKey).toHaveBeenCalledTimes(1);
    expect(harness.claimCommit).toHaveBeenCalledTimes(1);
    expect(harness.addEpochKey).not.toHaveBeenCalled();
    expect(harness.liveEpoch()).toEqual(nextEpoch);
    expect(harness.installedBeeKEM()).toBe(harness.stagedBeeKEM);
    expect(harness.order).toEqual([
      'prepare',
      'admission',
      'claim',
      'finalize',
      'beekem-swap',
    ]);
  });

  test.each(['missing', 'accessor'] as const)(
    'fails closed without poisoning when the prepared epoch claim is %s',
    async (claimProperty) => {
      const harness = pathUpdateHarness({ claimProperty });

      await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
        new Uint8Array([1]),
      );

      expect(harness.prepareEpochKey).toHaveBeenCalledTimes(1);
      expect(harness.claimCommit).not.toHaveBeenCalled();
      expect(harness.claimAccessor).not.toHaveBeenCalled();
      expect(harness.liveEpoch()).toBeUndefined();
      expect(harness.installedBeeKEM()).toBe(harness.liveBeeKEM);
      expect(harness.document._bootstrapLoadApplicationState).toBe('complete');
    },
  );

  test('poisons and keeps the old tree when the prepared epoch claim throws', async () => {
    const harness = pathUpdateHarness({
      claimFactory: () => {
        throw new Error('indeterminate epoch claim');
      },
    });

    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
      new Uint8Array([1]),
    );

    expect(harness.claimCommit).toHaveBeenCalledTimes(1);
    expect(harness.liveEpoch()).toBeUndefined();
    expect(harness.installedBeeKEM()).toBe(harness.liveBeeKEM);
    expect(harness.document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(harness.order).toEqual(['prepare', 'claim']);
  });

  test('uses the authenticated epoch snapshot when processing mutates the message buffer', async () => {
    const mutableEpoch = new Uint8Array(nextEpoch);
    const harness = pathUpdateHarness({
      message: { pathUpdateEpochId: mutableEpoch },
      onProcess: () => mutableEpoch.fill(0xee),
    });

    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
      new Uint8Array([1]),
    );

    expect(mutableEpoch).toEqual(new Uint8Array(32).fill(0xee));
    expect(harness.prepareEpochKey).toHaveBeenCalledWith(
      nextEpoch,
      derivedDocumentKey,
    );
    expect(harness.liveEpoch()).toEqual(nextEpoch);
    expect(harness.installedBeeKEM()).toBe(harness.stagedBeeKEM);
  });

  test('leaves the live tree untouched when the transactional keychain rejects an epoch replay', async () => {
    const harness = pathUpdateHarness({
      initialEpoch: nextEpoch,
      onPrepare: () => {
        throw new Error('Duplicate keychain key ID');
      },
    });

    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
      new Uint8Array([1]),
    );

    expect(harness.stagedBeeKEM.processPathUpdate).toHaveBeenCalledTimes(1);
    expect(harness.prepareEpochKey).toHaveBeenCalledTimes(1);
    expect(harness.claimCommit).not.toHaveBeenCalled();
    expect(harness.addEpochKey).not.toHaveBeenCalled();
    expect(harness.liveEpoch()).toEqual(nextEpoch);
    expect(harness.installedBeeKEM()).toBe(harness.liveBeeKEM);
    expect(harness.document._bootstrapLoadApplicationState).toBe('complete');
  });

  test('abandons the staged epoch and tree when mutation admission expires', async () => {
    let active = true;
    const harness = pathUpdateHarness({
      onPrepare: () => {
        active = false;
      },
    });
    const admission = {
      isActive: jest.fn(() => active),
      runMutation: jest.fn(),
    };

    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
      new Uint8Array([1]),
      admission,
    );

    expect(harness.prepareEpochKey).toHaveBeenCalledTimes(1);
    expect(admission.runMutation).not.toHaveBeenCalled();
    expect(harness.claimCommit).not.toHaveBeenCalled();
    expect(harness.liveEpoch()).toBeUndefined();
    expect(harness.installedBeeKEM()).toBe(harness.liveBeeKEM);
    expect(harness.order).toEqual(['prepare']);
  });

  test('poisons and keeps the old tree when an epoch finalizer violates its contract', async () => {
    const harness = pathUpdateHarness({
      finalizer: (apply) => {
        apply();
        return Promise.resolve();
      },
    });

    await harness.document._handleBeeKEMPathUpdateRequestDataUnlocked(
      new Uint8Array([1]),
    );

    expect(harness.liveEpoch()).toEqual(nextEpoch);
    expect(harness.installedBeeKEM()).toBe(harness.liveBeeKEM);
    expect(harness.document._bootstrapLoadApplicationState).toBe('poisoned');
    expect(harness.order).toEqual(['prepare', 'claim', 'finalize']);
    expect(() => harness.document.invitationEpoch).toThrow(
      /indeterminate authorization state/,
    );
  });
});
