import { describe, expect, jest, test } from '@jest/globals';
import { BeeKEM } from './beekem/beekem';
import {
  BeeKEMWelcome,
  BeeKEMWelcomeV2,
  PathUpdate,
  PathUpdateV2,
  TreeNode,
} from './beekem/types';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key';
import { eciesSeal, generateEciesKeyPair } from './ecies';
import { SubtleCrypto } from './auth-subtlecrypto';
import { PeerborneDocument } from './peerborne-document';
import { InvitationMembershipQueue } from './invitation-membership';
import {
  encodeWelcomeSealedPayload,
  encodeWelcomeSealedPayloadV2,
} from './welcome-sealed-payload';
import { concatUint8Arrays } from './utils';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('./peerborne.js', () => ({ MAX_DOCUMENT_PATH_LENGTH: 4096 }));
jest.mock('multiformats', () => ({ CID: { parse: (value: string) => value } }), {
  virtual: true,
});
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock(
  '@libp2p/gossipsub',
  () => ({ TopicValidatorResult: { Accept: 'accept', Ignore: 'ignore' } }),
  { virtual: true },
);

const harnessMutationQueues = new WeakMap<object, InvitationMembershipQueue>();
Object.defineProperty(PeerborneDocument.prototype, '_mutationQueue', {
  configurable: true,
  get(this: object) {
    let queue = harnessMutationQueues.get(this);
    if (queue === undefined) {
      queue = new InvitationMembershipQueue();
      harnessMutationQueues.set(this, queue);
    }
    return queue;
  },
});

function projectLegacyWelcome(welcome: BeeKEMWelcomeV2): BeeKEMWelcome {
  return {
    leafIndex: welcome.leafIndex,
    pathKeys: welcome.pathKeys.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: node.publicKey,
      encryptedPrivateKey: node.encryptedPrivateKey,
    })),
    treeNodePublicKeys: welcome.treeNodePublicKeys,
    treeHash: welcome.treeHash,
  };
}

function projectLegacyPathUpdate(update: PathUpdateV2): PathUpdate {
  return {
    senderLeafIndex: update.senderLeafIndex,
    senderLeafPublicKey: update.senderLeafPublicKey,
    nodes: update.nodes.map((node) => ({
      nodeIndex: node.nodeIndex,
      publicKey: node.publicKey,
      encryptedPrivateKey: node.encryptedPrivateKey,
    })),
  };
}

async function treeFingerprint(beekem: BeeKEM): Promise<string> {
  const nodes = (beekem as unknown as { _nodes: Map<number, TreeNode> })._nodes;
  const entries = await Promise.all(
    [...nodes.entries()]
      .sort(([left], [right]) => left - right)
      .map(async ([index, node]) => ({
        index,
        type: node.type,
        hasPrivateKey: node.privateKey !== undefined,
        publicKey:
          node.publicKey === null
            ? null
            : Buffer.from(
                await crypto.subtle.exportKey('raw', node.publicKey),
              ).toString('base64'),
      })),
  );
  return JSON.stringify(entries);
}

type TransitionHarness = {
  documentPath: string;
  _kemKeyPair: CryptoKeyPair | undefined;
  _kemPublicKeyRaw: Uint8Array | undefined;
  _beekem: null;
  _beekemInitialized: boolean;
  _beekemInitPromise: null;
  _readerKemPublicKeys: Map<string, Uint8Array>;
  _readerLeafIndices: Map<string, number>;
  _beekemTransitionTail: Promise<void>;
  _beekemTransitionsPending: number;
  _beekemRemoteTransitionsPending: number;
  _beekemRemoteIngressPending: number;
  _beekemFanoutTail: Promise<void>;
  _writerMutationsInFlight: number;
  _writerKeysVersion: number;
  _cachedWriterKeys: ReadonlyArray<string> | null;
  _keychain: {
    prepareEpochKey(): Promise<{
      changes: Uint8Array;
      history: Uint8Array;
      currentKeyChange: Uint8Array;
      commit(): void;
    }>;
    prepareMerge(changes: Uint8Array): {
      changes: Uint8Array;
      keyIds: Uint8Array[];
      commit(): void;
    };
  };
  swarm: { resolveTrustedDocumentWriters?: (path: string) => unknown };
  _writers: { users(): Promise<ReadonlyArray<string>> };
  _authProvider: {
    serializePublicKey(key: string): Promise<string>;
    verify(
      raw: Uint8Array,
      key: string,
      signature: Uint8Array,
    ): Promise<boolean>;
  };
  setKemKeyPair(keyPair: CryptoKeyPair | undefined): Promise<void>;
  getKemPublicKeyRaw(): Uint8Array | undefined;
  _runBeeKEMTransition<T>(
    operation: () => Promise<T>,
    remote?: boolean,
  ): Promise<T>;
  _runBeeKEMRemoteIngress<T>(operation: () => Promise<T>): Promise<T>;
  _enqueueBeeKEMFanout(operation: () => Promise<void>): Promise<void>;
  _withMembershipDeliveryDeadline<T>(
    operation: (signal: AbortSignal) => Promise<T>,
    onTimeout?: (error: Error) => void,
  ): Promise<T>;
  _verifyWelcomeWriterSignature(
    raw: Uint8Array,
    signature: string,
  ): Promise<boolean>;
  _captureBeeKEMWelcomeWriterAuthorities(): Promise<any>;
  _verifyWelcomeWriterSignatureFromSnapshot(
    raw: Uint8Array,
    signature: string,
    snapshot: any,
  ): Promise<boolean>;
};

function makeHarness(): TransitionHarness {
  const document = Object.create(
    PeerborneDocument.prototype,
  ) as TransitionHarness;
  document.documentPath = '/beekem-transition';
  document._kemKeyPair = undefined;
  document._kemPublicKeyRaw = undefined;
  document._beekem = null;
  document._beekemInitialized = false;
  document._beekemInitPromise = null;
  document._readerKemPublicKeys = new Map();
  document._readerLeafIndices = new Map();
  document._beekemTransitionTail = Promise.resolve();
  document._beekemTransitionsPending = 0;
  document._beekemRemoteTransitionsPending = 0;
  document._beekemRemoteIngressPending = 0;
  document._beekemFanoutTail = Promise.resolve();
  document._writerMutationsInFlight = 0;
  document._writerKeysVersion = 0;
  document._cachedWriterKeys = null;
  document._keychain = {
    prepareEpochKey: async () => ({
      changes: new Uint8Array(),
      history: new Uint8Array(),
      currentKeyChange: new Uint8Array(),
      commit: () => {},
    }),
    prepareMerge: (changes) => ({
      changes,
      keyIds: [],
      commit: () => {},
    }),
  };
  document.swarm = {};
  document._writers = { users: async () => ['writer'] };
  document._authProvider = {
    serializePublicKey: async (key) => key,
    verify: async () => true,
  };
  return document;
}

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
}

async function makeInvitationAcceptanceHarness(
  useInconsistentInstalledKey = false,
) {
  const founderKeys = await generateEciesKeyPair();
  const recipientKeys = await generateEciesKeyPair();
  const founder = new BeeKEM();
  await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
  const { welcome, rootSecret } = await founder.addMember(
    recipientKeys.publicKey,
  );
  const epochId = await deriveEpochIdFromRootSecret(rootSecret);
  const derivedKey = await deriveDocumentKeyFromRootSecret(rootSecret);
  const installedKey = useInconsistentInstalledKey
    ? await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      )
    : derivedKey;
  const keychainChanges = new Uint8Array([9]);
  const sealedWelcome = await eciesSeal(
    encodeWelcomeSealedPayloadV2({
      keychainChanges,
      beekemWelcome: welcome,
    }),
    recipientKeys.publicKey,
  );
  const serializer = {
    serializeSyncMessage(message: Record<string, unknown>) {
      return new TextEncoder().encode(
        JSON.stringify(message, (_key, value) =>
          value instanceof Uint8Array
            ? { __bytes: Array.from(value) }
            : value,
        ),
      );
    },
    deserializeSyncMessage(data: Uint8Array) {
      return JSON.parse(
        new TextDecoder().decode(data),
        (_key, value) =>
          value &&
          typeof value === 'object' &&
          Array.isArray(value.__bytes)
            ? new Uint8Array(value.__bytes)
            : value,
      );
    },
  };
  const bootstrapPlaintext = serializer.serializeSyncMessage({
    documentId: '/invitation-key-hydration',
    keychainChanges,
    signature: 'AQ==',
  });
  const cryptoProvider = new SubtleCrypto();
  const encrypted = await cryptoProvider.encrypt(
    bootstrapPlaintext,
    derivedKey,
  );
  const encryptedBootstrap = concatUint8Arrays(
    epochId,
    encrypted.nonce,
    encrypted.data,
  );
  const rawRecipient = new Uint8Array(
    await crypto.subtle.exportKey('raw', recipientKeys.publicKey),
  );
  let committed = false;
  let hydrated = false;
  const keychain = {
    prepareEpochKey: jest.fn(),
    prepareMerge: jest.fn((changes: Uint8Array) => ({
      changes,
      keyIds: [new Uint8Array(epochId)],
      commit: () => {
        committed = true;
      },
    })),
    keys: jest.fn(async () => {
      if (!committed) throw new Error('keychain was not committed');
      hydrated = true;
      return [[new Uint8Array(epochId), installedKey]];
    }),
    getKey: jest.fn((keyId: Uint8Array) =>
      hydrated && Buffer.from(keyId).equals(Buffer.from(epochId))
        ? installedKey
        : undefined,
    ),
  };
  const close = jest.fn(async () => undefined);
  const loadInvitationCatchUp = jest.fn(async () => {
    expect(keychain.getKey(epochId)).toBe(installedKey);
    return true;
  });
  const document = Object.create(PeerborneDocument.prototype) as any;
  Object.assign(document, {
    documentPath: '/invitation-key-hydration',
    _hashes: new Set<string>(),
    _subscribed: false,
    _invitationEpoch: undefined,
    _pendingFounderInitialization: undefined,
    _securityProviderMutationFailure: undefined,
    _writerKeysVersion: 0,
    _cachedWriterKeys: ['founder'],
    _kemKeyPair: recipientKeys,
    _kemPublicKeyRaw: rawRecipient,
    _beekem: null,
    _beekemInitialized: false,
    _keychainProvider: { keyIDLength: 32 },
    _keychain: keychain,
    _authProvider: {
      nonceBits: cryptoProvider.nonceBits,
      decrypt: cryptoProvider.decrypt.bind(cryptoProvider),
      verify: jest.fn(async () => true),
      serializePublicKey: jest.fn(async (key: string) => key),
    },
    _changesSerializer: {
      serializeChanges: (changes: Uint8Array) => new Uint8Array(changes),
      deserializeChanges: (changes: Uint8Array) => new Uint8Array(changes),
    },
    _syncMessageSerializer: serializer,
    _userPublicKey: 'recipient',
    _assertInitialInvitationCapacityProfile: jest.fn(),
    _runInMutationQueue: (operation: () => Promise<unknown>) => operation(),
    _runBeeKEMTransition: (operation: () => Promise<unknown>) => operation(),
    _syncUnlocked: jest.fn(async () => true),
    _assertAcceptedInvitationMembership: jest.fn(async () => undefined),
    open: jest.fn(async () => true),
    _loadInvitationCatchUp: loadInvitationCatchUp,
    close,
  });
  return {
    bundle: {
      welcomeEpochId: epochId,
      sealedWelcome,
      encryptedBootstrap,
    },
    document,
    keychain,
    loadInvitationCatchUp,
    close,
  };
}

async function legacyPathUpdateSequence() {
  const writer = new BeeKEM();
  const writerKeys = await generateKeyPair();
  await writer.initialize(writerKeys.privateKey, writerKeys.publicKey);
  const recipientKeys = await generateKeyPair();
  const { welcome } = await writer.addMember(recipientKeys.publicKey);
  const legacyWelcome = projectLegacyWelcome(welcome);
  legacyWelcome.treeHash = await (
    writer as unknown as { _computeLegacyTreeHash(): Promise<Uint8Array> }
  )._computeLegacyTreeHash();
  const recipient = new BeeKEM();
  await recipient.processWelcome(
    legacyWelcome,
    recipientKeys.privateKey,
    recipientKeys.publicKey,
  );

  const first = await writer.update();
  const second = await writer.update();
  return {
    recipient,
    first: {
      pathUpdate: projectLegacyPathUpdate(first.pathUpdate),
      rootSecret: first.rootSecret,
      epochId: await deriveEpochIdFromRootSecret(first.rootSecret),
    },
    second: {
      pathUpdate: projectLegacyPathUpdate(second.pathUpdate),
      rootSecret: second.rootSecret,
      epochId: await deriveEpochIdFromRootSecret(second.rootSecret),
    },
  };
}

function makeLegacyPathUpdateHarness(
  recipient: BeeKEM,
  allowLegacyV1: boolean,
  updates: ReadonlyMap<number, { pathUpdate: PathUpdate; epochId: Uint8Array }>,
) {
  const document = makeHarness() as any;
  const installedEpochs: string[] = [];
  document.swarm = {
    allowInsecureLegacyBeeKEMPathUpdateV1: allowLegacyV1,
  };
  document._beekem = recipient;
  document._beekemInitialized = true;
  document._syncMessageSerializer = {
    serializeSyncMessage: () => new Uint8Array([1]),
  };
  document._verifyWelcomeWriterSignature = jest.fn(async () => true);
  document._reauthorizeCanonicalBeeKEMMessage = jest.fn(async () => true);
  document._keychain.prepareEpochKey = jest.fn(
    async (epochId: Uint8Array) => ({
      commit: () => {
        installedEpochs.push(Buffer.from(epochId).toString('hex'));
      },
    }),
  );
  document._preauthenticateBeeKEMPathUpdate = jest.fn(
    async (payload: Uint8Array) => {
      const update = updates.get(payload[0]);
      if (!update) return null;
      return {
        message: {
          documentId: document.documentPath,
          signature: 'AQ==',
          pathUpdate: {},
          pathUpdateEpochId: update.epochId,
        },
        pathUpdate: update.pathUpdate,
      };
    },
  );
  return { document, installedEpochs };
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('timed out waiting for transition state');
}

async function expectFirstAddReaderSucceeds(document: any): Promise<void> {
  const founderKeys = await generateKeyPair();
  const stagedCommit = jest.fn();
  Object.assign(document._keychain, {
    prepareEpochKey: async () => ({
      changes: new Uint8Array([1]),
      history: new Uint8Array([1]),
      currentKeyChange: new Uint8Array([1]),
      commit: stagedCommit,
    }),
    prepareMerge: (changes: Uint8Array) => ({
      changes,
      keyIds: [],
      commit: () => {},
    }),
  });
  await document.setKemKeyPair(founderKeys);
  const recipientKeys = await generateKeyPair();
  const recipientRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', recipientKeys.publicKey),
  );
  const welcomeDelivery = {
    protocol: '/test/welcome',
    payload: new Uint8Array([1]),
    label: 'Welcome',
  };
  const pathDelivery = {
    protocol: '/test/path',
    payload: new Uint8Array([2]),
    label: 'PathUpdate',
  };
  Object.assign(document, {
    _ensureCurrentUserCanWrite: async () => undefined,
    _readers: { check: async () => true, add: jest.fn() },
    _keychain: {
      prepareEpochKey: async () => ({
        changes: new Uint8Array([1]),
        history: new Uint8Array([1]),
        currentKeyChange: new Uint8Array([1]),
        commit: stagedCommit,
      }),
      prepareMerge: (changes: Uint8Array) => ({
        changes,
        keyIds: [],
        commit: () => {},
      }),
    },
    _pendingBeeKEMAdds: new Map(),
    _pendingBeeKEMRemovals: new Map(),
    _beekemWelcomeByLeaf: new Map(),
    _historyVisibility: 'current_only',
    _prepareBeeKEMPathUpdate: async () => pathDelivery,
    _prepareBeeKEMWelcome: async () => welcomeDelivery,
    _enqueueBeeKEMFanout: (operation: () => Promise<void>) => operation(),
    _fanoutPreparedBeeKEMDelivery: jest.fn(async () => undefined),
  });

  const result = await document._addReaderUnderBeeKEMLock(
    'recipient',
    recipientRaw,
  );
  await result.fanout;
  expect(document._beekemInitialized).toBe(true);
  expect(document._beekem.generation).toBe(1);
  expect(stagedCommit).toHaveBeenCalledTimes(1);
}

function makeWriterMembershipHarness(): {
  document: any;
  writers: Set<string>;
  addWriterAcl: ReturnType<typeof jest.fn>;
  removeWriterAcl: ReturnType<typeof jest.fn>;
} {
  const document = makeHarness() as any;
  const writers = new Set<string>(['local']);
  const addWriterAcl = jest.fn(async (writer: string) => {
    writers.add(writer);
    return new Uint8Array([0xa1]);
  });
  const removeWriterAcl = jest.fn(async (writer: string) => {
    writers.delete(writer);
    return new Uint8Array([0xb1]);
  });
  Object.assign(document, {
    _userPublicKey: 'local',
    _writerMembershipTail: Promise.resolve(),
    _pendingWriterAdds: new Map(),
    _pendingWriterRemovals: new Map(),
    _securityProviderMutationFailure: undefined,
    _writers: {
      check: jest.fn(async (writer: string) => writers.has(writer)),
      add: addWriterAcl,
      remove: removeWriterAcl,
      users: jest.fn(async () => [...writers]),
    },
    _authProvider: {
      serializePublicKey: jest.fn(async (writer: string) => writer),
      verify: jest.fn(async () => true),
    },
    _keychainProvider: { keyIDLength: 2 },
    _keychain: {
      current: jest.fn(async () => [
        new Uint8Array([1, 2]),
        { key: 'old' },
      ]),
      add: jest.fn(async () => [
        new Uint8Array([3, 4]),
        { key: 'new' },
        new Uint8Array([0xc1]),
      ]),
    },
    _prepareChange: jest.fn(async (changes: Uint8Array) => ({ changes })),
    _publishPreparedChange: jest.fn(async () => undefined),
    _prepareKeyUpdate: jest.fn(async () => ({
      payload: new Uint8Array([0xd1]),
    })),
    _fanoutPreparedKeyUpdate: jest.fn(async () => undefined),
    close: jest.fn(async () => undefined),
  });
  return { document, writers, addWriterAcl, removeWriterAcl };
}

describe('PeerborneDocument BeeKEM transition ownership', () => {
  test('normal sync rejects a codec Proxy using the detached document ID', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/sync-local';
    const target = { documentId: '/sync-other' };
    let documentIdReads = 0;
    const unstable = new Proxy(target, {
      get(object, property, receiver) {
        if (property === 'documentId') {
          documentIdReads++;
          return documentIdReads === 1 ? '/sync-local' : '/sync-other';
        }
        return Reflect.get(object, property, receiver);
      },
    });
    document._syncMessageSerializer = {
      serializeSyncMessage: () => new Uint8Array([1]),
      deserializeSyncMessage: () => unstable,
    };

    await expect(document.sync({ documentId: '/sync-local' })).resolves.toBe(
      false,
    );
    expect(documentIdReads).toBe(0);
  });

  test('normal sync rejects a nested codec accessor before signature or tree apply', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/sync-nested';
    let accessorCalls = 0;
    const hostileChanges = Object.defineProperty(
      { kind: 'document' },
      'change',
      {
        enumerable: true,
        get() {
          accessorCalls++;
          return new Uint8Array([9]);
        },
      },
    );
    document._syncMessageSerializer = {
      serializeSyncMessage: () => new Uint8Array([1]),
      deserializeSyncMessage: () => ({
        documentId: '/sync-nested',
        changes: hostileChanges,
        signature: 'AQ==',
      }),
    };
    document._verifyWriterSignatureAtStableVersion = jest.fn(async () => 0);
    document._syncDocumentChanges = jest.fn(async () => true);

    await expect(document.sync({ documentId: '/sync-nested' })).resolves.toBe(
      false,
    );
    expect(accessorCalls).toBe(0);
    expect(document._verifyWriterSignatureAtStableVersion).not.toHaveBeenCalled();
    expect(document._syncDocumentChanges).not.toHaveBeenCalled();
  });

  test('normal sync surfaces retirement triggered during codec canonicalization', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const retirement = new Error('retired during codec canonicalization');
    Object.assign(document, {
      documentPath: '/sync-codec-retirement',
      _securityProviderMutationFailure: undefined,
      _syncMessageSerializer: {
        serializeSyncMessage: () => {
          document._securityProviderMutationFailure = retirement;
          throw new Error('codec failed');
        },
      },
    });

    await expect(
      document.sync({ documentId: '/sync-codec-retirement' }),
    ).rejects.toBe(retirement);
  });

  test('normal sync surfaces retirement during signature verification before mutation', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/sync-provider-retirement',
      keychainChanges: new Uint8Array([1]),
      signature: 'AQ==',
    };
    let verifyEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      verifyEntered = resolve;
    });
    let releaseVerify!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseVerify = resolve;
    });
    const keychainMerge = jest.fn();
    Object.assign(document, {
      documentPath: '/sync-provider-retirement',
      _securityProviderMutationFailure: undefined,
      _canonicalSyncMessages: new WeakSet([message]),
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 5,
      _keychain: { merge: keychainMerge },
      _syncMessageSerializer: {
        serializeSyncMessage: () => new Uint8Array([1]),
      },
      _verifyWriterSignatureAtStableVersion: async () => {
        verifyEntered();
        await released;
        return 5;
      },
      swarm: { enableSigning: true },
    });

    const syncing = document.sync(message);
    await entered;
    const retirement = new Error('retired while verifying');
    document._securityProviderMutationFailure = retirement;
    releaseVerify();

    await expect(syncing).rejects.toBe(retirement);
    expect(keychainMerge).not.toHaveBeenCalled();
  });

  test('normal sync rechecks its writer lease before keychain mutation', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/sync-writer-barrier';
    document.swarm = { enableSigning: true };
    document._writerKeysVersion = 0;
    document._writerMutationsInFlight = 0;
    document._keychain = { merge: jest.fn() };
    document._syncMessageSerializer = {
      serializeSyncMessage: (message: Record<string, unknown>) =>
        new TextEncoder().encode(JSON.stringify(message)),
      deserializeSyncMessage: (bytes: Uint8Array) =>
        JSON.parse(new TextDecoder().decode(bytes)),
    };
    let verifyEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      verifyEntered = resolve;
    });
    let releaseVerify!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseVerify = resolve;
    });
    document._verifyWriterSignatureAtStableVersion = async () => {
      verifyEntered();
      await released;
      return 0;
    };

    const syncing = document.sync({
      documentId: '/sync-writer-barrier',
      keychainChanges: 'delta',
      signature: 'AQ==',
    });
    await entered;
    document._writerKeysVersion = 1;
    releaseVerify();

    await expect(syncing).resolves.toBe(false);
    expect(document._keychain.merge).not.toHaveBeenCalled();
  });

  test('local writer authorization surfaces retirement that occurs while ACL check awaits', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    let checkEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      checkEntered = resolve;
    });
    let releaseCheck!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseCheck = resolve;
    });
    Object.assign(document, {
      documentPath: '/local-writer-retirement',
      _securityProviderMutationFailure: undefined,
      _writers: {
        check: async () => {
          checkEntered();
          await released;
          return true;
        },
      },
    });

    const authorizing = document._ensureCurrentUserCanWrite();
    await entered;
    const retirement = new Error('retired during writer check');
    document._securityProviderMutationFailure = retirement;
    releaseCheck();

    await expect(authorizing).rejects.toBe(retirement);
  });

  test('normal sync applies detached nested bytes when a pooled codec graph mutates during verification', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/sync-pooled';
    document.swarm = { enableSigning: true };
    document._writerKeysVersion = 0;
    document._writerMutationsInFlight = 0;
    const sharedChanges = new Uint8Array([1, 2, 3]);
    const decoded = {
      documentId: '/sync-pooled',
      keychainChanges: sharedChanges,
      signature: 'AQ==',
    };
    document._syncMessageSerializer = {
      serializeSyncMessage: () => new Uint8Array([1]),
      deserializeSyncMessage: () => decoded,
    };
    document._keychain = { merge: jest.fn() };
    let verifyEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      verifyEntered = resolve;
    });
    let releaseVerify!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseVerify = resolve;
    });
    document._verifyWriterSignatureAtStableVersion = async () => {
      verifyEntered();
      await released;
      return 0;
    };

    const syncing = document.sync({ documentId: '/sync-pooled' });
    await entered;
    sharedChanges[0] = 9;
    releaseVerify();

    await expect(syncing).resolves.toBe(true);
    expect(document._keychain.merge).toHaveBeenCalledWith(
      new Uint8Array([1, 2, 3]),
    );
    expect(document._keychain.merge.mock.calls[0][0]).not.toBe(sharedChanges);
  });

  test('writer verification tolerates one rejected key but requires exact true', async () => {
    const document = makeHarness() as any;
    document.swarm.enableSigning = true;
    document._cachedWriterKeys = null;
    document._writers = { users: async () => ['broken', 'valid'] };
    document._deserializeSignature = () => new Uint8Array([1]);
    document._authProvider.verify = async (
      _raw: Uint8Array,
      key: string,
    ) => {
      if (key === 'broken') throw new Error('provider key failure');
      return true;
    };
    await expect(
      document._verifyWriterSignatureAtStableVersion(
        new Uint8Array([1]),
        'AQ==',
      ),
    ).resolves.toBe(0);

    document._cachedWriterKeys = null;
    document._writers = { users: async () => ['truthy'] };
    document._authProvider.verify = async () => 'true' as unknown as boolean;
    await expect(
      document._verifyWriterSignatureAtStableVersion(
        new Uint8Array([1]),
        'AQ==',
      ),
    ).resolves.toBeNull();
  });

  test('ambiguous writer add globally retires an already-open document before ingress or serving', async () => {
    const { document, writers, addWriterAcl } = makeWriterMembershipHarness();
    addWriterAcl.mockImplementationOnce(async (writer: string) => {
      writers.add(writer);
      throw new Error('writer ACL mutated before rejection');
    });

    await expect(document.addWriter('remote-writer')).rejects.toThrow(
      /addWriter\(remote-writer\).*ambiguous.*discard this document/,
    );
    const retirement = document._securityProviderMutationFailure;
    expect(retirement.cause).toEqual(
      new Error('writer ACL mutated before rejection'),
    );
    expect(addWriterAcl).toHaveBeenCalledTimes(1);
    expect(document.close).toHaveBeenCalledTimes(1);

    await expect(document.addWriter('remote-writer')).rejects.toBe(retirement);
    expect(addWriterAcl).toHaveBeenCalledTimes(1);

    const serializeSyncMessage = jest.fn(() => new Uint8Array([1]));
    const mergeKeychain = jest.fn();
    document._syncMessageSerializer = {
      serializeSyncMessage,
      deserializeSyncMessage: jest.fn(),
    };
    document._keychain.merge = mergeKeychain;
    await expect(
      document.sync({
        documentId: document.documentPath,
        keychainChanges: new Uint8Array([7]),
        signature: 'AQ==',
      }),
    ).rejects.toBe(retirement);
    expect(serializeSyncMessage).not.toHaveBeenCalled();
    expect(mergeKeychain).not.toHaveBeenCalled();
    expect(document._authProvider.verify).not.toHaveBeenCalled();

    const loadSink = jest.fn(async () => undefined);
    const tipSink = jest.fn(async () => undefined);
    await document.handleLoadRequestData(
      { documentId: document.documentPath },
      { sink: loadSink },
    );
    await document.handleTipAdvertiseRequestData(
      { documentId: document.documentPath },
      { sink: tipSink },
    );
    expect(loadSink).toHaveBeenCalledTimes(1);
    expect(loadSink).toHaveBeenCalledWith([]);
    expect(tipSink).toHaveBeenCalledTimes(1);
    expect(tipSink).toHaveBeenCalledWith([]);
    expect(document._authProvider.verify).not.toHaveBeenCalled();

    document._decryptBlock = jest.fn();
    await document.handleKeyUpdateRequestData(new Uint8Array([1, 2, 3]));
    expect(document._decryptBlock).not.toHaveBeenCalled();
  });

  test.each(['prepare', 'publish'] as const)(
    'writer add retains its exact ACL delta across a %s failure',
    async (failureStage) => {
      const { document, addWriterAcl } = makeWriterMembershipHarness();
      const originalDelta = new Uint8Array([0xd1, 0xd2]);
      addWriterAcl.mockResolvedValueOnce(originalDelta);
      const prepared = { changes: originalDelta };
      let prepareCalls = 0;
      document._prepareChange = jest.fn(async (changes: Uint8Array) => {
        expect(changes).toBe(originalDelta);
        prepareCalls++;
        if (failureStage === 'prepare' && prepareCalls === 1) {
          throw new Error('writer prepare failed');
        }
        return prepared;
      });
      let publishCalls = 0;
      document._publishPreparedChange = jest.fn(async (value: unknown) => {
        expect(value).toBe(prepared);
        publishCalls++;
        if (failureStage === 'publish' && publishCalls === 1) {
          throw new Error('writer publish failed');
        }
      });

      await expect(document.addWriter('new-writer')).rejects.toThrow(
        failureStage === 'prepare'
          ? 'writer prepare failed'
          : 'writer publish failed',
      );
      await expect(document.addWriter('new-writer')).resolves.toBeUndefined();

      expect(addWriterAcl).toHaveBeenCalledTimes(1);
      expect(document._prepareChange).toHaveBeenCalledTimes(
        failureStage === 'prepare' ? 2 : 1,
      );
      expect(document._publishPreparedChange).toHaveBeenCalledTimes(
        failureStage === 'publish' ? 2 : 1,
      );
      expect(document._pendingWriterAdds.size).toBe(0);
    },
  );

  test('ambiguous writer removal is terminal and never reports an absent ACL row as success', async () => {
    const { document, writers, removeWriterAcl } =
      makeWriterMembershipHarness();
    writers.add('target');
    removeWriterAcl.mockImplementationOnce(async (writer: string) => {
      writers.delete(writer);
      throw new Error('writer removal mutated before rejection');
    });

    await expect(document.removeWriter('target')).rejects.toThrow(
      /removeWriter\(target\).*ambiguous.*discard this document/,
    );
    const retirement = document._securityProviderMutationFailure;
    expect(retirement.cause).toEqual(
      new Error('writer removal mutated before rejection'),
    );
    await expect(document.removeWriter('target')).rejects.toBe(retirement);
    expect(removeWriterAcl).toHaveBeenCalledTimes(1);
    expect(document._prepareChange).not.toHaveBeenCalled();
    expect(document._keychain.add).not.toHaveBeenCalled();
    expect(document._prepareKeyUpdate).not.toHaveBeenCalled();
    expect(document._fanoutPreparedKeyUpdate).not.toHaveBeenCalled();
  });

  test('ambiguous removeWriter key rotation retires without repeating ACL or keychain mutation', async () => {
    const { document, writers, removeWriterAcl } =
      makeWriterMembershipHarness();
    writers.add('target');
    document._keychain.add = jest.fn(async () => {
      throw new Error('keychain mutated before rejection');
    });

    await expect(document.removeWriter('target')).rejects.toThrow(
      /removeWriter\(target\) keychain rotation.*ambiguous.*discard this document/,
    );
    const retirement = document._securityProviderMutationFailure;
    expect(retirement.cause).toEqual(
      new Error('keychain mutated before rejection'),
    );
    await expect(document.removeWriter('target')).rejects.toBe(retirement);
    expect(removeWriterAcl).toHaveBeenCalledTimes(1);
    expect(document._keychain.add).toHaveBeenCalledTimes(1);
    expect(document._prepareKeyUpdate).not.toHaveBeenCalled();
    expect(document._fanoutPreparedKeyUpdate).not.toHaveBeenCalled();
  });

  test('self-removal retries exact retained distribution after local ACL authority is gone', async () => {
    const { document, removeWriterAcl } = makeWriterMembershipHarness();
    const keychainDelta = new Uint8Array([0xe1]);
    document._keychain.add = jest.fn(async () => [
      new Uint8Array([3, 4]),
      { key: 'new' },
      keychainDelta,
    ]);
    const prepared = { changes: new Uint8Array([0xb1]) };
    document._prepareChange = jest.fn(
      async (
        writerChanges: Uint8Array,
        _kind: unknown,
        previous: unknown,
        combinedKeychainChanges: { value: Uint8Array },
      ) => {
        expect(writerChanges).toEqual(new Uint8Array([0xb1]));
        expect(previous).toBe(
          document._pendingWriterRemovals.get('local').previousKey,
        );
        expect(combinedKeychainChanges.value).toBe(keychainDelta);
        return prepared;
      },
    );
    const preparedDelivery = { payload: new Uint8Array([0xe2]) };
    document._prepareKeyUpdate = jest.fn(async (preparedChange: unknown) => {
      expect(preparedChange).toBe(prepared);
      return preparedDelivery;
    });
    let distributionCalls = 0;
    document._fanoutPreparedKeyUpdate = jest.fn(
      async (delivery: unknown) => {
        expect(delivery).toBe(preparedDelivery);
        distributionCalls++;
        if (distributionCalls === 1) {
          throw new Error('distribution interrupted');
        }
      },
    );

    await expect(document.removeWriter('local')).rejects.toThrow(
      'distribution interrupted',
    );
    await expect(document.removeWriter('local')).resolves.toBeUndefined();

    expect(removeWriterAcl).toHaveBeenCalledTimes(1);
    expect(document._keychain.current).toHaveBeenCalledTimes(1);
    expect(document._keychain.add).toHaveBeenCalledTimes(1);
    expect(document._prepareChange).toHaveBeenCalledTimes(1);
    expect(document._prepareKeyUpdate).toHaveBeenCalledTimes(1);
    expect(document._fanoutPreparedKeyUpdate).toHaveBeenCalledTimes(2);
    expect(document._publishPreparedChange).toHaveBeenCalledTimes(1);
    expect(document._pendingWriterRemovals.size).toBe(0);
  });

  test('self-removal publishes the combined envelope before a stalled direct fanout', async () => {
    const { document } = makeWriterMembershipHarness();
    const observedOrder: string[] = [];
    const keychainDelta = new Uint8Array([0xc1]);
    document._keychain.add = jest.fn(async () => [
      new Uint8Array([3, 4]),
      { key: 'new' },
      keychainDelta,
    ]);
    const prepared = { encryptedPayload: new Uint8Array([0xe1]) };
    document._prepareChange = jest.fn(
      async (
        writerChanges: Uint8Array,
        _kind: unknown,
        _previousKey: unknown,
        combinedKeychainChanges: { value: Uint8Array },
      ) => {
        expect(writerChanges).toEqual(new Uint8Array([0xb1]));
        expect(combinedKeychainChanges.value).toBe(keychainDelta);
        return prepared;
      },
    );
    const preparedDelivery = { payload: new Uint8Array([0xf1]) };
    document._prepareKeyUpdate = jest.fn(async (preparedChange: unknown) => {
      expect(preparedChange).toBe(prepared);
      return preparedDelivery;
    });
    let fanoutEntered!: () => void;
    const entered = new Promise<void>((resolve) => {
      fanoutEntered = resolve;
    });
    let releaseFanout!: () => void;
    const released = new Promise<void>((resolve) => {
      releaseFanout = resolve;
    });
    document._fanoutPreparedKeyUpdate = jest.fn(async (delivery: unknown) => {
      expect(delivery).toBe(preparedDelivery);
      observedOrder.push('direct-fanout');
      fanoutEntered();
      await released;
    });
    document._publishPreparedChange = jest.fn(async (preparedChange: unknown) => {
      expect(preparedChange).toBe(prepared);
      observedOrder.push('gossipsub-publish');
    });

    const removal = document.removeWriter('local');
    await entered;
    expect(observedOrder).toEqual(['gossipsub-publish', 'direct-fanout']);
    expect(document._publishPreparedChange).toHaveBeenCalledTimes(1);
    releaseFanout();
    await expect(removal).resolves.toBeUndefined();

    expect(document._prepareKeyUpdate).toHaveBeenCalledTimes(1);
    expect(document._fanoutPreparedKeyUpdate).toHaveBeenCalledTimes(1);
  });

  test('writer removal retires when a provider delta is not representable on the wire', async () => {
    const { document } = makeWriterMembershipHarness();
    document._keychain.add = jest.fn(async () => [
      new Uint8Array([3, 4]),
      { key: 'new' },
      undefined,
    ]);

    await expect(document.removeWriter('local')).rejects.toThrow(
      /unrepresentable keychain change.*ambiguous.*discard this document/,
    );
    expect(document._prepareChange).not.toHaveBeenCalled();
    expect(document._publishPreparedChange).not.toHaveBeenCalled();
    expect(document._fanoutPreparedKeyUpdate).not.toHaveBeenCalled();
  });

  test('a non-self pending removal cannot resume after the local actor is revoked', async () => {
    const { document, writers, removeWriterAcl } =
      makeWriterMembershipHarness();
    writers.add('target');
    document._fanoutPreparedKeyUpdate = jest
      .fn<(delivery: unknown) => Promise<void>>()
      .mockRejectedValueOnce(new Error('distribution interrupted'));

    await expect(document.removeWriter('target')).rejects.toThrow(
      'distribution interrupted',
    );
    writers.delete('local');
    await expect(document.removeWriter('target')).rejects.toThrow(
      /does not have write permissions/,
    );

    expect(removeWriterAcl).toHaveBeenCalledTimes(1);
    expect(document._keychain.add).toHaveBeenCalledTimes(1);
    expect(document._prepareKeyUpdate).toHaveBeenCalledTimes(1);
    expect(document._fanoutPreparedKeyUpdate).toHaveBeenCalledTimes(1);
    expect(document._pendingWriterRemovals.has('target')).toBe(true);
  });

  test('key update rejects a codec Proxy before signature or keychain mutation', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/key-local';
    document._keychainProvider = { keyIDLength: 1 };
    document._authProvider = { nonceBits: 1 };
    document._decryptBlock = async () => new Uint8Array([1]);
    const target = {
      documentId: '/key-other',
      keychainChanges: new Uint8Array([9]),
      signature: 'AQ==',
    };
    let documentIdReads = 0;
    const unstable = new Proxy(target, {
      get(object, property, receiver) {
        if (property === 'documentId') {
          documentIdReads++;
          return documentIdReads === 1 ? '/key-local' : '/key-other';
        }
        return Reflect.get(object, property, receiver);
      },
    });
    document._syncMessageSerializer = {
      serializeSyncMessage: () => new Uint8Array([1]),
      deserializeSyncMessage: () => unstable,
    };
    document._keychain = { merge: jest.fn() };
    document._verifyWriterSignatureAtStableVersion = jest.fn(async () => 0);

    await document.handleKeyUpdateRequestData(new Uint8Array([1, 2, 3]));
    expect(documentIdReads).toBe(0);
    expect(document._verifyWriterSignatureAtStableVersion).not.toHaveBeenCalled();
    expect(document._keychain.merge).not.toHaveBeenCalled();
  });

  test('key update rejects nested accessor-backed keychain changes without invocation', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/key-nested';
    document._keychainProvider = { keyIDLength: 1 };
    document._authProvider = { nonceBits: 1 };
    document._decryptBlock = async () => new Uint8Array([1]);
    let accessorCalls = 0;
    const hostileKeychain = new Proxy(
      Object.defineProperty({}, 'delta', {
        enumerable: true,
        get() {
          accessorCalls++;
          return new Uint8Array([9]);
        },
      }),
      {
        get(target, property, receiver) {
          accessorCalls++;
          return Reflect.get(target, property, receiver);
        },
      },
    );
    document._syncMessageSerializer = {
      serializeSyncMessage: () => new Uint8Array([1]),
      deserializeSyncMessage: () => ({
        documentId: '/key-nested',
        keychainChanges: hostileKeychain,
        signature: 'AQ==',
      }),
    };
    document._keychain = { merge: jest.fn() };
    document._verifyWriterSignatureAtStableVersion = jest.fn(async () => 0);

    await document.handleKeyUpdateRequestData(new Uint8Array([1, 2, 3]));
    expect(accessorCalls).toBe(0);
    expect(document._verifyWriterSignatureAtStableVersion).not.toHaveBeenCalled();
    expect(document._keychain.merge).not.toHaveBeenCalled();
  });

  test('direct V2 delivery applies a combined keychain and writer-removal envelope through sync ordering', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const order: string[] = [];
    const writerDelta = new Uint8Array([0xb1]);
    const combinedMessage = {
      documentId: '/key-combined',
      changeId: 'writer-removal',
      changes: {
        kind: 'writer',
        change: writerDelta,
      },
      keychainChanges: new Uint8Array([0xe1]),
      signature: 'AQ==',
    };
    Object.assign(document, {
      documentPath: '/key-combined',
      _securityProviderMutationFailure: undefined,
      _keychainProvider: { keyIDLength: 1 },
      _authProvider: { nonceBits: 1 },
      _decryptBlock: async () => new Uint8Array([1]),
      _syncMessageSerializer: {
        serializeSyncMessage: () => new Uint8Array([2]),
        deserializeSyncMessage: () => combinedMessage,
      },
      _keychain: {
        merge: jest.fn(() => {
          order.push('keychain');
        }),
      },
      _writers: {
        merge: jest.fn(() => {
          order.push('writer-acl');
        }),
      },
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 7,
      _cachedWriterKeys: null,
      _document: { value: 'unchanged' },
      _hashes: new Set(),
      _referencedAncestors: new Set(),
      _recentTips: [],
      _lastSyncMessage: undefined,
      _verifyWriterSignatureAtStableVersion: jest.fn(async () => 7),
      _mergeSyncTree: jest.fn(async () => [
        ['writer-removal', 'writer', writerDelta],
      ]),
      _fireRemoteUpdateHandlers: jest.fn(async () => undefined),
      _maybeCompact: jest.fn(async () => undefined),
      swarm: { enableSigning: true },
    });

    await document.handleKeyUpdateRequestData(new Uint8Array([1, 2, 3]));

    expect(order).toEqual(['keychain', 'writer-acl']);
    expect(document._verifyWriterSignatureAtStableVersion).toHaveBeenCalledTimes(1);
    expect(document._keychain.merge).toHaveBeenCalledWith(
      combinedMessage.keychainChanges,
    );
    expect(document._writers.merge).toHaveBeenCalledWith(writerDelta);
    expect(document._hashes).toEqual(new Set(['writer-removal']));
    expect(document._lastSyncMessage).toMatchObject({
      documentId: '/key-combined',
      changeId: 'writer-removal',
    });
    expect(document._writerKeysVersion).toBe(9);
  });

  test.each([
    ['the exact writer merge increment', 2, true],
    ['an unrelated extra writer mutation', 4, false],
  ])(
    'sync authorization lease accepts %s only',
    async (_label, versionDelta, expected) => {
      const document = Object.create(PeerborneDocument.prototype) as any;
      const message = {
        documentId: '/lease',
        changes: { kind: 'writer', change: new Uint8Array([1]) },
      };
      Object.assign(document, {
        documentPath: '/lease',
        _securityProviderMutationFailure: undefined,
        _canonicalSyncMessages: new WeakSet([message]),
        _writerMutationsInFlight: 0,
        _writerKeysVersion: 11,
        swarm: { enableSigning: false },
        _syncDocumentChanges: jest.fn(async (
          _changeId: string | undefined,
          _changes: unknown,
          lease: { advanceAfterWriterMutation(): boolean },
        ) => {
          document._writerKeysVersion += versionDelta;
          return lease.advanceAfterWriterMutation();
        }),
      });

      await expect(document.sync(message)).resolves.toBe(expected);
    },
  );

  test('authenticated initial-load lease rejects an intervening writer mutation even when reverify is skipped', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/load-lease',
      keychainChanges: new Uint8Array([1]),
      signature: 'AQ==',
    };
    const keychainMerge = jest.fn();
    Object.assign(document, {
      documentPath: '/load-lease',
      _securityProviderMutationFailure: undefined,
      _canonicalSyncMessages: new WeakSet([message]),
      _initialLoadSyncAuthorizations: new WeakMap([
        [message, { writerKeys: ['writer-a'], writerVersion: 3 }],
      ]),
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 5,
      _keychain: { merge: keychainMerge },
      swarm: { enableSigning: true },
    });

    await expect(document.sync(message, false)).resolves.toBe(false);
    expect(keychainMerge).not.toHaveBeenCalled();
  });

  test('public sync cannot bypass signing by passing verifySignature false', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/no-auth-bypass',
      keychainChanges: new Uint8Array([1]),
      signature: 'AQ==',
    };
    const keychainMerge = jest.fn();
    Object.assign(document, {
      documentPath: '/no-auth-bypass',
      _securityProviderMutationFailure: undefined,
      _canonicalSyncMessages: new WeakSet([message]),
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 3,
      _keychain: { merge: keychainMerge },
      swarm: { enableSigning: true },
    });

    await expect(document.sync(message, false)).resolves.toBe(false);
    expect(keychainMerge).not.toHaveBeenCalled();
  });

  test('an exact private initial-load authorization permits skip-reverify apply', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/load-authenticated',
      keychainChanges: new Uint8Array([1]),
      signature: 'AQ==',
    };
    const keychainMerge = jest.fn();
    Object.assign(document, {
      documentPath: '/load-authenticated',
      _securityProviderMutationFailure: undefined,
      _canonicalSyncMessages: new WeakSet([message]),
      _initialLoadSyncAuthorizations: new WeakMap([
        [message, { writerKeys: ['writer-a'], writerVersion: 3 }],
      ]),
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 3,
      _keychain: { merge: keychainMerge },
      swarm: { enableSigning: true },
    });

    await expect(document.sync(message, false)).resolves.toBe(true);
    expect(keychainMerge).toHaveBeenCalledWith(message.keychainChanges);
  });

  test.each([
    ['readers ACL', '_mergeReaders', '_readers'],
    ['writers ACL', '_mergeWriters', '_writers'],
  ])(
    'a mutate-then-throw inbound %s merge permanently retires the document',
    (_label, mergeMethod, providerField) => {
      const document = Object.create(PeerborneDocument.prototype) as any;
      let mutated = false;
      Object.assign(document, {
        documentPath: '/ambiguous-inbound-acl',
        _securityProviderMutationFailure: undefined,
        _writerMutationsInFlight: 0,
        _writerKeysVersion: 0,
        _cachedWriterKeys: null,
        close: jest.fn(async () => undefined),
      });
      document[providerField] = {
        merge: () => {
          mutated = true;
          throw new Error('mutated before rejection');
        },
      };

      expect(() => document[mergeMethod](new Uint8Array([1]))).toThrow(
        /inbound .*ACL merge.*ambiguous.*discard this document/,
      );
      expect(mutated).toBe(true);
      expect(document._securityProviderMutationFailure.cause).toEqual(
        new Error('mutated before rejection'),
      );
      expect(() => document._throwIfSecurityProviderMutationFailed()).toThrow(
        document._securityProviderMutationFailure,
      );
    },
  );

  test('a staged keychain commit-then-throw retires while its BeeKEM transaction rolls back', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(document, {
      documentPath: '/ambiguous-staged-keychain',
      _securityProviderMutationFailure: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 0,
      _cachedWriterKeys: null,
      close: jest.fn(async () => undefined),
    });
    const founderKeys = await generateKeyPair();
    const recipientKeys = await generateKeyPair();
    const beekem = new BeeKEM();
    await beekem.initialize(founderKeys.privateKey, founderKeys.publicKey);
    let keychainMutated = false;

    await expect(
      beekem.addMemberTransactionally(
        recipientKeys.publicKey,
        async () => {
          document._commitPreparedKeychainState(
            {
              commit: () => {
                keychainMutated = true;
                throw new Error('commit rejected after mutation');
              },
            },
            'test staged epoch commit',
          );
        },
      ),
    ).rejects.toThrow(
      /test staged epoch commit.*ambiguous.*discard this document/,
    );
    expect(keychainMutated).toBe(true);
    expect(beekem.memberCount).toBe(1);
    expect(beekem.generation).toBe(0);
    expect(
      await beekem.findLeafByPublicKey(recipientKeys.publicKey),
    ).toBeUndefined();

    const retryCommit = jest.fn();
    const retirement = document._securityProviderMutationFailure;
    expect(() =>
      document._commitPreparedKeychainState(
        { commit: retryCommit },
        'retry staged epoch commit',
      ),
    ).toThrow(retirement);
    expect(retryCommit).not.toHaveBeenCalled();
  });

  test('a mutate-then-throw inbound keychain merge permanently retires before later sync', async () => {
    const document = Object.create(PeerborneDocument.prototype) as any;
    const message = {
      documentId: '/ambiguous-inbound-keychain',
      keychainChanges: new Uint8Array([1]),
    };
    let mutated = false;
    Object.assign(document, {
      documentPath: '/ambiguous-inbound-keychain',
      _securityProviderMutationFailure: undefined,
      _canonicalSyncMessages: new WeakSet([message]),
      _keychain: {
        merge: () => {
          mutated = true;
          throw new Error('mutated before rejection');
        },
      },
      close: jest.fn(async () => undefined),
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 0,
      _cachedWriterKeys: null,
      swarm: { enableSigning: false },
    });

    await expect(document.sync(message)).rejects.toThrow(
      /inbound keychain merge.*ambiguous.*discard this document/,
    );
    expect(mutated).toBe(true);
    const retirement = document._securityProviderMutationFailure;
    await expect(document.sync(message)).rejects.toBe(retirement);
  });

  test('PathUpdate routing and signature checks use one detached codec snapshot', async () => {
    const document = makeHarness() as any;
    const target = {
      documentId: '/other-document',
      signature: 'AQ==',
      pathUpdate: {},
      pathUpdateEpochId: new Uint8Array(32),
    };
    let documentIdReads = 0;
    const unstable = new Proxy(target, {
      get(object, property, receiver) {
        if (property === 'documentId') {
          documentIdReads++;
          return documentIdReads === 1
            ? '/beekem-transition'
            : '/other-document';
        }
        return Reflect.get(object, property, receiver);
      },
    });
    let deserializeCalls = 0;
    document._syncMessageSerializer = {
      serializeSyncMessage: () => new Uint8Array([1]),
      deserializeSyncMessage: () => {
        deserializeCalls++;
        return deserializeCalls === 1 ? target : unstable;
      },
    };
    const verify = jest.fn(async () => true);
    document._verifyWelcomeWriterSignature = verify;

    await expect(
      document._preauthenticateBeeKEMPathUpdate(new Uint8Array([1]), 2),
    ).resolves.toBeNull();
    expect(documentIdReads).toBe(0);
    expect(verify).not.toHaveBeenCalled();
  });

  test.each([
    ['legacy v1 key-only', false],
    ['v2 ratchet', true],
  ])(
    'a concurrent pre-open %s Welcome suppresses no-peer founder initialization',
    async (_label, ratchetInitialized) => {
      const document = makeHarness() as any;
      document._hashes = new Set();
      document._invitationEpoch = undefined;
      document._userPublicKey = 'recipient';
      document._addWriter = jest.fn(async () => new Uint8Array([1]));
      document._keychain = { add: jest.fn(async () => undefined) };
      document._makeChange = jest.fn(async () => undefined);

      let enter!: () => void;
      const entered = new Promise<void>((resolve) => {
        enter = resolve;
      });
      let release!: () => void;
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      const welcomeCommit = document._runBeeKEMTransition(async () => {
        enter();
        await released;
        document._invitationEpoch = new Uint8Array(32).fill(4);
        document._beekemInitialized = ratchetInitialized;
      });
      await entered;

      const founderDecision = document._initializeFounderIfStillNew(false);
      release();
      await welcomeCommit;

      await expect(founderDecision).resolves.toBe(true);
      expect(document._addWriter).not.toHaveBeenCalled();
      expect(document._keychain.add).not.toHaveBeenCalled();
      expect(document._makeChange).not.toHaveBeenCalled();
    },
  );

  test('fresh local creation can install KEM and complete the first addReader', async () => {
    const document = makeHarness() as any;
    document._hashes = new Set();
    document._invitationEpoch = undefined;
    document._userPublicKey = 'founder';
    document._addWriter = jest.fn(async () => new Uint8Array([1]));
    document._keychain = { add: jest.fn(async () => undefined) };
    const preparedFounderChange = { committed: false };
    document._prepareChange = jest.fn(async () => preparedFounderChange);
    document._commitPreparedChange = jest.fn((prepared) => {
      prepared.committed = true;
      document._hashes.add('founder-writer-change');
    });
    document._publishPreparedChange = jest.fn(async () => undefined);

    await expect(document._initializeFounderIfStillNew(false)).resolves.toBe(
      false,
    );
    expect(document._localFounderEstablished).toBe(true);
    expect(document._hashes.size).toBe(1);
    expect(preparedFounderChange.committed).toBe(true);

    await expectFirstAddReaderSucceeds(document);
  });

  test('post-commit founder publish or handler failure remains retryable', async () => {
    const document = makeHarness() as any;
    document._hashes = new Set();
    document._invitationEpoch = undefined;
    document._localFounderEstablished = false;
    document._userPublicKey = 'founder';
    document._addWriter = jest.fn(async () => new Uint8Array([1]));
    document._keychain = { add: jest.fn(async () => undefined) };
    const preparedFounderChange = { committed: false };
    document._prepareChange = jest.fn(async () => preparedFounderChange);
    document._commitPreparedChange = jest.fn((prepared) => {
      prepared.committed = true;
      document._hashes.add('founder-writer-change');
    });
    document._publishPreparedChange = jest.fn(async () => {
      expect(document._localFounderEstablished).toBe(true);
      throw new Error('post-commit publish failed');
    });

    await expect(document._initializeFounderIfStillNew(false)).rejects.toThrow(
      'post-commit publish failed',
    );
    expect(document._localFounderEstablished).toBe(true);
    expect(document._hashes).toEqual(new Set(['founder-writer-change']));

    // A retry observes the committed founder state and does not duplicate the
    // writer/key transition, while explicit founder provenance still permits
    // the first BeeKEM membership add.
    await expect(document._initializeFounderIfStillNew(false)).resolves.toBe(
      true,
    );
    expect(document._addWriter).toHaveBeenCalledTimes(1);
    expect(document._keychain.add).toHaveBeenCalledTimes(1);
    await expectFirstAddReaderSucceeds(document);
  });

  test('founder preparation retry republishes the original nonempty writer delta', async () => {
    const document = makeHarness() as any;
    document._hashes = new Set();
    document._invitationEpoch = undefined;
    document._localFounderEstablished = false;
    document._userPublicKey = 'founder';
    const originalWriterChanges = new Uint8Array([0xa1, 0xa2]);
    document._addWriter = jest.fn(async () => originalWriterChanges);
    document._keychain = { add: jest.fn(async () => undefined) };
    const preparedFounderChange = {
      committed: false,
      writerChanges: originalWriterChanges,
    };
    let prepareCalls = 0;
    document._prepareChange = jest.fn(async (writerChanges) => {
      expect(writerChanges).toBe(originalWriterChanges);
      prepareCalls += 1;
      if (prepareCalls === 1) throw new Error('prepare failed');
      return preparedFounderChange;
    });
    document._commitPreparedChange = jest.fn((prepared) => {
      prepared.committed = true;
      document._hashes.add('founder-writer-change');
    });
    let replicatedWriterChanges: Uint8Array | undefined;
    document._publishPreparedChange = jest.fn(async (prepared) => {
      replicatedWriterChanges = prepared.writerChanges;
    });

    await expect(document._initializeFounderIfStillNew(false)).rejects.toThrow(
      'prepare failed',
    );
    expect(document._pendingFounderInitialization).toEqual({
      writerAddState: 'succeeded',
      writerChanges: originalWriterChanges,
      keyAddState: 'succeeded',
    });

    await expect(document._initializeFounderIfStillNew(false)).resolves.toBe(
      false,
    );
    expect(document._addWriter).toHaveBeenCalledTimes(1);
    expect(document._keychain.add).toHaveBeenCalledTimes(1);
    expect(document._prepareChange).toHaveBeenCalledTimes(2);
    expect(replicatedWriterChanges).toBe(originalWriterChanges);
    expect(replicatedWriterChanges).toEqual(new Uint8Array([0xa1, 0xa2]));
    expect(document._pendingFounderInitialization).toBeUndefined();
  });

  test('founder key-add rejection is terminally ambiguous and is never retried', async () => {
    const document = makeHarness() as any;
    document._hashes = new Set();
    document._invitationEpoch = undefined;
    document._localFounderEstablished = false;
    document._userPublicKey = 'founder';
    const originalWriterChanges = new Uint8Array([0xb1]);
    document._addWriter = jest.fn(async () => originalWriterChanges);
    let keyProviderMutated = false;
    document._keychain = {
      add: jest.fn(async () => {
        keyProviderMutated = true;
        throw new Error('key add failed after mutation');
      }),
    };
    const preparedFounderChange = { committed: false };
    document._prepareChange = jest.fn(async (writerChanges) => {
      expect(writerChanges).toBe(originalWriterChanges);
      return preparedFounderChange;
    });
    document._commitPreparedChange = jest.fn((prepared) => {
      prepared.committed = true;
      document._hashes.add('founder-writer-change');
    });
    document._publishPreparedChange = jest.fn(async () => undefined);

    await expect(document._initializeFounderIfStillNew(false)).rejects.toThrow(
      /founder keychain initialization.*ambiguous.*discard this document/,
    );
    expect(document._securityProviderMutationFailure.cause).toEqual(
      new Error('key add failed after mutation'),
    );
    expect(keyProviderMutated).toBe(true);
    expect(document._pendingFounderInitialization).toEqual({
      writerAddState: 'succeeded',
      writerChanges: originalWriterChanges,
      keyAddState: 'started',
    });
    expect(document._prepareChange).not.toHaveBeenCalled();

    await expect(
      document._initializeFounderIfStillNew(false),
    ).rejects.toThrow(/ambiguous.*discard this document.*provider instances/);
    expect(document._addWriter).toHaveBeenCalledTimes(1);
    expect(document._keychain.add).toHaveBeenCalledTimes(1);
    expect(document._prepareChange).not.toHaveBeenCalled();
    expect(document._commitPreparedChange).not.toHaveBeenCalled();
    expect(document._publishPreparedChange).not.toHaveBeenCalled();
  });

  test.each([
    ['a clean-state retry', false, false],
    ['a peer load', true, false],
    ['an authenticated Welcome', false, true],
  ])(
    'a mutate-then-reject founder writer add fails closed before %s',
    async (_label, loadedFromPeer, installInvitation) => {
      const document = makeHarness() as any;
      document._hashes = new Set();
      document._invitationEpoch = undefined;
      document._localFounderEstablished = false;
      document._userPublicKey = 'founder';
      let writerProviderMutated = false;
      document._addWriter = jest.fn(async () => {
        writerProviderMutated = true;
        throw new Error('writer add failed after mutation');
      });
      document._keychain = { add: jest.fn(async () => undefined) };
      document._prepareChange = jest.fn();
      document._commitPreparedChange = jest.fn();
      document._publishPreparedChange = jest.fn();
      document.swarm.registerDocument = jest.fn();

      await expect(
        document._initializeFounderIfStillNew(false),
      ).rejects.toThrow(
        /founder writer-ACL initialization.*ambiguous.*discard this document/,
      );
      expect(document._securityProviderMutationFailure.cause).toEqual(
        new Error('writer add failed after mutation'),
      );
      expect(writerProviderMutated).toBe(true);
      expect(document._pendingFounderInitialization).toEqual({
        writerAddState: 'started',
        keyAddState: 'not-started',
      });
      if (installInvitation) {
        document._invitationEpoch = new Uint8Array(32).fill(0xc3);
      }

      await expect(
        document._initializeFounderIfStillNew(loadedFromPeer),
      ).rejects.toThrow(/discard this document.*provider instances/);
      expect(document._addWriter).toHaveBeenCalledTimes(1);
      expect(document._keychain.add).not.toHaveBeenCalled();
      expect(document._prepareChange).not.toHaveBeenCalled();
      expect(document._commitPreparedChange).not.toHaveBeenCalled();
      expect(document._publishPreparedChange).not.toHaveBeenCalled();
      expect(document.swarm.registerDocument).not.toHaveBeenCalled();
      expect(document._pendingFounderInitialization).toEqual({
        writerAddState: 'started',
        keyAddState: 'not-started',
      });
    },
  );

  test.each([
    ['a peer load', true, false],
    ['an authenticated Welcome', false, true],
  ])(
    'fails closed when pending founder initialization collides with %s',
    async (_label, loadedFromPeer, installInvitation) => {
      const document = makeHarness() as any;
      document._hashes = new Set();
      document._invitationEpoch = undefined;
      document._localFounderEstablished = false;
      document._userPublicKey = 'founder';
      const originalWriterChanges = new Uint8Array([0xc1]);
      document._addWriter = jest.fn(async () => originalWriterChanges);
      document._keychain = { add: jest.fn(async () => undefined) };
      document._prepareChange = jest.fn(async () => {
        throw new Error('prepare failed');
      });
      document._commitPreparedChange = jest.fn();
      document._publishPreparedChange = jest.fn();

      await expect(
        document._initializeFounderIfStillNew(false),
      ).rejects.toThrow('prepare failed');
      expect(document._pendingFounderInitialization).toEqual({
        writerAddState: 'succeeded',
        writerChanges: originalWriterChanges,
        keyAddState: 'succeeded',
      });
      if (installInvitation) {
        document._invitationEpoch = new Uint8Array(32).fill(0xc2);
      }

      await expect(
        document._initializeFounderIfStillNew(loadedFromPeer),
      ).rejects.toThrow(/discard this document.*provider instances/);
      expect(document._localFounderEstablished).toBe(false);
      expect(document._pendingFounderInitialization).toEqual({
        writerAddState: 'succeeded',
        writerChanges: originalWriterChanges,
        keyAddState: 'succeeded',
      });
      expect(document._addWriter).toHaveBeenCalledTimes(1);
      expect(document._keychain.add).toHaveBeenCalledTimes(1);
      expect(document._prepareChange).toHaveBeenCalledTimes(1);
      expect(document._commitPreparedChange).not.toHaveBeenCalled();
      expect(document._publishPreparedChange).not.toHaveBeenCalled();
    },
  );

  test.each([
    ['loaded', new Set(['existing-change']), undefined],
    ['invited-v1', new Set<string>(), new Uint8Array(32).fill(8)],
  ])(
    '%s writer state without a ratchet cannot initialize a founder tree',
    async (_label, hashes, invitationEpoch) => {
      const document = makeHarness() as any;
      const localKeys = await generateKeyPair();
      const recipientKeys = await generateKeyPair();
      document._hashes = hashes;
      document._invitationEpoch = invitationEpoch;
      document._localFounderEstablished = false;
      document._kemKeyPair = localKeys;
      document._keychain = { prepareEpochKey: jest.fn() };
      document._ensureCurrentUserCanWrite = async () => undefined;
      const recipientRaw = new Uint8Array(
        await crypto.subtle.exportKey('raw', recipientKeys.publicKey),
      );

      await expect(
        document._addReaderUnderBeeKEMLock('recipient', recipientRaw),
      ).rejects.toThrow(/no BeeKEM tree bootstrapped from a Welcome/);
      expect(document._keychain.prepareEpochKey).not.toHaveBeenCalled();
      expect(document._beekem).toBeNull();
    },
  );

  test('a concurrent active transition prevents KEM replacement and clearing', async () => {
    const document = makeHarness();
    const original = await generateKeyPair();
    const replacement = await generateKeyPair();
    await document.setKemKeyPair(original);
    const originalRaw = document.getKemPublicKeyRaw();

    let enter!: () => void;
    const entered = new Promise<void>((resolve) => {
      enter = resolve;
    });
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const welcomeTransition = document._runBeeKEMTransition(async () => {
      enter();
      await released;
      document._beekemInitialized = true;
    });
    await entered;

    const replacementPromise = document.setKemKeyPair(replacement);
    const replacementRejection = expect(replacementPromise).rejects.toThrow(
      /cannot replace the active KEM key/,
    );
    await waitUntil(() => document._beekemTransitionsPending === 2);
    expect(document.getKemPublicKeyRaw()).toEqual(originalRaw);

    release();
    await welcomeTransition;
    await replacementRejection;
    expect(document.getKemPublicKeyRaw()).toEqual(originalRaw);
    await expect(document.setKemKeyPair(undefined)).rejects.toThrow(
      /cannot clear the KEM key/,
    );

    await expect(
      document.setKemKeyPair({
        publicKey: original.publicKey,
        privateKey: original.privateKey,
      }),
    ).resolves.toBeUndefined();
    expect(document.getKemPublicKeyRaw()).toEqual(originalRaw);
  });

  test('setKemKeyPair snapshots pair fields before validation awaits', async () => {
    const document = makeHarness();
    const original = await generateKeyPair();
    const replacement = await generateKeyPair();
    const mutable = {
      publicKey: original.publicKey,
      privateKey: original.privateKey,
    };

    const installing = document.setKemKeyPair(mutable);
    mutable.publicKey = replacement.publicKey;
    mutable.privateKey = replacement.privateKey;
    await installing;

    const expected = new Uint8Array(
      await crypto.subtle.exportKey('raw', original.publicKey),
    );
    expect(document.getKemPublicKeyRaw()).toEqual(expected);
    expect(document._kemKeyPair?.publicKey).toBe(original.publicKey);
    expect(document._kemKeyPair?.privateKey).toBe(original.privateKey);
  });

  test('setKemKeyPair rejects a non-transactional custom keychain before installation', async () => {
    const document = makeHarness() as any;
    const keyPair = await generateKeyPair();
    document._keychain = {
      prepareEpochKey: jest.fn(),
    };
    document.swarm.registerWelcomeRecipient = jest.fn();

    await expect(document.setKemKeyPair(keyPair)).rejects.toThrow(
      /requires a TransactionalKeychain.*prepareEpochKey and prepareMerge/,
    );
    expect(document._kemKeyPair).toBeUndefined();
    expect(document._kemPublicKeyRaw).toBeUndefined();
    expect(document.swarm.registerWelcomeRecipient).not.toHaveBeenCalled();
  });

  test('invitation bootstrap retains its full-history policy across a mid-flight flip', async () => {
    const document = makeHarness() as any;
    document._historyVisibility = 'full_history';
    document._keychainProvider = { keyIDLength: 32 };
    let added = false;
    let entered!: () => void;
    const addEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    document._prepareInvitationBootstrapCapacity = jest.fn(async () => ({
      keychainChanges: new Uint8Array([1]),
      serializedBootstrapBaselineBytes: 0,
      welcomeWithoutBeeKEMBytes: 0,
    }));
    document._initialInvitationMembershipState = jest.fn(async () => ({
      createdLocally: true,
      founder: 'founder',
      recipient: 'recipient',
      readers: added ? ['recipient'] : [],
      writers: ['founder'],
    }));
    document._addReaderUnlocked = jest.fn(
      async (
        _reader: unknown,
        _kem: Uint8Array,
        _broadcast: boolean,
        beginMutation: () => void,
      ) => {
        entered();
        await released;
        beginMutation();
        added = true;
        return { version: 2 };
      },
    );
    document._readers = { current: () => ({}) };
    document._writers = { current: () => ({}) };
    document._makeChange = jest.fn(async () => undefined);
    document._keychain = {
      current: async () => [new Uint8Array(32), {}],
    };
    document._keychainChangesForWelcome = jest.fn(async () => {
      throw new Error('stop after captured policy check');
    });
    const assertCanMutate = jest.fn();
    const admitStateMutation = jest.fn();

    const bootstrap = document.buildInvitationBootstrap(
      'recipient',
      new Uint8Array(65),
      'reader',
      assertCanMutate,
      admitStateMutation,
    );
    await addEntered;
    expect(admitStateMutation).not.toHaveBeenCalled();
    document.historyVisibility = 'current_only';
    release();

    await expect(bootstrap).rejects.toThrow(/captured policy/);
    expect(assertCanMutate).toHaveBeenCalled();
    expect(admitStateMutation).toHaveBeenCalledTimes(1);
    expect(document._prepareInvitationBootstrapCapacity).toHaveBeenCalledWith(
      'recipient',
      'full_history',
    );
    expect(document._keychainChangesForWelcome).toHaveBeenCalledWith(
      'full_history',
    );
  });

  test('invitation bootstrap hydrates the committed epoch key before founder catch-up', async () => {
    const {
      bundle,
      document,
      keychain,
      loadInvitationCatchUp,
    } = await makeInvitationAcceptanceHarness();

    await expect(
      document.acceptInvitationBootstrap(
        bundle,
        'founder',
        'editor',
        '/ip4/127.0.0.1/tcp/4001',
      ),
    ).resolves.toBeUndefined();

    expect(keychain.keys).toHaveBeenCalledTimes(1);
    expect(loadInvitationCatchUp).toHaveBeenCalledTimes(1);
    expect(document._invitationBootstrapReady).toBe(true);
    expect(document._securityProviderMutationFailure).toBeUndefined();
  });

  test('invitation bootstrap retires when the same epoch ID carries a non-BeeKEM key', async () => {
    const {
      bundle,
      document,
      keychain,
      loadInvitationCatchUp,
      close,
    } = await makeInvitationAcceptanceHarness(true);

    let rejection: unknown;
    try {
      await document.acceptInvitationBootstrap(
        bundle,
        'founder',
        'editor',
        '/ip4/127.0.0.1/tcp/4001',
      );
    } catch (error) {
      rejection = error;
    }

    expect(rejection).toBe(document._securityProviderMutationFailure);
    expect(rejection).toBeInstanceOf(Error);
    expect((rejection as Error).message).toMatch(/ambiguous ACL or keychain/);
    expect(((rejection as Error).cause as Error).message).toMatch(
      /staged epoch key does not match its BeeKEM root/,
    );
    expect(keychain.keys).toHaveBeenCalledTimes(1);
    expect(document._syncUnlocked).not.toHaveBeenCalled();
    expect(loadInvitationCatchUp).not.toHaveBeenCalled();
    expect(document._beekem).toBeNull();
    expect(document._invitationEpoch).toBeUndefined();
    expect(close).toHaveBeenCalled();
  });

  test('captured full-history Welcome selection ignores the mutable field', async () => {
    const document = makeHarness() as any;
    const history = jest.fn(async () => new Uint8Array([1]));
    const currentKeyChange = jest.fn(async () => new Uint8Array([2]));
    document._keychain = { history, currentKeyChange };
    document._historyVisibility = 'current_only';

    await expect(
      document._keychainChangesForWelcome('full_history'),
    ).resolves.toEqual(new Uint8Array([1]));
    expect(history).toHaveBeenCalledTimes(1);
    expect(currentKeyChange).not.toHaveBeenCalled();
  });

  test('remote ingress and authenticated queue saturation preserve local capacity', async () => {
    const document = makeHarness();
    let releaseIngress!: () => void;
    const ingressReleased = new Promise<void>((resolve) => {
      releaseIngress = resolve;
    });
    const ingress = Array.from({ length: 4 }, () =>
      document._runBeeKEMRemoteIngress(async () => ingressReleased),
    );
    await waitUntil(() => document._beekemRemoteIngressPending === 4);
    await expect(
      document._runBeeKEMRemoteIngress(async () => undefined),
    ).rejects.toThrow(/remote ingress is at capacity/);

    let releaseTransition!: () => void;
    const transitionReleased = new Promise<void>((resolve) => {
      releaseTransition = resolve;
    });
    const blockingLocal = document._runBeeKEMTransition(
      async () => transitionReleased,
    );
    const remoteTransitions = Array.from({ length: 3 }, () =>
      document._runBeeKEMTransition(async () => undefined, true),
    );
    await expect(
      document._runBeeKEMTransition(async () => undefined, true),
    ).rejects.toThrow(/remote transition queue is at capacity/);

    let secondLocalRan = false;
    const secondLocal = document._runBeeKEMTransition(async () => {
      secondLocalRan = true;
    });
    expect(secondLocalRan).toBe(false);
    releaseTransition();
    await Promise.all([blockingLocal, ...remoteTransitions, secondLocal]);
    expect(secondLocalRan).toBe(true);

    releaseIngress();
    await Promise.all(ingress);
    expect(document._beekemRemoteIngressPending).toBe(0);
  });

  test.each([
    [
      'Welcome',
      'handleBeeKEMWelcomeRequestData',
      '_preauthenticateBeeKEMWelcome',
      '_handleBeeKEMWelcomeRequestDataUnlocked',
    ],
    [
      'PathUpdate',
      'handleBeeKEMPathUpdateRequestData',
      '_preauthenticateBeeKEMPathUpdate',
      '_handleBeeKEMPathUpdateRequestDataUnlocked',
    ],
  ])(
    '%s ingress bounds authenticated backlog before the mutation queue',
    async (_label, handlerName, preauthenticateName, applyName) => {
      const document = makeHarness() as any;
      let release!: () => void;
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      document[preauthenticateName] = jest.fn(async () => ({}));
      let applyCount = 0;
      document[applyName] = jest.fn(async () => {
        applyCount++;
        if (applyCount === 1) await released;
      });
      const log = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const error = jest.spyOn(console, 'error').mockImplementation(() => {});

      const accepted = Array.from({ length: 4 }, () =>
        document[handlerName](new Uint8Array([1]), 2),
      );
      await waitUntil(() => document._beekemRemoteIngressPending === 4);
      await expect(
        document[handlerName](new Uint8Array([1]), 2),
      ).resolves.toBeUndefined();
      expect(document[preauthenticateName]).toHaveBeenCalledTimes(4);
      expect(document[applyName]).toHaveBeenCalledTimes(1);

      release();
      await Promise.all(accepted);
      expect(document[applyName]).toHaveBeenCalledTimes(4);
      expect(document._beekemRemoteIngressPending).toBe(0);
      log.mockRestore();
      error.mockRestore();
    },
  );

  test('a stalled peer delivery times out without holding local transition ownership', async () => {
    jest.useFakeTimers();
    try {
      const document = makeHarness();
      let timedOut = false;
      const fanout = document._enqueueBeeKEMFanout(() =>
        document._withMembershipDeliveryDeadline(
          async () => new Promise<never>(() => undefined),
          () => {
            timedOut = true;
          },
        ),
      );
      const fanoutRejection = expect(fanout).rejects.toThrow(
        /delivery timed out/,
      );
      await Promise.resolve();

      let localRan = false;
      await expect(
        document._runBeeKEMTransition(async () => {
          localRan = true;
        }),
      ).resolves.toBeUndefined();
      expect(localRan).toBe(true);

      await jest.advanceTimersByTimeAsync(5_000);
      await fanoutRejection;
      expect(timedOut).toBe(true);
    } finally {
      jest.useRealTimers();
    }
  });

  test('a throwing stream abort cannot swallow the membership delivery timeout', async () => {
    jest.useFakeTimers();
    try {
      const document = makeHarness();
      const delivery = document._withMembershipDeliveryDeadline(
        async () => new Promise<never>(() => undefined),
        () => {
          throw new Error('PRIVATE-ABORT-FAILURE');
        },
      );
      const rejection = expect(delivery).rejects.toThrow(/delivery timed out/);

      await jest.advanceTimersByTimeAsync(5_000);
      await rejection;
    } finally {
      jest.useRealTimers();
    }
  });

  test('writer verification fails closed when the ACL version changes in flight', async () => {
    const document = makeHarness();
    let enter!: () => void;
    const entered = new Promise<void>((resolve) => {
      enter = resolve;
    });
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    document._authProvider.verify = async () => {
      enter();
      await released;
      return true;
    };

    const verifying = document._verifyWelcomeWriterSignature(
      new Uint8Array([1]),
      'AQ==',
    );
    await entered;
    document._writerKeysVersion++;
    release();

    await expect(verifying).resolves.toBe(false);
  });

  test('pinned Welcome writers are captured once and become stale when ACL writers appear', async () => {
    const document = makeHarness();
    const resolver = jest.fn(async () => ['pinned-writer', 'pinned-writer']);
    document.swarm.resolveTrustedDocumentWriters = resolver;
    document._writers = { users: async () => [] };

    const snapshot = await document._captureBeeKEMWelcomeWriterAuthorities();
    expect(snapshot).toMatchObject({ source: 'bootstrap' });
    expect(snapshot.authorities).toHaveLength(1);
    expect(resolver).toHaveBeenCalledTimes(1);
    await expect(
      document._verifyWelcomeWriterSignatureFromSnapshot(
        new Uint8Array([1]),
        'AQ==',
        snapshot,
      ),
    ).resolves.toBe(true);

    // Even without relying on the version counter, a current ACL trust root
    // takes precedence over the captured bootstrap set at final commit.
    document._cachedWriterKeys = null;
    document._writers = { users: async () => ['acl-writer'] };
    await expect(
      document._verifyWelcomeWriterSignatureFromSnapshot(
        new Uint8Array([1]),
        'AQ==',
        snapshot,
      ),
    ).resolves.toBe(false);
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  test('v2 Welcome rejects a signed keychain epoch that does not match the ratchet root without mutation', async () => {
    const founderKeys = await generateEciesKeyPair();
    const recipientKeys = await generateEciesKeyPair();
    const founder = new BeeKEM();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const { welcome } = await founder.addMember(recipientKeys.publicKey);
    const envelope = encodeWelcomeSealedPayloadV2({
      keychainChanges: new Uint8Array([9]),
      beekemWelcome: welcome,
    });
    const sealed = await eciesSeal(envelope, recipientKeys.publicKey);
    const rawRecipient = new Uint8Array(
      await crypto.subtle.exportKey('raw', recipientKeys.publicKey),
    );
    const wrongEpoch = new Uint8Array(32).fill(7);
    const keychainCommit = jest.fn();
    const serializer = {
      serializeSyncMessage(message: Record<string, unknown>) {
        return new TextEncoder().encode(
          JSON.stringify(message, (_key, value) =>
            value instanceof Uint8Array
              ? { __bytes: Array.from(value) }
              : value,
          ),
        );
      },
      deserializeSyncMessage(data: Uint8Array) {
        return JSON.parse(
          new TextDecoder().decode(data),
          (_key, value) =>
            value &&
            typeof value === 'object' &&
            Array.isArray(value.__bytes)
              ? new Uint8Array(value.__bytes)
              : value,
        );
      },
    };
    const document = Object.create(PeerborneDocument.prototype) as any;
    Object.assign(document, {
      documentPath: '/v2-root-epoch-binding',
      _userPublicKey: 'recipient',
      _authProvider: {
        serializePublicKey: async (key: string) => key,
        verify: async () => true,
      },
      _syncMessageSerializer: serializer,
      _changesSerializer: {
        deserializeChanges: (bytes: Uint8Array) => bytes,
      },
      _keychain: {
        prepareMerge: (changes: Uint8Array) => ({
          changes,
          keyIds: [wrongEpoch],
          commit: keychainCommit,
        }),
      },
      _kemKeyPair: recipientKeys,
      _kemPublicKeyRaw: rawRecipient,
      _beekem: null,
      _beekemInitialized: false,
      _invitationEpoch: undefined,
      _writerMutationsInFlight: 0,
      _writerKeysVersion: 0,
      _cachedWriterKeys: ['writer'],
      _writers: { users: async () => ['writer'] },
    });

    await expect(
      document._evaluateAndApplyBeeKEMWelcome(
        {
          message: {
            documentId: '/v2-root-epoch-binding',
            welcomeEpochId: wrongEpoch,
            welcomeRecipient: 'recipient',
            welcomeRecipientKemPublicKey: rawRecipient,
            eciesSealed: sealed,
            signature: 'AQ==',
          },
          writerAuthorities: {
            source: 'acl',
            writerKeysVersion: 0,
            authorities: [{ authorityId: 'writer', publicKey: 'writer' }],
          },
        },
        2,
      ),
    ).resolves.toBe(false);
    expect(keychainCommit).not.toHaveBeenCalled();
    expect(document._beekem).toBeNull();
    expect(document._beekemInitialized).toBe(false);
    expect(document._invitationEpoch).toBeUndefined();
  });

  test('legacy Welcome stages ratchet crypto before final auth and leaves keychain untouched on writer removal', async () => {
    const founderKeys = await generateEciesKeyPair();
    const recipientKeys = await generateEciesKeyPair();
    const founder = new BeeKEM();
    await founder.initialize(founderKeys.privateKey, founderKeys.publicKey);
    const { welcome } = await founder.addMember(recipientKeys.publicKey);
    const envelope = encodeWelcomeSealedPayload({
      keychainChanges: new Uint8Array([9]),
      beekemWelcome: projectLegacyWelcome(welcome),
    });
    const sealed = await eciesSeal(envelope, recipientKeys.publicKey);
    const rawRecipient = new Uint8Array(
      await crypto.subtle.exportKey('raw', recipientKeys.publicKey),
    );

    const serializer = {
      serializeSyncMessage(message: Record<string, unknown>) {
        return new TextEncoder().encode(
          JSON.stringify(message, (_key, value) =>
            value instanceof Uint8Array
              ? { __bytes: Array.from(value) }
              : value,
          ),
        );
      },
      deserializeSyncMessage(data: Uint8Array) {
        return JSON.parse(
          new TextDecoder().decode(data),
          (_key, value) =>
            value &&
            typeof value === 'object' &&
            Array.isArray(value.__bytes)
              ? new Uint8Array(value.__bytes)
              : value,
        );
      },
    };
    const keychainCommit = jest.fn();
    const document = Object.create(PeerborneDocument.prototype) as any;
    document.documentPath = '/legacy-welcome-barrier';
    document._userPublicKey = 'recipient';
    document._authProvider = {
      serializePublicKey: async (key: string) => key,
      verify: async () => true,
    };
    document._syncMessageSerializer = serializer;
    document._changesSerializer = {
      deserializeChanges: (bytes: Uint8Array) => bytes,
    };
    document._keychain = {
      prepareMerge: (changes: Uint8Array) => ({
        changes,
        keyIds: [new Uint8Array(32).fill(7)],
        commit: keychainCommit,
      }),
    };
    document._kemKeyPair = recipientKeys;
    document._kemPublicKeyRaw = rawRecipient;
    document._beekem = null;
    document._beekemInitialized = false;
    document._writerMutationsInFlight = 0;
    document._writerKeysVersion = 0;
    document._cachedWriterKeys = ['writer'];
    document._writers = { users: async () => ['writer'] };

    let entered!: () => void;
    const processEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let release!: () => void;
    const processReleased = new Promise<void>((resolve) => {
      release = resolve;
    });
    const original = BeeKEM.prototype.processWelcome;
    const processSpy = jest
      .spyOn(BeeKEM.prototype, 'processWelcome')
      .mockImplementationOnce(async function (
        this: BeeKEM,
        incomingWelcome,
        privateKey,
        publicKey,
      ) {
        entered();
        await processReleased;
        return original.call(this, incomingWelcome, privateKey, publicKey);
      });
    try {
      const applying = document._evaluateAndApplyBeeKEMWelcome(
        {
          message: {
            documentId: '/legacy-welcome-barrier',
            welcomeEpochId: new Uint8Array(32).fill(7),
            welcomeRecipient: 'recipient',
            welcomeRecipientKemPublicKey: rawRecipient,
            eciesSealed: sealed,
            signature: 'AQ==',
          },
          writerAuthorities: {
            source: 'acl',
            writerKeysVersion: 0,
            authorities: [{ authorityId: 'writer', publicKey: 'writer' }],
          },
        },
        1,
      );
      await processEntered;
      document._cachedWriterKeys = null;
      document._writers = { users: async () => [] };
      document._writerKeysVersion++;
      release();

      await expect(applying).resolves.toBe(false);
      expect(keychainCommit).not.toHaveBeenCalled();
      expect(document._beekem).toBeNull();
      expect(document._beekemInitialized).toBe(false);
    } finally {
      processSpy.mockRestore();
    }
  });

  test('default policy drops U1, U2, and replayed U1 without ratchet or keychain mutation', async () => {
    const { recipient, first, second } = await legacyPathUpdateSequence();
    const beforeRoot = await recipient.getRootSecret();
    const beforeTree = await treeFingerprint(recipient);
    const { document, installedEpochs } = makeLegacyPathUpdateHarness(
      recipient,
      false,
      new Map([
        [1, first],
        [2, second],
      ]),
    );
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});

    try {
      await document.handleBeeKEMPathUpdateRequestData(
        new Uint8Array([1]),
        1,
      );
      await document.handleBeeKEMPathUpdateRequestData(
        new Uint8Array([2]),
        1,
      );
      await document.handleBeeKEMPathUpdateRequestData(
        new Uint8Array([1]),
        1,
      );

      expect(document._preauthenticateBeeKEMPathUpdate).not.toHaveBeenCalled();
      expect(document._keychain.prepareEpochKey).not.toHaveBeenCalled();
      expect(installedEpochs).toEqual([]);
      expect(recipient.generation).toBeNull();
      expect(await recipient.getRootSecret()).toEqual(beforeRoot);
      expect(await treeFingerprint(recipient)).toBe(beforeTree);
    } finally {
      warn.mockRestore();
    }
  });

  test('explicit insecure migration opt-in accepts a legacy v1 PathUpdate', async () => {
    const { recipient, first } = await legacyPathUpdateSequence();
    const beforeTree = await treeFingerprint(recipient);
    const { document, installedEpochs } = makeLegacyPathUpdateHarness(
      recipient,
      true,
      new Map([[1, first]]),
    );
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});

    try {
      await document.handleBeeKEMPathUpdateRequestData(
        new Uint8Array([1]),
        1,
      );

      expect(document._preauthenticateBeeKEMPathUpdate).toHaveBeenCalledTimes(1);
      expect(document._keychain.prepareEpochKey).toHaveBeenCalledTimes(1);
      expect(installedEpochs).toEqual([
        Buffer.from(first.epochId).toString('hex'),
      ]);
      expect(recipient.generation).toBeNull();
      expect(await recipient.getRootSecret()).toEqual(first.rootSecret);
      expect(await treeFingerprint(recipient)).not.toBe(beforeTree);
    } finally {
      warn.mockRestore();
      log.mockRestore();
    }
  });

  test('legacy opt-in does not admit an unknown runtime protocol version', async () => {
    const { recipient, first } = await legacyPathUpdateSequence();
    const beforeRoot = await recipient.getRootSecret();
    const beforeTree = await treeFingerprint(recipient);
    const { document, installedEpochs } = makeLegacyPathUpdateHarness(
      recipient,
      true,
      new Map([[1, first]]),
    );
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});

    try {
      await document.handleBeeKEMPathUpdateRequestData(
        new Uint8Array([1]),
        3 as never,
      );

      expect(document._preauthenticateBeeKEMPathUpdate).not.toHaveBeenCalled();
      expect(document._keychain.prepareEpochKey).not.toHaveBeenCalled();
      expect(installedEpochs).toEqual([]);
      expect(await recipient.getRootSecret()).toEqual(beforeRoot);
      expect(await treeFingerprint(recipient)).toBe(beforeTree);
    } finally {
      warn.mockRestore();
    }
  });
});
