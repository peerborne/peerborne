import { describe, expect, jest, test } from '@jest/globals';
import { Peerborne } from './peerborne.js';
import type { PeerborneConfig } from './peerborne-config.js';
import { createAndStartHeliaNode } from './helia-node.js';
import {
  beekemPathUpdateV1,
  beekemPathUpdateV2,
} from './wire-protocols.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock('@libp2p/peer-id', () => ({ peerIdFromString: jest.fn() }), {
  virtual: true,
});
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./peerborne-config.js', () => ({
  defaultBootstrapConfig: jest.fn(),
  defaultConfig: jest.fn(),
}));
jest.mock('./peerborne-document.js', () => ({ PeerborneDocument: class {} }));
jest.mock('./helia-node.js', () => ({
  createAndStartHeliaNode: jest.fn(),
}));

const mockCreateAndStartHeliaNode = jest.mocked(createAndStartHeliaNode);

function makePeerborne(): Peerborne<
  unknown,
  unknown,
  unknown,
  unknown,
  unknown,
  unknown
> {
  const peerborne = new Peerborne(
    {},
    {},
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
  );
  (peerborne as any)._registerSharedProtocolHandlers = jest.fn(
    async () => undefined,
  );
  return peerborne;
}

describe('Peerborne initialization security policy', () => {
  test('caller config mutation cannot downgrade captured policy or its effective config view', async () => {
    const libp2p = {
      addEventListener: jest.fn(),
      peerId: { toString: () => 'peer-id' },
    };
    mockCreateAndStartHeliaNode.mockResolvedValueOnce({
      heliaNode: { libp2p } as never,
      openedLegacyStores: [],
    });
    const trustedWriterResolver = () => [];
    const securityCommitmentResolver = () => ({
      version: 1 as const,
      controlHead: new Uint8Array(32),
      groupId: 'group',
      epoch: 0n,
      treeHash: new Uint8Array(32),
      confirmedTranscriptHash: new Uint8Array(32),
    });
    const documentPathValidator = () => false;
    const config = {
      pubsubDocumentPrefix: '/peerborne/doc/',
      pubsubDocumentPublishPath: '/documents',
      enableSigning: true,
      enableTopicValidators: true,
      allowInsecureLegacyBeeKEMPathUpdateV1: true,
      loadQuorumEnabled: true,
      loadQuorumK: 5,
      loadQuorumQ: 4,
      loadQuorumTimeoutMs: 4000,
      loadQuorumAllowSinglePeer: false,
      requireAuthenticatedInitialLoad: true,
      requireSecurityStateQuorum: true,
      resolveTrustedDocumentWriters: trustedWriterResolver,
      resolveLoadSecurityCommitments: securityCommitmentResolver,
      validateDocumentPath: documentPathValidator,
    } as PeerborneConfig;
    const peerborne = makePeerborne();

    await peerborne.initialize(config);
    config.enableSigning = false;
    config.enableTopicValidators = false;
    config.allowInsecureLegacyBeeKEMPathUpdateV1 = false;
    config.loadQuorumEnabled = false;
    config.loadQuorumK = 1;
    config.loadQuorumQ = 1;
    config.loadQuorumTimeoutMs = 1;
    config.loadQuorumAllowSinglePeer = true;
    config.requireAuthenticatedInitialLoad = false;
    config.requireSecurityStateQuorum = false;
    config.resolveTrustedDocumentWriters = () => ['attacker'];
    config.resolveLoadSecurityCommitments = () => ({
      version: 1,
      controlHead: new Uint8Array(32).fill(1),
      groupId: 'attacker',
      epoch: 1n,
      treeHash: new Uint8Array(32).fill(1),
      confirmedTranscriptHash: new Uint8Array(32).fill(1),
    });
    config.validateDocumentPath = () => true;
    config.pubsubDocumentPrefix = '/attacker/';

    expect(peerborne.config).not.toBe(config);
    expect(Object.isFrozen(peerborne.config)).toBe(true);
    expect(peerborne.config).toEqual(
      expect.objectContaining({
        pubsubDocumentPrefix: '/peerborne/doc/',
        pubsubDocumentPublishPath: '/documents',
        enableSigning: true,
        enableTopicValidators: true,
        allowInsecureLegacyBeeKEMPathUpdateV1: true,
        loadQuorumEnabled: true,
        loadQuorumK: 5,
        loadQuorumQ: 4,
        loadQuorumTimeoutMs: 4000,
        loadQuorumAllowSinglePeer: false,
        requireAuthenticatedInitialLoad: true,
        requireSecurityStateQuorum: true,
        resolveTrustedDocumentWriters: trustedWriterResolver,
        resolveLoadSecurityCommitments: securityCommitmentResolver,
        validateDocumentPath: documentPathValidator,
      }),
    );
    expect(Reflect.set(peerborne.config!, 'enableSigning', false)).toBe(false);
    expect(peerborne.enableSigning).toBe(true);
    expect(peerborne.enableTopicValidators).toBe(true);
    expect(peerborne.allowInsecureLegacyBeeKEMPathUpdateV1).toBe(true);
    expect(peerborne.loadQuorumEnabled).toBe(true);
    expect(peerborne.loadQuorumK).toBe(5);
    expect(peerborne.loadQuorumQ).toBe(4);
    expect(peerborne.loadQuorumTimeoutMs).toBe(4000);
    expect(peerborne.loadQuorumAllowSinglePeer).toBe(false);
    expect(peerborne.requireAuthenticatedInitialLoad).toBe(true);
    expect(peerborne.requireSecurityStateQuorum).toBe(true);
    expect(peerborne.resolveTrustedDocumentWriters).toBe(
      trustedWriterResolver,
    );
    expect(peerborne.resolveLoadSecurityCommitments).toBe(
      securityCommitmentResolver,
    );
    expect(peerborne.validateDocumentPath).toBe(documentPathValidator);

    const document = {
      documentPath: '/captured-policy',
      historyVisibility: 'full_history',
      assertCanCreateInitialInvitation: jest.fn(async () => {
        throw new Error('captured signing policy used');
      }),
    };
    (peerborne as any)._documentRegistry.set(document.documentPath, document);
    await expect(
      peerborne.createInvitationForDocument(document as never, {
        role: 'reader',
        rendezvous: ['/ip4/127.0.0.1/tcp/1/p2p/test'],
      }),
    ).rejects.toThrow('captured signing policy used');
    await expect(
      peerborne.acceptInvitation(new Uint8Array(), {} as CryptoKeyPair),
    ).rejects.not.toThrow(/application-level signing/);
  });

  test('caller config mutation cannot enable invitation signing', async () => {
    const libp2p = {
      addEventListener: jest.fn(),
      peerId: { toString: () => 'peer-id' },
    };
    mockCreateAndStartHeliaNode.mockResolvedValueOnce({
      heliaNode: { libp2p } as never,
      openedLegacyStores: [],
    });
    const config = { enableSigning: false } as PeerborneConfig;
    const peerborne = makePeerborne();

    await peerborne.initialize(config);
    config.enableSigning = true;

    expect(peerborne.config).not.toBe(config);
    expect(peerborne.config?.enableSigning).toBe(false);
    expect(peerborne.config?.enableTopicValidators).toBe(false);
    expect(peerborne.config?.allowInsecureLegacyBeeKEMPathUpdateV1).toBe(false);
    expect(peerborne.config?.loadQuorumEnabled).toBe(true);
    expect(peerborne.config?.loadQuorumK).toBe(3);
    expect(peerborne.config?.loadQuorumTimeoutMs).toBe(5000);

    const document = {
      documentPath: '/captured-disabled-policy',
      historyVisibility: 'full_history',
      assertCanCreateInitialInvitation: jest.fn(async () => undefined),
    };
    (peerborne as any)._documentRegistry.set(document.documentPath, document);
    await expect(
      peerborne.createInvitationForDocument(document as never, {
        role: 'reader',
        rendezvous: ['/ip4/127.0.0.1/tcp/1/p2p/test'],
      }),
    ).rejects.toThrow(/application-level signing/);
    expect(document.assertCanCreateInitialInvitation).not.toHaveBeenCalled();
    await expect(
      peerborne.acceptInvitation(new Uint8Array(), {} as CryptoKeyPair),
    ).rejects.toThrow(/application-level signing/);
  });

  test('normalizes topic validators off when message signing is disabled', async () => {
    const libp2p = {
      addEventListener: jest.fn(),
      peerId: { toString: () => 'peer-id' },
    };
    mockCreateAndStartHeliaNode.mockResolvedValueOnce({
      heliaNode: { libp2p } as never,
      openedLegacyStores: [],
    });
    const peerborne = makePeerborne();

    await peerborne.initialize({
      enableSigning: false,
      enableTopicValidators: true,
    } as PeerborneConfig);

    expect(peerborne.enableSigning).toBe(false);
    expect(peerborne.enableTopicValidators).toBe(false);
    expect(peerborne.allowInsecureLegacyBeeKEMPathUpdateV1).toBe(false);
    expect(peerborne.config?.enableTopicValidators).toBe(false);
  });

  test.each([
    [false, false],
    [true, true],
  ])(
    'registers legacy BeeKEM PathUpdate v1 only with explicit opt-in=%p',
    async (allowLegacyV1, expectedRegistered) => {
      const handle = jest.fn(async () => undefined);
      const libp2p = {
        addEventListener: jest.fn(),
        handle,
        peerId: { toString: () => 'peer-id' },
      };
      mockCreateAndStartHeliaNode.mockResolvedValueOnce({
        heliaNode: { libp2p } as never,
        openedLegacyStores: [],
      });
      const peerborne = makePeerborne();

      await peerborne.initialize({
        allowInsecureLegacyBeeKEMPathUpdateV1: allowLegacyV1,
      } as PeerborneConfig);
      await (Peerborne.prototype as any)._registerSharedProtocolHandlers.call(
        peerborne,
      );

      const protocols = handle.mock.calls.map(([protocol]) => protocol);
      expect(protocols).toContain(beekemPathUpdateV2);
      expect(protocols.includes(beekemPathUpdateV1)).toBe(expectedRegistered);
    },
  );

  test('rejects accessor-backed security policy fields without invoking them', async () => {
    const getter = jest.fn(() => true);
    const config = Object.defineProperty(
      {
        pubsubDocumentPrefix: '/peerborne/doc/',
        pubsubDocumentPublishPath: '/peerborne/doc/',
      },
      'requireAuthenticatedInitialLoad',
      {
        enumerable: true,
        get: getter,
      },
    ) as PeerborneConfig;
    const peerborne = makePeerborne();
    const createCallsBefore = mockCreateAndStartHeliaNode.mock.calls.length;

    await expect(peerborne.initialize(config)).rejects.toThrow(
      /requireAuthenticatedInitialLoad must be an own data property/,
    );
    expect(getter).not.toHaveBeenCalled();
    expect(mockCreateAndStartHeliaNode).toHaveBeenCalledTimes(
      createCallsBefore,
    );
  });

  test('validates and installs one descriptor snapshot from a stateful config Proxy', async () => {
    const libp2p = {
      addEventListener: jest.fn(),
      peerId: { toString: () => 'peer-id' },
    };
    mockCreateAndStartHeliaNode.mockResolvedValueOnce({
      heliaNode: { libp2p } as never,
      openedLegacyStores: [],
    });
    const trustedWriterResolver = () => [];
    const securityCommitmentResolver = () => ({
      version: 1 as const,
      controlHead: new Uint8Array(32),
      groupId: 'group',
      epoch: 0n,
      treeHash: new Uint8Array(32),
      confirmedTranscriptHash: new Uint8Array(32),
    });
    const target = {
      pubsubDocumentPrefix: '/peerborne/doc/',
      pubsubDocumentPublishPath: '/peerborne/doc/',
      enableSigning: true,
      loadQuorumEnabled: true,
      loadQuorumK: 5,
      loadQuorumQ: 4,
      loadQuorumTimeoutMs: 4000,
      loadQuorumAllowSinglePeer: false,
      requireAuthenticatedInitialLoad: true,
      requireSecurityStateQuorum: true,
      resolveTrustedDocumentWriters: trustedWriterResolver,
      resolveLoadSecurityCommitments: securityCommitmentResolver,
    } satisfies PeerborneConfig;
    const policyFields = new Set([
      'enableSigning',
      'loadQuorumEnabled',
      'loadQuorumK',
      'loadQuorumQ',
      'loadQuorumTimeoutMs',
      'loadQuorumAllowSinglePeer',
      'requireAuthenticatedInitialLoad',
      'requireSecurityStateQuorum',
      'resolveTrustedDocumentWriters',
      'resolveLoadSecurityCommitments',
    ]);
    let policyReads = 0;
    const config = new Proxy(target, {
      get(object, property, receiver) {
        if (typeof property === 'string' && policyFields.has(property)) {
          policyReads++;
          if (property.startsWith('resolve')) return () => [];
          return false;
        }
        return Reflect.get(object, property, receiver);
      },
    });
    const peerborne = makePeerborne();

    await peerborne.initialize(config);

    expect(policyReads).toBe(0);
    expect(peerborne.config).not.toBe(config);
    expect(Object.isFrozen(peerborne.config)).toBe(true);
    expect(peerborne.config?.enableSigning).toBe(true);
    expect(peerborne.config?.loadQuorumK).toBe(5);
    expect(peerborne.config?.resolveTrustedDocumentWriters).toBe(
      trustedWriterResolver,
    );
    expect(peerborne.enableSigning).toBe(true);
    expect(peerborne.loadQuorumEnabled).toBe(true);
    expect(peerborne.loadQuorumK).toBe(5);
    expect(peerborne.loadQuorumQ).toBe(4);
    expect(peerborne.loadQuorumTimeoutMs).toBe(4000);
    expect(peerborne.loadQuorumAllowSinglePeer).toBe(false);
    expect(peerborne.requireAuthenticatedInitialLoad).toBe(true);
    expect(peerborne.requireSecurityStateQuorum).toBe(true);
    expect(peerborne.resolveTrustedDocumentWriters).toBe(
      trustedWriterResolver,
    );
    expect(peerborne.resolveLoadSecurityCommitments).toBe(
      securityCommitmentResolver,
    );
  });
});
