import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import { cloneInitialLoadChallenge } from './initial-load-challenge.js';
import { InitialLoadAuthenticationBudget } from './initial-load-auth.js';
import { createInitialLoadSignerLookup } from './initial-load-trust.js';
import { JSONSerializer } from './json-serializer.js';
import { LoadQuorumFailedError } from './load-quorum.js';
import { PeerborneDocument } from './peerborne-document.js';
import { fixtureLoadCommitments } from './__testutils__/load-session.js';
import { concatUint8Arrays } from './utils.js';
import {
  documentLoadV4,
  securityAdvertiseV1,
  snapshotLoadV4,
} from './wire-protocols.js';

jest.mock(
  'it-pipe',
  () => ({
    pipe: async (...stages: unknown[]) => {
      let value = stages[0];
      for (const stage of stages.slice(1)) {
        value = await (stage as (input: unknown) => unknown)(value);
      }
      return value;
    },
  }),
  { virtual: true },
);
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

const documentPath = '/responder-binding';
const keyId = new Uint8Array(32).fill(6);
const relayAddress = '/ip4/10.0.0.1/tcp/1/p2p/relay';
const writerOneAddress = '/ip4/10.0.0.2/tcp/1/p2p/writer-one';
const writerTwoAddress = '/ip4/10.0.0.3/tcp/1/p2p/writer-two';
const oldFrontier = ['bafy-old-frontier'];
const newFrontier = ['bafy-new-frontier'];
const handlers: Record<string, string> = {
  [documentLoadV4]: 'handleLoadRequestData',
  [snapshotLoadV4]: 'handleSnapshotLoadRequestData',
  [securityAdvertiseV1]: 'handleSecurityAdvertiseRequestData',
};

type Respond = (protocol: string, request: Uint8Array) => Promise<Uint8Array>;

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function collectingStream() {
  const chunks: Uint8Array[] = [];
  return {
    chunks,
    send: (chunk: Uint8Array) => {
      chunks.push(new Uint8Array(chunk));
      return true;
    },
    onDrain: async () => undefined,
    close: async () => undefined,
  };
}

function clientStream(protocol: string, respond: Respond) {
  const sent: Uint8Array[] = [];
  const closed = deferred();
  return {
    send: (chunk: Uint8Array) => {
      sent.push(new Uint8Array(chunk));
      return true;
    },
    onDrain: async () => undefined,
    close: async () => closed.resolve(),
    closeRead: async () => undefined,
    abort: () => undefined,
    async *[Symbol.asyncIterator]() {
      await closed.promise;
      const response = await respond(protocol, concatUint8Arrays(...sent));
      if (response.length > 0) yield response;
    },
  };
}

async function signingKeys(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
}

type Fixture = Awaited<ReturnType<typeof networkFixture>>;

async function networkFixture() {
  const provider = new SubtleCrypto();
  const serializer = new JSONSerializer<any>();
  const documentKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
  const loaderKeys = await signingKeys();
  const writerOneKeys = await signingKeys();
  const writerTwoKeys = await signingKeys();

  function writerNode(peerId: string, authority: string, keys: CryptoKeyPair) {
    const node = {
      frontier: oldFrontier,
      plans: 0,
      document: Object.assign(Object.create(PeerborneDocument.prototype), {
        documentPath,
        swarm: {
          config: {},
          heliaNode: { libp2p: { peerId: { toString: () => peerId } } },
        },
        _mutationQueue: { run: (operation: () => Promise<unknown>) => operation() },
        _bootstrapLoadApplicationRevision: 0,
        _writerKeysVersion: 0,
        _writerMutationsInFlight: 0,
        _authProvider: provider,
        _userKey: keys.privateKey,
        _readers: { users: async () => [loaderKeys.publicKey] },
        _writers: { users: async () => [writerOneKeys.publicKey, writerTwoKeys.publicKey] },
        _keychain: { current: async () => [keyId, documentKey] },
        _syncMessageSerializer: serializer,
        _latestSnapshot: { lastChangeNodeCID: 'bafy-snapshot' },
      }) as any,
    };
    node.document._createLoadResponsePlan = async (request: any) => {
      node.plans++;
      return {
        documentId: documentPath,
        signatureContext: 'load-response-v4',
        tips: [...node.frontier],
        loadChallenge: cloneInitialLoadChallenge(request.loadChallenge),
        loadSecurityState: fixtureLoadCommitments(),
        signerAuthority: authority,
      };
    };
    node.document._loadResponseManifestHash = async () => new Uint8Array(32).fill(4);
    return node;
  }

  const writerOne = writerNode('writer-one', 'writer-one-authority', writerOneKeys);
  const writerTwo = writerNode('writer-two', 'writer-two-authority', writerTwoKeys);
  writerTwo.frontier = newFrontier;

  async function serve(
    node: { document: any },
    protocol: string,
    requestBytes: Uint8Array,
  ): Promise<Uint8Array> {
    let request;
    try {
      request = serializer.deserializeLoadRequest(requestBytes);
    } catch {
      return new Uint8Array(0);
    }
    const stream = collectingStream();
    await node.document[handlers[protocol]](request, stream);
    return concatUint8Arrays(...stream.chunks);
  }

  const relayed = deferred();
  const relayedResponses: Uint8Array[] = [];
  const responders = new Map<string, Respond>([
    [
      relayAddress,
      async (protocol, request) => {
        try {
          const response = await serve(writerOne, protocol, request);
          relayedResponses.push(response);
          return response;
        } finally {
          writerOne.frontier = newFrontier;
          relayed.resolve();
        }
      },
    ],
    [
      writerOneAddress,
      async (protocol, request) => {
        await relayed.promise;
        return serve(writerOne, protocol, request);
      },
    ],
    [writerTwoAddress, (protocol, request) => serve(writerTwo, protocol, request)],
  ]);

  const authorities = [
    { authorityId: 'writer-one-authority', publicKey: writerOneKeys.publicKey },
    { authorityId: 'writer-two-authority', publicKey: writerTwoKeys.publicKey },
  ];
  const loadedFrom: string[] = [];
  const loader = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    swarm: {
      config: { loadQuorumK: 3, loadQuorumQ: 2, loadQuorumTimeoutMs: 5000 },
      heliaNode: {
        libp2p: {
          peerId: { toString: () => 'loader' },
          getConnections: () =>
            [...responders.keys()].map((address) => ({
              remoteAddr: { toString: () => address },
              remotePeer: { toString: () => address.split('/').at(-1) },
            })),
          dialProtocol: async (peer: { toString(): string }, protocols: string[]) =>
            protocols[0] === securityAdvertiseV1
              ? clientStream(protocols[0], responders.get(peer.toString())!)
              : { peer: peer.toString() },
        },
      },
    },
    _mutationQueue: { run: (operation: () => Promise<unknown>) => operation() },
    _writerKeysVersion: 0,
    _writerMutationsInFlight: 0,
    _compactionConfig: { enabled: false },
    _authProvider: provider,
    _userKey: loaderKeys.privateKey,
    _loadMessageSerializer: serializer,
    _syncMessageSerializer: serializer,
    _keychainProvider: { keyIDLength: keyId.length },
    _keychain: {
      getKey: (id: Uint8Array) =>
        id.length === keyId.length && id.every((byte, index) => byte === keyId[index])
          ? documentKey
          : undefined,
    },
  }) as any;
  loader._captureLoadSession = async () =>
    Object.freeze({
      authorities,
      trustedSigners: createInitialLoadSignerLookup(authorities),
      authenticationBudget: new InitialLoadAuthenticationBudget(),
      writerVersion: 0,
      bootstrap: false,
      context: 'load-response-v4',
      commitments: fixtureLoadCommitments(),
    });
  loader._sendLoadRequestAndSync = jest.fn(
    async (_session: unknown, stream: { peer?: string }) => {
      loadedFrom.push(String(stream.peer));
      return true;
    },
  );

  async function signedRequest(responder: string): Promise<Uint8Array> {
    const session = loader._addressLoadSession(
      await loader._captureLoadSession(),
      responder,
    );
    return loader._serializeInitialLoadRequest(session);
  }

  return {
    loader,
    loadedFrom,
    relayedResponses,
    responders,
    serializer,
    serve,
    signedRequest,
    writerOne,
    writerTwo,
  };
}

let consoleSpies: Array<{ mockRestore(): void }>;

beforeEach(() => {
  consoleSpies = [
    jest.spyOn(console, 'warn').mockImplementation(() => undefined),
    jest.spyOn(console, 'error').mockImplementation(() => undefined),
    jest.spyOn(console, 'log').mockImplementation(() => undefined),
  ];
});

afterEach(() => {
  for (const spy of consoleSpies) spy.mockRestore();
});

describe('initial-load responder binding', () => {
  test('a keyless relay cannot turn a writer state change into an equivocation abort', async () => {
    const fixture: Fixture = await networkFixture();

    let failure: unknown;
    const loaded = await fixture.loader.load().catch((error: unknown) => {
      failure = error;
      return undefined;
    });

    expect(
      failure instanceof LoadQuorumFailedError ? failure.reason : failure,
    ).toBeUndefined();
    expect(loaded).toBe(true);
    expect(fixture.relayedResponses).toEqual([new Uint8Array(0)]);
    expect(fixture.writerOne.plans).toBe(1);
    expect(fixture.loadedFrom).not.toContain(relayAddress);
    expect(fixture.loadedFrom[0]).toMatch(/writer-(one|two)$/);
  });

  test('a forwarded copy of a writer answer cannot occupy the relay probe slot', async () => {
    const fixture: Fixture = await networkFixture();
    fixture.writerOne.frontier = newFrontier;
    const writerOneAnswer = deferred();
    let writerOneResponse = new Uint8Array(0);
    fixture.responders.set(writerOneAddress, async (protocol, request) => {
      writerOneResponse = await fixture.serve(fixture.writerOne, protocol, request);
      writerOneAnswer.resolve();
      return writerOneResponse;
    });
    fixture.responders.set(relayAddress, async () => {
      await writerOneAnswer.promise;
      return writerOneResponse;
    });

    await expect(fixture.loader.load('relay')).resolves.toBe(true);

    expect(writerOneResponse.length).toBeGreaterThan(0);
    expect(fixture.loadedFrom).not.toContain(relayAddress);
    expect(fixture.loadedFrom[0]).toMatch(/writer-(one|two)$/);
  });

  test.each([documentLoadV4, snapshotLoadV4, securityAdvertiseV1])(
    '%s refuses a request addressed to another responder',
    async (protocol) => {
      const fixture: Fixture = await networkFixture();
      const misaddressed = await fixture.signedRequest('relay');

      await expect(
        fixture.serve(fixture.writerOne, protocol, misaddressed),
      ).resolves.toEqual(new Uint8Array(0));
      expect(fixture.writerOne.plans).toBe(0);

      const addressed = await fixture.signedRequest('writer-one');
      await fixture.serve(fixture.writerOne, protocol, addressed);
      expect(fixture.writerOne.plans).toBe(1);
    },
  );

  test.each([documentLoadV4, snapshotLoadV4, securityAdvertiseV1])(
    '%s refuses a relay that rewrites the signed responder',
    async (protocol) => {
      const fixture: Fixture = await networkFixture();
      const wire = JSON.parse(
        new TextDecoder().decode(await fixture.signedRequest('relay')),
      );
      const rewritten = new TextEncoder().encode(
        JSON.stringify({ ...wire, responder: 'writer-one' }),
      );

      await expect(
        fixture.serve(fixture.writerOne, protocol, rewritten),
      ).resolves.toEqual(new Uint8Array(0));
      expect(fixture.writerOne.plans).toBe(0);
    },
  );

  test.each([documentLoadV4, snapshotLoadV4, securityAdvertiseV1])(
    '%s refuses a request replayed to a second responder',
    async (protocol) => {
      const fixture: Fixture = await networkFixture();
      const request = await fixture.signedRequest('writer-one');

      await fixture.serve(fixture.writerOne, protocol, request);
      expect(fixture.writerOne.plans).toBe(1);
      await expect(
        fixture.serve(fixture.writerTwo, protocol, request),
      ).resolves.toEqual(new Uint8Array(0));
      expect(fixture.writerTwo.plans).toBe(0);
    },
  );

  test('a writer without a libp2p PeerId refuses every addressed request', async () => {
    const fixture: Fixture = await networkFixture();
    fixture.writerOne.document.swarm.heliaNode.libp2p.peerId = undefined;

    await expect(
      fixture.serve(
        fixture.writerOne,
        securityAdvertiseV1,
        await fixture.signedRequest('writer-one'),
      ),
    ).resolves.toEqual(new Uint8Array(0));
    expect(fixture.writerOne.plans).toBe(0);
  });

  test('each responder receives a distinct challenge and signature', async () => {
    const fixture: Fixture = await networkFixture();
    const relay = fixture.serializer.deserializeLoadRequest(
      await fixture.signedRequest('relay'),
    );
    const writer = fixture.serializer.deserializeLoadRequest(
      await fixture.signedRequest('writer-one'),
    );

    expect(relay.responder).toBe('relay');
    expect(writer.responder).toBe('writer-one');
    expect(relay.loadChallenge).not.toEqual(writer.loadChallenge);
    expect(relay.signature).not.toBe(writer.signature);
  });
});
