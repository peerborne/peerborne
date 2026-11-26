import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';
import { SubtleCrypto } from './auth-subtlecrypto.js';
import { cloneInitialLoadChallenge } from './initial-load-challenge.js';
import { InitialLoadAuthenticationBudget } from './initial-load-auth.js';
import { createInitialLoadSignerLookup } from './initial-load-trust.js';
import { JSONSerializer } from './json-serializer.js';
import { loadAdvertisementHash } from './load-advertisement-hash.js';
import { LoadQuorumFailedError } from './load-quorum.js';
import { PeerborneDocument } from './peerborne-document.js';
import { tipsHashToHex } from './tips-hash.js';
import { fixtureLoadCommitments } from './__testutils__/load-session.js';
import { concatUint8Arrays } from './utils.js';
import { documentLoadV4, securityAdvertiseV1 } from './wire-protocols.js';

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

const documentPath = '/single-writer';
const keyId = new Uint8Array(32).fill(6);
const manifestHash = new Uint8Array(32).fill(4);
const synced = ['bafy-synced-frontier'];
const behind = ['bafy-behind-frontier'];
const address = (peerId: string) => `/ip4/10.0.0.1/tcp/1/p2p/${peerId}`;
const SOLE_WRITER = 'sole-writer-authority';
const SECOND_WRITER = 'second-writer-authority';

type Respond = (protocol: string, request: Uint8Array) => Promise<Uint8Array>;

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
  let closed!: () => void;
  const done = new Promise<void>((resolve) => {
    closed = resolve;
  });
  return {
    send: (chunk: Uint8Array) => {
      sent.push(new Uint8Array(chunk));
      return true;
    },
    onDrain: async () => undefined,
    close: async () => closed(),
    closeRead: async () => undefined,
    abort: () => undefined,
    async *[Symbol.asyncIterator]() {
      await done;
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

async function digestOf(frontier: string[]): Promise<string> {
  return tipsHashToHex(
    await loadAdvertisementHash(
      documentPath,
      frontier,
      fixtureLoadCommitments(),
      manifestHash,
    ),
  );
}

async function singleWriterFixture() {
  const provider = new SubtleCrypto();
  const serializer = new JSONSerializer<any>();
  const documentKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
  const loaderKeys = await signingKeys();
  const soleWriterKeys = await signingKeys();
  const secondWriterKeys = await signingKeys();
  const readerKeys = await signingKeys();

  function holder(
    peerId: string,
    authority: string,
    keys: CryptoKeyPair,
    frontier: string[],
  ) {
    const node = {
      frontier,
      document: Object.assign(Object.create(PeerborneDocument.prototype), {
        documentPath,
        swarm: {
          config: {},
          heliaNode: { libp2p: { peerId: { toString: () => peerId } } },
        },
        _mutationQueue: {
          run: (operation: () => Promise<unknown>) => operation(),
        },
        _bootstrapLoadApplicationRevision: 0,
        _writerKeysVersion: 0,
        _writerMutationsInFlight: 0,
        _authProvider: provider,
        _userKey: keys.privateKey,
        _readers: { users: async () => [loaderKeys.publicKey] },
        _writers: { users: async () => [keys.publicKey] },
        _keychain: { current: async () => [keyId, documentKey] },
        _syncMessageSerializer: serializer,
      }) as any,
    };
    node.document._createLoadResponsePlan = async (request: any) => ({
      documentId: documentPath,
      signatureContext: 'load-response-v4',
      tips: [...node.frontier],
      loadChallenge: cloneInitialLoadChallenge(request.loadChallenge),
      loadSecurityState: fixtureLoadCommitments(),
      signerAuthority: authority,
    });
    node.document._loadResponseManifestHash = async () => manifestHash;
    return node;
  }

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
    await node.document.handleSecurityAdvertiseRequestData(request, stream);
    return concatUint8Arrays(...stream.chunks);
  }

  const responders = new Map<string, Respond>();
  const device = (peerId: string, frontier = synced) => {
    const node = holder(peerId, SOLE_WRITER, soleWriterKeys, frontier);
    responders.set(address(peerId), (protocol, request) =>
      serve(node, protocol, request),
    );
    return node;
  };
  const secondWriter = (peerId: string, frontier = synced) => {
    const node = holder(peerId, SECOND_WRITER, secondWriterKeys, frontier);
    responders.set(address(peerId), (protocol, request) =>
      serve(node, protocol, request),
    );
    return node;
  };
  const reader = (peerId: string, claimedAuthority: string) => {
    const node = holder(peerId, claimedAuthority, readerKeys, synced);
    responders.set(address(peerId), (protocol, request) =>
      serve(node, protocol, request),
    );
    return node;
  };
  responders.set(address('relay'), async () => new Uint8Array(0));

  const trusted = [
    { authorityId: SOLE_WRITER, publicKey: soleWriterKeys.publicKey },
  ];
  const loads: Array<{ peerId: string; expected: string | null }> = [];
  const loadOutcome = jest.fn(async (_peerId: string) => true);
  const loader = Object.assign(Object.create(PeerborneDocument.prototype), {
    documentPath,
    swarm: {
      config: {},
      heliaNode: {
        libp2p: {
          peerId: { toString: () => 'fresh-device' },
          getConnections: () =>
            [...responders.keys()].map((remote) => ({
              remoteAddr: { toString: () => remote },
              remotePeer: { toString: () => remote.split('/').at(-1) },
            })),
          dialProtocol: async (
            peer: { toString(): string },
            protocols: string[],
          ) =>
            protocols[0] === securityAdvertiseV1
              ? clientStream(protocols[0], responders.get(peer.toString())!)
              : {
                  peerId: peer.toString().split('/').at(-1),
                  protocol: protocols[0],
                },
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
        id.length === keyId.length &&
        id.every((byte, index) => byte === keyId[index])
          ? documentKey
          : undefined,
    },
  }) as any;
  loader._captureLoadSession = async () =>
    Object.freeze({
      authorities: [...trusted],
      trustedSigners: createInitialLoadSignerLookup(trusted),
      authenticationBudget: new InitialLoadAuthenticationBudget(),
      writerVersion: 0,
      bootstrap: true,
      context: 'load-response-v4',
      commitments: fixtureLoadCommitments(),
    });
  loader._sendLoadRequestAndSync = jest.fn(
    async (
      _session: unknown,
      stream: { peerId: string; protocol: string },
      _request: Uint8Array,
      expected: string | null,
    ) => {
      expect(stream.protocol).toBe(documentLoadV4);
      loads.push({ peerId: stream.peerId, expected });
      return loadOutcome(stream.peerId);
    },
  );

  return {
    device,
    secondWriter,
    reader,
    loader,
    loads,
    loadOutcome,
    responders,
    serve,
    trustSecondWriter: () =>
      trusted.push({
        authorityId: SECOND_WRITER,
        publicKey: secondWriterKeys.publicKey,
      }),
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

describe('initial load of a single-writer document', () => {
  test('a fresh device loads from one device of the sole writer behind a relay with the default config', async () => {
    const fixture = await singleWriterFixture();
    fixture.device('laptop');

    await expect(fixture.loader.load()).resolves.toBe(true);
    expect(fixture.loads).toEqual([
      { peerId: 'laptop', expected: await digestOf(synced) },
    ]);
  });

  test('agreeing devices of the sole writer pass without a second authority', async () => {
    const fixture = await singleWriterFixture();
    fixture.device('laptop');
    fixture.device('phone');

    await expect(fixture.loader.load()).resolves.toBe(true);
    expect(fixture.loads).toHaveLength(1);
    expect(['laptop', 'phone']).toContain(fixture.loads[0].peerId);
    expect(fixture.loads[0].expected).toBe(await digestOf(synced));
  });

  test('out-of-sync devices do not abort the load; each is bound to the state it advertised', async () => {
    const fixture = await singleWriterFixture();
    fixture.device('laptop', synced);
    fixture.device('phone', behind);
    fixture.loadOutcome.mockResolvedValueOnce(false);

    await expect(fixture.loader.load()).resolves.toBe(true);
    expect(fixture.loads).toHaveLength(2);
    const expected = new Map([
      ['laptop', await digestOf(synced)],
      ['phone', await digestOf(behind)],
    ]);
    for (const { peerId, expected: digest } of fixture.loads) {
      expect(digest).toBe(expected.get(peerId));
    }
    expect(new Set(fixture.loads.map(({ peerId }) => peerId))).toEqual(
      new Set(['laptop', 'phone']),
    );
  });

  test('the state most devices advertise is loaded first', async () => {
    const fixture = await singleWriterFixture();
    fixture.responders.delete(address('relay'));
    fixture.device('laptop', synced);
    fixture.device('phone', behind);
    fixture.device('tablet', synced);

    await expect(fixture.loader.load()).resolves.toBe(true);
    expect(fixture.loads).toHaveLength(1);
    expect(['laptop', 'tablet']).toContain(fixture.loads[0].peerId);
    expect(fixture.loads[0].expected).toBe(await digestOf(synced));
  });

  test.each([
    ['its own authority', 'reader-authority'],
    ["the writer's authority", SOLE_WRITER],
  ])(
    'a non-writer response claiming %s is not a vote',
    async (_label, claimedAuthority) => {
      const fixture = await singleWriterFixture();
      fixture.reader('reader', claimedAuthority);

      const failure = await fixture.loader
        .load()
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(LoadQuorumFailedError);
      expect(failure).toMatchObject({
        reason: 'insufficient-responses',
        respondingCount: 0,
        requiredQ: 1,
      });
      expect(fixture.loads).toEqual([]);

      fixture.device('laptop');
      await expect(fixture.loader.load()).resolves.toBe(true);
      expect(fixture.loads).toEqual([
        { peerId: 'laptop', expected: await digestOf(synced) },
      ]);
    },
  );

  test('a response replayed from an earlier load is not a vote', async () => {
    const fixture = await singleWriterFixture();
    const laptop = fixture.device('laptop');
    let recorded = new Uint8Array(0);
    fixture.responders.set(address('laptop'), async (protocol, request) => {
      recorded = await fixture.serve(laptop, protocol, request);
      return recorded;
    });
    await expect(fixture.loader.load()).resolves.toBe(true);
    expect(recorded.length).toBeGreaterThan(0);

    fixture.responders.set(address('laptop'), async () => recorded);
    fixture.loads.length = 0;
    await expect(fixture.loader.load()).rejects.toMatchObject({
      name: 'LoadQuorumFailedError',
      reason: 'insufficient-responses',
      requiredQ: 1,
    });
    expect(fixture.loads).toEqual([]);
  });

  test('a document with two trusted writers still needs both authorities', async () => {
    const fixture = await singleWriterFixture();
    fixture.responders.delete(address('relay'));
    fixture.trustSecondWriter();
    fixture.device('laptop');
    fixture.device('phone');

    await expect(fixture.loader.load()).rejects.toMatchObject({
      name: 'LoadQuorumFailedError',
      reason: 'insufficient-responses',
      respondingCount: 1,
      requiredQ: 2,
    });
    expect(fixture.loads).toEqual([]);

    fixture.secondWriter('desktop');
    await expect(fixture.loader.load()).resolves.toBe(true);
    expect(fixture.loads).toHaveLength(1);
    expect(fixture.loads[0].expected).toBe(await digestOf(synced));
  });
});
