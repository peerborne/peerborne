import { afterEach, describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  decodeDocumentCatchUpCheckpoint,
  decodeDocumentCatchUpRequest,
  decodeDocumentTopicCatchUpRequest,
  decodeEncryptedDocumentCatchUp,
  documentCatchUpAAD,
  encodeDocumentCatchUpCheckpoint,
  encodeDocumentTopicCatchUpRequest,
  encodeEncryptedDocumentCatchUp,
  isDocumentCatchUpCheckpointFrame,
  isDocumentCatchUpRequestFrame,
  MAX_DOCUMENT_CATCH_UP_TOPIC_REQUEST_BYTES,
  type DocumentCatchUpBinding,
  type DocumentTopicCatchUpRequest,
} from './document-catch-up-wire.js';
import { isDocumentRedeliveryFrame } from './document-redelivery-wire.js';
import {
  encodeEncryptedDocumentContent,
  encodeSignedDocumentContent,
} from './document-security-wire.js';
import { testCRDT, testChanges } from './__testutils__/coordinated-document.js';
import {
  coordinatedGroupFixture,
  groupPeer,
} from './__testutils__/coordinated-group.js';
import {
  floodUntil,
  joinCatchUpScenario,
  missedWindowCatchUpScenario,
} from './__testutils__/coordinated-scenarios.js';
import { id, publicState } from './__testutils__/group-security-coordinator.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('libp2p', () => ({}), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({
    TopicValidatorResult: {
      Accept: 'accept',
      Ignore: 'ignore',
      Reject: 'reject',
    },
  }),
  { virtual: true },
);
jest.mock('@libp2p/peer-id', () => ({ peerIdFromString: jest.fn() }), {
  virtual: true,
});
jest.mock('@multiformats/multiaddr', () => ({ multiaddr: jest.fn() }), {
  virtual: true,
});
jest.mock('./helia-node.js', () => ({ createAndStartHeliaNode: jest.fn() }));
jest.mock('./peerborne-config.js', () => ({
  defaultBootstrapConfig: jest.fn(),
  defaultConfig: jest.fn(),
}));

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The test CRDT with a set-union snapshot merge, for authenticated catch-up. */
const mergingCRDT: typeof testCRDT = {
  ...testCRDT,
  createDocumentSession(initial) {
    const session = testCRDT.createDocumentSession!(initial);
    return Object.assign(session, {
      prepareMergeSnapshot(snapshot: number[]) {
        return session.prepareSnapshot!([
          ...new Set([...session.document, ...snapshot]),
        ]);
      },
    });
  },
};
const labels: string[] = [];
const adapter = {
  crdt: mergingCRDT,
  serializer: testChanges,
  edit: (label: string) => (document: number[]) => {
    if (!labels.includes(label)) labels.push(label);
    document.push(labels.indexOf(label) + 1);
  },
  read: (document: number[]) =>
    [...new Set(document)].map((value) => labels[value - 1]).sort(),
};

const realNow = Date.now.bind(Date);
let offset = 0;
const shiftClock = (ms: number) => {
  offset += ms;
  jest.spyOn(Date, 'now').mockImplementation(() => realNow() + offset);
};
afterEach(() => {
  offset = 0;
  jest.restoreAllMocks();
});

function topicRequest(
  peer: string,
  receipts: number,
  issuedAt: number,
): DocumentTopicCatchUpRequest {
  return {
    documentId: '/catch-up',
    genesisId: id(1),
    authorityHead: id(2),
    context: { state: publicState(4n), controlHead: id(3) },
    requesterId: id(4),
    challenge: id(5),
    requesterPeer: peer,
    issuedAt,
    receipts: Array.from({ length: receipts }, (_, index) => {
      const memberId = new Uint8Array(32);
      memberId[0] = index;
      return { memberId, sequence: index + 1, hash: id(6) };
    }),
  };
}

type Engine = any;
const engine = (document: object): Engine =>
  (document as { _coordinated: Engine })._coordinated;

async function group(members = 3) {
  const g = await coordinatedGroupFixture(mergingCRDT, testChanges, {
    members,
    catchUp: true,
    peers: true,
  });
  for (let index = 1; index < members; index++) await g.addMember(index);
  for (let index = 0; index < members; index++) await g.open(index);
  const engines = Array.from({ length: members }, (_, index) =>
    engine(g.doc(index)),
  );
  /** Seal a topic message under the current epoch, signed by any member. */
  const seal = async (
    kind: 'topic-request' | 'topic-checkpoint',
    encode: (binding: DocumentCatchUpBinding) => Uint8Array,
    signer: number,
  ) => {
    const context = g.coordinators[0].documentContext;
    const material = await engines[0].materialFor(context);
    const binding: DocumentCatchUpBinding = {
      documentId: g.path,
      genesisId: g.logs[0].genesisId,
      authorityHead: g.logs[0].headId,
      context,
    };
    const unsigned = encode(binding);
    const signature = await g.auth.sign(unsigned, g.members[signer]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: documentCatchUpAAD(kind, binding) as BufferSource,
      },
      material.key,
      encodeSignedDocumentContent(unsigned, signature) as BufferSource,
    );
    return encodeEncryptedDocumentCatchUp(
      kind,
      material.epochTag,
      nonce,
      new Uint8Array(ciphertext),
    );
  };
  return { g, engines, seal };
}

describe('topic catch-up wire', () => {
  test('round trips canonical topic requests in their own domain and rejects malformed encodings', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[1-9A-HJ-NP-Za-km-z]{1,128}$/),
        fc.integer({ min: 0, max: 256 }),
        fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
        fc.nat(),
        fc.integer({ min: 0, max: 255 }),
        (peer, count, issuedAt, cut, trailing) => {
          const value = topicRequest(peer, count, issuedAt);
          const encoded = encodeDocumentTopicCatchUpRequest(value);
          expect(decodeDocumentTopicCatchUpRequest(encoded)).toEqual(value);
          expect(() => decodeDocumentCatchUpRequest(encoded)).toThrow('domain');
          expect(() =>
            decodeDocumentTopicCatchUpRequest(
              encoded.subarray(0, cut % encoded.length),
            ),
          ).toThrow();
          const extended = new Uint8Array(encoded.length + 1);
          extended.set(encoded);
          extended[encoded.length] = trailing;
          expect(() => decodeDocumentTopicCatchUpRequest(extended)).toThrow();
          const outer = encodeEncryptedDocumentCatchUp(
            'topic-request',
            id(7).subarray(0, 16),
            id(8).subarray(0, 12),
            encoded,
          );
          expect(isDocumentCatchUpRequestFrame(outer)).toBe(true);
          expect(isDocumentCatchUpCheckpointFrame(outer)).toBe(false);
          expect(isDocumentRedeliveryFrame(outer)).toBe(false);
          expect(
            decodeEncryptedDocumentCatchUp('topic-request', outer).ciphertext,
          ).toEqual(encoded);
          expect(() =>
            decodeEncryptedDocumentCatchUp('topic-checkpoint', outer),
          ).toThrow('domain');
        },
      ),
      { seed: 202611261, numRuns: 40 },
    );
  });

  test('separates every catch-up domain and bounds the topic envelopes', () => {
    const binding = topicRequest('Peer', 0, 1);
    const domains = (
      ['request', 'checkpoint', 'topic-request', 'topic-checkpoint'] as const
    ).map((kind) =>
      Buffer.from(documentCatchUpAAD(kind, binding)).toString('hex'),
    );
    expect(new Set(domains).size).toBe(4);
    const checkpoint = {
      ...binding,
      controllerId: id(9),
      suffixes: [],
      snapshot: id(10),
    };
    const topic = encodeDocumentCatchUpCheckpoint(
      checkpoint,
      'topic-checkpoint',
    );
    expect(
      decodeDocumentCatchUpCheckpoint(topic, 'topic-checkpoint').challenge,
    ).toEqual(binding.challenge);
    expect(() => decodeDocumentCatchUpCheckpoint(topic)).toThrow('domain');
    expect(() =>
      decodeDocumentCatchUpCheckpoint(
        encodeDocumentCatchUpCheckpoint(checkpoint),
        'topic-checkpoint',
      ),
    ).toThrow('domain');
    for (const peer of ['', '0OIl', 'x'.repeat(129), 'peer/1'])
      expect(() =>
        encodeDocumentTopicCatchUpRequest(topicRequest(peer, 0, 1)),
      ).toThrow('peer');
    for (const issuedAt of [-1, 1.5, Number.MAX_SAFE_INTEGER + 2])
      expect(() =>
        encodeDocumentTopicCatchUpRequest(topicRequest('Peer', 0, issuedAt)),
      ).toThrow('time');
    const tag = id(7).subarray(0, 16),
      nonce = id(8).subarray(0, 12);
    expect(() =>
      decodeEncryptedDocumentCatchUp(
        'topic-checkpoint',
        encodeEncryptedDocumentCatchUp(
          'topic-checkpoint',
          tag,
          nonce,
          id(9).subarray(0, 15),
        ),
      ),
    ).toThrow('body');
    expect(() =>
      encodeEncryptedDocumentCatchUp(
        'topic-request',
        tag,
        nonce,
        new Uint8Array(MAX_DOCUMENT_CATCH_UP_TOPIC_REQUEST_BYTES + 1),
      ),
    ).toThrow();
    const content = encodeEncryptedDocumentContent(tag, nonce, id(9));
    expect(isDocumentCatchUpRequestFrame(content)).toBe(false);
    expect(isDocumentCatchUpCheckpointFrame(content)).toBe(false);
    expect(() =>
      decodeEncryptedDocumentCatchUp('topic-request', content),
    ).toThrow('domain');
  });
});

describe('automatic topic catch-up', () => {
  test('a member added in a new epoch converges without an application relay', async () => {
    const result = await joinCatchUpScenario(adapter);
    expect(result.traffic.requests).toContain(2);
    expect(result.traffic.checkpoints.length).toBeGreaterThan(0);
    expect(new Set(result.traffic.checkpoints)).toEqual(new Set([0]));
    expect(result.before).toBe(true);
    expect(result.empty).toEqual([]);
    expect(result.joined).toBe(true);
    expect(result.after).toBe(true);
    for (const view of result.views)
      expect(view).toEqual(['first', 'fourth', 'second', 'third']);
  }, 60_000);

  test('a member that missed more frames than peers retain converges after redelivery finds none', async () => {
    const result = await missedWindowCatchUpScenario(adapter);
    expect(result.traffic.redeliveries).toContain(2);
    expect(result.traffic.requests).toContain(2);
    expect(new Set(result.traffic.checkpoints)).toEqual(new Set([0]));
    expect(result.joined).toBe(true);
    expect(result.behind).toBe(true);
    expect(result.recovered).toBe(true);
    expect(result.live).toBe(true);
    expect(result.held).toBe(false);
    expect(result.views[2]).toHaveLength(73);
    for (const view of result.views) expect(view).toEqual(result.views[2]);
  }, 90_000);

  test('a member holding the start of a writer’s history gets the missed content but keeps its receipt', async () => {
    const { g } = await group();
    const has = (values: readonly string[]) =>
      values.every((value) => adapter.read(g.doc(2).document).includes(value));
    try {
      await g.doc(0).change(adapter.edit('root'));
      expect(
        await floodUntil(
          g,
          [0, 1, 2],
          () => has(['root']) && !engine(g.doc(2)).needsJoinCatchUp(),
        ),
      ).toBe(true);
      await g.doc(1).change(adapter.edit('start'));
      expect(await floodUntil(g, [0, 1, 2], () => has(['start']))).toBe(true);
      const missed: string[] = [];
      for (let index = 0; index < 70; index++) {
        missed.push(`gap${index}`);
        await g.doc(1).change(adapter.edit(missed[index]));
        for (const publication of g.take())
          if (
            publication.sender === 1 &&
            !isDocumentRedeliveryFrame(publication.data)
          )
            await g.deliver(publication, [0]);
      }
      await g.doc(1).change(adapter.edit('tail'));
      expect(
        await floodUntil(g, [0, 1, 2], () => has([...missed, 'tail'])),
      ).toBe(true);
      expect(engine(g.doc(2)).hasHeldFrames()).toBe(true);
    } finally {
      await g.close();
    }
  }, 90_000);

  test('refuses unbound, damaged, forged, replayed and stale requests', async () => {
    const { g, engines, seal } = await group();
    const [controller, other, member] = engines;
    try {
      const request = await member.createTopicCatchUpRequest(groupPeer(2));
      await expect(
        controller.answerTopicCatchUp(request, groupPeer(1)),
      ).rejects.toThrow('not from its signer');
      await expect(
        controller.answerTopicCatchUp(request, undefined),
      ).rejects.toThrow('not from its signer');
      const damaged = request.slice();
      damaged[damaged.length - 1] ^= 1;
      await expect(
        controller.answerTopicCatchUp(damaged, groupPeer(2)),
      ).rejects.toThrow('does not decrypt');
      const forged = await seal(
        'topic-request',
        (binding) =>
          encodeDocumentTopicCatchUpRequest({
            ...binding,
            requesterId: g.members[2],
            challenge: id(11),
            requesterPeer: groupPeer(2),
            issuedAt: Date.now(),
            receipts: [],
          }),
        1,
      );
      await expect(
        controller.answerTopicCatchUp(forged, groupPeer(2)),
      ).rejects.toThrow('signature');
      expect(
        await other.answerTopicCatchUp(request, groupPeer(2)),
      ).toBeUndefined();
      const checkpoint = await controller.answerTopicCatchUp(
        request,
        groupPeer(2),
      );
      expect(isDocumentCatchUpCheckpointFrame(checkpoint)).toBe(true);
      expect(
        await controller.answerTopicCatchUp(request, groupPeer(2)),
      ).toBeUndefined();
      const newer = await member.createTopicCatchUpRequest(groupPeer(2));
      expect(
        await controller.answerTopicCatchUp(newer, groupPeer(2)),
      ).toBeUndefined();
      shiftClock(11_000);
      expect(
        await controller.answerTopicCatchUp(request, groupPeer(2)),
      ).toBeUndefined();
      expect(
        await controller.answerTopicCatchUp(newer, groupPeer(2)),
      ).toBeUndefined();
      shiftClock(-72_000);
      const stale = await member.createTopicCatchUpRequest(groupPeer(2));
      shiftClock(72_000);
      expect(
        await controller.answerTopicCatchUp(stale, groupPeer(2)),
      ).toBeUndefined();
      expect(g.doc(0).securityCatchUpStaleRequests).toBe(1);
      const fresh = await member.createTopicCatchUpRequest(groupPeer(2));
      const later = await controller.answerTopicCatchUp(fresh, groupPeer(2));
      expect(isDocumentCatchUpCheckpointFrame(later)).toBe(true);
      expect(await member.receiveTopicCatchUp(later, groupPeer(0))).toBe(true);
      expect(await member.receiveTopicCatchUp(later, groupPeer(0))).toBe(false);
      expect(await member.receiveTopicCatchUp(checkpoint, groupPeer(0))).toBe(
        false,
      );
    } finally {
      await g.close();
    }
  }, 60_000);

  test('a requester merges only the current controller’s checkpoint', async () => {
    const { g, engines, seal } = await group();
    const [controller, , member] = engines;
    try {
      await g.doc(0).change(adapter.edit('controller'));
      g.take();
      const request = await member.createTopicCatchUpRequest(groupPeer(2));
      const { challenge } = member.topicCatchUps.at(-1);
      const checkpointFrom = (controllerId: number, signer: number) =>
        seal(
          'topic-checkpoint',
          (binding) =>
            encodeDocumentCatchUpCheckpoint(
              {
                ...binding,
                requesterId: g.members[2],
                challenge,
                controllerId: g.members[controllerId],
                receipts: [],
                suffixes: [],
                snapshot: testChanges.serializeChanges([99]),
              },
              'topic-checkpoint',
            ),
          signer,
        );
      await expect(
        member.receiveTopicCatchUp(await checkpointFrom(1, 1), groupPeer(1)),
      ).rejects.toThrow('controller');
      await expect(
        member.receiveTopicCatchUp(await checkpointFrom(0, 1), groupPeer(1)),
      ).rejects.toThrow('signature');
      expect(g.doc(2).document).not.toContain(99);
      const checkpoint = await controller.answerTopicCatchUp(
        request,
        groupPeer(2),
      );
      expect(await member.receiveTopicCatchUp(checkpoint, groupPeer(0))).toBe(
        true,
      );
      expect(adapter.read(g.doc(2).document)).toContain('controller');
      expect(member.needsJoinCatchUp()).toBe(false);
    } finally {
      await g.close();
    }
  }, 60_000);

  test('backs off while no checkpoint arrives and stops once one merges', async () => {
    const g = await coordinatedGroupFixture(mergingCRDT, testChanges, {
      members: 2,
      catchUp: true,
      peers: true,
    });
    try {
      await g.addMember(1);
      await g.open(0);
      await g.doc(0).change(adapter.edit('before'));
      g.take();
      const opened = Date.now();
      await g.open(1);
      const requests: number[] = [];
      for (; requests.length < 2 && Date.now() - opened < 9_000;) {
        for (const publication of g.take())
          if (
            publication.sender === 1 &&
            isDocumentCatchUpRequestFrame(publication.data)
          )
            requests.push(Date.now() - opened);
        await pause(20);
      }
      expect(requests).toHaveLength(2);
      expect(requests[0]).toBeGreaterThanOrEqual(1_000);
      expect(requests[1] - requests[0]).toBeGreaterThanOrEqual(4_900);
      expect(engine(g.doc(1)).needsJoinCatchUp()).toBe(true);
      await g.doc(1).requestSecurityCatchUp();
      expect(
        await floodUntil(g, [0, 1], () =>
          adapter.read(g.doc(1).document).includes('before'),
        ),
      ).toBe(true);
      expect(engine(g.doc(1)).needsJoinCatchUp()).toBe(false);
      await pause(6_000);
      expect(
        g
          .take()
          .filter((publication) =>
            isDocumentCatchUpRequestFrame(publication.data),
          ),
      ).toEqual([]);
    } finally {
      await g.close();
    }
  }, 60_000);

  test('one request yields one checkpoint, and members and the process are rate limited', async () => {
    const { g, engines } = await group(6);
    const [controller] = engines;
    try {
      await pause(2_000);
      g.take();
      await g.doc(1).requestSecurityCatchUp();
      const [request] = g
        .take()
        .filter((publication) =>
          isDocumentCatchUpRequestFrame(publication.data),
        );
      for (let round = 0; round < 5; round++)
        for (const recipient of [0, 2, 3, 4, 5]) g.dispatch(request, recipient);
      await pause(1_500);
      const checkpoints = g
        .take()
        .filter((publication) =>
          isDocumentCatchUpCheckpointFrame(publication.data),
        );
      expect(checkpoints.map((publication) => publication.sender)).toEqual([0]);
      const next = await engines[1].createTopicCatchUpRequest(groupPeer(1));
      expect(
        await controller.answerTopicCatchUp(next, groupPeer(1)),
      ).toBeUndefined();
      shiftClock(60_000);
      const burst = await Promise.all(
        [1, 2, 3, 4, 5].map(async (index) =>
          controller.answerTopicCatchUp(
            await engines[index].createTopicCatchUpRequest(groupPeer(index)),
            groupPeer(index),
          ),
        ),
      );
      expect(burst.filter((value) => value !== undefined)).toHaveLength(4);
      const refused = burst.findIndex((value) => value === undefined) + 1;
      shiftClock(2_000);
      expect(
        isDocumentCatchUpCheckpointFrame(
          await controller.answerTopicCatchUp(
            await engines[refused].createTopicCatchUpRequest(
              groupPeer(refused),
            ),
            groupPeer(refused),
          ),
        ),
      ).toBe(true);
    } finally {
      await g.close();
    }
  }, 90_000);
});
