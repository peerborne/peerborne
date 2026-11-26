import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  decodeDocumentRedeliveryRequest,
  decodeEncryptedDocumentRedelivery,
  DOCUMENT_REDELIVERY_MARKER,
  encodeDocumentRedeliveryRequest,
  encodeEncryptedDocumentRedelivery,
  isDocumentRedeliveryFrame,
  type DocumentRedeliveryRequest,
} from './document-redelivery-wire.js';
import { testCRDT, testChanges } from './__testutils__/coordinated-document.js';
import {
  coordinatedGroupFixture,
  groupPeer,
  type GroupPublication,
} from './__testutils__/coordinated-group.js';
import { id, publicState } from './__testutils__/group-security-coordinator.js';

jest.mock('it-pipe', () => ({ pipe: jest.fn() }), { virtual: true });
jest.mock('libp2p', () => ({}), { virtual: true });
jest.mock('multiformats', () => ({ CID: class {} }), { virtual: true });
jest.mock('@helia/unixfs', () => ({ unixfs: jest.fn() }), { virtual: true });
jest.mock(
  '@libp2p/gossipsub',
  () => ({
    TopicValidatorResult: { Accept: 'accept', Ignore: 'ignore', Reject: 'reject' },
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

const push =
  (value: number) =>
  (document: number[]): void => {
    document.push(value);
  };
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const isRequest = (publication: GroupPublication) =>
  isDocumentRedeliveryFrame(publication.data);

async function settled(condition: () => boolean) {
  for (let turn = 0; !condition() && turn < 300; turn++) await pause(10);
  return condition();
}

async function group() {
  const g = await coordinatedGroupFixture(testCRDT, testChanges, {
    members: 3,
    peers: true,
  });
  await g.addMember(1);
  await g.addMember(2);
  for (let index = 0; index < 3; index++) await g.open(index);
  // Let the requests sent shortly after open go out before each scenario starts.
  await pause(900);
  g.take();
  const content = () => g.take().filter((publication) => !isRequest(publication));
  /** Member 2 writes `count` frames; member 1 receives only `kept` of them. */
  const write = async (count: number, kept: (index: number) => boolean) => {
    const frames: GroupPublication[] = [];
    for (let index = 0; index < count; index++) {
      await g.doc(2).change(push(index + 1));
      frames.push(...content());
    }
    for (const [index, frame] of frames.entries()) {
      expect(await g.deliver(frame, [0])).toEqual([]);
      if (kept(index)) expect(await g.deliver(frame, [1])).toEqual([]);
    }
    return frames;
  };
  const request = async () => {
    g.take();
    await g.doc(1).requestSecurityRedelivery();
    const [value] = g.take().filter(isRequest);
    return value;
  };
  return { g, content, write, request };
}

const request = (peer: string, receipts = 0): DocumentRedeliveryRequest => ({
  documentId: '/redelivery',
  genesisId: id(1),
  authorityHead: id(2),
  context: { state: publicState(4n), controlHead: id(3) },
  requesterId: id(4),
  requesterPeer: peer,
  nonce: new Uint8Array(16).fill(5),
  receipts: Array.from({ length: receipts }, (_, index) => {
    const memberId = new Uint8Array(32);
    memberId[0] = index;
    return { memberId, sequence: index + 1, hash: id(6) };
  }),
});

describe('coordinated redelivery', () => {
  test('round trips canonical requests and rejects malformed or unbound encodings', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[1-9A-HJ-NP-Za-km-z]{1,128}$/),
        fc.integer({ min: 0, max: 256 }),
        fc.nat(),
        fc.integer({ min: 0, max: 255 }),
        (peer, count, cut, trailing) => {
          const value = request(peer, count);
          const encoded = encodeDocumentRedeliveryRequest(value);
          expect(decodeDocumentRedeliveryRequest(encoded)).toEqual(value);
          expect(() =>
            decodeDocumentRedeliveryRequest(encoded.subarray(0, cut % encoded.length)),
          ).toThrow();
          const extended = new Uint8Array(encoded.length + 1);
          extended.set(encoded);
          extended[encoded.length] = trailing;
          expect(() => decodeDocumentRedeliveryRequest(extended)).toThrow();
          const outer = encodeEncryptedDocumentRedelivery(
            id(7).subarray(0, 16),
            id(8).subarray(0, 12),
            encoded,
          );
          expect(isDocumentRedeliveryFrame(outer)).toBe(true);
          expect(decodeEncryptedDocumentRedelivery(outer).ciphertext).toEqual(encoded);
        },
      ),
      { seed: 202611255, numRuns: 40 },
    );
    for (const peer of ['', 'l'.repeat(4), '0OIl', 'x'.repeat(129), 'peer/1'])
      expect(() => encodeDocumentRedeliveryRequest(request(peer))).toThrow('peer');
    expect(() =>
      encodeDocumentRedeliveryRequest({ ...request('Peer'), nonce: id(1) }),
    ).toThrow();
    expect(() => encodeDocumentRedeliveryRequest(request('Peer', 257))).toThrow();
    expect(() =>
      decodeEncryptedDocumentRedelivery(
        encodeEncryptedDocumentRedelivery(id(7).subarray(0, 16), id(8).subarray(0, 12), id(9).subarray(0, 15)),
      ),
    ).toThrow('body');
    const content = encodeEncryptedDocumentRedelivery(
      id(7).subarray(0, 16),
      id(8).subarray(0, 12),
      id(9),
    );
    content[3] = 1;
    expect(isDocumentRedeliveryFrame(content)).toBe(false);
    expect(() => decodeEncryptedDocumentRedelivery(content)).toThrow('domain');
    expect(DOCUMENT_REDELIVERY_MARKER).toEqual(Uint8Array.of(0x50, 0x42, 0x44, 2));
  });

  test('peers resend the frames past a member’s heads and suppress repeats', async () => {
    const { g, content, write, request: ask } = await group();
    try {
      await write(4, (index) => index === 0 || index === 3);
      expect(g.doc(1).document).toEqual([1]);
      const value = await ask();
      expect(value.sender).toBe(1);
      const random = jest.spyOn(Math, 'random').mockReturnValue(0.99);
      try {
        g.dispatch(value, 0);
        g.dispatch(value, 2);
        expect(await settled(() => g.publications.length === 3)).toBe(true);
        const own = content();
        expect(own.every((publication) => publication.sender === 2)).toBe(true);
        for (const publication of own) await g.deliver(publication, [0, 1]);
        await pause(700);
        expect(content()).toEqual([]);
      } finally {
        random.mockRestore();
      }
      expect(g.doc(1).document).toEqual([1, 2, 3, 4]);
      await g.doc(2).change(push(5));
      expect(await g.deliver(content()[0], [0, 1])).toEqual([]);
      expect(g.doc(1).document).toEqual([1, 2, 3, 4, 5]);
    } finally {
      await g.close();
    }
  });

  test('ignores unbound, replayed, too frequent or damaged requests', async () => {
    const { g, content, write, request: ask } = await group();
    try {
      await write(2, (index) => index === 0);
      const value = await ask();
      g.dispatch(value, 2, groupPeer(0));
      const damaged = { ...value, data: value.data.slice() };
      damaged.data[damaged.data.length - 1] ^= 1;
      g.dispatch(damaged, 2);
      await pause(300);
      expect(content()).toEqual([]);
      g.dispatch(value, 2);
      expect(await settled(() => g.publications.length === 1)).toBe(true);
      expect(content()).toHaveLength(1);
      g.dispatch(value, 2);
      const again = await ask();
      g.dispatch(again, 2);
      await pause(300);
      expect(content()).toEqual([]);
    } finally {
      await g.close();
    }
  });

  test('caps one answer and resends only a complete retained suffix', async () => {
    const { g, content, write, request: ask } = await group();
    try {
      await write(70, () => false);
      g.dispatch(await ask(), 2);
      await pause(300);
      expect(content()).toEqual([]);
      const g2 = await group();
      try {
        await g2.write(64, () => false);
        g2.g.dispatch(await g2.request(), 2);
        expect(await settled(() => g2.g.publications.length === 64)).toBe(true);
        for (const publication of g2.content())
          expect(await g2.g.deliver(publication, [1])).toEqual([]);
        expect(g2.g.doc(1).document).toHaveLength(64);
      } finally {
        await g2.g.close();
      }
    } finally {
      await g.close();
    }
  });

  test('asks automatically while a received frame waits for its predecessor', async () => {
    const { g, write } = await group();
    try {
      await write(2, (index) => index === 1);
      expect(await settled(() => g.publications.some(isRequest))).toBe(true);
      const [value] = g.take().filter(isRequest);
      expect(value.sender).toBe(1);
      g.dispatch(value, 2);
      expect(await settled(() => g.publications.length >= 1)).toBe(true);
      for (const publication of g.take().filter((entry) => !isRequest(entry)))
        await g.deliver(publication, [1]);
      expect(g.doc(1).document).toEqual([1, 2]);
    } finally {
      await g.close();
    }
  });
});
