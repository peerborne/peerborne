import { describe, expect, test } from '@jest/globals';
import {
  BeeKEMWelcome,
  BeeKEMWelcomeV2,
  PathUpdate,
  PathUpdateV2,
} from './beekem/types.js';
import { serializeBeeKEMWelcomeForWire } from './beekem-welcome-wire.js';
import { serializePathUpdateForWire } from './path-update-wire.js';

const bytes = new Uint8Array([1]);

const welcomeV1 = (): BeeKEMWelcome => ({
  leafIndex: 2,
  pathKeys: [
    {
      nodeIndex: 1,
      publicKey: new Uint8Array(65).fill(2),
      encryptedPrivateKey: new Uint8Array(125).fill(3),
    },
  ],
  treeNodePublicKeys: [{ nodeIndex: 0, publicKey: null }],
  treeHash: new Uint8Array(32).fill(4),
});

const pathUpdateV1 = (): PathUpdate => ({
  senderLeafIndex: 0,
  senderLeafPublicKey: new Uint8Array(65).fill(1),
  nodes: [],
});

describe('BeeKEM wire-version separation', () => {
  test('v1 Welcome serializer rejects complete and partial v2 shapes', () => {
    const v2: BeeKEMWelcomeV2 = {
      ...welcomeV1(),
      version: 2,
      generation: 1,
      numLeaves: 2,
    };
    expect(() => serializeBeeKEMWelcomeForWire(v2)).toThrow(/v2-only.*v1/);

    for (const marker of [
      { version: 2 },
      { generation: 1 },
      { numLeaves: 2 },
    ]) {
      expect(() =>
        serializeBeeKEMWelcomeForWire({
          ...welcomeV1(),
          ...marker,
        } as BeeKEMWelcome),
      ).toThrow(/v2-only.*v1/);
    }
    expect(() => serializeBeeKEMWelcomeForWire(welcomeV1())).not.toThrow();
  });

  test('v1 PathUpdate serializer rejects complete and nested-only v2 shapes', () => {
    const v2: PathUpdateV2 = {
      ...pathUpdateV1(),
      version: 2,
      generation: 1,
      parentTreeHash: bytes,
      numLeaves: 2,
      nodes: [],
      treeNodePublicKeys: [],
      treeHash: bytes,
    };
    expect(() => serializePathUpdateForWire(v2 as unknown as PathUpdate)).toThrow(/v2-only.*v1/);

    const nestedMarker = {
      ...pathUpdateV1(),
      nodes: [
        {
          nodeIndex: 0,
          publicKey: bytes,
          encryptedPrivateKey: bytes,
          encryptedPathKeyBundles: [],
        },
      ],
    } as PathUpdate;
    expect(() => serializePathUpdateForWire(nestedMarker)).toThrow(
      /encryptedPathKeyBundles.*v1/,
    );
    expect(() => serializePathUpdateForWire(pathUpdateV1())).not.toThrow();
  });
});
