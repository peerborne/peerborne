import type { BeeKEMWelcomeV2, PathUpdateV2 } from '../beekem/types.js';

export function welcomeFixture(generation = 1): BeeKEMWelcomeV2 {
  return {
    version: 2,
    generation,
    numLeaves: 2,
    leafIndex: 2,
    pathKeys: [
      {
        nodeIndex: 1,
        publicKey: new Uint8Array(65).fill(2),
        encryptedPrivateKey: new Uint8Array([3, 4]),
      },
    ],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: new Uint8Array(65).fill(1) },
    ],
    treeHash: new Uint8Array(32).fill(5),
  };
}

export function pathUpdateFixture(generation = 2): PathUpdateV2 {
  return {
    version: 2,
    generation,
    parentTreeHash: new Uint8Array(32).fill(6),
    numLeaves: 2,
    senderLeafIndex: 0,
    senderLeafPublicKey: new Uint8Array(65).fill(1),
    nodes: [
      {
        nodeIndex: 1,
        publicKey: new Uint8Array(65).fill(2),
        encryptedPathKeyBundles: [
          { recipientNodeIndex: 2, ciphertext: new Uint8Array([7, 8]) },
        ],
      },
    ],
    treeNodePublicKeys: [
      { nodeIndex: 0, publicKey: new Uint8Array(65).fill(1) },
      { nodeIndex: 1, publicKey: new Uint8Array(65).fill(2) },
      { nodeIndex: 2, publicKey: new Uint8Array(65).fill(3) },
    ],
    treeHash: new Uint8Array(32).fill(9),
  };
}
