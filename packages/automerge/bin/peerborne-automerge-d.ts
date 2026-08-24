#!/usr/bin/env node

import { webcrypto } from 'node:crypto';
import {
  defaultBootstrapConfig,
  SubtleCrypto,
} from '@peerborne/core';
import {
  PeerborneNode,
  defaultNodeConfig,
} from '@peerborne/core/node';
import { AutomergeJSONSerializer, AutomergeProvider } from '../src/index.js';
import {
  AutomergeACLProvider,
  AutomergeKeychainProvider,
} from '../src/peerborne-automerge.js';

const crypto = webcrypto as Crypto;

console.log('Creating a new swarm node...');
const crdt = new AutomergeProvider();
const serializer = new AutomergeJSONSerializer();
const auth = new SubtleCrypto();
const acl = new AutomergeACLProvider();
const keychain = new AutomergeKeychainProvider();
void crypto.subtle
  .generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-384',
    },
    true,
    ['sign', 'verify'],
  )
  .then(async (keypair) => {
    const peerborneNode = new PeerborneNode(
      keypair.privateKey,
      keypair.publicKey,
      crdt,
      serializer,
      serializer,
      serializer,
      auth,
      acl,
      keychain,
      defaultNodeConfig(defaultBootstrapConfig([])),
    );
    console.log('Starting node...');
    await peerborneNode.start();
    console.log('Node started.');
  })
  .catch((error: unknown) => {
    console.error('Failed to start node:', error);
    process.exitCode = 1;
  });
