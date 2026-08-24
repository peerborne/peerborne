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
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '../src/index.js';

const crypto = webcrypto as Crypto;

console.log('Creating a new swarm node...');
const crdt = new YjsProvider();
const serializer = new YjsJSONSerializer();
const auth = new SubtleCrypto();
const acl = new YjsACLProvider();
const keychain = new YjsKeychainProvider();
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
