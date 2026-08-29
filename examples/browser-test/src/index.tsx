import React from 'react';
import { createRoot } from 'react-dom/client';
import 'jsoneditor/dist/jsoneditor.css';
import 'jsoneditor-react/es/editor.css';
import './index.css';
import App from './App';
import { Provider } from 'react-redux';
import { createStore, applyMiddleware } from 'redux';
import {
  changeDocumentAsync,
  peerborneReducer,
  connectAsync,
  openDocument,
  openDocumentAsync,
  syncDocument,
} from '@peerborne/redux';
import {
  AutomergeACLProvider,
  AutomergeJSONSerializer,
  AutomergeKeychainProvider,
  AutomergeProvider,
} from '@peerborne/automerge';
import {
  encodeInvitationOffer,
  generateEciesKeyPair,
  SubtleCrypto,
} from '@peerborne/core';
import { thunk } from 'redux-thunk';
import { AutomergeSwarmActions, AutomergeSwarmState } from './utils';

declare global {
  interface Window {
    __PEERBORNE_TEST_IDENTITY__?: { privateKey: JsonWebKey; publicKey: JsonWebKey };
    __PEERBORNE_TEST__?: {
      open: (path: string) => Promise<unknown>;
      createInvitation: (
        path: string,
        role?: 'reader' | 'editor',
      ) => Promise<number[]>;
      acceptInvitation: (encodedOffer: number[]) => Promise<string>;
      connect: (addresses: string[]) => Promise<unknown>;
      addresses: () => string[];
      circuitAddress: () => string | undefined;
      change: (path: string, key: string, value: unknown) => Promise<unknown>;
      writerCount: (path: string) => Promise<number>;
      state: () => AutomergeSwarmState<any>;
    };
  }
}

const crossNatTest = import.meta.env.VITE_CROSS_NAT_TEST === '1';
const injectedIdentity = crossNatTest
  ? window.__PEERBORNE_TEST_IDENTITY__
  : undefined;
const userKeyPair = injectedIdentity
  ? {
      privateKey: await crypto.subtle.importKey(
        'jwk', injectedIdentity.privateKey,
        { name: 'ECDSA', namedCurve: 'P-384' }, false, ['sign'],
      ),
      publicKey: await crypto.subtle.importKey(
        'jwk', injectedIdentity.publicKey,
        { name: 'ECDSA', namedCurve: 'P-384' }, true, ['verify'],
      ),
    }
  : (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
const serializer = new AutomergeJSONSerializer();

const store = createStore(
  peerborneReducer(
    userKeyPair.privateKey,
    userKeyPair.publicKey,
    new AutomergeProvider(),
    serializer,
    serializer,
    serializer,
    new SubtleCrypto(),
    new AutomergeACLProvider(),
    new AutomergeKeychainProvider(),
  ),
  applyMiddleware(thunk),
);

let invitationKemKeyPair: CryptoKeyPair | undefined;
async function getInvitationKemKeyPair(): Promise<CryptoKeyPair> {
  if (!invitationKemKeyPair) {
    invitationKemKeyPair = await generateEciesKeyPair();
  }
  return invitationKemKeyPair;
}

function observedCircuitAddress(): string | undefined {
  const node = store.getState().node;
  const peerId = node?.libp2p.peerId.toString();
  if (!node || !peerId) return undefined;
  const suffix = `/p2p-circuit/p2p/${peerId}`;
  return node.libp2p
    .getMultiaddrs()
    .map((address: { toString(): string }) => address.toString())
    .find((address: string) =>
      address.includes('/p2p-circuit/') && address.endsWith(suffix),
    );
}

// Deliberately test-only: Playwright uses this narrow bridge to exercise the
// real Redux -> Peerborne -> Automerge path without coupling assertions to
// jsoneditor's implementation details.
if (crossNatTest && injectedIdentity) {
  window.__PEERBORNE_TEST__ = {
    open: (path) => store.dispatch<any>(openDocumentAsync(path)),
    createInvitation: async (path, role = 'editor') => {
      const documentRef = store.getState().documents[path]?.documentRef;
      if (!documentRef) throw new Error(`Document is not open: ${path}`);
      documentRef.historyVisibility = 'full_history';
      await documentRef.setKemKeyPair(await getInvitationKemKeyPair());
      const circuitAddress = observedCircuitAddress();
      if (!circuitAddress) {
        throw new Error('Observed Circuit Relay reservation is unavailable');
      }
      const offer = await documentRef.createInvitation({
        role,
        rendezvous: [circuitAddress],
      });
      return Array.from(encodeInvitationOffer(offer));
    },
    acceptInvitation: async (encodedOffer) => {
      const node = store.getState().node;
      if (!node) throw new Error('Peerborne node is not ready');
      const documentRef = await node.acceptInvitation(
        new Uint8Array(encodedOffer),
        await getInvitationKemKeyPair(),
      );
      const path = documentRef.documentPath;
      documentRef.subscribe(
        path,
        (document) => store.dispatch(syncDocument(path, document)),
        'remote',
      );
      store.dispatch(openDocument(path, documentRef));
      return path;
    },
    connect: (addresses) => store.dispatch<any>(connectAsync(addresses)),
    addresses: () => {
      try {
        return store.getState().node?.libp2p.getMultiaddrs().map(
          (address: { toString(): string }) => address.toString(),
        ) ?? [];
      } catch (error) {
        console.warn('Unable to read Peerborne peer addresses', error);
        return [];
      }
    },
    circuitAddress: () => {
      try {
        return observedCircuitAddress();
      } catch (error) {
        console.warn('Unable to read the Peerborne circuit address', error);
        return undefined;
      }
    },
    change: (path, key, value) =>
      store.dispatch<any>(
        changeDocumentAsync(path, (doc: Record<string, unknown>) => {
          doc[key] = value;
        }),
      ),
    writerCount: async (path) => {
      const documentRef = store.getState().documents[path]?.documentRef;
      if (!documentRef) throw new Error(`Document is not open: ${path}`);
      return (await documentRef.getWriters()).length;
    },
    state: () => store.getState() as AutomergeSwarmState<any>,
  };
}

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Missing #root element');
}

createRoot(rootElement).render(
  <Provider store={store}>
    <React.StrictMode>
      <App />
    </React.StrictMode>
  </Provider>,
);
