import {
  Peerborne,
  SubtleCrypto,
  defaultBootstrapConfig,
  defaultConfig,
} from '@peerborne/core';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '@peerborne/yjs';
import { createDocumentStore } from '@peerborne/store';

const start = document.querySelector<HTMLButtonElement>('#start')!;
const save = document.querySelector<HTMLButtonElement>('#save')!;
const close = document.querySelector<HTMLButtonElement>('#close')!;
const title = document.querySelector<HTMLInputElement>('#title')!;
const value = document.querySelector<HTMLOutputElement>('#value')!;
const status = document.querySelector<HTMLParagraphElement>('#status')!;

start.onclick = async () => {
  start.disabled = true;
  status.textContent = 'opening';
  try {
    const keys = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const serializer = new YjsJSONSerializer();
    const node = new Peerborne(
      keys.privateKey,
      keys.publicKey,
      new YjsProvider(),
      serializer,
      serializer,
      serializer,
      new SubtleCrypto(),
      new YjsACLProvider(),
      new YjsKeychainProvider(),
    );
    await node.initialize(defaultConfig(defaultBootstrapConfig([])));
    const handle = node.doc(`/vanilla-pilot/${crypto.randomUUID()}`);
    await handle.create();
    const store = createDocumentStore(handle, { manageLifecycle: false });
    const unsubscribe = store.subscribe(() => {
      const snapshot = store.getSnapshot();
      status.textContent = snapshot.status;
      value.textContent = String(
        snapshot.data?.getMap('data').get('title') ?? 'Untitled',
      );
    });
    await store.start();
    save.disabled = false;
    close.disabled = false;
    save.onclick = async () => {
      try {
        await store.change((data) => {
          data.getMap('data').set('title', title.value);
        });
      } catch {
        status.textContent = 'error';
      }
    };
    close.onclick = async () => {
      close.disabled = true;
      save.disabled = true;
      try {
        await store.stop();
        unsubscribe();
        await handle.close();
        await node.heliaNode.stop();
        status.textContent = 'closed';
      } catch {
        status.textContent = 'error';
      }
    };
  } catch {
    status.textContent = 'error';
  }
};
