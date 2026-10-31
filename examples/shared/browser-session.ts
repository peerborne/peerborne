import type { CRDTProvider } from '@peerborne/core';

/** Local exercise: each invocation creates a fresh, non-extractable identity. */
export async function createSession<Doc, Change>(
  provider: CRDTProvider<Doc, Uint8Array, Change>,
  path: string,
) {
  const [core, yjs, { createDocumentStore }] = await Promise.all([
    import('@peerborne/core'),
    import('@peerborne/yjs'),
    import('@peerborne/store'),
  ]);
  const keys = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const serializer = new yjs.YjsJSONSerializer();
  const node = new core.Peerborne(
    keys.privateKey,
    keys.publicKey,
    provider,
    serializer,
    serializer,
    serializer,
    new core.SubtleCrypto(),
    new yjs.YjsACLProvider(),
    new yjs.YjsKeychainProvider(),
  );
  await node.initialize(core.defaultConfig(core.defaultBootstrapConfig([])));
  const document = node.doc(path);
  try {
    await document.create();
  } catch (error) {
    try {
      await document.close();
    } finally {
      await node.heliaNode.stop();
    }
    throw error;
  }
  const store = createDocumentStore(document, { manageLifecycle: false });
  let disposal: Promise<void> | undefined;
  return {
    document,
    store,
    dispose() {
      disposal ??= (async () => {
        try {
          await store.stop();
        } finally {
          try {
            await document.close();
          } finally {
            await node.heliaNode.stop();
          }
        }
      })();
      return disposal;
    },
  };
}

export async function createBrowserSession(path = '/examples/workspace') {
  const { YjsProvider } = await import('@peerborne/yjs');
  return createSession(new YjsProvider(), path);
}

export type BrowserSession = Awaited<ReturnType<typeof createBrowserSession>>;
