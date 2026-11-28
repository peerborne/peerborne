# Peerborne wiki

This Vite and React example explores a collaborative wiki interface with the
Peerborne Automerge and Redux packages.

This workspace is a source example with single-browser coverage, not a complete collaborative product.

## Run from source

Use Node.js 26.13.1 and Yarn 4.19.0 through Corepack. From the repository root:

```sh
npm install --global corepack@0.36.0
corepack enable
yarn install --immutable
yarn build
yarn workspace @peerborne/wiki-swarm start
```

Open the URL printed by Vite. The landing page provides a document ID field for
navigating to the wiki editor.

## Browser-local storage

The wiki keeps a non-extractable ECDSA P-384 signing identity, a P-256 KEM key
pair, and an AES-GCM storage key in IndexedDB, so the same identity returns
after a reload. Each article stays open for the tab, and every change saves an
encrypted, self-signed checkpoint. Search reopens a saved article after
navigation or a reload. **Create article** refuses an ID that this browser
already holds. Clearing site data removes the identity and saved articles.

Redux receives an article only after its change is applied, and title edits are
applied as text splices. The Slate body still replaces the whole editor value
on each edit. Development builds log Redux action types, never article content.

## Verify the current example

```sh
yarn exec playwright install chromium
yarn test:e2e:wiki-swarm
```

The suite builds this workspace and verifies that Automerge WASM loads and the
wiki interface renders in Chromium without runtime errors. It creates an
article, types its title, reloads it from its checkpoint, reopens it in the
same tab, and checks that an existing ID cannot be created again. It does not
assert two-browser synchronization, concurrent editing, or invitation delivery.

- [Collaborative wiki guide](https://peerborne.io/cookbook/collaborative-wiki/)
- [Verified quick start](https://peerborne.io/getting-started/quick-start/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
