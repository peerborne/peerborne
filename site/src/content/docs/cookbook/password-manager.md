---
title: Encrypted shared secrets store
description: Assess the password-manager source example and the incomplete distinct-identity onboarding flow.
---

**Status: Runnable from source for startup smoke; Deferred/incomplete integration for sharing and revocation.**

[`examples/password-manager`](https://github.com/Peerborne/peerborne/tree/main/examples/password-manager) is a Vite, React, and Yjs reference application. Its typechecked production build and strict Chromium startup smoke test pass. It has no acceptance test proving two-user sharing, invitation delivery, restart recovery, or revocation.

:::caution
Do not store real passwords, recovery codes, API tokens, or other credentials in this example. Peerborne is under active development, is not independently audited, and has no assured durability or recovery path.
:::

Packages are unpublished. From a repository checkout prepared with the [quick start](../../getting-started/quick-start/), run:

Build and smoke-test the application:

```sh
yarn build
yarn workspace @peerborne/password-manager build
yarn test:e2e:password-manager
```

To run the Vite development server separately:

```sh
yarn workspace @peerborne/password-manager start
```

The smoke test proves startup only, not operational sharing.

## Required key material

A deployable application must generate, authenticate, persist, restore, and back up separate keys:

- a stable **ECDSA P-384** key pair for identity signing and ACL membership;
- a stable **ECDH P-256** KEM key pair whose private key permits `deriveBits`, for encrypted BeeKEM Welcomes;
- document epoch keys and membership state needed for recovery.

The application, not Peerborne, owns identity binding and recovery. Exchange the recipient's signing public key and raw 65-byte SEC1-uncompressed KEM public key over an authenticated out-of-band channel. A pasted, unauthenticated key is vulnerable to substitution.

## Correct onboarding sequence

**Status: Illustrative core sequence; not an end-to-end application recipe.** The direct document API has the necessary shape:

```ts
const kemKeyPair = await crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' },
  true,
  ['deriveBits'],
);

await recipientDocumentRef.setKemKeyPair(kemKeyPair);
const recipientKemRaw = recipientDocumentRef.getKemPublicKeyRaw();

await ownerDocumentRef.addReader(recipientIdentityPublicKey, recipientKemRaw);
await ownerDocumentRef.addWriter(recipientIdentityPublicKey);
```

Each participant must call `setKemKeyPair` on the relevant document ref before receiving Welcomes or administering BeeKEM membership. Add the recipient as a reader with `addReader(identity, kemRaw)` before granting writer status. Calling `addReader(identity)` without KEM bytes changes the reader ACL but sends no encrypted Welcome.

The current React wrapper exposes only `addReader(user)` and `addWriter(user)`. It cannot pass `kemRaw`, cannot call `setKemKeyPair`, and therefore cannot implement this onboarding sequence by itself. The password-manager UI currently pastes only an ECDSA public key, so its sharing controls are not evidence that a second identity can decrypt the document.

## Safer implementation checklist

**Status: Deferred/incomplete integration.** Prefer completing and testing these items over copying a runnable vault snippet:

- Persist and restore signing keys and P-256 KEM keys without logging or exposing private material.
- Bind both public keys to the intended human through an authenticated channel.
- Install KEM state on every opened document before invitation handling.
- Add a reader with signing identity plus raw KEM key; only then add writer rights if needed.
- Confirm the recipient decrypts and edits in a two-browser, two-identity test.
- Test dropped, replayed, delayed, and out-of-order Welcome and PathUpdate messages.
- Test restart before and after invitation, removal, and key rotation.
- Provide explicit backup, export, recovery, and destructive-loss UX.
- Reconcile the per-user index and secret document after partial dual-write failure.

BeeKEM reader mappings, tree state, and cached Welcomes have important memory-only paths. PathUpdate delivery is best effort, and restart, missed-update, multiwriter, and complete revocation behavior remain unresolved. Removing a member cannot erase plaintext or old keys they already copied. See [Security](../../concepts/security/) and [Limitations](../../concepts/limitations/).
