---
title: Encrypted shared secrets store
description: Assess the password-manager source example and the incomplete distinct-identity onboarding flow.
---

**Status: Browser-local vault recovery is tested; sharing and distributed revocation remain incomplete.**

[`examples/password-manager`](https://github.com/Peerborne/peerborne/tree/main/examples/password-manager) is a Vite, React, and Yjs reference application. Its Chromium suite saves and reopens a vault after reload and after closing and relaunching the browser with the same profile. It also covers offline document reopening after the application loads, damaged checkpoints, failed writes and retry, and the permissions UI. It has no acceptance test proving two-user sharing, invitation delivery, peer-assisted recovery, or distributed revocation.

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

These tests establish the browser-local recovery path, not operational sharing.

## Reopen a saved vault

Login reuses non-extractable signing and KEM key handles from IndexedDB. The
vault selector lists saved vaults. Each vault index and secret is checkpointed
with its data, document keys, history, and membership state, signed by the local
identity, and encrypted with a separate non-extractable AES-GCM storage key.
Restoration authenticates the identity and document binding before installing
state, then opens locally without trusting a network response. Network V4 load
trust configuration is not needed for this local path.

Wait for **Saved in this browser** before closing the tab. Failed writes remain
visible with a retry action; missing or invalid state never silently creates a
replacement. Writes are atomic per document, so the vault index and a secret
are still separate writes. Only one active tab may write this browser's vaults.

This is not a password lock, backup, cross-device identity transfer, or
peer-assisted recovery. Clearing site data removes access. Authenticated old
checkpoints can still be replayed by a storage attacker; preventing rollback
requires an independently protected anchor. Checkpoints are bounded to 16 MiB
and must not be transmitted or persisted without encryption.

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

Each participant must call `setKemKeyPair` on the relevant document ref before receiving Welcomes or administering BeeKEM membership. Add the recipient as a reader with `addReader(identity, kemRaw)` before granting writer status; `addReader` requires the KEM bytes.

The example restores its persistent KEM identity before opening each document
and shows its public half on the Settings page. Its permissions table requires
a new member's signing public key and raw KEM public key, both base64, before
membership changes, so the owner sends a recipient-sealed Welcome. Its Chromium
test promotes a reader to editor in one browser. The example has no recipient
flow that opens the shared secret afterwards, so no two-browser test proves
that a second identity receives the Welcome and decrypts the document.

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

Local checkpoints retain BeeKEM reader mappings, tree state, rotated local
leaf keys, replay metadata, and cached Welcomes. Focused tests reconstruct a
founder, remove a reader, reconstruct again, and edit. This does not establish
distributed delivery or crash consistency across membership changes. PathUpdate
delivery is best effort; missed-update, multiwriter, and complete revocation
behavior remain unresolved. Removing a member cannot erase plaintext or old
keys they already copied. See [Security](../../concepts/security/) and
[Limitations](../../concepts/limitations/).
