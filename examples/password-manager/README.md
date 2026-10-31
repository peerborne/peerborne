# Peerborne password manager

This Vite and React reference interface explores Yjs documents, encrypted
browser checkpoints, and item-specific access-control UI.

Do not enter real credentials or other sensitive data into this example.

## Run from source

Use Node.js 22.19.0 and Yarn 4.5.0 through Corepack. From the repository root:

```sh
corepack enable
yarn install --immutable
yarn build
yarn workspace @peerborne/password-manager start
```

Open the URL printed by Vite. The application redirects its root route to the
login interface.

## Verify the current example

```sh
yarn exec playwright install chromium
yarn test:e2e:password-manager
```

The Chromium suite creates a vault, saves a secret, reloads and logs in as the
same identity, reopens the vault, and edits it again. A separate persistent-profile
test closes and relaunches Chromium before reopening. It also checks damaged
checkpoints, failed writes and retry, and the existing permissions UI. Run the
focused storage and document tests with `yarn test:password-manager`.

## Browser-local recovery

Login uses the signing and KEM identities stored as non-extractable CryptoKey
handles in IndexedDB. It is not a password lock. Each document checkpoint is
signed by that identity and encrypted with a separate non-extractable AES-GCM
storage key. The vault list and each secret retain their data, document keys,
history, and membership state. Open a saved vault from the vault selector after
logging in. Wait for **Saved in this browser** before closing the tab.

Checkpoint writes are atomic per document and carry revision checks. A vault
index edit and a secret edit are separate writes. A storage failure is shown in
the UI with a retry action; missing or invalid identity/checkpoint data never
creates an empty replacement. Only one active tab may write this browser's vaults.

This path restores authenticated local state without a network load. It does
not implement peer-assisted recovery, multi-device identity transfer, backup,
or rollback protection against an attacker replaying an older valid checkpoint.
Clearing or losing browser storage removes the identity and vault access. It
does not prove distinct-identity sharing, invitation delivery, distributed
revocation, or protection of real credentials.

- [Encrypted shared-secrets guide](https://peerborne.io/cookbook/password-manager/)
- [Security model](https://peerborne.io/concepts/security/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
