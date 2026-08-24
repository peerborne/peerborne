# Peerborne password manager

This Vite and React reference interface explores Yjs documents, Peerborne React
hooks, and item-specific access-control UI.

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

The smoke test builds this workspace and verifies that the login interface
renders in Chromium without runtime errors. It does not prove distinct-identity
sharing, invitation delivery, restart recovery, revocation, or protection of
real credentials.

- [Encrypted shared-secrets guide](https://peerborne.io/cookbook/password-manager/)
- [Security model](https://peerborne.io/concepts/security/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
