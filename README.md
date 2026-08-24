# Peerborne

[![CI](https://github.com/Peerborne/peerborne/actions/workflows/ci.yml/badge.svg)](https://github.com/Peerborne/peerborne/actions/workflows/ci.yml)
[![Site](https://github.com/Peerborne/peerborne/actions/workflows/site.yml/badge.svg)](https://github.com/Peerborne/peerborne/actions/workflows/site.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://peerborne.io/community/contributing/)
[![Docs](https://img.shields.io/badge/docs-peerborne.io-4f46e5)](https://peerborne.io/)

**Encrypted local-first state, carried by peers.**

Peerborne is an open-source TypeScript toolkit for encrypted CRDT documents
that live on user devices and synchronize over peer-to-peer networks.

**Documentation:** https://peerborne.io/

A centralized database is simpler and should be the default for most
applications. Peerborne is for collaboration where requiring every participant
to trust one plaintext data custodian—or one always-reachable application
server—is itself the problem.

**Status:** alpha software for experiments and prototypes; not production-ready.

## Quick start from source

Requires Node.js 22.19.0 and Yarn 4.5.0 through Corepack.

```sh
git clone https://github.com/Peerborne/peerborne.git peerborne
cd peerborne
corepack enable
yarn install --immutable
yarn build
yarn exec playwright install chromium
yarn test:e2e:browser-test
```

The browser test builds and smoke-tests one real encrypted Automerge document. It does not prove multi-peer convergence, persistence across restart, or invitation delivery. Continue with the [verified quick start](site/src/content/docs/getting-started/quick-start.mdx) for an interactive run and the exact evidence boundaries.

## Packages

| Workspace | Purpose |
| --- | --- |
| `@peerborne/core` | Core document, storage, networking, crypto, ACL, and key-management primitives |
| `@peerborne/automerge` | Automerge adapter and headless daemon |
| `@peerborne/yjs` | Yjs adapter and headless daemon |
| `@peerborne/react` | React context and hooks |
| `@peerborne/redux` | Redux actions and reducers |
| `@peerborne/index` | Local/blind indexes, Bloom-filter gossip, and query bindings |

All public packages and APIs use Peerborne names. The packages are source
workspaces and have not been published to npm; release tooling validates packed
tarballs in a clean external consumer. See the [migration notes](MIGRATING.md)
for the old-to-new API map and the legacy wire/storage identifiers intentionally
retained for compatibility.

## Architecture and evidence

Peerborne composes CRDT providers with Helia/IPFS content-addressed storage and libp2p discovery, pubsub, browser transports, and relay fallback. Changes can be signed and encrypted; ACL, UCAN, epoch, BeeKEM, and welcome-message primitives have focused tests.

Those implemented primitives do not establish every end-to-end product flow. Invitation acceptance and persisted KEM state, revocation across hostile peers, restart recovery, partition/rejoin convergence, pinning/restore, relay failover, and distributed search still need stronger integration evidence. Some networking paths require relay or Docker infrastructure.

See the [feature and verification audit](docs/feature-audit.md), [concepts](site/src/content/docs/concepts/), and [limitations](site/src/content/docs/concepts/limitations.md) before making capability claims.

## Examples

- [`examples/browser-test`](examples/browser-test) — minimal Automerge/Redux document app
- [`examples/wiki-swarm`](examples/wiki-swarm) — Automerge collaborative editor
- [`examples/password-manager`](examples/password-manager) — Yjs/React access-control UI

`yarn test:e2e` builds and smoke-tests all three Vite examples. They are development examples, not complete end-to-end showcases.

## Project links

- [Questions and ideas](https://github.com/Peerborne/peerborne/discussions)
- [Bugs and actionable work](https://github.com/Peerborne/peerborne/issues)
- [Contributing guide](site/src/content/docs/community/contributing.md)
- [Help wanted](site/src/content/docs/community/help-wanted.md)
- [Security policy](site/src/content/docs/community/index.md#security-reports)

For suspected vulnerabilities, use private vulnerability reporting from the repository **Security** tab. Do not disclose them in public issues or discussions.

## License

Peerborne and all six package manifests use the [MIT License](LICENSE).
