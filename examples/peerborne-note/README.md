# Peerborne Note

Peerborne Note is a zero-install, two-browser demonstration of the initial
Peerborne invitation flow. It creates an encrypted Automerge document locally,
then uses a configured Circuit Relay rendezvous to invite one distinct browser
identity as an editor or reader.

This is early-stage software and is not production-ready. Do not enter sensitive
or durable information. Both browsers must remain open and online; delivery,
automatic reconnect, and restart recovery are not guaranteed.

## Run locally

Build the library workspaces from the repository root, then provide a complete,
peer-ID-qualified relay multiaddr:

```sh
yarn build
VITE_PEERBORNE_RELAY_MULTIADDR=/dns4/relay.example.com/tcp/443/wss/p2p/12D3KooW... \
  yarn workspace @peerborne/peerborne-note start
```

The relay address is public deployment configuration, not a secret. Production
pages served over HTTPS require a `/wss/` relay address.

## Verify

```sh
yarn workspace @peerborne/peerborne-note test
yarn workspace @peerborne/peerborne-note build
```

The focused tests cover canonical invitation fragments and the versioned
IndexedDB identity boundary. The repository's separate NAT-isolated Playwright
suite is the end-to-end evidence for distinct-identity invitation acceptance
and bidirectional encrypted convergence; these utility tests do not replace it.

After deployment, the mandatory live gate uses separate browser contexts to
exercise editor and reader invitations, explicit acceptance, read-only UX, and
fresh edits through the public WSS relay:

```sh
PEERBORNE_NOTE_LIVE_URL=https://try.peerborne.io/ \
  yarn test:e2e:peerborne-note:live
```

Hosted builds must fail closed when the relay configuration is absent or not a
complete DNS/TCP 443/WSS/peer-ID multiaddr:

```sh
VITE_PEERBORNE_RELAY_MULTIADDR=/dns4/relay.example.com/tcp/443/wss/p2p/12D3KooW... \
  yarn workspace @peerborne/peerborne-note build:deployment
```
