---
title: Run your own relay node
description: Run the repository's development relay and configure Vite browser clients to dial it.
---

**Status: Runnable development relay.** The relay builds and has unit coverage; deployment, failover, stable identity, and scale are not yet production-validated.

Browser deployments generally need bootstrap/relay infrastructure because browsers cannot usually accept arbitrary inbound connections. Not every topology routes all traffic through a relay: peers may discover direct WebRTC paths, and Node/LAN topologies may use other discovery. See [Networking](../../concepts/networking/).

## Start the development relay

From the repository root:

```sh
docker build -t peerborne-relay relay-server/
docker run -d \
  --name peerborne-relay \
  -p 9001:9001 \
  -p 9002:9002 \
  -v relay-data:/shared \
  peerborne-relay
```

Port 9001 is WebSocket; port 9002 is plain TCP. The equivalent checked-in Compose command is:

```sh
docker compose -f guides/docker/docker-compose.single.yaml up -d
docker compose -f guides/docker/docker-compose.single.yaml exec relay \
  cat /shared/relay-info.json
```

For the direct `docker run` container, inspect the same file with:

```sh
docker exec peerborne-relay cat /shared/relay-info.json
```

The file contains the generated peer ID and listen multiaddrs. Do not give clients `/ip4/0.0.0.0/...`; construct a dialable address:

```text
/dns4/relay.example.com/tcp/9001/ws/p2p/<peer-id>
```

## Configure Vite clients

The repository examples read `VITE_RELAY_MULTIADDR`:

```sh
VITE_RELAY_MULTIADDR='/dns4/relay.example.com/tcp/9001/ws/p2p/<peer-id>' \
  yarn workspace @peerborne/browser-test start
```

Application code passes it to the bootstrap list:

```ts
const relay = import.meta.env.VITE_RELAY_MULTIADDR;
const config = defaultConfig(defaultBootstrapConfig(relay ? [relay] : []));
```

## TLS and reverse proxying

An HTTPS page must dial secure WebSockets. Terminate TLS at a reverse proxy on 443, configure it to preserve the WebSocket HTTP Upgrade and proxy that connection to relay port 9001, then use:

```text
/dns4/relay.example.com/tcp/443/wss/p2p/<peer-id>
```

This source recipe does not establish a production deployment. Validate proxy timeouts, connection limits, certificates, resource limits, logs, and denial-of-service behavior in your environment.

## Operational limits

- The relay generates a new libp2p peer identity at startup. Restart changes the peer ID and invalidates client multiaddrs. Stable identity requires unsupported application/code work today.
- There is no supported relay-meshing or startup-dial configuration. Multiple isolated relays are not proven failover simply because all addresses are listed in a client.
- `TOPIC_ALLOWLIST` limits which non-system topics the relay **auto-subscribes** to. It is not user authentication, document authorization, or a confidentiality boundary.
- `MAX_AUTO_TOPICS` caps automatic subscriptions. `EXTRA_TOPICS` adds static subscriptions; neither creates relay peering.
- Docker health checks only establish a TCP connection to port **9001**. There is no HTTP readiness endpoint and the check does not prove GossipSub, circuit reservation, or end-to-end document sync.
- The relay forwards traffic and metadata but does not durably store documents. Pinning remains [incomplete](../pinning/).
- Relay failover during edits, upgrade/rollback, capacity, abuse resistance, monitoring, and production scale are unverified. Relays can observe metadata and can censor, delay, or partition traffic.

Use separate DNS names for distinct peer IDs; a load-balanced hostname can route a multiaddr ending in one peer ID to the wrong relay process. Consult [Limitations](../../concepts/limitations/) before deployment.
