---
title: Run your own relay node
description: Run the repository's development relay and configure Vite browser clients to dial it.
---

**Status: Runnable relay with deployment-oriented controls.** The relay builds
and has unit coverage for persisted identity and readiness. Hosted deployment,
failover, capacity, and scale are not yet production-validated.

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

The volume also holds `/shared/relay-identity.key`; keep it across container
replacement to retain the peer ID. Never publish or log that private file. The
JSON file contains only the public peer ID and listen multiaddrs. Do not give
clients `/ip4/0.0.0.0/...`; construct a dialable address:

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

`defaultConfig` keeps libp2p's browser dial policy, which refuses insecure `/ws`
WebSockets and loopback or private addresses, so give applications a `/wss/`
relay address. The browser-test harness passes
`{ allowLocalNetworkDials: true }` as the third argument of `defaultConfig` so
it can use plain `/ws`, local and Docker relays; see
[Dial policy](../../concepts/networking/#dial-policy).

## TLS and reverse proxying

An HTTPS page must dial secure WebSockets. Terminate TLS at a reverse proxy on 443, configure it to preserve the WebSocket HTTP Upgrade and proxy that connection to relay port 9001, then use:

```text
/dns4/relay.example.com/tcp/443/wss/p2p/<peer-id>
```

Behind a reverse proxy the relay sees every browser at the proxy's address. GossipSub penalizes many peer IDs sharing one IP and keeps scores of disconnected peers for an hour, so from about the 15th browser identity in an hour it silently ignores new subscriptions. Set `TRUSTED_PROXY_IPS` on proxied relays:

- `TRUSTED_PROXY_IPS=*` disables GossipSub IP-colocation scoring. Use it only when every connection arrives through a proxy, as in the checked-in Fly configuration.
- A comma-separated list of IPv4 or IPv6 addresses or CIDR ranges, such as `TRUSTED_PROXY_IPS=172.30.0.2` or `10.0.0.0/8`, exempts only matching addresses and keeps IP scoring for peers that connect directly. The Docker+Caddy compose file pins Caddy's address and lists it because it also publishes TCP 9002. Hostnames, `*` inside a list and other unparseable entries stop the relay at startup.

When every listener is bound to `127.0.0.1` or `::1`, as in the Render gateway, the relay exempts the loopback addresses automatically. The relay does not read forwarded-for headers, so the trade-off is that GossipSub can no longer limit Sybil identities by client IP; enforce per-client connection and rate limits at the proxy.

This source recipe does not establish a production deployment. Validate proxy timeouts, connection limits, certificates, resource limits, logs, and denial-of-service behavior in your environment.

## Operational limits

- The standard image persists an app-managed libp2p identity at `/shared/relay-identity.key`. Direct process runs default to `./relay-identity.key`; set `RELAY_IDENTITY_KEY_PATH` to durable storage. Losing the file changes the peer ID and invalidates pinned multiaddrs. Do not share one key between live relay processes.
- There is no supported relay-meshing or startup-dial configuration. Multiple isolated relays are not proven failover simply because all addresses are listed in a client.
- `TOPIC_ALLOWLIST` defaults to `/peerborne/document/v3/,peerborne/coordinated/v1/` (ordinary and coordinated documents) and limits which non-system GossipSub topics the relay node **auto-subscribes** to. Entries ending in `/` are namespace prefixes; entries without a trailing slash are exact topics, so `/announcements` does not admit `/announcements-extra`. All peers sharing a custom topic must use the same runtime. Add every custom document prefix to each relay's allowlist. Configure permanent subscriptions with `EXTRA_TOPICS`. Set exactly `*` only for intentional open mode. Topic names are routing labels, not authentication. The allowlist does not inspect or restrict opaque, Noise-encrypted Circuit Relay streams and is not authentication, document authorization, or a confidentiality boundary.
- `MAX_AUTO_TOPICS` caps automatic subscriptions globally, `MAX_AUTO_TOPICS_PER_PEER` (default `32`) prevents one peer from consuming that allowance, and `GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER` (default `65536`) bounds remote topic metadata at ingestion. Each subscription costs its topic name's length plus 1024 bytes, and a subscription over budget is silently ignored, so the relay does not forward that topic for that peer. A client uses the 38-character discovery topic plus one topic per open document; core's coordinated-document topics are 89 characters. The default fits about 57 such topics, and the Render blueprint's `16384` fits the discovery topic plus 13. `EXTRA_TOPICS` adds static subscriptions; none of these settings creates relay peering.
- The global transport-connection cap, reservation cap/TTL, per-connection HOP/STOP stream limits, and per-circuit duration/data limits have finite configurable defaults. Circuit Relay v2 keys reservations by peer ID and would otherwise hold one until its TTL; the relay expires a peer's reservation when its last connection closes, so reloads and closed tabs return their slot. A connected client's renewals extend its reservation by one TTL each; the relay project patches `retimeable-signal@1.0.1`, which otherwise expired the reservation one TTL after the first renewal. Keep `RELAY_MAX_RESERVATIONS` at or above the number of clients that can be connected at once (`MAX_CONNECTIONS`, or 16 on the Render blueprint) so the reservation cap is not the first limit reached. These controls are not a capacity claim.
- The standard Docker health check calls `/readyz` on internal port **9000**. Readiness proves identity loading, libp2p startup, seed subscriptions, and relay-info output; it does not prove a remote reservation or end-to-end document sync. `/livez` is available separately.
- The relay forwards traffic and metadata but does not durably store documents. Pinning remains [incomplete](../pinning/).
- Relay failover during edits, upgrade/rollback, capacity, abuse resistance, monitoring, and production scale are unverified. Relays can observe metadata and can censor, delay, or partition traffic.

Use separate DNS names for distinct peer IDs; a load-balanced hostname can route a multiaddr ending in one peer ID to the wrong relay process. Consult [Limitations](../../concepts/limitations/) before deployment.
