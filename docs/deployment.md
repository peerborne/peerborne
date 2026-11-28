# Peerborne Coordination Server Deployment Guide

Peerborne browser peers connect through coordination servers that provide two
functions: **circuit relay** (proxying connections between browsers that cannot
reach each other directly) and **bootstrap** (helping new peers discover the
network via pubsub peer discovery).

The relay server in `relay-server/` fulfills both roles. Every deployment needs
at least one relay server. Browser peers connect to it over WebSocket; Node.js
peers can also connect over TCP.

> **Scope.** This document is the operational reference for running the
> relay/bootstrap server (Docker images, TLS, multi-relay, Kubernetes,
> monitoring, troubleshooting). For a broader overview of *all* Peerborne
> coordination server types -- including signaling, STUN/TURN, and pinning
> services -- see [`guides/coordination-servers.md`](../guides/coordination-servers.md).
> Where the two documents disagree on relay/bootstrap operations, this one is
> authoritative; the overview doc will be reconciled in a follow-up.

## Quick Start -- Single Server

The fastest way to get a relay running:

```bash
# Build the relay image
docker build -t peerborne-relay relay-server/

# Run it
docker run -d \
  --name peerborne-relay \
  -p 9001:9001 \
  -p 9002:9002 \
  -v relay-data:/shared \
  peerborne-relay
```

Port 9001 serves WebSocket connections (browsers). Port 9002 serves TCP
connections (Node.js peers and inter-relay communication).

The named `/shared` volume also stores `relay-identity.key`. Keep that volume
across container replacement: the relay derives the same public peer ID from
that private key on every start. The key is created with mode `0600`; do not
print it, copy it into logs, or share one identity between running relays.

After startup the relay writes `/shared/relay-info.json` containing its peer ID
and multiaddresses. Retrieve it with:

```bash
docker exec peerborne-relay cat /shared/relay-info.json
```

Example output:

```json
{
  "peerId": "12D3KooW...",
  "multiaddrs": [
    "/ip4/0.0.0.0/tcp/9001/ws/p2p/12D3KooW...",
    "/ip4/0.0.0.0/tcp/9002/p2p/12D3KooW..."
  ],
  "wsMultiaddr": "/ip4/0.0.0.0/tcp/9001/ws/p2p/12D3KooW..."
}
```

**Important:** The `wsMultiaddr` in `relay-info.json` contains the relay's
*listen* address (e.g. `/ip4/0.0.0.0/...`), which is not dialable from another
machine. Clients must construct a multiaddr using the relay's public IP or DNS
name and the `peerId`:

```text
/dns4/relay.example.com/tcp/9001/ws/p2p/<peerId>
```

or for a bare IP:

```text
/ip4/<PUBLIC_IP>/tcp/9001/ws/p2p/<peerId>
```

Pass this constructed multiaddr to your Peerborne client configuration so browsers
know where to connect.

Or use the provided single-server Compose file:

```bash
docker compose -f guides/docker/docker-compose.single.yaml up -d

# Retrieve relay info
docker compose -f guides/docker/docker-compose.single.yaml \
  exec relay cat /shared/relay-info.json
```

## Environment Variables

All configuration is done through environment variables on the relay process.

| Variable | Default | Description |
| --- | --- | --- |
| `WS_PORT` | `9001` | WebSocket listen port |
| `TCP_PORT` | `9002` | TCP listen port |
| `WS_LISTEN` | `/ip4/0.0.0.0/tcp/$WS_PORT/ws` | Full WebSocket multiaddr |
| `TCP_LISTEN` | `/ip4/0.0.0.0/tcp/$TCP_PORT` | Full TCP multiaddr |
| `ENABLE_IPV6` | (unset) | Set to `1` to add IPv6 listeners |
| `WS_LISTEN_V6` | `/ip6/::/tcp/$WS_PORT/ws` | IPv6 WebSocket multiaddr |
| `TCP_LISTEN_V6` | `/ip6/::/tcp/$TCP_PORT` | IPv6 TCP multiaddr |
| `READINESS_PORT` | `9000` | Internal HTTP port for `/livez` and `/readyz` |
| `RELAY_IDENTITY_KEY_PATH` | `./relay-identity.key` | App-managed protobuf libp2p private-key file. The standard image sets `/shared/relay-identity.key` |
| `EXTRA_TOPICS` | (unset) | Comma-separated additional topics to subscribe |
| `TOPIC_ALLOWLIST` | `/peerborne/document/v3/,peerborne/coordinated/v1/` | Comma-separated exact topics or slash-terminated namespace prefixes for auto-subscribe. Set exactly `*` for explicit open mode |
| `MAX_AUTO_TOPICS` | `1000` | Cap on auto-subscribed topics to prevent unbounded growth |
| `MAX_AUTO_TOPICS_PER_PEER` | `32` | Cap on dynamic topics tracked for one remote peer |
| `GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER` | `65536` | Ingestion-layer topic-name byte budget for one remote peer. Each subscription costs its name length plus 1024 bytes |
| `TRUSTED_PROXY_IPS` | (unset) | Comma-separated proxy IPs or CIDR ranges exempt from GossipSub IP-colocation scoring, or `*` when every connection arrives through a proxy. Invalid entries stop startup. See [Reverse proxies](#reverse-proxies-and-gossipsub-ip-scoring) |
| `MAX_CONNECTIONS` | `256` | Global ceiling for established libp2p transport connections |
| `RELAY_MAX_RESERVATIONS` | `128` | Maximum active Circuit Relay v2 reservations. A peer's reservation is freed when its last connection closes and lasts one TTL from its latest renewal |
| `RELAY_RESERVATION_TTL_MS` | `600000` | Reservation lifetime before renewal, in milliseconds |
| `RELAY_MAX_CIRCUIT_DURATION_MS` | `1800000` | Per-circuit duration limit, in milliseconds |
| `RELAY_MAX_CIRCUIT_BYTES` | `16777216` | Per-circuit data limit, in bytes |
| `RELAY_HOP_TIMEOUT_MS` | `30000` | HOP negotiation timeout, in milliseconds |
| `RELAY_MAX_INBOUND_HOP_STREAMS` | `8` | Maximum simultaneous inbound HOP streams per connection |
| `RELAY_MAX_OUTBOUND_HOP_STREAMS` | `8` | Maximum simultaneous outbound HOP streams per connection |
| `RELAY_MAX_OUTBOUND_STOP_STREAMS` | `8` | Maximum simultaneous outbound STOP streams per connection |

### IPv6 Notes

On most Linux hosts `::` is dual-stack, so binding both IPv4 and IPv6 on the
same port causes `EADDRINUSE`. Only set `ENABLE_IPV6=1` on platforms where the
IPv6 socket is **not** dual-stack, or when using separate ports.

### Topic Auto-Subscribe

The relay automatically subscribes to document topics as peers join them. This
means the relay can forward messages between browser peers that have not yet
established a direct WebRTC connection. When all peers leave a topic the relay
automatically unsubscribes. The relay tracks subscriptions by peer, cleans them
on disconnect, and periodically reconciles its bounded dynamic-topic set with
GossipSub as a backstop for missed unsubscribe events.

The default admits the `/peerborne/document/v3/` document namespace and the
`peerborne/coordinated/v1/` namespace that core uses for coordinated documents.
Allowlist entries ending in `/` match a namespace prefix; entries without a
trailing slash match one exact topic. A custom client namespace must be added
to every relay's `TOPIC_ALLOWLIST`. All peers must use the same runtime and
topic configuration. Topic names are routing labels, not authentication or
wire validation.
Keep both `MAX_AUTO_TOPICS` and `MAX_AUTO_TOPICS_PER_PEER` at reasonable limits
for your deployment. The global cap bounds total dynamic state; the per-peer cap
prevents one connected peer from consuming that allowance. The GossipSub byte
budget rejects oversized or excessive remote subscription metadata before it
reaches the relay registry. `*` is an
intentional opt-out of topic filtering, not a recommended public-relay default.
This policy controls only the topics to which the relay node itself subscribes
for GossipSub forwarding. It does not inspect or restrict opaque, Noise-encrypted
Circuit Relay streams, and it is not document authorization.

GossipSub silently ignores a subscription that would exceed
`GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER`, so the relay never forwards that topic for
that peer. Each subscription costs its topic name's length plus 1024 bytes. A
client subscribes to the 38-character discovery topic plus one topic per open
document; coordinated-document topics are 89 characters. The default 64 KiB
budget fits about 57 such document topics; Render's 16 KiB fits 13. Keep the
budget above the discovery topic plus `MAX_AUTO_TOPICS_PER_PEER` document topics.

Every client subscribes to the peer-discovery topic, so the relay forwards each
message there to every subscriber. It validates the topic before forwarding.
A message must be signed and carry its signer's own pubsub-peer-discovery
record, holding only the signer's public key and addresses, of at most 4 KiB;
anything else is rejected. A Peerborne Note tab's record is about 600 bytes.
Each connected peer that delivers messages on the topic may deliver 3 at once
and then 1 every 5 seconds, twice the 10-second broadcast interval; further
messages are ignored. Rejected messages count against that allowance too. The
relay forwards neither, so a flooding peer reaches each subscriber with at most
about 0.8 KiB/s. A peer that forwards other peers' records to the relay before
their authors do spends its own allowance on them; once that is spent, the
relay skips those records until the next broadcast.

### Reverse proxies and GossipSub IP scoring

GossipSub penalizes many peer IDs that share one source IP and retains the
scores of disconnected peers for an hour. Behind Fly, Caddy, a Kubernetes
Ingress or any other reverse proxy, every browser arrives from the proxy's
address. From about the 15th browser identity in an hour, new peers fall below
the graylist threshold and the relay silently ignores their subscriptions.

Set `TRUSTED_PROXY_IPS` on every proxied relay:

- `*` disables IP-colocation scoring entirely. The checked-in Fly
  configuration and the Kubernetes example use it because every connection they
  accept arrives through the proxy.
- A comma-separated list of IPv4 or IPv6 addresses or CIDR ranges, such as
  `172.30.0.2` or `10.0.0.0/8`, exempts only matching addresses. Peers that
  connect directly, for example over TCP 9002, keep IP scoring. The
  Docker+Caddy compose file pins Caddy at `172.30.0.2` and lists only that
  address, because it also publishes TCP 9002. Hostnames, `*` inside a list and
  other unparseable entries stop the relay at startup rather than being
  ignored.

Do not use `*` on a relay that also accepts direct connections. IP-colocation
scoring is GossipSub's only Sybil defence there: without it, one host can open
enough identities to fill `MAX_AUTO_TOPICS`.

When every libp2p listener is loopback-only, as in the Render gateway, the relay
exempts `127.0.0.1` and `::1` automatically.

The trade-off: the relay does not read forwarded-for headers, so an exempted
address loses GossipSub's protection against one host creating many identities.
Enforce per-client connection and request-rate limits at the proxy, and keep
`MAX_CONNECTIONS`, `MAX_AUTO_TOPICS_PER_PEER` and the topic byte budget bounded.

## Fly.io: persistent identity and WSS

The checked-in `relay-server/fly.toml` exposes the internal WebSocket listener
through Fly TLS termination on public port 443. Browser clients therefore dial:

```text
/dns4/<APP_NAME>.fly.dev/tcp/443/wss/p2p/<peerId>
```

Create the volume named by `fly.toml` before the first deploy. Its region must
match `primary_region`:

```bash
cd relay-server
fly launch --no-deploy
fly volumes create peerborne_relay_data --region iad --size 1
fly deploy
fly checks list
```

`RELAY_IDENTITY_KEY_PATH=/data/relay-identity.key` is already set in
`fly.toml`; no identity secret needs to be generated or passed to Fly.
`TRUSTED_PROXY_IPS=*` is also set because every browser arrives through
fly-proxy; see [Reverse proxies](#reverse-proxies-and-gossipsub-ip-scoring).
Back up the volume if preserving the peer ID matters. Losing the file creates a new
identity and invalidates multiaddrs pinned to the previous `/p2p/<peerId>`.

For `relay.peerborne.io`, add the hostname to the Fly app, follow Fly's emitted
DNS targets, and wait for certificate validation before publishing the client
multiaddr:

```bash
fly certs add relay.peerborne.io
fly certs check relay.peerborne.io
```

Then use `/dns4/relay.peerborne.io/tcp/443/wss/p2p/<peerId>`. This browser-only
Fly configuration deliberately does not publish raw TCP port 9002: Fly's
shared IPv4 addresses do not provide that dedicated TCP service here.

The readiness check stays private on port 9000. `/readyz` becomes successful only after the
stable identity is loaded, libp2p is listening, topic subscriptions are
installed, and `relay-info.json` has been written. Fly monitors that check for
deployment health, but the public WSS service uses a TCP routing check; `/readyz`
does not gate Fly request routing.

Keep this volume-backed configuration at one Fly Machine. Higher availability
requires a separate volume, key, peer ID, and hostname per relay; never mount
or copy one private identity into concurrently running processes.

## Render Free: bounded public demo behind Cloudflare

The root [`render.yaml`](../render.yaml) deploys one Free Docker web service for
`relay.peerborne.io`. It runs `node dist/render.js`, which puts a small HTTP and
WebSocket gateway in front of loopback-only libp2p listeners. The ordinary Docker
and Fly entry points retain their existing behavior.

When every libp2p listener is loopback-only, the relay excludes `127.0.0.1` and
`::1` from GossipSub's IP-colocation penalty. Those addresses identify the local
gateway, not individual clients. Without this exception, retained scores from
closed browser sessions eventually suppress subscriptions for new sessions.
The gateway continues to enforce real client IP limits. Relays with any public
listener retain GossipSub's default IP scoring unless `TRUSTED_PROXY_IPS` is set.

Render Free has no persistent disk. The Blueprint generates a private
`RELAY_IDENTITY_SEED` once; the entry point reconstructs the same Ed25519 identity
after each restart. Preserve this environment variable and never print or commit
it. Changing it changes the public peer ID and invalidates existing multiaddrs.

The gateway's public `/readyz` returns the public peer ID after libp2p is ready.
Browser clients use:

```text
/dns4/relay.peerborne.io/tcp/443/wss/p2p/<peerId>
```

### Origin protection and Cloudflare

1. Create the Blueprint using the **Free** service plan. Set
   `RELAY_GATEWAY_SECRET` to a random secret of at least 32 ASCII characters.
   Keep the Render workspace without a payment method if service suspension at
   the free bandwidth allowance is required; a paid workspace can incur
   bandwidth overages even when its compute instance is Free.
2. Add `relay.peerborne.io` as the Render custom domain. Create a CNAME pointing
   `relay` to the actual assigned `onrender.com` hostname. Initially use DNS-only
   mode so Render can verify the domain and issue its certificate.
3. In Cloudflare, create a Request Header Transform Rule matching only
   `http.host eq "relay.peerborne.io"`. **Set**, rather than append, the request
   header `X-Peerborne-Origin` to the same private `RELAY_GATEWAY_SECRET`.
   Never send this secret to the browser or put it in a response header.
4. Add a custom Block rule scoped to the relay hostname that permits only
   WebSocket upgrades at `/`, GET/HEAD requests at `/readyz` and `/livez`, and
   GET/HEAD certificate challenges under `/.well-known/acme-challenge/`.
   The certificate exception allows Render to renew TLS while proxying is on.
   Use Block rather than an interactive challenge on the WebSocket endpoint;
   a browser's WebSocket API cannot complete that challenge.
5. After Render has issued its certificate, enable Cloudflare proxying and use
   Full (strict) TLS for this hostname. The Blueprint disables access through
   the default Render subdomain; the gateway independently rejects upgrades
   without the secret. Only then publish the client multiaddr.

Cloudflare's WAF inspects the upgrade request, not subsequent WebSocket frames.
The gateway therefore enforces limits on the opaque encrypted byte stream in
both directions, including traffic outside document GossipSub topics:

| Limit | Demo value |
| --- | --- |
| Simultaneous WebSocket connections | 16 total, 4 per client |
| Upgrade attempts | 6/minute and 3/10 seconds per client |
| New clients admitted | 30 distinct clients/minute; their reconnects are not counted again |
| Tracked client records | 512, kept until the minute window has passed and the client's traffic share has refilled; when full, the least recently seen client without a session is forgotten |
| Rejected upgrade lifetime | 1 second to drain the response, then closed |
| Session lifetime / inactivity | 10 minutes / 60 seconds |
| Total bytes per session | 8 MiB across both directions |
| Session throughput | 64 KiB/second with a 128 KiB burst |
| Shared tunnel traffic window (`RELAY_GATEWAY_WINDOW_BYTES`) | 128 MiB, refilling continuously over 10 minutes; below 128 KiB, upgrades get `503` and sessions that send more close |
| Tunnel traffic per client (`RELAY_GATEWAY_CLIENT_WINDOW_BYTES`) | 32 MiB across the client's sessions, refilling continuously over 10 minutes; below 128 KiB, the client's upgrades get `429` and its sessions that send more close |
| GossipSub topic budget per peer | 16 KiB: discovery plus 13 coordinated-document topics |
| Circuit Relay reservations / individual circuit bytes | 16 / 1 MiB |
| Individual circuit lifetime | 5 minutes |

A client is one IPv4 address or one IPv6 /64, so rotating addresses inside a
/64 does not create new clients. Per-client limits are checked first, and the
new-client budget counts distinct clients admitted in the current minute rather
than sessions. A few clients reconnecting cannot exhaust it, and a client
already admitted this minute can reconnect after the budget is spent. A full
registry forgets idle clients instead of rejecting unseen ones.

Each tunnel's bytes in both directions count against its session, its client's
share, and the shared window. A client's sessions draw on one share, so
reconnecting does not refill it. Both allowances refill continuously, so neither
stays spent after traffic stops, and one client can use at most a quarter of the
window: 32 MiB at once, then about 56 KB/s. Other clients keep connecting while
it does.

The values are sized from Peerborne Note traffic measured through this gateway.
Sixteen idle tabs on eight shared notes, two tabs per client, moved about
100 KB/s in total for the first five minutes after connecting and about
31 KB/s afterwards, and sharing one note moved about 240 KB. Per-tab traffic
grows with the number of connected tabs: two idle tabs alone move about
2.5 KB/s. The window refills at about twice the peak traffic of 16 idle tabs,
a client's share at about twice that of the 4 tabs it can hold, and 8 MiB
covers a 10-minute session at the peak rate twice over. With the previous
2 MiB session cap, those idle tabs began losing sessions after about five
minutes.

These limits bound rather than remove lockout. An attacker with 4 clients can
hold all 16 connections, or spend the shared window and keep it nearly empty;
upgrades then get `503` and sessions that send more close until the attack
stops and the window refills. With 30 clients it can also use up the new-client
budget for the rest of each minute. One IPv6 /56 provides 256 /64 clients.
Stopping these needs limits upstream of the gateway, such as Cloudflare
rate-limiting rules.

Traffic counts against the session that carries it, including GossipSub
messages that the relay forwards from other clients. On the peer-discovery
topic that every client subscribes to, the relay forwards at most 3 records and
then about 0.8 KiB/s from each connected peer, as described under
[Topic Auto-Subscribe](#topic-auto-subscribe). One client's 4 sessions can
therefore send each subscriber at most about 3.2 KiB/s there, or about 48 KiB/s
across 15 subscribers, under a quarter of the window's refill. In a local test,
three sessions from one client flooding the topic with random 10 KiB messages
at about 43 KiB/s each delivered nothing to six subscribers; with valid 4 KiB
records they delivered about 2.4 KiB/s to each, and no subscriber session
closed.

While the window holds less than one session burst, the public `/readyz` still
returns HTTP 200 but reports
`{"status":"budget-exhausted","peerId":"<peerId>","retryAfterSeconds":<seconds>}`.
Rejected upgrades carry the same `Retry-After`, and the gateway logs
`Relay gateway traffic window exhausted` at most once a minute. Monitor that
status or log line. The health check deliberately keeps passing: Render stops
routing to an instance after 15 seconds of failed checks and restarts it after
60 seconds. With one instance, failing the check would turn throttling into an
outage, and each restart would give an attacker a fresh window. The window
recovers by itself.

The reservation cap matches the 16 sessions, and reservations are freed when a
client disconnects, so it is not the first limit reached.

IP headers are trusted only after checking the origin secret. The gateway never
forwards that credential to libp2p or logs credentials, IP addresses, or payloads.
The traffic limits cover bytes passing through the gateway's tunnels, not every
HTTP header, rejection response, or byte billed by Render. They are
**per-process** limits, not a durable daily or monthly quota: Render restarts and
idle spin-down reset them. They bound abuse to about twice the traffic of a full
gateway, not to Render's allowance. Render's Hobby workspace includes 5 GB of
outbound bandwidth per month; 16 idle Note tabs move 2.7 to 8.6 GB a day
through the tunnels, and the window refills at up to about 19 GB a day. Render's
workspace allowance and suspension policy remain the billing boundary: without
a payment method, Render suspends Free services for the rest of the month once
the allowance is used.

Cloudflare Free currently has one rate-limit rule with restricted expression
fields and 10-second windows. Do not apply a broad path-only rule that also
limits the documentation site. The relay-specific origin limits above work
without a paid Cloudflare plan. Keep unrelated zone rules and DNS records intact.

Before publishing, verify a successful WebSocket through Cloudflare, rejection
of a direct origin upgrade, `429` responses after repeated attempts, and stable
peer identity after a Render restart. Then run the Peerborne Note live browser
suite against the separately deployed frontend. Render Free sleeps after 15
minutes without inbound traffic and can take roughly a minute to wake; clients
must allow for cold starts. Short demo sessions can be disconnected by the
aggressive limits. These controls do not establish production readiness.

Provider references: [Render Free](https://render.com/docs/free),
[Blueprints](https://render.com/docs/blueprint-spec),
[health checks](https://render.com/docs/health-checks),
[outbound bandwidth](https://render.com/docs/outbound-bandwidth),
[Cloudflare DNS setup](https://render.com/docs/configure-cloudflare-dns),
[WebSocket WAF behavior](https://developers.cloudflare.com/network/websockets/),
and [rate-limit plan availability](https://developers.cloudflare.com/waf/rate-limiting-rules/).

## Production Multi-Server Deployment

Give each relay its own hostname, persistent identity volume, and advertised
libp2p multiaddr. Caddy routes each hostname to one specific backend. A shared
round-robin hostname can route a dial to the wrong peer ID and fail the libp2p
handshake.

The Compose example runs two relays on one host to verify identity routing.
It assigns a separate volume to each relay and binds published ports to
`127.0.0.1` by default.

### Rehearse locally

```bash
relay_demo() {
  docker compose -p peerborne-relay-routing -f guides/docker/docker-compose.production.yaml "$@"
}

relay_demo config
relay_demo up -d --wait
relay_demo exec relay-1 node -p 'require("/shared/relay-info.json").peerId'
relay_demo exec relay-2 node -p 'require("/shared/relay-info.json").peerId'
```

The two IDs should differ. Use them in the corresponding WSS multiaddrs.

```text
/dns4/relay-1.localhost/tcp/443/wss/p2p/<relay-1-peerId>
/dns4/relay-2.localhost/tcp/443/wss/p2p/<relay-2-peerId>
```

Caddy uses its local CA for these names. Trust the local root certificate from
`/data/caddy/pki/authorities/local/root.crt` inside the Caddy container in the
test client before dialing. Confirm that each client dials the expected peer ID.
Stop `relay-1` and confirm that `relay-2` still accepts its own pinned address.
Recreate `relay-1` with its volume retained and confirm that its peer ID and
pinned address still work. Stop the local project with `relay_demo down`
and retain its volumes for the next run.
[Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https#local-https)

### Configure public staging

Set `RELAY_1_DOMAIN` and `RELAY_2_DOMAIN` to distinct DNS names and set
`RELAY_BIND_ADDRESS` to the intended listen address. Point each name's A or AAAA
record at its TLS endpoint and allow ports 80 and 443 for Caddy certificates.
Assign each additional relay a hostname, an upstream route and its own
identity volume. Use separate hosts when rehearsing independent host failure.

### Inter-relay peering

Each relay starts with its own GossipSub mesh. The Compose example exposes a
TCP listener for each relay and leaves peering to the deployment. Configure the
relays to dial each other's pinned TCP multiaddrs and reconnect after restarts
before expecting pubsub forwarding across relays. The local example maps host
ports `9002` and `9012` to each relay's container port `9002`.

Applications also need to discover and reconnect through more than one
configured relay for client failover. Peerborne Note currently accepts a single
relay multiaddr. Exercise cross-relay pubsub forwarding and bidirectional edits
after relay loss in staging before counting the topology as failover coverage.

### Hardening Checklist

- Set `TOPIC_ALLOWLIST` to restrict auto-subscribed topics.
- Set `MAX_AUTO_TOPICS` to cap memory usage from topic subscriptions.
- Set `MAX_AUTO_TOPICS_PER_PEER` so one peer cannot consume the global dynamic-topic allowance.
- Keep `GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER` bounded at the protocol ingestion layer.
- Tune the global transport-connection cap, reservation cap/TTL, per-connection
  HOP/STOP stream limits, and per-circuit duration/data limits for measured
  capacity. The relay frees a peer's reservation when its last connection
  closes. A connected client renews its reservation 5 minutes before expiry,
  or 30 seconds after the previous renewal if that is later, and each renewal
  extends it by one TTL. The relay project patches
  `retimeable-signal@1.0.1`, whose `reset()` otherwise left the first renewal's
  timer armed. That expired a connected peer's reservation, and cut its
  circuits, one TTL after its first renewal. These are resource controls, not a
  scale guarantee.
- Set `TRUSTED_PROXY_IPS` on relays behind a reverse proxy and enforce
  per-client limits at that proxy.
- Run the relay as a non-root user (the Dockerfiles already do this).
- Use `restart: unless-stopped` in Compose (already set in the production file).
- Monitor container health via Docker's built-in `HEALTHCHECK` -- the relay
  image checks `http://127.0.0.1:9000/readyz`
  (`docker inspect --format='{{.State.Health.Status}}' peerborne-relay`).

## Docker Images

The repository provides four relay-related Dockerfiles:

| File | Purpose | Build command |
| --- | --- | --- |
| `relay-server/Dockerfile` | Standard relay (used by the root and `guides/docker/` Compose files) | `docker build -t peerborne-relay relay-server/` |
| `Dockerfile.relay` | Relay built from repo root context | `docker build -f Dockerfile.relay -t peerborne-relay .` |
| `guides/docker/Dockerfile.relay` | Standalone relay with extended comments | `docker build -f guides/docker/Dockerfile.relay -t peerborne-relay relay-server/` |
| `guides/docker/Dockerfile.bootstrap` | Relay with pubsub peer discovery (same code) | `docker build -f guides/docker/Dockerfile.bootstrap -t peerborne-bootstrap relay-server/` |

The standard `relay-server/Dockerfile` is based on `node:26.13.1-alpine`, runs
as a non-root `app` user, persists its identity under `/shared`, and uses the
HTTP readiness check. Wrapper images should be audited separately before
deployment.

> **Note:** `Dockerfile.relay` (repo root) does **not** create or chown the
> `/shared` directory. If you mount a volume at `/shared`, the non-root `app`
> user will get `EACCES` when writing `relay-info.json`. Either use one of the
> other Dockerfiles (which do create `/shared`), or pre-create the directory on
> the host with appropriate permissions before mounting.

### Bootstrap Node vs Relay Server

For most deployments, the standard relay server is sufficient. It provides both
circuit relay and pubsub-based peer discovery.

`Dockerfile.bootstrap` currently runs the **same relay-server code** -- it does
not configure Kademlia DHT. The separate Dockerfile exists as a placeholder for
future large-scale deployments where DHT-based discovery may be added. Today,
all peer discovery goes through GossipSub pubsub.

## Kubernetes Deployment

Peerborne relay servers are straightforward to run on Kubernetes, but they are
**not** fully interchangeable replicas: each pod has its own libp2p peer
identity. That identity matters because clients dial relays using multiaddrs
such as `/dns4/relay.example.com/tcp/9001/wss/p2p/<peerId>`. If a load
balancer sends that connection to a different pod than the one that owns
`<peerId>`, the dial can fail. If a pod loses its persisted identity,
previously advertised addresses also break.

### Key Considerations

- **WebSocket affinity**: The relay uses long-lived WebSocket connections. Use
  session affinity (`service.spec.sessionAffinity: ClientIP`) or a WebSocket-
  aware ingress controller (NGINX Ingress, Traefik, etc.). This keeps existing
  upgraded connections stable, but by itself does **not** solve the peer-ID
  matching problem for new dials.
- **Stable relay identity**: For multi-replica Kubernetes deployments, prefer a
  `StatefulSet` with one persisted libp2p identity per replica and a headless
  Service that gives each pod stable DNS (for example,
  `peerborne-relay-0.peerborne-relay-headless.default.svc.cluster.local`). Publish
  each pod's own address with its own peer ID, and let clients dial the
  specific replica they intend to reach. Set `RELAY_IDENTITY_KEY_PATH` to that
  replica's persistent volume path. Never share one identity file between
  concurrently running pods.
- **Avoid one shared address for many peer IDs**: Do not put multiple relay
  pods behind a single Service/Ingress address and then advertise
  `/.../p2p/<peerId>` for those pods unless you also make peer IDs
  deterministic/persistent and can guarantee sticky routing to the pod that
  owns the advertised peer ID. Otherwise `/.../p2p/<peerId>` may resolve to the
  wrong backend or break after pod restarts.
- **Health checks**: Use HTTP `/livez` for liveness and `/readyz` for readiness
  on internal port 9000.
- **Scaling and pubsub topology**: Multiple relay pods are also multiple pubsub
  nodes. Each relay maintains its own independent pubsub mesh. Peers connected
  to different relay pods will not see each other's messages unless the relays
  are peered. For multi-replica deployments, configure relays to dial each
  other on startup (for example via stable per-pod DNS from a headless
  Service) so they form a connected pubsub graph. This pubsub peering
  requirement is in addition to the stable identity/routing requirements
  above.

### Example Manifests

The following `Deployment` shows the basic container ports, probes, and
resource settings. If you intend to advertise more than one relay replica to
clients, adapt this to a `StatefulSet` with persistent per-pod libp2p identity
and stable per-pod DNS rather than placing multiple interchangeable pods
behind one shared relay address.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: peerborne-relay
spec:
  replicas: 2
  selector:
    matchLabels:
      app: peerborne-relay
  template:
    metadata:
      labels:
        app: peerborne-relay
    spec:
      containers:
        - name: relay
          image: peerborne-relay:latest
          ports:
            - containerPort: 9000
              name: health
            - containerPort: 9001
              name: ws
            - containerPort: 9002
              name: tcp
          env:
            - name: TOPIC_ALLOWLIST
              value: "/peerborne/document/v3/,peerborne/coordinated/v1/"
            - name: TRUSTED_PROXY_IPS
              value: "*"
            - name: MAX_AUTO_TOPICS
              value: "5000"
            - name: MAX_AUTO_TOPICS_PER_PEER
              value: "32"
            - name: GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER
              value: "65536"
          livenessProbe:
            httpGet:
              path: /livez
              port: health
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /readyz
              port: health
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
---
apiVersion: v1
kind: Service
metadata:
  name: peerborne-relay
spec:
  type: ClusterIP
  sessionAffinity: ClientIP
  selector:
    app: peerborne-relay
  ports:
    - name: ws
      port: 9001
      targetPort: 9001
    - name: tcp
      port: 9002
      targetPort: 9002
```

Pair with an Ingress resource that supports WebSocket upgrade for external
browser access:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: peerborne-relay
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
spec:
  tls:
    - hosts:
        - relay.example.com
      secretName: relay-tls
  rules:
    - host: relay.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: peerborne-relay
                port:
                  number: 9001
```

## Monitoring

The relay server logs the following events to stdout:

- Peer connections and disconnections
- Topic auto-subscribe and auto-unsubscribe events
- Aggregate auto-subscribe limit warnings (global or per-peer)

Use standard container log aggregation (e.g., `docker logs`, Loki, CloudWatch)
to monitor relay health. Dynamic topic names and connected peer IDs are omitted
from routine subscription logs. The readiness body contains only status and the
public peer ID; private identity bytes and relayed payloads are never logged.

## Troubleshooting

**Peers cannot discover each other**
- Verify the relay is running and healthy: `docker exec peerborne-relay cat /shared/relay-info.json`
- Ensure browser clients are configured with a constructed public dialable
  multiaddr (e.g. `/dns4/relay.example.com/tcp/443/wss/p2p/<peerId>` or
  `/ip4/<PUBLIC_IP>/tcp/9001/ws/p2p/<peerId>`) -- not the raw `wsMultiaddr`
  value from `/shared/relay-info.json`, which contains a `0.0.0.0` listen
  address that is not dialable from another host.
- Check that port 9001 is accessible from the browser's network.

**Messages not relaying between peers**
- The relay must be subscribed to the same topics as the peers. Verify
  auto-subscribe is working by checking relay logs for
  `Auto-subscribed to a dynamic topic`.
- If `TOPIC_ALLOWLIST` is set, confirm each document topic matches an exact
  entry or a slash-terminated namespace prefix.

**EADDRINUSE on startup**
- Another process is using port 9001 or 9002. Change ports via `WS_PORT` /
  `TCP_PORT` environment variables.
- If using `ENABLE_IPV6=1`, your platform's `::` may be dual-stack. Remove the
  IPv6 flag or use separate ports.
