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
| `DOCUMENT_PUBLISH_PATH` | `/documents` | Topic for document publish notifications |
| `EXTRA_TOPICS` | (unset) | Comma-separated additional topics to subscribe |
| `TOPIC_ALLOWLIST` | `/document/,/documents` | Comma-separated topic prefixes for auto-subscribe. Set exactly `*` for explicit open mode |
| `MAX_AUTO_TOPICS` | `1000` | Cap on auto-subscribed topics to prevent unbounded growth |
| `MAX_AUTO_TOPICS_PER_PEER` | `32` | Cap on dynamic topics tracked for one remote peer |
| `GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER` | `65536` | Ingestion-layer topic-name byte budget for one remote peer |
| `MAX_CONNECTIONS` | `256` | Global ceiling for established libp2p transport connections |
| `RELAY_MAX_RESERVATIONS` | `128` | Maximum active Circuit Relay v2 reservations |
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

The safe default accepts the current `/document/` and `/documents` namespaces.
Keep both `MAX_AUTO_TOPICS` and `MAX_AUTO_TOPICS_PER_PEER` at reasonable limits
for your deployment. The global cap bounds total dynamic state; the per-peer cap
prevents one connected peer from consuming that allowance. The GossipSub byte
budget rejects oversized or excessive remote subscription metadata before it
reaches the relay registry. `*` is an
intentional opt-out of topic filtering, not a recommended public-relay default.
This policy controls only the topics to which the relay node itself subscribes
for GossipSub forwarding. It does not inspect or restrict opaque, Noise-encrypted
Circuit Relay streams, and it is not document authorization.

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
`fly.toml`; no identity secret needs to be generated or passed to Fly. Back up
the volume if preserving the peer ID matters. Losing the file creates a new
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

## Production Multi-Server Deployment

For reliability, run two or more relay servers with TLS. The `guides/docker/`
directory contains an example Compose file and Caddy configuration, but it is
**not** a drop-in production setup for multiple relays behind a single
load-balanced hostname.

Each relay has its own libp2p peer ID, so clients must be able to dial a
specific relay address. With the current relay implementation, a single shared
hostname that load-balances across multiple relays will break dialing (see the
"Important" callout below). For production, use **one public DNS name per
relay** (e.g. `relay-1.example.com`, `relay-2.example.com`) so each hostname
consistently resolves to exactly one relay. The provided `guides/docker/`
config is a starting point -- treat the single-hostname `round_robin` example
as a demo, and adapt it to one DNS name per relay (or implement stable peer
IDs + sticky sessions) before deploying to production.

### Prerequisites

1. Public DNS names for each relay server, with A/AAAA records pointing to the
   host that serves that relay (e.g. `relay-1.example.com` and
   `relay-2.example.com`).
2. Ports 80 and 443 open for Caddy's automatic Let's Encrypt certificates.
3. For inter-relay peering in a real multi-host deployment, expose TCP port
   `9002` on each relay server (see "Inter-Relay Peering" below). The
   `guides/docker/` single-host demo may remap a second relay to a different
   host port such as `9012:9002` only to avoid local port conflicts; that
   offset is for the demo host layout and does not change the relay's actual
   service port.

> **Limitation:** By default each relay server is standalone -- it does not
> configure bootstrap peers or attempt to discover other relays. Clients
> connected to different relays will **not** see each other's pubsub messages
> unless the relays are manually peered (e.g. by dialing each other's TCP
> multiaddr at startup). A future release may add automatic inter-relay
> discovery.

### Deploy

```bash
export RELAY_DOMAIN=relay.example.com

docker compose -f guides/docker/docker-compose.production.yaml up -d
```

This starts:

- **Caddy** -- Reverse proxy on ports 80/443. Terminates TLS and load-balances
  WebSocket connections across relay nodes with round-robin.
- **relay-1** -- Primary relay / bootstrap node.
- **relay-2** -- Secondary relay node.

Browser clients connect using a libp2p multiaddr through the TLS-terminated
proxy.

> **Important:** A single load-balanced hostname does **not** work as a libp2p
> multiaddr because each relay generates a unique peer ID. A connection to
> `/dns4/relay.example.com/tcp/443/wss/p2p/<peerId-of-relay-1>` will fail if the
> load balancer routes the TCP connection to relay-2 instead. Use:
>
> 1. **One multiaddr per relay.** Give each relay its own DNS name (e.g.
>    `relay-1.example.com`, `relay-2.example.com`) and configure clients with
>    all of them.

There is no supported single-hostname load-balancing alternative. Source-IP
hashing does not pin a libp2p peer ID and can still route the same multiaddr to
the wrong relay. Use one hostname/SNI route per durable relay identity.

The multiaddr format for each relay is:

```text
/dns4/relay-1.example.com/tcp/443/wss/p2p/<relay-1-peerId>
```

This replaces the raw WebSocket multiaddr used in the single-server setup.

### Scaling Beyond Two Relays

Add more relay services to `docker-compose.production.yaml` and include them in
the Caddyfile's `reverse_proxy` upstream list:

```caddyfile
# Caddyfile
{$RELAY_DOMAIN} {
    reverse_proxy relay-1:9001 relay-2:9001 relay-3:9001 {
        # This single-hostname block is illustrative only and cannot preserve
        # libp2p peer-ID routing. Production needs one hostname/SNI route per
        # relay identity, with clients configured with all relay multiaddrs.
        lb_policy round_robin
        header_up Connection {>Connection}
        header_up Upgrade {>Upgrade}
    }
}
```

In a true production deployment, run each relay on a separate server and point
Caddy (or your own load balancer) at their IP addresses.

### Hardening Checklist

- Set `TOPIC_ALLOWLIST` to restrict auto-subscribed topics.
- Set `MAX_AUTO_TOPICS` to cap memory usage from topic subscriptions.
- Set `MAX_AUTO_TOPICS_PER_PEER` so one peer cannot consume the global dynamic-topic allowance.
- Keep `GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER` bounded at the protocol ingestion layer.
- Tune the global transport-connection cap, reservation cap/TTL, per-connection
  HOP/STOP stream limits, and per-circuit duration/data limits for measured
  capacity. The pinned relay dependency may retain a disconnected reservation
  until its TTL, so the browser launch uses a 10-minute TTL and a 128-reservation
  cap to bound stale capacity. These are resource controls, not a scale guarantee.
- Run the relay as a non-root user (the Dockerfiles already do this).
- Use `restart: unless-stopped` in Compose (already set in the production file).
- Monitor container health via Docker's built-in `HEALTHCHECK` -- the relay
  image checks `http://127.0.0.1:9000/readyz`
  (`docker inspect --format='{{.State.Health.Status}}' peerborne-relay`).

## Docker Images

The repository provides four relay-related Dockerfiles:

| File | Purpose | Build command |
| --- | --- | --- |
| `relay-server/Dockerfile` | Standard relay (used by `docker-compose.yaml`) | `docker build -t peerborne-relay relay-server/` |
| `Dockerfile.relay` | Relay built from repo root context | `docker build -f Dockerfile.relay -t peerborne-relay .` |
| `guides/docker/Dockerfile.relay` | Standalone relay with extended comments | `docker build -f guides/docker/Dockerfile.relay -t peerborne-relay relay-server/` |
| `guides/docker/Dockerfile.bootstrap` | Relay with pubsub peer discovery (same code) | `docker build -f guides/docker/Dockerfile.bootstrap -t peerborne-bootstrap relay-server/` |

The standard `relay-server/Dockerfile` is based on `node:22.19.0-alpine`, runs
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
              value: "/document/,/documents"
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
- If `TOPIC_ALLOWLIST` is set, confirm the document topics match one of the
  allowed prefixes.

**EADDRINUSE on startup**
- Another process is using port 9001 or 9002. Change ports via `WS_PORT` /
  `TCP_PORT` environment variables.
- If using `ENABLE_IPV6=1`, your platform's `::` may be dual-stack. Remove the
  IPv6 flag or use separate ports.
