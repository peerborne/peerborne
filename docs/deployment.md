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
| `DOCUMENT_PUBLISH_PATH` | `/documents` | Topic for document publish notifications |
| `EXTRA_TOPICS` | (unset) | Comma-separated additional topics to subscribe |
| `TOPIC_ALLOWLIST` | (unset) | Comma-separated topic prefixes for auto-subscribe. Unset = open mode. Example: `/document/,/documents` |
| `MAX_AUTO_TOPICS` | `1000` | Cap on auto-subscribed topics to prevent unbounded growth |

### IPv6 Notes

On most Linux hosts `::` is dual-stack, so binding both IPv4 and IPv6 on the
same port causes `EADDRINUSE`. Only set `ENABLE_IPV6=1` on platforms where the
IPv6 socket is **not** dual-stack, or when using separate ports.

### Topic Auto-Subscribe

The relay automatically subscribes to document topics as peers join them. This
means the relay can forward messages between browser peers that have not yet
established a direct WebRTC connection. When all peers leave a topic the relay
automatically unsubscribes.

For production, set `TOPIC_ALLOWLIST` to restrict which topic prefixes are
accepted, and keep `MAX_AUTO_TOPICS` at a reasonable limit for your deployment.

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
> load balancer routes the TCP connection to relay-2 instead. You have two
> options:
>
> 1. **One multiaddr per relay.** Give each relay its own DNS name (e.g.
>    `relay-1.example.com`, `relay-2.example.com`) and configure clients with
>    all of them.
> 2. **Stable peer IDs (requires relay changes).** In principle, you can
>    pre-generate a libp2p key for each relay and inject it at startup so the
>    peer ID is deterministic, then use sticky sessions (e.g. Caddy
>    `lb_policy ip_hash`) so a client always reaches the relay whose peer ID
>    it dialed. The current `relay-server/` implementation does **not** expose
>    a configuration option for a deterministic peer identity -- every start
>    generates a fresh peer ID. Using this approach requires modifying the
>    relay code/image to load a persisted key. Option 1 above is the supported
>    path today.

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
        # NOTE: `round_robin` only works with option 1 above (one DNS name per
        # relay, clients configured with multiple multiaddrs). If you are using
        # a single load-balanced hostname, switch to `lb_policy ip_hash` and
        # use stable, pre-generated peer IDs so a client is always routed back
        # to the relay whose peer ID it dialed.
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
- Run the relay as a non-root user (the Dockerfiles already do this).
- Use `restart: unless-stopped` in Compose (already set in the production file).
- Monitor container health via Docker's built-in `HEALTHCHECK` -- the relay
  image's health check verifies port 9001 is accepting TCP connections
  (`docker inspect --format='{{.State.Health.Status}}' peerborne-relay`). There
  is no HTTP health endpoint.

## Docker Images

The repository provides four relay-related Dockerfiles:

| File | Purpose | Build command |
| --- | --- | --- |
| `relay-server/Dockerfile` | Standard relay (used by `docker-compose.yaml`) | `docker build -t peerborne-relay relay-server/` |
| `Dockerfile.relay` | Relay built from repo root context | `docker build -f Dockerfile.relay -t peerborne-relay .` |
| `guides/docker/Dockerfile.relay` | Standalone relay with extended comments | `docker build -f guides/docker/Dockerfile.relay -t peerborne-relay relay-server/` |
| `guides/docker/Dockerfile.bootstrap` | Relay with pubsub peer discovery (same code) | `docker build -f guides/docker/Dockerfile.bootstrap -t peerborne-bootstrap relay-server/` |

All images are based on `node:22-alpine`, run as a non-root `app` user, and
include a built-in health check (TCP connect on port 9001).

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
`<peerId>`, the dial can fail. If pod identities are regenerated on restart,
previously advertised addresses can also break.

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
  specific replica they intend to reach. The current `relay-server/` code does
  not expose a configuration option for a deterministic peer identity -- every
  start generates a fresh peer ID -- so using this pattern requires modifying
  the relay image to load a persisted key.
- **Avoid one shared address for many peer IDs**: Do not put multiple relay
  pods behind a single Service/Ingress address and then advertise
  `/.../p2p/<peerId>` for those pods unless you also make peer IDs
  deterministic/persistent and can guarantee sticky routing to the pod that
  owns the advertised peer ID. Otherwise `/.../p2p/<peerId>` may resolve to the
  wrong backend or break after pod restarts.
- **Health checks**: Use the built-in TCP check on port 9001 for both liveness
  and readiness probes.
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
            - containerPort: 9001
              name: ws
            - containerPort: 9002
              name: tcp
          env:
            - name: TOPIC_ALLOWLIST
              value: "/document/,/documents"
            - name: MAX_AUTO_TOPICS
              value: "5000"
          livenessProbe:
            tcpSocket:
              port: 9001
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            tcpSocket:
              port: 9001
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
- Auto-subscribe cap warnings (when `MAX_AUTO_TOPICS` is reached)

Use standard container log aggregation (e.g., `docker logs`, Loki, CloudWatch)
to monitor relay health.

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
  auto-subscribe is working by checking relay logs for `Auto-subscribed to topic`.
- If `TOPIC_ALLOWLIST` is set, confirm the document topics match one of the
  allowed prefixes.

**EADDRINUSE on startup**
- Another process is using port 9001 or 9002. Change ports via `WS_PORT` /
  `TCP_PORT` environment variables.
- If using `ENABLE_IPV6=1`, your platform's `::` may be dual-stack. Remove the
  IPv6 flag or use separate ports.
