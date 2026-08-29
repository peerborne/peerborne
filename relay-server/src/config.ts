/**
 * Pure configuration parsing for the relay server.
 *
 * Extracted from index.ts so the env-var → typed-config translation can be
 * unit-tested without spinning up a libp2p stack.
 */

import type { CircuitRelayServerInit } from '@libp2p/circuit-relay-v2'

/** Topic the relay subscribes to so it can forward peer-discovery messages. */
export const PUBSUB_PEER_DISCOVERY_TOPIC = 'swarmdb._peer-discovery._p2p._pubsub'

/** Default cap on the number of auto-subscribed topics. */
export const DEFAULT_MAX_AUTO_TOPICS = 1000

/** Default cap on dynamic topics attributed to one remote peer. */
export const DEFAULT_MAX_AUTO_TOPICS_PER_PEER = 32

/** Default GossipSub topic-name byte budget for each connected peer. */
export const DEFAULT_GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER = 64 * 1024

/** Default topic prefixes accepted by the public relay. */
export const DEFAULT_TOPIC_ALLOWLIST: readonly string[] = [
  '/document/',
  '/documents',
]

/** Default websocket port. */
export const DEFAULT_WS_PORT = '9001'

/** Default plain-TCP port. */
export const DEFAULT_TCP_PORT = '9002'

/** Default internal HTTP readiness port. */
export const DEFAULT_READINESS_PORT = 9000

/** Global ceiling for established libp2p transport connections. */
export const DEFAULT_MAX_CONNECTIONS = 256

/** Default location for the persisted libp2p private key outside Fly. */
export const DEFAULT_IDENTITY_KEY_PATH = './relay-identity.key'

/** Maximum number of clients that may hold Circuit Relay reservations. */
export const DEFAULT_RELAY_MAX_RESERVATIONS = 128

/** Reservation lifetime before the client must renew it. */
export const DEFAULT_RELAY_RESERVATION_TTL_MS = 10 * 60 * 1000

/** Maximum lifetime of one relayed connection. */
export const DEFAULT_RELAY_MAX_CIRCUIT_DURATION_MS = 30 * 60 * 1000

/** Maximum bytes carried by one relayed connection. */
export const DEFAULT_RELAY_MAX_CIRCUIT_BYTES = 16n * 1024n * 1024n

/** Timeout for Circuit Relay HOP negotiation. */
export const DEFAULT_RELAY_HOP_TIMEOUT_MS = 30 * 1000

/** Maximum simultaneous inbound HOP streams per connection. */
export const DEFAULT_RELAY_MAX_INBOUND_HOP_STREAMS = 8

/** Maximum simultaneous outbound HOP streams per connection. */
export const DEFAULT_RELAY_MAX_OUTBOUND_HOP_STREAMS = 8

/** Maximum simultaneous outbound STOP streams per connection. */
export const DEFAULT_RELAY_MAX_OUTBOUND_STOP_STREAMS = 8

/** Default document publish path (matches peerborne-config.ts default). */
export const DEFAULT_DOCUMENT_PUBLISH_PATH = '/documents'

/**
 * Topic prefixes that are treated as system/internal and should never be
 * auto-subscribed. This module is the canonical definition; `topic-policy.ts`
 * imports this constant rather than redeclaring it, so there's no duplication.
 */
export const SYSTEM_TOPIC_PREFIXES: readonly string[] = ['_', 'floodsub:']

/**
 * Parsed relay server configuration. All fields are derived purely from
 * environment variables — there is no I/O.
 */
export interface RelayConfig {
  /** Topic the relay subscribes to so it can forward peer-discovery messages. */
  readonly peerDiscoveryTopic: string
  /** Topic used as the document publish path (seed topic). */
  readonly documentPublishPath: string
  /** Websocket listen multiaddr. */
  readonly wsListen: string
  /** Plain-TCP listen multiaddr. */
  readonly tcpListen: string
  /** Whether IPv6 dual-stack listeners are enabled. */
  readonly ipv6Enabled: boolean
  /** Websocket IPv6 listen multiaddr (only used when ipv6Enabled). */
  readonly wsListenV6: string
  /** Plain-TCP IPv6 listen multiaddr (only used when ipv6Enabled). */
  readonly tcpListenV6: string
  /** Internal HTTP port serving /livez and /readyz. */
  readonly readinessPort: number
  /** File containing the protobuf-serialized libp2p private key. */
  readonly identityKeyPath: string
  /**
   * Topic-prefix allowlist, or null for explicitly configured open mode.
   */
  readonly topicAllowlist: string[] | null
  /** Hard cap on number of auto-subscribed topics. */
  readonly maxAutoTopics: number
  /** Hard cap on dynamic topics tracked for one remote peer. */
  readonly maxAutoTopicsPerPeer: number
  /** GossipSub's ingestion-layer topic-name byte budget for one remote peer. */
  readonly gossipsubMaxTopicBytesPerPeer: number
  /** Global ceiling for established libp2p transport connections. */
  readonly maxConnections: number
  /**
   * Extra topics from EXTRA_TOPICS that the relay subscribes to at startup
   * in addition to the seed topics. Useful for integration tests / static
   * configs. May be empty.
   */
  readonly extraTopics: string[]
  /** Circuit Relay v2 resource limits. */
  readonly relayLimits: {
    readonly maxReservations: number
    readonly reservationTtlMs: number
    readonly maxCircuitDurationMs: number
    readonly maxCircuitDataBytes: bigint
    readonly hopTimeoutMs: number
    readonly maxInboundHopStreams: number
    readonly maxOutboundHopStreams: number
    readonly maxOutboundStopStreams: number
  }
}

/**
 * Parse a comma-separated env var into a trimmed, empty-segment-filtered
 * array.
 *
 * Returns `null` only when the env var is truly unset or set to the empty
 * string. Callers decide what an omitted value means for their setting.
 *
 * Returns `[]` when the env var is set to a non-empty value that
 * nonetheless parses to zero usable entries (e.g. "," or "   "). This
 * matches the historical inline behaviour where any non-empty string
 * produced an array (possibly empty), and crucially keeps a misconfigured
 * allowlist in "closed mode" rather than silently flipping it open.
 */
function parseCsv(value: string | undefined): string[] | null {
  if (value === undefined || value === '') {
    return null
  }
  return value
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean)
}

function parsePositiveSafeInteger(
  value: string | undefined,
  fallback: number,
): number {
  if (value === undefined || !/^[1-9]\d*$/.test(value)) {
    return fallback
  }
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) ? parsed : fallback
}

function parsePort(value: string | undefined, fallback: number): number {
  const parsed = parsePositiveSafeInteger(value, fallback)
  return parsed <= 65_535 ? parsed : fallback
}

function parsePositiveBigInt(
  value: string | undefined,
  fallback: bigint,
): bigint {
  if (value === undefined || !/^[1-9]\d*$/.test(value)) {
    return fallback
  }
  try {
    return BigInt(value)
  } catch {
    return fallback
  }
}

function parseTopicAllowlist(value: string | undefined): string[] | null {
  if (value === undefined || value.trim() === '') {
    return [...DEFAULT_TOPIC_ALLOWLIST]
  }
  if (value.trim() === '*') {
    return null
  }
  return parseCsv(value) ?? []
}

/**
 * Translate a `NodeJS.ProcessEnv`-shaped record into a `RelayConfig`.
 *
 * This is the only place env-var defaults are encoded; everything downstream
 * consumes the typed config.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayConfig {
  const wsPort = env.WS_PORT || DEFAULT_WS_PORT
  const tcpPort = env.TCP_PORT || DEFAULT_TCP_PORT

  const wsListen = env.WS_LISTEN || `/ip4/0.0.0.0/tcp/${wsPort}/ws`
  const tcpListen = env.TCP_LISTEN || `/ip4/0.0.0.0/tcp/${tcpPort}`
  const ipv6Enabled = env.ENABLE_IPV6 === '1'
  // ?? semantics matches the inline behaviour: empty string is treated as
  // "user explicitly set it to empty", not "unset". An empty string acts
  // as an opt-out for that specific IPv6 listener — `listenAddresses()`
  // filters empty entries out of the bind list so the libp2p node never
  // sees an invalid multiaddr.
  const wsListenV6 = env.WS_LISTEN_V6 ?? `/ip6/::/tcp/${wsPort}/ws`
  const tcpListenV6 = env.TCP_LISTEN_V6 ?? `/ip6/::/tcp/${tcpPort}`

  return {
    peerDiscoveryTopic: PUBSUB_PEER_DISCOVERY_TOPIC,
    documentPublishPath: env.DOCUMENT_PUBLISH_PATH || DEFAULT_DOCUMENT_PUBLISH_PATH,
    wsListen,
    tcpListen,
    ipv6Enabled,
    wsListenV6,
    tcpListenV6,
    readinessPort: parsePort(env.READINESS_PORT, DEFAULT_READINESS_PORT),
    identityKeyPath:
      env.RELAY_IDENTITY_KEY_PATH || DEFAULT_IDENTITY_KEY_PATH,
    topicAllowlist: parseTopicAllowlist(env.TOPIC_ALLOWLIST),
    maxAutoTopics: parsePositiveSafeInteger(
      env.MAX_AUTO_TOPICS,
      DEFAULT_MAX_AUTO_TOPICS,
    ),
    maxAutoTopicsPerPeer: parsePositiveSafeInteger(
      env.MAX_AUTO_TOPICS_PER_PEER,
      DEFAULT_MAX_AUTO_TOPICS_PER_PEER,
    ),
    gossipsubMaxTopicBytesPerPeer: parsePositiveSafeInteger(
      env.GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER,
      DEFAULT_GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER,
    ),
    maxConnections: parsePositiveSafeInteger(
      env.MAX_CONNECTIONS,
      DEFAULT_MAX_CONNECTIONS,
    ),
    extraTopics: parseCsv(env.EXTRA_TOPICS) ?? [],
    relayLimits: {
      maxReservations: parsePositiveSafeInteger(
        env.RELAY_MAX_RESERVATIONS,
        DEFAULT_RELAY_MAX_RESERVATIONS,
      ),
      reservationTtlMs: parsePositiveSafeInteger(
        env.RELAY_RESERVATION_TTL_MS,
        DEFAULT_RELAY_RESERVATION_TTL_MS,
      ),
      maxCircuitDurationMs: parsePositiveSafeInteger(
        env.RELAY_MAX_CIRCUIT_DURATION_MS,
        DEFAULT_RELAY_MAX_CIRCUIT_DURATION_MS,
      ),
      maxCircuitDataBytes: parsePositiveBigInt(
        env.RELAY_MAX_CIRCUIT_BYTES,
        DEFAULT_RELAY_MAX_CIRCUIT_BYTES,
      ),
      hopTimeoutMs: parsePositiveSafeInteger(
        env.RELAY_HOP_TIMEOUT_MS,
        DEFAULT_RELAY_HOP_TIMEOUT_MS,
      ),
      maxInboundHopStreams: parsePositiveSafeInteger(
        env.RELAY_MAX_INBOUND_HOP_STREAMS,
        DEFAULT_RELAY_MAX_INBOUND_HOP_STREAMS,
      ),
      maxOutboundHopStreams: parsePositiveSafeInteger(
        env.RELAY_MAX_OUTBOUND_HOP_STREAMS,
        DEFAULT_RELAY_MAX_OUTBOUND_HOP_STREAMS,
      ),
      maxOutboundStopStreams: parsePositiveSafeInteger(
        env.RELAY_MAX_OUTBOUND_STOP_STREAMS,
        DEFAULT_RELAY_MAX_OUTBOUND_STOP_STREAMS,
      ),
    },
  }
}

/**
 * Compute the actual list of listen multiaddrs the libp2p node should bind,
 * honouring the IPv6 gate. Pure function of a `RelayConfig`.
 *
 * Empty IPv6 listen strings are filtered out: operators can disable an
 * individual IPv6 listener by setting `WS_LISTEN_V6=""` or
 * `TCP_LISTEN_V6=""` (with `ENABLE_IPV6=1` still keeping the other one
 * active). The IPv4 listeners always have a default fallback so they are
 * unconditionally present.
 */
export function listenAddresses(config: RelayConfig): string[] {
  return [
    config.wsListen,
    config.tcpListen,
    ...(config.ipv6Enabled
      ? [config.wsListenV6, config.tcpListenV6].filter((addr) => addr !== '')
      : []),
  ]
}

/** Translate typed relay limits to the pinned Circuit Relay v2 API. */
export function circuitRelayServerOptions(
  config: RelayConfig,
): CircuitRelayServerInit {
  const { relayLimits } = config
  return {
    hopTimeout: relayLimits.hopTimeoutMs,
    reservations: {
      maxReservations: relayLimits.maxReservations,
      reservationTtl: relayLimits.reservationTtlMs,
      applyDefaultLimit: true,
      defaultDurationLimit: relayLimits.maxCircuitDurationMs,
      defaultDataLimit: relayLimits.maxCircuitDataBytes,
    },
    maxInboundHopStreams: relayLimits.maxInboundHopStreams,
    maxOutboundHopStreams: relayLimits.maxOutboundHopStreams,
    maxOutboundStopStreams: relayLimits.maxOutboundStopStreams,
  }
}
