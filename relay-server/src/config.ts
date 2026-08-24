/**
 * Pure configuration parsing for the relay server.
 *
 * Extracted from index.ts so the env-var → typed-config translation can be
 * unit-tested without spinning up a libp2p stack.
 */

/** Topic the relay subscribes to so it can forward peer-discovery messages. */
export const PUBSUB_PEER_DISCOVERY_TOPIC = 'swarmdb._peer-discovery._p2p._pubsub'

/** Default cap on the number of auto-subscribed topics. */
export const DEFAULT_MAX_AUTO_TOPICS = 1000

/** Default websocket port. */
export const DEFAULT_WS_PORT = '9001'

/** Default plain-TCP port. */
export const DEFAULT_TCP_PORT = '9002'

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
  /**
   * Comma-split topic allowlist, or null if unset (open mode — all
   * non-system topics are eligible for auto-subscribe).
   */
  readonly topicAllowlist: string[] | null
  /** Hard cap on number of auto-subscribed topics. */
  readonly maxAutoTopics: number
  /**
   * Extra topics from EXTRA_TOPICS that the relay subscribes to at startup
   * in addition to the seed topics. Useful for integration tests / static
   * configs. May be empty.
   */
  readonly extraTopics: string[]
}

/**
 * Parse a comma-separated env var into a trimmed, empty-segment-filtered
 * array.
 *
 * Returns `null` only when the env var is truly unset or set to the empty
 * string — i.e. the operator hasn't expressed an opinion, so callers should
 * treat this as "open mode".
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

/**
 * Parse a positive-integer env var with a fallback default. Non-numeric,
 * negative, zero, or non-finite values all fall back to the default.
 */
function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (value === undefined || value === '') {
    return fallback
  }
  const parsed = parseInt(value, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

/**
 * Translate a `NodeJS.ProcessEnv`-shaped record into a `RelayConfig`.
 *
 * Defaults match the historical inline behaviour of index.ts. This is the
 * only place env-var defaults are encoded; everything downstream consumes
 * the typed config.
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
    topicAllowlist: parseCsv(env.TOPIC_ALLOWLIST),
    maxAutoTopics: parsePositiveInt(env.MAX_AUTO_TOPICS, DEFAULT_MAX_AUTO_TOPICS),
    extraTopics: parseCsv(env.EXTRA_TOPICS) ?? [],
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
