import {
  DEFAULT_DOCUMENT_PUBLISH_PATH,
  DEFAULT_GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER,
  DEFAULT_IDENTITY_KEY_PATH,
  DEFAULT_MAX_CONNECTIONS,
  DEFAULT_MAX_AUTO_TOPICS,
  DEFAULT_MAX_AUTO_TOPICS_PER_PEER,
  DEFAULT_READINESS_PORT,
  DEFAULT_RELAY_HOP_TIMEOUT_MS,
  DEFAULT_RELAY_MAX_CIRCUIT_BYTES,
  DEFAULT_RELAY_MAX_CIRCUIT_DURATION_MS,
  DEFAULT_RELAY_MAX_INBOUND_HOP_STREAMS,
  DEFAULT_RELAY_MAX_OUTBOUND_HOP_STREAMS,
  DEFAULT_RELAY_MAX_OUTBOUND_STOP_STREAMS,
  DEFAULT_RELAY_MAX_RESERVATIONS,
  DEFAULT_RELAY_RESERVATION_TTL_MS,
  DEFAULT_TCP_PORT,
  DEFAULT_TOPIC_ALLOWLIST,
  DEFAULT_WS_PORT,
  PUBSUB_PEER_DISCOVERY_TOPIC,
  circuitRelayServerOptions,
  listenAddresses,
  loadConfig,
} from './config.js'

describe('loadConfig', () => {
  describe('defaults', () => {
    it('returns the documented defaults when env is empty', () => {
      const cfg = loadConfig({})
      expect(cfg.peerDiscoveryTopic).toBe(PUBSUB_PEER_DISCOVERY_TOPIC)
      expect(cfg.documentPublishPath).toBe(DEFAULT_DOCUMENT_PUBLISH_PATH)
      expect(cfg.wsListen).toBe(`/ip4/0.0.0.0/tcp/${DEFAULT_WS_PORT}/ws`)
      expect(cfg.tcpListen).toBe(`/ip4/0.0.0.0/tcp/${DEFAULT_TCP_PORT}`)
      expect(cfg.ipv6Enabled).toBe(false)
      expect(cfg.wsListenV6).toBe(`/ip6/::/tcp/${DEFAULT_WS_PORT}/ws`)
      expect(cfg.tcpListenV6).toBe(`/ip6/::/tcp/${DEFAULT_TCP_PORT}`)
      expect(cfg.readinessPort).toBe(DEFAULT_READINESS_PORT)
      expect(cfg.identityKeyPath).toBe(DEFAULT_IDENTITY_KEY_PATH)
      expect(cfg.topicAllowlist).toEqual(DEFAULT_TOPIC_ALLOWLIST)
      expect(cfg.maxAutoTopics).toBe(DEFAULT_MAX_AUTO_TOPICS)
      expect(cfg.maxAutoTopicsPerPeer).toBe(DEFAULT_MAX_AUTO_TOPICS_PER_PEER)
      expect(cfg.gossipsubMaxTopicBytesPerPeer).toBe(
        DEFAULT_GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER,
      )
      expect(cfg.maxConnections).toBe(DEFAULT_MAX_CONNECTIONS)
      expect(cfg.extraTopics).toEqual([])
      expect(cfg.relayLimits).toEqual({
        maxReservations: DEFAULT_RELAY_MAX_RESERVATIONS,
        reservationTtlMs: DEFAULT_RELAY_RESERVATION_TTL_MS,
        maxCircuitDurationMs: DEFAULT_RELAY_MAX_CIRCUIT_DURATION_MS,
        maxCircuitDataBytes: DEFAULT_RELAY_MAX_CIRCUIT_BYTES,
        hopTimeoutMs: DEFAULT_RELAY_HOP_TIMEOUT_MS,
        maxInboundHopStreams: DEFAULT_RELAY_MAX_INBOUND_HOP_STREAMS,
        maxOutboundHopStreams: DEFAULT_RELAY_MAX_OUTBOUND_HOP_STREAMS,
        maxOutboundStopStreams: DEFAULT_RELAY_MAX_OUTBOUND_STOP_STREAMS,
      })
      expect(cfg.relayLimits.reservationTtlMs).toBe(600_000)
    })
  })

  describe('listen addresses', () => {
    it('honours custom WS_PORT / TCP_PORT', () => {
      const cfg = loadConfig({ WS_PORT: '7001', TCP_PORT: '7002' })
      expect(cfg.wsListen).toBe('/ip4/0.0.0.0/tcp/7001/ws')
      expect(cfg.tcpListen).toBe('/ip4/0.0.0.0/tcp/7002')
      expect(cfg.wsListenV6).toBe('/ip6/::/tcp/7001/ws')
      expect(cfg.tcpListenV6).toBe('/ip6/::/tcp/7002')
    })

    it('honours explicit WS_LISTEN / TCP_LISTEN overrides', () => {
      const cfg = loadConfig({
        MAX_CONNECTIONS: '200',
        WS_LISTEN: '/ip4/127.0.0.1/tcp/9999/ws',
        TCP_LISTEN: '/ip4/127.0.0.1/tcp/8888',
      })
      expect(cfg.maxConnections).toBe(200)
      expect(cfg.wsListen).toBe('/ip4/127.0.0.1/tcp/9999/ws')
      expect(cfg.tcpListen).toBe('/ip4/127.0.0.1/tcp/8888')
    })

    it('honours explicit WS_LISTEN_V6 / TCP_LISTEN_V6 overrides', () => {
      const cfg = loadConfig({
        WS_LISTEN_V6: '/ip6/::1/tcp/9999/ws',
        TCP_LISTEN_V6: '/ip6/::1/tcp/8888',
      })
      expect(cfg.wsListenV6).toBe('/ip6/::1/tcp/9999/ws')
      expect(cfg.tcpListenV6).toBe('/ip6/::1/tcp/8888')
    })
  })

  describe('IPv6 gate', () => {
    it('disables IPv6 listeners by default', () => {
      expect(loadConfig({}).ipv6Enabled).toBe(false)
    })

    it('enables IPv6 listeners when ENABLE_IPV6=1', () => {
      expect(loadConfig({ ENABLE_IPV6: '1' }).ipv6Enabled).toBe(true)
    })

    it('treats ENABLE_IPV6 values other than "1" as disabled', () => {
      // Historical behaviour: only the literal string "1" enables IPv6.
      expect(loadConfig({ ENABLE_IPV6: 'true' }).ipv6Enabled).toBe(false)
      expect(loadConfig({ ENABLE_IPV6: 'yes' }).ipv6Enabled).toBe(false)
      expect(loadConfig({ ENABLE_IPV6: '0' }).ipv6Enabled).toBe(false)
      expect(loadConfig({ ENABLE_IPV6: '' }).ipv6Enabled).toBe(false)
    })
  })

  describe('DOCUMENT_PUBLISH_PATH', () => {
    it('uses the default when unset', () => {
      expect(loadConfig({}).documentPublishPath).toBe(DEFAULT_DOCUMENT_PUBLISH_PATH)
    })

    it('honours the explicit override', () => {
      expect(loadConfig({ DOCUMENT_PUBLISH_PATH: '/custom-docs' }).documentPublishPath).toBe(
        '/custom-docs',
      )
    })
  })

  describe('TOPIC_ALLOWLIST parsing', () => {
    it('uses the document-only allowlist when unset', () => {
      expect(loadConfig({}).topicAllowlist).toEqual(DEFAULT_TOPIC_ALLOWLIST)
    })

    it('uses the document-only allowlist when empty', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '' }).topicAllowlist).toEqual(
        DEFAULT_TOPIC_ALLOWLIST,
      )
    })

    it('uses null only for explicit wildcard open mode', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '*' }).topicAllowlist).toBeNull()
      expect(loadConfig({ TOPIC_ALLOWLIST: ' * ' }).topicAllowlist).toBeNull()
    })

    it('splits a single value', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '/document/' }).topicAllowlist).toEqual(['/document/'])
    })

    it('splits multiple comma-separated values', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '/document/,/documents,/peerborne/' }).topicAllowlist)
        .toEqual(['/document/', '/documents', '/peerborne/'])
    })

    it('trims surrounding whitespace from each segment', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '  /a/ ,/b/,   /c/  ' }).topicAllowlist).toEqual([
        '/a/',
        '/b/',
        '/c/',
      ])
    })

    it('drops empty segments', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '/a/,,/b/,' }).topicAllowlist).toEqual([
        '/a/',
        '/b/',
      ])
    })

    it('returns [] (closed mode) when set to "," — operator expressed intent, just no entries', () => {
      // A malformed explicit value stays closed instead of silently reverting
      // to the safe default or explicit wildcard open mode.
      expect(loadConfig({ TOPIC_ALLOWLIST: ',' }).topicAllowlist).toEqual([])
    })

    it('uses the document-only allowlist when set to whitespace-only', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '   ' }).topicAllowlist).toEqual(
        DEFAULT_TOPIC_ALLOWLIST,
      )
    })

    it('returns [] (closed mode) when every segment is empty or whitespace', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: ',,, , ' }).topicAllowlist).toEqual([])
    })
  })

  describe('MAX_AUTO_TOPICS parsing', () => {
    it('falls back to the default when unset', () => {
      expect(loadConfig({}).maxAutoTopics).toBe(DEFAULT_MAX_AUTO_TOPICS)
    })

    it('honours a positive integer', () => {
      expect(loadConfig({ MAX_AUTO_TOPICS: '42' }).maxAutoTopics).toBe(42)
    })

    it('falls back when the value is non-numeric', () => {
      expect(loadConfig({ MAX_AUTO_TOPICS: 'abc' }).maxAutoTopics).toBe(DEFAULT_MAX_AUTO_TOPICS)
    })

    it('falls back when the value is empty', () => {
      expect(loadConfig({ MAX_AUTO_TOPICS: '' }).maxAutoTopics).toBe(DEFAULT_MAX_AUTO_TOPICS)
    })

    it('falls back when the value is zero', () => {
      expect(loadConfig({ MAX_AUTO_TOPICS: '0' }).maxAutoTopics).toBe(DEFAULT_MAX_AUTO_TOPICS)
    })

    it('falls back when the value is negative', () => {
      expect(loadConfig({ MAX_AUTO_TOPICS: '-5' }).maxAutoTopics).toBe(DEFAULT_MAX_AUTO_TOPICS)
    })

    it.each(['1.5', '100topics', '9007199254740992'])(
      'falls back when the value is not a positive safe integer: %s',
      (value) => {
        expect(loadConfig({ MAX_AUTO_TOPICS: value }).maxAutoTopics).toBe(
          DEFAULT_MAX_AUTO_TOPICS,
        )
      },
    )
  })

  describe('MAX_AUTO_TOPICS_PER_PEER parsing', () => {
    it('falls back to the default when unset', () => {
      expect(loadConfig({}).maxAutoTopicsPerPeer).toBe(
        DEFAULT_MAX_AUTO_TOPICS_PER_PEER,
      )
    })

    it('honours a positive safe integer', () => {
      expect(
        loadConfig({ MAX_AUTO_TOPICS_PER_PEER: '12' }).maxAutoTopicsPerPeer,
      ).toBe(12)
    })

    it.each(['', '0', '-1', '1.5', '12topics', '9007199254740992'])(
      'falls back for invalid value %j',
      (value) => {
        expect(
          loadConfig({ MAX_AUTO_TOPICS_PER_PEER: value })
            .maxAutoTopicsPerPeer,
        ).toBe(DEFAULT_MAX_AUTO_TOPICS_PER_PEER)
      },
    )
  })

  describe('GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER parsing', () => {
    it('uses a bounded default', () => {
      expect(loadConfig({}).gossipsubMaxTopicBytesPerPeer).toBe(65_536)
    })

    it('honours a positive safe-integer override', () => {
      expect(
        loadConfig({ GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER: '32768' })
          .gossipsubMaxTopicBytesPerPeer,
      ).toBe(32_768)
    })

    it.each(['', '0', '-1', '1.5', '64kb', '9007199254740992'])(
      'falls back for invalid value %j',
      (value) => {
        expect(
          loadConfig({ GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER: value })
            .gossipsubMaxTopicBytesPerPeer,
        ).toBe(DEFAULT_GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER)
      },
    )
  })

  describe('EXTRA_TOPICS parsing', () => {
    it('returns an empty array when unset', () => {
      expect(loadConfig({}).extraTopics).toEqual([])
    })

    it('splits, trims and filters empty segments', () => {
      expect(loadConfig({ EXTRA_TOPICS: ' /a/ , ,/b/,' }).extraTopics).toEqual(['/a/', '/b/'])
    })
  })

  describe('relay launch configuration', () => {
    it('honours readiness and identity path overrides', () => {
      const cfg = loadConfig({
        READINESS_PORT: '9100',
        RELAY_IDENTITY_KEY_PATH: '/data/relay.key',
      })
      expect(cfg.readinessPort).toBe(9100)
      expect(cfg.identityKeyPath).toBe('/data/relay.key')
    })

    it('rejects an out-of-range readiness port', () => {
      expect(loadConfig({ READINESS_PORT: '65536' }).readinessPort).toBe(
        DEFAULT_READINESS_PORT,
      )
    })

    it('honours explicit Circuit Relay limits', () => {
      const cfg = loadConfig({
        RELAY_MAX_RESERVATIONS: '64',
        RELAY_RESERVATION_TTL_MS: '3600000',
        RELAY_MAX_CIRCUIT_DURATION_MS: '600000',
        RELAY_MAX_CIRCUIT_BYTES: '8388608',
        RELAY_HOP_TIMEOUT_MS: '15000',
        RELAY_MAX_INBOUND_HOP_STREAMS: '80',
        RELAY_MAX_OUTBOUND_HOP_STREAMS: '81',
        RELAY_MAX_OUTBOUND_STOP_STREAMS: '82',
      })
      expect(cfg.relayLimits).toEqual({
        maxReservations: 64,
        reservationTtlMs: 3_600_000,
        maxCircuitDurationMs: 600_000,
        maxCircuitDataBytes: 8_388_608n,
        hopTimeoutMs: 15_000,
        maxInboundHopStreams: 80,
        maxOutboundHopStreams: 81,
        maxOutboundStopStreams: 82,
      })
    })

    it.each([
      ['0'],
      ['-1'],
      ['1.5'],
      ['12ms'],
      ['9007199254740992'],
    ])('rejects unsafe numeric limit %s', (value) => {
      const cfg = loadConfig({
        READINESS_PORT: value,
        MAX_CONNECTIONS: value,
        RELAY_MAX_RESERVATIONS: value,
        RELAY_RESERVATION_TTL_MS: value,
        RELAY_MAX_CIRCUIT_DURATION_MS: value,
        RELAY_HOP_TIMEOUT_MS: value,
        RELAY_MAX_INBOUND_HOP_STREAMS: value,
        RELAY_MAX_OUTBOUND_HOP_STREAMS: value,
        RELAY_MAX_OUTBOUND_STOP_STREAMS: value,
      })
      expect(cfg.readinessPort).toBe(DEFAULT_READINESS_PORT)
      expect(cfg.maxConnections).toBe(DEFAULT_MAX_CONNECTIONS)
      expect(cfg.relayLimits.maxReservations).toBe(DEFAULT_RELAY_MAX_RESERVATIONS)
      expect(cfg.relayLimits.reservationTtlMs).toBe(DEFAULT_RELAY_RESERVATION_TTL_MS)
      expect(cfg.relayLimits.maxCircuitDurationMs).toBe(
        DEFAULT_RELAY_MAX_CIRCUIT_DURATION_MS,
      )
      expect(cfg.relayLimits.hopTimeoutMs).toBe(DEFAULT_RELAY_HOP_TIMEOUT_MS)
      expect(cfg.relayLimits.maxInboundHopStreams).toBe(
        DEFAULT_RELAY_MAX_INBOUND_HOP_STREAMS,
      )
      expect(cfg.relayLimits.maxOutboundHopStreams).toBe(
        DEFAULT_RELAY_MAX_OUTBOUND_HOP_STREAMS,
      )
      expect(cfg.relayLimits.maxOutboundStopStreams).toBe(
        DEFAULT_RELAY_MAX_OUTBOUND_STOP_STREAMS,
      )
    })

    it.each(['0', '-1', '1.5', '12MB'])('rejects unsafe byte limit %s', (value) => {
      expect(
        loadConfig({ RELAY_MAX_CIRCUIT_BYTES: value }).relayLimits
          .maxCircuitDataBytes,
      ).toBe(DEFAULT_RELAY_MAX_CIRCUIT_BYTES)
    })
  })
})

describe('listenAddresses', () => {
  it('returns IPv4-only listeners by default', () => {
    const cfg = loadConfig({})
    expect(listenAddresses(cfg)).toEqual([cfg.wsListen, cfg.tcpListen])
  })

  it('adds IPv6 listeners when enabled', () => {
    const cfg = loadConfig({ ENABLE_IPV6: '1' })
    expect(listenAddresses(cfg)).toEqual([
      cfg.wsListen,
      cfg.tcpListen,
      cfg.wsListenV6,
      cfg.tcpListenV6,
    ])
  })

  it('preserves explicit overrides', () => {
    const cfg = loadConfig({
      ENABLE_IPV6: '1',
      WS_LISTEN: '/ip4/127.0.0.1/tcp/9999/ws',
      TCP_LISTEN: '/ip4/127.0.0.1/tcp/8888',
      WS_LISTEN_V6: '/ip6/::1/tcp/9999/ws',
      TCP_LISTEN_V6: '/ip6/::1/tcp/8888',
    })
    expect(listenAddresses(cfg)).toEqual([
      '/ip4/127.0.0.1/tcp/9999/ws',
      '/ip4/127.0.0.1/tcp/8888',
      '/ip6/::1/tcp/9999/ws',
      '/ip6/::1/tcp/8888',
    ])
  })

  it('drops an empty WS_LISTEN_V6 from the bind list', () => {
    const cfg = loadConfig({ ENABLE_IPV6: '1', WS_LISTEN_V6: '' })
    expect(listenAddresses(cfg)).toEqual([cfg.wsListen, cfg.tcpListen, cfg.tcpListenV6])
  })

  it('drops an empty TCP_LISTEN_V6 from the bind list', () => {
    const cfg = loadConfig({ ENABLE_IPV6: '1', TCP_LISTEN_V6: '' })
    expect(listenAddresses(cfg)).toEqual([cfg.wsListen, cfg.tcpListen, cfg.wsListenV6])
  })

  it('drops both empty IPv6 listeners (effectively IPv4-only)', () => {
    const cfg = loadConfig({
      ENABLE_IPV6: '1',
      WS_LISTEN_V6: '',
      TCP_LISTEN_V6: '',
    })
    expect(listenAddresses(cfg)).toEqual([cfg.wsListen, cfg.tcpListen])
  })
})

describe('circuitRelayServerOptions', () => {
  it('maps every configured limit to Circuit Relay v2', () => {
    const config = loadConfig({
      RELAY_MAX_RESERVATIONS: '64',
      RELAY_RESERVATION_TTL_MS: '3600000',
      RELAY_MAX_CIRCUIT_DURATION_MS: '600000',
      RELAY_MAX_CIRCUIT_BYTES: '8388608',
      RELAY_HOP_TIMEOUT_MS: '15000',
      RELAY_MAX_INBOUND_HOP_STREAMS: '80',
      RELAY_MAX_OUTBOUND_HOP_STREAMS: '81',
      RELAY_MAX_OUTBOUND_STOP_STREAMS: '82',
    })

    expect(circuitRelayServerOptions(config)).toEqual({
      hopTimeout: 15_000,
      reservations: {
        maxReservations: 64,
        reservationTtl: 3_600_000,
        applyDefaultLimit: true,
        defaultDurationLimit: 600_000,
        defaultDataLimit: 8_388_608n,
      },
      maxInboundHopStreams: 80,
      maxOutboundHopStreams: 81,
      maxOutboundStopStreams: 82,
    })
  })
})
