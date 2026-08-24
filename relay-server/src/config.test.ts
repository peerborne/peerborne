import {
  DEFAULT_DOCUMENT_PUBLISH_PATH,
  DEFAULT_MAX_AUTO_TOPICS,
  DEFAULT_TCP_PORT,
  DEFAULT_WS_PORT,
  PUBSUB_PEER_DISCOVERY_TOPIC,
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
      expect(cfg.topicAllowlist).toBeNull()
      expect(cfg.maxAutoTopics).toBe(DEFAULT_MAX_AUTO_TOPICS)
      expect(cfg.extraTopics).toEqual([])
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
        WS_LISTEN: '/ip4/127.0.0.1/tcp/9999/ws',
        TCP_LISTEN: '/ip4/127.0.0.1/tcp/8888',
      })
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
    it('returns null when unset (open mode)', () => {
      expect(loadConfig({}).topicAllowlist).toBeNull()
    })

    it('returns null when empty (open mode)', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '' }).topicAllowlist).toBeNull()
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
      // Distinguishes "unset" (null → open mode) from "set but parses to no
      // entries" (empty array → closed mode, rejects everything). This
      // matches the historical inline behaviour and protects a misconfigured
      // relay from silently flipping open.
      expect(loadConfig({ TOPIC_ALLOWLIST: ',' }).topicAllowlist).toEqual([])
    })

    it('returns [] (closed mode) when set to whitespace-only', () => {
      expect(loadConfig({ TOPIC_ALLOWLIST: '   ' }).topicAllowlist).toEqual([])
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

    it('parses leading-digit strings via parseInt semantics', () => {
      // parseInt('100abc', 10) === 100 — match historical inline behaviour.
      expect(loadConfig({ MAX_AUTO_TOPICS: '100abc' }).maxAutoTopics).toBe(100)
    })
  })

  describe('EXTRA_TOPICS parsing', () => {
    it('returns an empty array when unset', () => {
      expect(loadConfig({}).extraTopics).toEqual([])
    })

    it('splits, trims and filters empty segments', () => {
      expect(loadConfig({ EXTRA_TOPICS: ' /a/ , ,/b/,' }).extraTopics).toEqual(['/a/', '/b/'])
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
