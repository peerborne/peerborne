import {
  clientKey,
  demoGatewayLimits,
  GatewayLimiter,
  gatewayLimitsFromEnv,
  type GatewaySession,
} from './gateway-limits.js'

describe('gateway client keys', () => {
  it('keys IPv4 by address', () => {
    expect(clientKey('192.0.2.1')).toBe('192.0.2.1')
  })

  it('keys every spelling of an IPv6 address by its /64', () => {
    const key = clientKey('2001:db8:1:2::1')
    expect(key).toBe('2001:db8:1:2::/64')
    for (const address of [
      '2001:0db8:0001:0002:0000:0000:0000:0001',
      '2001:DB8:1:2:ffff:ffff:ffff:ffff',
      '2001:db8:1:2::192.0.2.1',
      '2001:db8:1:2::1%eth0',
    ]) {
      expect(clientKey(address)).toBe(key)
    }
    expect(clientKey('2001:db8:1:3::1')).not.toBe(key)
    expect(clientKey('::')).toBe('0:0:0:0::/64')
  })

  it('keys IPv4-mapped IPv6 by the IPv4 address', () => {
    expect(clientKey('::ffff:192.0.2.1')).toBe('192.0.2.1')
    expect(clientKey('::ffff:c000:201')).toBe('192.0.2.1')
  })

  it('rejects values that are not IP addresses', () => {
    expect(() => clientKey('relay.peerborne.io')).toThrow('IP address')
  })
})

describe('demo gateway resource limits', () => {
  let now: number
  beforeEach(() => { now = 0 })

  it('limits repeated reconnects even after sessions close', () => {
    const limiter = new GatewayLimiter(demoGatewayLimits, () => now)
    for (let index = 0; index < 3; index++) {
      const session = limiter.admit('192.0.2.1')!
      expect(session).toBeDefined()
      limiter.release(session)
    }
    expect(limiter.admit('192.0.2.1')).toBeUndefined()
    now = 10_000
    for (let index = 0; index < 2; index++) {
      const session = limiter.admit('192.0.2.1')!
      expect(session).toBeDefined()
      limiter.release(session)
    }
    expect(limiter.admit('192.0.2.1')).toBeUndefined()
    now = 60_000
    expect(limiter.admit('192.0.2.1')).toBeDefined()
  })

  it('bounds simultaneous sessions per client and globally', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits, maxConnections: 3, maxConnectionsPerClient: 2,
    }, () => now)
    const first = limiter.admit('192.0.2.1')!
    expect(limiter.admit('192.0.2.1')).toBeDefined()
    expect(limiter.admit('192.0.2.1')).toBeUndefined()
    expect(limiter.admit('192.0.2.2')).toBeDefined()
    expect(limiter.admit('192.0.2.3')).toBeUndefined()
    limiter.release(first)
    limiter.release(first)
    expect(limiter.admit('192.0.2.3')).toBeDefined()
  })

  it('evicts the least recently seen idle client instead of locking out new ones', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits, maxTrackedClients: 8, newClientsPerMinute: 1000,
    }, () => now)
    for (let index = 0; index < 600; index++) {
      const session = limiter.admit(`198.51.${index >> 8}.${index & 0xff}`)
      expect(session).toBeDefined()
      limiter.release(session!)
    }
    expect(limiter.admit('192.0.2.1')).toBeDefined()
  })

  it('keeps the rate state of clients that hold sessions when the registry is full', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits, maxTrackedClients: 2, attemptsPerClientPerTenSeconds: 1,
    }, () => now)
    expect(limiter.admit('192.0.2.1')).toBeDefined()
    limiter.release(limiter.admit('192.0.2.2')!)
    expect(limiter.admit('192.0.2.3')).toBeDefined()
    expect(limiter.admit('192.0.2.1')).toBeUndefined()
    expect(limiter.admit('192.0.2.4')).toBeUndefined()
  })

  it('treats every address in an IPv6 /64 as one client', () => {
    const limiter = new GatewayLimiter(demoGatewayLimits, () => now)
    for (let index = 1; index <= demoGatewayLimits.attemptsPerClientPerTenSeconds; index++) {
      limiter.release(limiter.admit(`2001:db8:1:2::${index.toString(16)}`)!)
    }
    for (let index = 0; index < 100; index++) {
      expect(limiter.admit(`2001:db8:1:2:${index.toString(16)}::1`)).toBeUndefined()
    }
    expect(limiter.admit('2001:db8:1:3::1')).toBeDefined()
  })

  it('limits new clients per minute across addresses', () => {
    const limiter = new GatewayLimiter({ ...demoGatewayLimits, newClientsPerMinute: 2 }, () => now)
    limiter.release(limiter.admit('192.0.2.1')!)
    limiter.release(limiter.admit('192.0.2.2')!)
    expect(limiter.admit('192.0.2.3')).toBeUndefined()
    expect(limiter.admit('192.0.2.1')).toBeDefined()
    now = 60_000
    expect(limiter.admit('192.0.2.3')).toBeDefined()
  })

  it('does not let one client spend the shared budget', () => {
    const limiter = new GatewayLimiter(demoGatewayLimits, () => now)
    for (let index = 0; index < demoGatewayLimits.newClientsPerMinute * 2; index++) {
      const session = limiter.admit('192.0.2.1')
      if (session) limiter.release(session)
      now += 500
    }
    expect(limiter.admit('192.0.2.2')).toBeDefined()
  })

  it('does not let a few clients spend the shared budget by reconnecting', () => {
    const limiter = new GatewayLimiter(demoGatewayLimits, () => now)
    const churning = Array.from({ length: 5 }, (_, index) => `192.0.2.${index + 1}`)
    let admitted = 0
    for (let step = 0; step < demoGatewayLimits.attemptsPerClientPerMinute; step++) {
      for (const address of churning) {
        const session = limiter.admit(address)
        if (session) {
          admitted++
          limiter.release(session)
        }
      }
      now += 4_000
    }
    expect(admitted).toBe(churning.length * demoGatewayLimits.attemptsPerClientPerMinute)
    expect(limiter.admit('198.51.100.1')).toBeDefined()
  })

  it('does not charge the shared budget while the gateway is full', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits, newClientsPerMinute: 2, maxConnections: 1,
    }, () => now)
    const first = limiter.admit('192.0.2.1')!
    for (let index = 2; index < 10; index++) {
      expect(limiter.admit(`192.0.2.${index}`)).toBeUndefined()
    }
    limiter.release(first)
    expect(limiter.admit('192.0.2.10')).toBeDefined()
  })

  it('caps cumulative bytes for one session', () => {
    const limiter = new GatewayLimiter({ ...demoGatewayLimits, sessionBytes: 10 }, () => now)
    const session = limiter.admit('192.0.2.1')!
    expect(limiter.consume(session, 6)).toBe(true)
    expect(limiter.consume(session, 5)).toBe(false)
    limiter.release(session)
    expect(limiter.consume(session, 1)).toBe(false)
  })

  it('caps throughput in both directions with a bounded token bucket', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits, bytesPerSecond: 10, burstBytes: 20,
    }, () => now)
    const session = limiter.admit('192.0.2.1')!
    expect(limiter.consume(session, 20)).toBe(true)
    now = 500
    expect(limiter.consume(session, 5)).toBe(true)
    expect(limiter.consume(session, 1)).toBe(false)
  })

  it('refills the shared window after it is spent', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits,
      windowMs: 4096, windowBytes: 4096, clientWindowBytes: 2048,
      burstBytes: 1024, bytesPerSecond: 1024 * 1000,
    }, () => now)
    const first = limiter.admit('192.0.2.1')!
    const second = limiter.admit('192.0.2.2')!
    expect(limiter.consume(first, 1024)).toBe(true)
    now = 1
    expect(limiter.consume(first, 1024)).toBe(true)
    expect(limiter.consume(second, 1024)).toBe(true)
    now = 2
    expect(limiter.consume(second, 1024)).toBe(true)
    expect(limiter.budgetExhausted).toBe(true)
    expect(limiter.budgetRetryAfterMs).toBe(1022)
    expect(limiter.admit('192.0.2.3')).toBeUndefined()
    now = 1024
    expect(limiter.budgetExhausted).toBe(false)
    const third = limiter.admit('192.0.2.3')!
    expect(third).toBeDefined()
    expect(limiter.consume(third, 1024)).toBe(true)
    expect(limiter.consume(first, 1)).toBe(false)
    expect(limiter.budgetExhausted).toBe(true)
  })

  it('caps one client\'s share of the window across its sessions and reconnects', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits,
      attemptsPerClientPerMinute: 10, attemptsPerClientPerTenSeconds: 10,
      windowMs: 4096, windowBytes: 8192, clientWindowBytes: 2048,
      burstBytes: 1024, bytesPerSecond: 1024 * 1000,
    }, () => now)
    const first = limiter.admit('192.0.2.1')!
    const second = limiter.admit('192.0.2.1')!
    expect(limiter.consume(first, 1024)).toBe(true)
    expect(limiter.consume(second, 1024)).toBe(true)
    now = 1
    expect(limiter.consume(first, 1)).toBe(false)
    limiter.release(first)
    limiter.release(second)
    expect(limiter.admit('192.0.2.1')).toBeUndefined()
    expect(limiter.admit('192.0.2.2')).toBeDefined()
    expect(limiter.budgetExhausted).toBe(false)
    now = 2049
    expect(limiter.admit('192.0.2.1')).toBeUndefined()
    now = 2050
    expect(limiter.admit('192.0.2.1')).toBeDefined()
  })

  it('remembers a spent share after the rate windows expire', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits,
      windowMs: 600_000, windowBytes: 8192, clientWindowBytes: 2048,
      burstBytes: 1024, bytesPerSecond: 1024 * 1000,
    }, () => now)
    const session = limiter.admit('192.0.2.1')!
    expect(limiter.consume(session, 1024)).toBe(true)
    now = 1
    expect(limiter.consume(session, 1024)).toBe(true)
    limiter.release(session)
    now = 120_000
    expect(limiter.admit('192.0.2.1')).toBeUndefined()
    now = 300_001
    expect(limiter.admit('192.0.2.1')).toBeDefined()
  })

  it('rejects invalid accounting input without granting extra allowance', () => {
    const limiter = new GatewayLimiter(demoGatewayLimits, () => now)
    const session = limiter.admit('192.0.2.1')!
    for (const bytes of [-1, NaN, Infinity, 0.5]) {
      expect(limiter.consume(session, bytes)).toBe(false)
    }
    expect(limiter.consume(session, demoGatewayLimits.burstBytes + 1)).toBe(false)
  })

  it('keeps admitting other clients while one client floods every session it can open', () => {
    const limiter = new GatewayLimiter(demoGatewayLimits, () => now)
    const seconds = 30 * 60
    const flood: GatewaySession[] = []
    let flooded = 0
    for (let second = 0; second < seconds; second++) {
      while (flood.length < demoGatewayLimits.maxConnectionsPerClient) {
        const session = limiter.admit('192.0.2.1')
        if (!session) break
        flood.push(session)
      }
      for (const session of [...flood]) {
        if (limiter.consume(session, demoGatewayLimits.bytesPerSecond)) {
          flooded += demoGatewayLimits.bytesPerSecond
        } else {
          limiter.release(session)
          flood.splice(flood.indexOf(session), 1)
        }
      }
      expect(limiter.budgetExhausted).toBe(false)
      if (second % 60 === 30) {
        const other = limiter.admit('198.51.100.1')!
        expect(other).toBeDefined()
        expect(limiter.consume(other, demoGatewayLimits.burstBytes)).toBe(true)
        limiter.release(other)
      }
      now += 1000
    }
    const { clientWindowBytes, windowMs } = demoGatewayLimits
    expect(flooded).toBeGreaterThan(clientWindowBytes)
    expect(flooded).toBeLessThanOrEqual(clientWindowBytes * (1 + seconds * 1000 / windowMs))
  })

  it('never limits a full gateway of idle Note tabs that keep sharing notes', () => {
    // Measured through the gateway: 16 idle Note tabs on 8 shared notes moved
    // about 100 KB/s in both directions; sharing one note moved about 240 KB.
    const idleBytesPerTab = 6_400
    const shareBytes = 240_000
    const limiter = new GatewayLimiter(demoGatewayLimits, () => now)
    const clients = ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4']
    const sessionSeconds = demoGatewayLimits.sessionMs / 1000
    const tabs = Array.from({ length: demoGatewayLimits.maxConnections }, (_, index) => ({
      ip: clients[index % clients.length],
      sharing: index < clients.length,
      opensAt: index * 37,
      session: undefined as GatewaySession | undefined,
    }))
    let refused = 0
    let limited = 0
    let exhausted = 0
    for (let second = 0; second < 6 * 60 * 60; second++) {
      for (const tab of tabs) {
        if (second >= tab.opensAt && (second - tab.opensAt) % sessionSeconds === 0) {
          if (tab.session) limiter.release(tab.session)
          tab.session = limiter.admit(tab.ip)
          if (!tab.session) refused++
        }
        if (!tab.session) continue
        const bytes = idleBytesPerTab + (tab.sharing && second % 300 < 5 ? shareBytes / 5 : 0)
        if (!limiter.consume(tab.session, bytes)) limited++
      }
      if (limiter.budgetExhausted) exhausted++
      now += 1000
    }
    expect({ refused, limited, exhausted }).toEqual({ refused: 0, limited: 0, exhausted: 0 })
  }, 20_000)
})

describe('gateway traffic window configuration', () => {
  it('defaults to the demo window', () => {
    expect(gatewayLimitsFromEnv({})).toEqual(demoGatewayLimits)
  })

  it('reads the shared and per-client window sizes', () => {
    expect(gatewayLimitsFromEnv({
      RELAY_GATEWAY_WINDOW_BYTES: '67108864',
      RELAY_GATEWAY_CLIENT_WINDOW_BYTES: '8388608',
    })).toEqual({
      ...demoGatewayLimits, windowBytes: 67_108_864, clientWindowBytes: 8_388_608,
    })
  })

  it('rejects malformed or inconsistent window sizes', () => {
    for (const value of ['', '0', '-1', '1.5', '1e6', ' 1048576', '9007199254740993']) {
      expect(() => gatewayLimitsFromEnv({ RELAY_GATEWAY_WINDOW_BYTES: value }))
        .toThrow('RELAY_GATEWAY_WINDOW_BYTES')
    }
    expect(() => gatewayLimitsFromEnv({ RELAY_GATEWAY_CLIENT_WINDOW_BYTES: '134217729' }))
      .toThrow('RELAY_GATEWAY_CLIENT_WINDOW_BYTES')
    expect(() => gatewayLimitsFromEnv({ RELAY_GATEWAY_CLIENT_WINDOW_BYTES: '131071' }))
      .toThrow('RELAY_GATEWAY_CLIENT_WINDOW_BYTES')
    expect(() => gatewayLimitsFromEnv({ RELAY_GATEWAY_WINDOW_BYTES: '1048576' }))
      .toThrow('RELAY_GATEWAY_CLIENT_WINDOW_BYTES')
  })
})
