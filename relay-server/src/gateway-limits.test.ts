import { clientKey, demoGatewayLimits, GatewayLimiter } from './gateway-limits.js'

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

  it('keeps the total budget exhausted across reconnects and time windows', () => {
    const limiter = new GatewayLimiter({ ...demoGatewayLimits, totalBytes: 10 }, () => now)
    const first = limiter.admit('192.0.2.1')!
    const second = limiter.admit('192.0.2.2')!
    expect(limiter.consume(first, 6)).toBe(true)
    expect(limiter.consume(second, 5)).toBe(false)
    expect(limiter.budgetExhausted).toBe(true)
    now = 86_400_000
    expect(limiter.consume(first, 1)).toBe(false)
    expect(limiter.admit('192.0.2.3')).toBeUndefined()
  })

  it('rejects invalid accounting input without granting extra allowance', () => {
    const limiter = new GatewayLimiter(demoGatewayLimits, () => now)
    const session = limiter.admit('192.0.2.1')!
    for (const bytes of [-1, NaN, Infinity, 0.5]) {
      expect(limiter.consume(session, bytes)).toBe(false)
    }
    expect(limiter.consume(session, demoGatewayLimits.burstBytes + 1)).toBe(false)
  })
})
