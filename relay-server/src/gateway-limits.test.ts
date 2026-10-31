import { demoGatewayLimits, GatewayLimiter } from './gateway-limits.js'

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

  it('bounds simultaneous sessions per IP and globally', () => {
    const limiter = new GatewayLimiter({
      ...demoGatewayLimits, maxConnections: 3, maxConnectionsPerIp: 2,
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

  it('bounds the IP registry and expires old entries', () => {
    const limiter = new GatewayLimiter({ ...demoGatewayLimits, maxTrackedIps: 2 }, () => now)
    limiter.release(limiter.admit('192.0.2.1')!)
    limiter.release(limiter.admit('192.0.2.2')!)
    expect(limiter.admit('192.0.2.3')).toBeUndefined()
    now = 60_000
    expect(limiter.admit('192.0.2.3')).toBeDefined()
  })

  it('limits attempts from many different IP addresses', () => {
    const limiter = new GatewayLimiter({ ...demoGatewayLimits, attemptsPerMinute: 2 }, () => now)
    limiter.release(limiter.admit('192.0.2.1')!)
    limiter.release(limiter.admit('192.0.2.2')!)
    expect(limiter.admit('192.0.2.3')).toBeUndefined()
    now = 60_000
    expect(limiter.admit('192.0.2.3')).toBeDefined()
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
