import { performance } from 'node:perf_hooks'

export const demoGatewayLimits = {
  maxConnections: 16,
  maxConnectionsPerIp: 4,
  attemptsPerMinute: 30,
  attemptsPerIpPerMinute: 6,
  attemptsPerIpPerTenSeconds: 3,
  maxTrackedIps: 512,
  sessionBytes: 2 * 1024 * 1024,
  totalBytes: 32 * 1024 * 1024,
  bytesPerSecond: 64 * 1024,
  burstBytes: 128 * 1024,
  sessionMs: 10 * 60 * 1000,
  idleMs: 60 * 1000,
}

export type GatewayLimits = typeof demoGatewayLimits

interface Window {
  start: number
  count: number
}

export interface GatewaySession {
  ip: string
  bytes: number
  tokens: number
  refilledAt: number
}

export class GatewayLimiter {
  private readonly addresses = new Map<string, { minute: Window; burst: Window }>()
  private readonly sessions = new Set<GatewaySession>()
  private readonly attempts: Window = { start: -Infinity, count: 0 }
  private bytes = 0
  private exhausted = false

  constructor(
    readonly limits: GatewayLimits = demoGatewayLimits,
    private readonly now: () => number = () => performance.now(),
  ) {}

  private increment(window: Window, duration: number): number {
    const now = this.now()
    if (now - window.start >= duration) {
      window.start = now
      window.count = 0
    }
    return ++window.count
  }

  get budgetExhausted(): boolean {
    return this.exhausted
  }

  admit(ip: string): GatewaySession | undefined {
    if (this.exhausted) return undefined
    if (this.increment(this.attempts, 60_000) > this.limits.attemptsPerMinute) {
      return undefined
    }
    for (const [address, windows] of this.addresses) {
      if (this.now() - windows.minute.start >= 60_000) this.addresses.delete(address)
    }
    let windows = this.addresses.get(ip)
    if (!windows) {
      if (this.addresses.size >= this.limits.maxTrackedIps) return undefined
      windows = {
        minute: { start: this.now(), count: 0 },
        burst: { start: this.now(), count: 0 },
      }
      this.addresses.set(ip, windows)
    }
    const minute = this.increment(windows.minute, 60_000)
    const burst = this.increment(windows.burst, 10_000)
    if (
      minute > this.limits.attemptsPerIpPerMinute ||
      burst > this.limits.attemptsPerIpPerTenSeconds ||
      this.sessions.size >= this.limits.maxConnections ||
      [...this.sessions].filter((session) => session.ip === ip).length >=
        this.limits.maxConnectionsPerIp
    ) {
      return undefined
    }

    const session = {
      ip,
      bytes: 0,
      tokens: this.limits.burstBytes,
      refilledAt: this.now(),
    }
    this.sessions.add(session)
    return session
  }

  consume(session: GatewaySession, bytes: number): boolean {
    if (!this.sessions.has(session) || this.exhausted) return false
    if (!Number.isSafeInteger(bytes) || bytes < 0) return false
    if (bytes > this.limits.totalBytes - this.bytes) {
      this.exhausted = true
      return false
    }
    // Count rejected session traffic too: it already reached this process.
    this.bytes += bytes
    session.bytes += bytes
    if (this.bytes >= this.limits.totalBytes) this.exhausted = true
    const now = this.now()
    session.tokens = Math.min(
      this.limits.burstBytes,
      session.tokens +
        Math.max(0, now - session.refilledAt) * this.limits.bytesPerSecond / 1000,
    )
    session.refilledAt = now
    session.tokens -= bytes
    return !this.exhausted &&
      session.bytes <= this.limits.sessionBytes &&
      session.tokens >= 0
  }

  release(session: GatewaySession): void {
    this.sessions.delete(session)
  }
}
