import { isIPv4, isIPv6 } from 'node:net'
import { performance } from 'node:perf_hooks'

export const demoGatewayLimits = {
  maxConnections: 16,
  maxConnectionsPerClient: 4,
  newClientsPerMinute: 30,
  attemptsPerClientPerMinute: 6,
  attemptsPerClientPerTenSeconds: 3,
  maxTrackedClients: 512,
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

interface ClientRecord {
  minute: Window
  burst: Window
}

export interface GatewaySession {
  client: string
  bytes: number
  tokens: number
  refilledAt: number
}

function ipv6Groups(address: string): number[] {
  let text = address.split('%')[0]
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text)
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number)
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`
  }
  const [head, tail] = text.split('::')
  const parse = (part: string | undefined) =>
    part ? part.split(':').map((group) => parseInt(group, 16)) : []
  const left = parse(head)
  const right = parse(tail)
  return [...left, ...new Array<number>(8 - left.length - right.length).fill(0), ...right]
}

/**
 * The unit the gateway rate-limits: an IPv4 address, or an IPv6 /64, which one
 * subscriber usually controls in full. IPv4-mapped IPv6 addresses count as
 * their IPv4 address.
 */
export function clientKey(address: string): string {
  if (isIPv4(address)) return address
  if (!isIPv6(address)) throw new Error('Gateway client address must be an IP address')
  const groups = ipv6Groups(address)
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    return [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join('.')
  }
  return `${groups.slice(0, 4).map((group) => group.toString(16)).join(':')}::/64`
}

export class GatewayLimiter {
  /** Rate windows by client, least recently seen first. */
  private readonly clients = new Map<string, ClientRecord>()
  private readonly sessions = new Set<GatewaySession>()
  private readonly newClients = { start: -Infinity, clients: new Set<string>() }
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

  private evictIdleClient(): boolean {
    const active = new Set([...this.sessions].map((session) => session.client))
    for (const client of this.clients.keys()) {
      if (!active.has(client)) {
        this.clients.delete(client)
        return true
      }
    }
    return false
  }

  admit(ip: string): GatewaySession | undefined {
    if (this.exhausted) return undefined
    const client = clientKey(ip)
    const now = this.now()
    for (const [tracked, record] of this.clients) {
      if (now - record.minute.start >= 60_000) this.clients.delete(tracked)
    }
    let record = this.clients.get(client)
    if (record) {
      this.clients.delete(client)
    } else {
      // A full registry must not lock out unseen clients: forget the least
      // recently seen client that holds no session instead.
      if (this.clients.size >= this.limits.maxTrackedClients && !this.evictIdleClient()) {
        return undefined
      }
      record = {
        minute: { start: now, count: 0 },
        burst: { start: now, count: 0 },
      }
    }
    this.clients.set(client, record)
    const minute = this.increment(record.minute, 60_000)
    const burst = this.increment(record.burst, 10_000)
    if (
      minute > this.limits.attemptsPerClientPerMinute ||
      burst > this.limits.attemptsPerClientPerTenSeconds ||
      [...this.sessions].filter((session) => session.client === client).length >=
        this.limits.maxConnectionsPerClient ||
      this.sessions.size >= this.limits.maxConnections
    ) {
      return undefined
    }
    // The shared budget counts distinct clients, not sessions: reconnects are
    // bounded per client above, so a few clients cannot spend it by churning.
    if (now - this.newClients.start >= 60_000) {
      this.newClients.start = now
      this.newClients.clients.clear()
    }
    if (!this.newClients.clients.has(client)) {
      if (this.newClients.clients.size >= this.limits.newClientsPerMinute) return undefined
      this.newClients.clients.add(client)
    }

    const session = {
      client,
      bytes: 0,
      tokens: this.limits.burstBytes,
      refilledAt: now,
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
