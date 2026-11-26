import { isIPv4, isIPv6 } from 'node:net'
import { performance } from 'node:perf_hooks'
import { RefillingBucket } from './refilling-bucket.js'

export const demoGatewayLimits = {
  maxConnections: 16,
  maxConnectionsPerClient: 4,
  newClientsPerMinute: 30,
  attemptsPerClientPerMinute: 6,
  attemptsPerClientPerTenSeconds: 3,
  maxTrackedClients: 512,
  sessionBytes: 8 * 1024 * 1024,
  windowMs: 10 * 60 * 1000,
  windowBytes: 128 * 1024 * 1024,
  clientWindowBytes: 32 * 1024 * 1024,
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
  share: RefillingBucket
}

export interface GatewaySession {
  readonly client: string
  bytes: number
  readonly rate: RefillingBucket
  readonly share: RefillingBucket
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
  /** Rate windows and traffic shares by client, least recently seen first. */
  private readonly clients = new Map<string, ClientRecord>()
  private readonly sessions = new Set<GatewaySession>()
  private readonly newClients = { start: -Infinity, clients: new Set<string>() }
  private readonly window: RefillingBucket

  constructor(
    readonly limits: GatewayLimits = demoGatewayLimits,
    private readonly now: () => number = () => performance.now(),
  ) {
    this.window = this.windowBucket(limits.windowBytes, now())
  }

  private windowBucket(bytes: number, now: number): RefillingBucket {
    return new RefillingBucket(bytes, bytes / this.limits.windowMs, now)
  }

  private increment(window: Window, duration: number): number {
    const now = this.now()
    if (now - window.start >= duration) {
      window.start = now
      window.count = 0
    }
    return ++window.count
  }

  /** Whether the shared window holds less than one session's burst. */
  get budgetExhausted(): boolean {
    return this.window.available(this.now()) < this.limits.burstBytes
  }

  /** Time until the shared window admits sessions again. */
  get budgetRetryAfterMs(): number {
    return this.window.msUntil(this.limits.burstBytes, this.now())
  }

  private evictIdleClient(active: Set<string>): boolean {
    for (const client of this.clients.keys()) {
      if (!active.has(client)) {
        this.clients.delete(client)
        return true
      }
    }
    return false
  }

  admit(ip: string): GatewaySession | undefined {
    if (this.budgetExhausted) return undefined
    const client = clientKey(ip)
    const now = this.now()
    const active = new Set([...this.sessions].map((session) => session.client))
    for (const [tracked, record] of this.clients) {
      if (
        !active.has(tracked) &&
        now - record.minute.start >= 60_000 &&
        record.share.available(now) >= record.share.capacity
      ) {
        this.clients.delete(tracked)
      }
    }
    let record = this.clients.get(client)
    if (record) {
      this.clients.delete(client)
    } else {
      // A full registry must not lock out unseen clients: forget the least
      // recently seen client that holds no session instead.
      if (this.clients.size >= this.limits.maxTrackedClients && !this.evictIdleClient(active)) {
        return undefined
      }
      record = {
        minute: { start: now, count: 0 },
        burst: { start: now, count: 0 },
        share: this.windowBucket(this.limits.clientWindowBytes, now),
      }
    }
    this.clients.set(client, record)
    const minute = this.increment(record.minute, 60_000)
    const burst = this.increment(record.burst, 10_000)
    if (
      minute > this.limits.attemptsPerClientPerMinute ||
      burst > this.limits.attemptsPerClientPerTenSeconds ||
      record.share.available(now) < this.limits.burstBytes ||
      [...this.sessions].filter((session) => session.client === client).length >=
        this.limits.maxConnectionsPerClient ||
      this.sessions.size >= this.limits.maxConnections
    ) {
      return undefined
    }
    // The new-client budget counts distinct clients, not sessions: reconnects are
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
      rate: new RefillingBucket(this.limits.burstBytes, this.limits.bytesPerSecond / 1000, now),
      share: record.share,
    }
    this.sessions.add(session)
    return session
  }

  consume(session: GatewaySession, bytes: number): boolean {
    if (!this.sessions.has(session)) return false
    if (!Number.isSafeInteger(bytes) || bytes < 0) return false
    const now = this.now()
    // Count rejected session traffic too: it already reached this process.
    session.bytes += bytes
    const paced = session.rate.spend(bytes, now)
    const withinShare = session.share.spend(bytes, now)
    const withinWindow = this.window.spend(bytes, now)
    return paced && withinShare && withinWindow && session.bytes <= this.limits.sessionBytes
  }

  release(session: GatewaySession): void {
    this.sessions.delete(session)
  }
}

function windowBytesFromEnv(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
): number {
  const value = env[name]
  if (value === undefined) return fallback
  const bytes = /^[1-9]\d*$/.test(value) ? Number(value) : NaN
  if (!Number.isSafeInteger(bytes)) throw new Error(`${name} must be a positive integer`)
  return bytes
}

export function gatewayLimitsFromEnv(
  env: NodeJS.ProcessEnv,
  limits: GatewayLimits = demoGatewayLimits,
): GatewayLimits {
  const windowBytes = windowBytesFromEnv(env, 'RELAY_GATEWAY_WINDOW_BYTES', limits.windowBytes)
  const clientWindowBytes = windowBytesFromEnv(
    env,
    'RELAY_GATEWAY_CLIENT_WINDOW_BYTES',
    limits.clientWindowBytes,
  )
  if (clientWindowBytes < limits.burstBytes || clientWindowBytes > windowBytes) {
    throw new Error(
      'RELAY_GATEWAY_CLIENT_WINDOW_BYTES must be at least one session burst ' +
        'and at most RELAY_GATEWAY_WINDOW_BYTES',
    )
  }
  return { ...limits, windowBytes, clientWindowBytes }
}
