import { timingSafeEqual } from 'node:crypto'
import { once } from 'node:events'
import { createServer, type IncomingMessage } from 'node:http'
import { connect, isIP, type Socket } from 'node:net'
import { Transform } from 'node:stream'
import { GatewayLimiter, type GatewayLimits } from './gateway-limits.js'
import { IntervalGate } from './interval-gate.js'

export interface GatewayConfig {
  port: number
  secret: string
  publicHost: string
  relayPort: number
  readinessPort: number
  limits: GatewayLimits
}

function singleHeader(request: IncomingMessage, name: string): string | undefined {
  let matches = 0
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === name) matches++
  }
  const value = request.headers[name]
  return matches === 1 && typeof value === 'string' ? value : undefined
}

function authenticated(request: IncomingMessage, config: GatewayConfig): boolean {
  const supplied = singleHeader(request, 'x-peerborne-origin')
  if (!supplied || supplied.length !== config.secret.length) return false
  const candidate = Buffer.from(supplied)
  const expected = Buffer.from(config.secret)
  return candidate.length === expected.length && timingSafeEqual(candidate, expected)
}

/** Time a rejected upgrade may stay open for its response to drain. */
const REJECTED_UPGRADE_LINGER_MS = 1000

function reject(socket: Socket, status: number, retryAfterSeconds = 60): void {
  // Upgraded sockets leave the HTTP server's timeouts behind; without this
  // deadline a client that never closes its side holds a connection slot.
  const deadline = setTimeout(() => socket.destroy(), REJECTED_UPGRADE_LINGER_MS)
  deadline.unref()
  socket.once('close', () => clearTimeout(deadline))
  socket.resume()
  socket.end(
    `HTTP/1.1 ${status} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n` +
    `Retry-After: ${retryAfterSeconds}\r\n\r\n`,
  )
}

export async function startRelayGateway(config: GatewayConfig) {
  if (!/^[A-Za-z0-9+/=_-]{32,128}$/.test(config.secret)) {
    throw new Error('RELAY_GATEWAY_SECRET must contain at least 32 random ASCII characters')
  }
  const limiter = new GatewayLimiter(config.limits)
  const originWarning = new IntervalGate(60_000)
  const budgetWarning = new IntervalGate(60_000)
  const budgetRetryAfterSeconds = () => Math.max(1, Math.ceil(limiter.budgetRetryAfterMs / 1000))
  const warnBudgetExhausted = () => {
    if (budgetWarning.open()) {
      console.warn('Relay gateway traffic window exhausted; rejecting upgrades until it refills', {
        retryAfterSeconds: budgetRetryAfterSeconds(),
      })
    }
  }
  const tunnels = new Set<() => void>()
  const sockets = new Set<Socket>()
  const server = createServer({ maxHeaderSize: 8192 }, async (request, response) => {
    response.setHeader('cache-control', 'no-store')
    response.setHeader('connection', 'close')
    if (
      (request.method === 'GET' || request.method === 'HEAD') &&
      (request.url === '/readyz' || request.url === '/livez')
    ) {
      try {
        const upstream = await fetch(
          `http://127.0.0.1:${config.readinessPort}${request.url}`,
          { signal: AbortSignal.timeout(1000) },
        )
        let body = await upstream.text()
        if (request.url === '/readyz' && upstream.ok && limiter.budgetExhausted) {
          const { peerId } = JSON.parse(body) as { peerId?: unknown }
          body = JSON.stringify({
            status: 'budget-exhausted',
            peerId,
            retryAfterSeconds: budgetRetryAfterSeconds(),
          })
        }
        response.writeHead(upstream.status, { 'content-type': 'application/json' })
        response.end(request.method === 'HEAD' ? undefined : body.slice(0, 1024))
      } catch {
        response.writeHead(503)
        response.end()
      }
      return
    }
    response.writeHead(authenticated(request, config) ? 426 : 403)
    response.end()
  })
  server.maxConnections = 64
  server.maxHeadersCount = 64
  server.headersTimeout = 5000
  server.requestTimeout = 5000
  server.keepAliveTimeout = 1000
  server.setTimeout(5000, (socket) => socket.destroy())
  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.on('error', () => socket.destroy())
    socket.once('close', () => sockets.delete(socket))
  })
  server.on('clientError', (_error, socket) => socket.destroy())
  server.on('upgrade', (request, stream, head) => {
    const client = stream as Socket
    client.pause()
    if (!authenticated(request, config)) {
      if (originWarning.open()) {
        console.warn('Relay gateway rejected origin authentication', {
          originHeaderCount: request.rawHeaders.filter(
            (value, index) => index % 2 === 0 && value.toLowerCase() === 'x-peerborne-origin',
          ).length,
        })
      }
      return reject(client, 403)
    }
    const host = singleHeader(request, 'host')
    const ip = singleHeader(request, 'cf-connecting-ip')
    const key = singleHeader(request, 'sec-websocket-key')
    if (
      host !== config.publicHost || !ip || isIP(ip) === 0 ||
      request.method !== 'GET' || request.url !== '/' ||
      singleHeader(request, 'upgrade')?.toLowerCase() !== 'websocket' ||
      singleHeader(request, 'sec-websocket-version') !== '13' ||
      !key || !/^[A-Za-z0-9+/]{22}==$/.test(key)
    ) {
      return reject(client, 400)
    }

    const session = limiter.admit(ip)
    if (!session) {
      if (!limiter.budgetExhausted) return reject(client, 429)
      warnBudgetExhausted()
      return reject(client, 503, budgetRetryAfterSeconds())
    }
    const upstream = connect({ host: '127.0.0.1', port: config.relayPort })
    let closed = false
    const close = () => {
      if (closed) return
      closed = true
      clearTimeout(expiry)
      tunnels.delete(close)
      limiter.release(session)
      client.destroy()
      upstream.destroy()
    }
    const expiry = setTimeout(close, config.limits.sessionMs)
    expiry.unref()
    tunnels.add(close)
    client.setTimeout(config.limits.idleMs, close)
    upstream.setTimeout(5000, close)
    client.on('error', close)
    client.once('close', close)
    upstream.on('error', close)
    upstream.once('close', close)

    const meter = () => {
      const transform = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          if (limiter.consume(session, chunk.length)) callback(null, chunk)
          else {
            if (limiter.budgetExhausted) warnBudgetExhausted()
            callback(new Error('Relay traffic limit reached'))
          }
        },
      })
      transform.on('error', close)
      return transform
    }
    upstream.once('connect', () => {
      if (closed) return
      upstream.setTimeout(config.limits.idleMs, close)
      // Forward only protocol headers; never forward the origin credential.
      upstream.write(
        `GET / HTTP/1.1\r\nHost: 127.0.0.1:${config.relayPort}\r\n` +
        `Connection: Upgrade\r\nUpgrade: websocket\r\n` +
        `Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${key}\r\n\r\n`,
      )
      const inbound = meter()
      client.pipe(inbound).pipe(upstream)
      upstream.pipe(meter()).pipe(client)
      if (head.length) inbound.write(head)
      client.resume()
    })
  })
  server.listen(config.port, '0.0.0.0')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Gateway failed to listen')
  return {
    port: address.port,
    async close() {
      const stopped = new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve())
      })
      for (const stop of [...tunnels]) stop()
      for (const socket of sockets) socket.destroy()
      await stopped
    },
  }
}
