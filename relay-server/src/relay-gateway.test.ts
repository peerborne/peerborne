import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { createServer, type Server } from 'node:http'
import { connect, type Socket } from 'node:net'
import { demoGatewayLimits } from './gateway-limits.js'
import { startRelayGateway, type GatewayConfig } from './relay-gateway.js'

const secret = 'test-only-origin-credential-0123456789'
const host = 'relay.peerborne.io'

describe('relay gateway', () => {
  const cleanup: Array<() => Promise<unknown>> = []
  afterEach(async () => {
    await Promise.all(cleanup.splice(0).map(close => close()))
  })

  async function listen(server: Server): Promise<number> {
    const sockets = new Set<Socket>()
    server.on('connection', socket => {
      sockets.add(socket)
      socket.once('close', () => sockets.delete(socket))
    })
    server.listen(0, '127.0.0.1')
    await once(server, 'listening')
    cleanup.push(() => new Promise<void>(resolve => {
      server.close(() => resolve())
      for (const socket of sockets) socket.destroy()
    }))
    return (server.address() as { port: number }).port
  }

  async function fixture(limits = demoGatewayLimits) {
    let forwardedHeaders: Record<string, string | string[] | undefined> = {}
    const relay = createServer()
    relay.on('upgrade', (request, socket, head) => {
      forwardedHeaders = request.headers
      const accept = createHash('sha1').update(request.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`)
      socket.on('error', () => socket.destroy())
      socket.on('data', chunk => socket.write(chunk))
      if (head.length) socket.write(head)
    })
    const relayPort = await listen(relay)
    const health = createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ status: 'ready', peerId: 'public-test-peer' }))
    })
    const config: GatewayConfig = {
      port: 0, secret, publicHost: host, relayPort,
      readinessPort: await listen(health), limits,
    }
    const gateway = await startRelayGateway(config)
    cleanup.push(() => gateway.close())
    return { gateway, config, headers: () => forwardedHeaders }
  }

  async function upgrade(port: number, headers: string[] = []) {
    const socket = connect({ host: '127.0.0.1', port })
    cleanup.push(async () => { socket.destroy() })
    await once(socket, 'connect')
    const received = once(socket, 'data') as Promise<[Buffer]>
    socket.write([
      'GET / HTTP/1.1', `Host: ${host}`, 'Connection: Upgrade', 'Upgrade: websocket',
      'Sec-WebSocket-Version: 13', 'Sec-WebSocket-Key: MDEyMzQ1Njc4OTAxMjM0NQ==',
      ...headers, '', '',
    ].join('\r\n'))
    const [response] = await received
    return { socket, response: response.toString() }
  }

  function trusted(ip = '192.0.2.1') {
    return [`X-Peerborne-Origin: ${secret}`, `CF-Connecting-IP: ${ip}`]
  }

  it('keeps health checks available and returns the public peer ID', async () => {
    const { gateway } = await fixture()
    const response = await fetch(`http://127.0.0.1:${gateway.port}/readyz`)
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ status: 'ready', peerId: 'public-test-peer' })
    const bypass = await fetch(`http://127.0.0.1:${gateway.port}/`)
    expect(bypass.status).toBe(403)
  })

  it('rejects a forged client IP without the Cloudflare origin credential', async () => {
    const { gateway } = await fixture()
    const { response } = await upgrade(gateway.port, ['CF-Connecting-IP: 192.0.2.1'])
    expect(response).toContain('403')
  })

  it('rejects duplicate credential and client-IP headers', async () => {
    const { gateway } = await fixture()
    expect((await upgrade(gateway.port, [...trusted(), `X-Peerborne-Origin: ${secret}`])).response).toContain('403')
    expect((await upgrade(gateway.port, [...trusted(), 'CF-Connecting-IP: 192.0.2.2'])).response).toContain('400')
  })

  it('rejects invalid client IPs after authenticating the proxy', async () => {
    const { gateway } = await fixture()
    expect((await upgrade(gateway.port, trusted('not-an-ip'))).response).toContain('400')
  })

  it('preserves opaque bytes and strips the credential before forwarding', async () => {
    const fixtureData = await fixture()
    const { socket, response } = await upgrade(fixtureData.gateway.port, trusted())
    expect(response).toContain('101 Switching Protocols')
    expect(fixtureData.headers()['x-peerborne-origin']).toBeUndefined()
    expect(fixtureData.headers()['cf-connecting-ip']).toBeUndefined()
    const received = once(socket, 'data') as Promise<[Buffer]>
    const payload = Buffer.from([0, 255, 17, 34, 0, 128])
    socket.write(payload)
    expect((await received)[0]).toEqual(payload)
  })

  it('rejects repeated connection attempts from one IP', async () => {
    const { gateway } = await fixture({ ...demoGatewayLimits, attemptsPerIpPerTenSeconds: 1 })
    const first = await upgrade(gateway.port, trusted())
    expect(first.response).toContain('101')
    first.socket.destroy()
    expect((await upgrade(gateway.port, trusted())).response).toContain('429')
  })

  it('closes active sessions when their lifetime expires', async () => {
    const { gateway } = await fixture({ ...demoGatewayLimits, sessionMs: 500 })
    const { socket } = await upgrade(gateway.port, trusted())
    await once(socket, 'close')
  })

  it('closes all sessions and rejects new ones after exhausting the global byte budget', async () => {
    const { gateway } = await fixture({ ...demoGatewayLimits, totalBytes: 2048 })
    const first = await upgrade(gateway.port, trusted())
    const second = await upgrade(gateway.port, trusted('192.0.2.2'))
    const closed = Promise.all([once(first.socket, 'close'), once(second.socket, 'close')])
    first.socket.write(Buffer.alloc(2048))
    await closed
    expect((await upgrade(gateway.port, trusted('192.0.2.3'))).response).toContain('503')
    expect((await fetch(`http://127.0.0.1:${gateway.port}/readyz`)).status).toBe(200)
  })

  it('fails closed when the origin credential is missing or weak', async () => {
    const { config } = await fixture()
    await expect(startRelayGateway({ ...config, secret: '' })).rejects.toThrow('RELAY_GATEWAY_SECRET')
  })
})
