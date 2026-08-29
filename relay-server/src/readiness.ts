import { once } from 'node:events'
import { createServer, type Server } from 'node:http'

export interface ReadinessServer {
  readonly port: number
  markReady(peerId: string): void
  markNotReady(): void
  close(): Promise<void>
}

function sendJson(
  response: import('node:http').ServerResponse,
  statusCode: number,
  body: Record<string, string>,
  includeBody: boolean,
): void {
  const serialized = JSON.stringify(body)
  response.writeHead(statusCode, {
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(serialized),
    'content-type': 'application/json; charset=utf-8',
  })
  response.end(includeBody ? serialized : undefined)
}

export async function startReadinessServer(
  port: number,
  host = '0.0.0.0',
): Promise<ReadinessServer> {
  let readyPeerId: string | undefined
  const server: Server = createServer((request, response) => {
    const includeBody = request.method !== 'HEAD'
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.setHeader('allow', 'GET, HEAD')
      sendJson(response, 405, { status: 'method-not-allowed' }, includeBody)
      return
    }
    if (request.url === '/livez') {
      sendJson(response, 200, { status: 'alive' }, includeBody)
      return
    }
    if (request.url === '/readyz') {
      if (readyPeerId) {
        sendJson(
          response,
          200,
          { status: 'ready', peerId: readyPeerId },
          includeBody,
        )
      } else {
        sendJson(response, 503, { status: 'not-ready' }, includeBody)
      }
      return
    }
    sendJson(response, 404, { status: 'not-found' }, includeBody)
  })

  server.listen(port, host)
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') {
    server.close()
    throw new Error('Readiness server did not bind a TCP port')
  }

  return {
    port: address.port,
    markReady(peerId: string): void {
      if (peerId.length === 0) {
        throw new Error('Readiness peer ID cannot be empty')
      }
      readyPeerId = peerId
    },
    markNotReady(): void {
      readyPeerId = undefined
    },
    async close(): Promise<void> {
      if (!server.listening) {
        return
      }
      const closed = once(server, 'close')
      server.close()
      await closed
    },
  }
}
