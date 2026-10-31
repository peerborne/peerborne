import { mkdir } from 'node:fs/promises'
import { demoGatewayLimits } from './gateway-limits.js'
import { prepareRenderIdentity } from './render-identity.js'
import { startRelayGateway } from './relay-gateway.js'

async function main() {
  const port = Number(process.env.PORT ?? '10000')
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || [9000, 9001, 9002].includes(port)) {
    throw new Error('PORT must be an unreserved TCP port between 1024 and 65535')
  }
  const secret = process.env.RELAY_GATEWAY_SECRET ?? ''
  if (!/^[A-Za-z0-9+/=_-]{32,128}$/.test(secret)) {
    throw new Error('RELAY_GATEWAY_SECRET must contain at least 32 random ASCII characters')
  }
  await mkdir('/shared', { recursive: true, mode: 0o700 })
  await prepareRenderIdentity(process.env.RELAY_IDENTITY_SEED, '/shared/relay-identity.key')
  process.env.RELAY_IDENTITY_KEY_PATH = '/shared/relay-identity.key'
  process.env.WS_LISTEN = '/ip4/127.0.0.1/tcp/9001/ws'
  process.env.TCP_LISTEN = '/ip4/127.0.0.1/tcp/9002'
  process.env.ENABLE_IPV6 = '0'
  process.env.READINESS_PORT = '9000'
  await import('./index.js')
  const gateway = await startRelayGateway({
    port,
    secret,
    publicHost: 'relay.peerborne.io',
    relayPort: 9001,
    readinessPort: 9000,
    limits: demoGatewayLimits,
  })
  process.once('SIGTERM', () => void gateway.close())
  process.once('SIGINT', () => void gateway.close())
  console.log('Render gateway listening with bounded demo traffic', { port })
}

main().catch(() => {
  console.error('Render relay startup failed; check seed, gateway secret, and port configuration')
  process.exit(1)
})
