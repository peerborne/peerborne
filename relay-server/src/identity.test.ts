import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { loadOrCreateRelayIdentity } from './identity.js'

describe('loadOrCreateRelayIdentity', () => {
  const temporaryDirectories: string[] = []

  async function identityPath(): Promise<string> {
    const directory = await mkdtemp(join(tmpdir(), 'peerborne-relay-identity-'))
    temporaryDirectories.push(directory)
    return join(directory, 'relay.key')
  }

  afterEach(async () => {
    await Promise.all(
      temporaryDirectories.splice(0).map((directory) =>
        rm(directory, { recursive: true, force: true }),
      ),
    )
  })

  it('persists the same peer ID across independent loads', async () => {
    const filePath = await identityPath()
    const first = await loadOrCreateRelayIdentity(filePath)
    const second = await loadOrCreateRelayIdentity(filePath)

    expect(peerIdFromPrivateKey(second).toString()).toBe(
      peerIdFromPrivateKey(first).toString(),
    )
    expect((await stat(filePath)).mode & 0o777).toBe(0o600)
  })

  it('coalesces concurrent creation onto one persisted peer ID', async () => {
    const filePath = await identityPath()
    const keys = await Promise.all([
      loadOrCreateRelayIdentity(filePath),
      loadOrCreateRelayIdentity(filePath),
      loadOrCreateRelayIdentity(filePath),
    ])
    const peerIds = keys.map((key) => peerIdFromPrivateKey(key).toString())

    expect(new Set(peerIds).size).toBe(1)
  })

  it('fails closed without replacing a malformed identity file', async () => {
    const filePath = await identityPath()
    const malformed = Buffer.from('not-a-libp2p-private-key')
    await writeFile(filePath, malformed, { mode: 0o600 })

    await expect(loadOrCreateRelayIdentity(filePath)).rejects.toThrow(
      `Relay identity file is invalid: ${filePath}`,
    )
    expect(await readFile(filePath)).toEqual(malformed)
  })
})
