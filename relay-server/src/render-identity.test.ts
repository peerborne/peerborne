import { mkdtemp, readFile, rm, stat, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { privateKeyFromProtobuf } from '@libp2p/crypto/keys'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { prepareRenderIdentity } from './render-identity.js'

describe('Render relay identity', () => {
  const directories: string[] = []
  async function keyPath() {
    const directory = await mkdtemp(join(tmpdir(), 'peerborne-render-identity-'))
    directories.push(directory)
    return join(directory, 'relay.key')
  }
  afterEach(async () => {
    await Promise.all(directories.splice(0).map(dir => rm(dir, { recursive: true, force: true })))
  })

  it('reconstructs the same peer ID after the ephemeral filesystem is replaced', async () => {
    const seed = randomBytes(32).toString('base64')
    const paths = [await keyPath(), await keyPath()]
    for (const path of paths) await prepareRenderIdentity(seed, path)
    const identities = await Promise.all(paths.map(async path =>
      peerIdFromPrivateKey(privateKeyFromProtobuf(await readFile(path))).toString(),
    ))
    expect(identities[0]).toBe(identities[1])
    expect((await stat(paths[0])).mode & 0o777).toBe(0o600)
    await prepareRenderIdentity(seed, paths[0])
  })

  it('fails closed instead of silently rotating an existing identity', async () => {
    const path = await keyPath()
    await prepareRenderIdentity(randomBytes(32).toString('base64'), path)
    const before = await readFile(path)
    await expect(prepareRenderIdentity(randomBytes(32).toString('base64'), path))
      .rejects.toThrow('Configured seed does not match the existing relay identity')
    expect(await readFile(path)).toEqual(before)
  })

  it('rejects missing, malformed, and noncanonical seeds without disclosing them', async () => {
    const path = await keyPath()
    for (const seed of [undefined, '', 'not-a-seed', randomBytes(31).toString('base64'), 'A'.repeat(42) + 'B=']) {
      await expect(prepareRenderIdentity(seed, path)).rejects.toThrow(
        'RELAY_IDENTITY_SEED must be a canonical base64-encoded 32-byte random seed',
      )
    }
  })

  it('rejects symbolic links instead of replacing another file', async () => {
    const path = await keyPath()
    const seed = randomBytes(32).toString('base64')
    await prepareRenderIdentity(seed, path)
    const link = join(directories[0], 'linked.key')
    await symlink(path, link)
    await expect(prepareRenderIdentity(seed, link)).rejects.toThrow('not a regular file')
  })
})
