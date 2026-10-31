import { writeFile } from 'node:fs/promises'
import { generateKeyPairFromSeed, privateKeyToProtobuf } from '@libp2p/crypto/keys'
import { loadOrCreateRelayIdentity } from './identity.js'

export async function prepareRenderIdentity(seed: string | undefined, filePath: string): Promise<void> {
  if (!seed || !/^[A-Za-z0-9+/]{43}=$/.test(seed)) {
    throw new Error('RELAY_IDENTITY_SEED must be a canonical base64-encoded 32-byte random seed')
  }
  const bytes = Buffer.from(seed, 'base64')
  if (bytes.length !== 32 || bytes.toString('base64') !== seed) {
    throw new Error('RELAY_IDENTITY_SEED must be a canonical base64-encoded 32-byte random seed')
  }
  const key = await generateKeyPairFromSeed('Ed25519', bytes)
  const serialized = privateKeyToProtobuf(key)
  try {
    await writeFile(filePath, serialized, { mode: 0o600, flag: 'wx' })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
    const existing = await loadOrCreateRelayIdentity(filePath)
    if (!Buffer.from(privateKeyToProtobuf(existing)).equals(Buffer.from(serialized))) {
      throw new Error('Configured seed does not match the existing relay identity')
    }
  }
}
