import { randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  unlink,
} from 'node:fs/promises'
import { dirname } from 'node:path'
import {
  generateKeyPair,
  privateKeyFromProtobuf,
  privateKeyToProtobuf,
} from '@libp2p/crypto/keys'
import type { PrivateKey } from '@libp2p/interface'

const inFlight = new Map<string, Promise<PrivateKey>>()

async function readIdentity(filePath: string): Promise<PrivateKey> {
  const stats = await lstat(filePath)
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new Error(`Relay identity path is not a regular file: ${filePath}`)
  }

  const serialized = await readFile(filePath)
  let key: PrivateKey
  try {
    key = privateKeyFromProtobuf(serialized)
  } catch {
    throw new Error(`Relay identity file is invalid: ${filePath}`)
  }
  await chmod(filePath, 0o600)
  return key
}

async function createOrReadIdentity(filePath: string): Promise<PrivateKey> {
  try {
    return await readIdentity(filePath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error
    }
  }

  await mkdir(dirname(filePath), { recursive: true, mode: 0o700 })
  const key = await generateKeyPair('Ed25519')
  const serialized = privateKeyToProtobuf(key)
  const temporaryPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`
  const handle = await open(
    temporaryPath,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
    0o600,
  )
  try {
    await handle.writeFile(serialized)
    await handle.sync()
  } finally {
    await handle.close()
  }

  try {
    await link(temporaryPath, filePath)
    await chmod(filePath, 0o600)
    const directory = await open(dirname(filePath), constants.O_RDONLY)
    try {
      await directory.sync()
    } finally {
      await directory.close()
    }
    return key
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
      throw error
    }
    return await readIdentity(filePath)
  } finally {
    await unlink(temporaryPath).catch(() => undefined)
  }
}

/** Load a stable libp2p identity, creating it with mode 0600 when absent. */
export function loadOrCreateRelayIdentity(filePath: string): Promise<PrivateKey> {
  const existing = inFlight.get(filePath)
  if (existing) {
    return existing
  }

  const operation = createOrReadIdentity(filePath).finally(() => {
    if (inFlight.get(filePath) === operation) {
      inFlight.delete(filePath)
    }
  })
  inFlight.set(filePath, operation)
  return operation
}
