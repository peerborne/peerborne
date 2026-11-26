import type { PrivateKey } from '@libp2p/interface';

/** The subset of the Web Locks API used to claim a persisted PeerId. */
export interface PeerIdentityLocks {
  request(
    name: string,
    options: { ifAvailable: true },
    callback: (lock: unknown) => Promise<void>,
  ): Promise<unknown>;
}

/**
 * The libp2p identity of one running instance. Without a `privateKey`, the
 * instance holds the datastore's persisted identity until `release()`.
 */
export interface PeerIdentityLease {
  readonly privateKey?: PrivateKey;
  release(): void;
}

const heldDatastores = new WeakSet<object>();

async function ephemeral(): Promise<PeerIdentityLease> {
  // Loaded on demand so Jest suites that import core source can omit it.
  const { generateKeyPair } = await import('@libp2p/crypto/keys');
  return {
    privateKey: await generateKeyPair('Ed25519'),
    release: () => undefined,
  };
}

function lockName(datastore: object): string | undefined {
  const location = (datastore as { location?: unknown }).location;
  return typeof location === 'string'
    ? `peerborne-peer-identity:${location}`
    : undefined;
}

function requestLock(
  locks: PeerIdentityLocks,
  name: string,
): Promise<(() => void) | undefined> {
  return new Promise((resolve) => {
    let release: () => void = () => undefined;
    const held = new Promise<void>((done) => {
      release = done;
    });
    locks
      .request(name, { ifAvailable: true }, async (lock) => {
        if (!lock) {
          resolve(undefined);
          return;
        }
        resolve(release);
        await held;
      })
      .catch(() => resolve(undefined));
  });
}

/**
 * Claim the persisted libp2p identity of `datastore` for one running
 * instance, or return a fresh key when another instance holds it.
 *
 * A named IndexedDB datastore is shared by every tab of an origin, so it is
 * claimed with a Web Lock named after the database, and gets a fresh key
 * where Web Locks are unavailable. Any other datastore is claimed within this
 * JavaScript realm.
 */
export async function acquirePeerIdentity(
  datastore: object | undefined,
  locks: PeerIdentityLocks | null = globalThis.navigator?.locks ?? null,
): Promise<PeerIdentityLease> {
  if (datastore === undefined) return ephemeral();
  const name = lockName(datastore);
  if (name === undefined) {
    if (heldDatastores.has(datastore)) return ephemeral();
    heldDatastores.add(datastore);
    let held = true;
    return {
      release: () => {
        if (!held) return;
        held = false;
        heldDatastores.delete(datastore);
      },
    };
  }
  const release = locks ? await requestLock(locks, name) : undefined;
  return release ? { release } : ephemeral();
}
