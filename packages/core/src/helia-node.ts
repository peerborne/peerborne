import { createHelia, createHeliaLight } from 'helia';
import { withBitswap } from '@helia/bitswap';
import { withLibp2pLight } from '@helia/libp2p';
import type { HeliaWithLibp2p } from '@helia/libp2p';
import * as dagCbor from '@ipld/dag-cbor';
import * as dagJson from '@ipld/dag-json';
import type { ServiceMap } from '@libp2p/interface';
// libp2p v3 retired `@libp2p/pubsub`, so use the concrete service type.
import type { GossipSub } from '@libp2p/gossipsub';
import { isLibp2p } from 'libp2p';
import * as json from 'multiformats/codecs/json';
import { sha512 } from 'multiformats/hashes/sha2';
import type { PeerborneConfig } from './peerborne-config.js';
import { acquirePeerIdentity } from './peer-identity.js';
import type { PeerIdentityLease } from './peer-identity.js';
import { closeHeliaStores, openHeliaStores } from './store-lifecycle.js';
import type { OpenableStore } from './store-lifecycle.js';

export type PeerborneHeliaNode = HeliaWithLibp2p<
  ServiceMap & { pubsub: GossipSub }
>;

interface StartedHeliaNode {
  heliaNode: PeerborneHeliaNode;
  openedStores: OpenableStore[];
}

export async function createAndStartHeliaNode(
  heliaInit?: NonNullable<PeerborneConfig['helia']>,
): Promise<StartedHeliaNode> {
  const openedStores = heliaInit
    ? await openHeliaStores(heliaInit.datastore, heliaInit.blockstore)
    : [];
  let heliaNode: PeerborneHeliaNode | undefined;
  let identity: PeerIdentityLease | undefined;

  try {
    const {
      libp2p: libp2pInit,
      bitswap: configuredBitswap,
      ...heliaOptions
    } = heliaInit ?? {};
    // Browser peers usually reach each other only through Circuit Relay, so
    // block fetches must be allowed on relayed (limited) connections.
    const bitswapInit = { runOnLimitedConnections: true, ...configuredBitswap };
    if (isLibp2p(libp2pInit)) {
      throw new Error(
        'Helia 7 requires libp2p creation options; preconfigured libp2p nodes are not supported',
      );
    }
    if (libp2pInit?.privateKey === undefined) {
      identity = await acquirePeerIdentity(heliaOptions.datastore);
    }
    const privateKey = libp2pInit?.privateKey ?? identity?.privateKey;
    heliaNode = (
      libp2pInit
        ? withBitswap(
            withLibp2pLight(
              // createHeliaLight always supplies dag-pb/raw and sha256/identity.
              // Add createHelia's extra codecs and hasher here while retaining
              // Peerborne's custom libp2p topology.
              createHeliaLight({
                ...heliaOptions,
                codecs: [
                  dagCbor,
                  dagJson,
                  json,
                  ...(heliaOptions.codecs ?? []),
                ],
                hashers: [sha512, ...(heliaOptions.hashers ?? [])],
              }),
              { ...libp2pInit, privateKey },
            ),
            bitswapInit,
          )
        : createHelia({
            ...heliaOptions,
            ...(privateKey && { libp2p: { privateKey } }),
            bitswap: bitswapInit,
          })
    ) as PeerborneHeliaNode;
    if (identity) {
      heliaNode.addMixin({
        name: 'peerborne-peer-identity',
        stop: identity.release,
      });
    }
    await heliaNode.start();
    if (!heliaNode.libp2p.services.pubsub) {
      throw new Error(
        'Helia node must be initialized with a pubsub service (e.g., gossipsub)',
      );
    }

    return { heliaNode, openedStores };
  } catch (error) {
    try {
      await heliaNode?.stop();
    } catch {
      // Best-effort cleanup preserves the startup error.
    }
    identity?.release();
    await closeHeliaStores(openedStores);
    throw error;
  }
}
