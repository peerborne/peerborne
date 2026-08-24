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
import { closeLegacyHeliaStores, openLegacyHeliaStores } from './store-lifecycle.js';
import type { OpenableStore } from './store-lifecycle.js';

export type PeerborneHeliaNode = HeliaWithLibp2p<
  ServiceMap & { pubsub: GossipSub }
>;

interface StartedHeliaNode {
  heliaNode: PeerborneHeliaNode;
  openedLegacyStores: OpenableStore[];
}

export async function createAndStartHeliaNode(
  heliaInit?: NonNullable<PeerborneConfig['helia']>,
): Promise<StartedHeliaNode> {
  const openedLegacyStores = heliaInit
    ? await openLegacyHeliaStores(heliaInit.datastore, heliaInit.blockstore)
    : [];
  let heliaNode: PeerborneHeliaNode | undefined;

  try {
    const {
      libp2p: libp2pInit,
      bitswap: bitswapInit,
      ...heliaOptions
    } = heliaInit ?? {};
    if (isLibp2p(libp2pInit)) {
      throw new Error(
        'Helia 7 requires libp2p creation options; preconfigured libp2p nodes are not supported',
      );
    }
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
              libp2pInit,
            ),
            bitswapInit,
          )
        : createHelia({ ...heliaOptions, bitswap: bitswapInit })
    ) as PeerborneHeliaNode;
    await heliaNode.start();
    if (!heliaNode.libp2p.services.pubsub) {
      throw new Error(
        'Helia node must be initialized with a pubsub service (e.g., gossipsub)',
      );
    }

    return { heliaNode, openedLegacyStores };
  } catch (error) {
    try {
      await heliaNode?.stop();
    } catch {
      // Best-effort cleanup preserves the startup error.
    }
    await closeLegacyHeliaStores(openedLegacyStores);
    throw error;
  }
}
