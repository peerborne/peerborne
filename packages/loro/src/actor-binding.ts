import { LoroDoc, decodeImportBlobMeta } from 'loro-crdt';
import {
  CRDTActorBindingError,
  attachCRDTActorPrefix,
  detachCRDTActorPrefix,
  type CRDTActorBinding,
} from '@peerborne/core';

const PEER_ID_RANGE = (1n << 64n) - 1n;

/**
 * Peers with operations in a blob of exactly `mode`. Shallow snapshots,
 * state-only exports and outdated encodings carry state whose operations
 * their version range does not list, so they are refused.
 */
function importedPeers(
  bytes: Uint8Array,
  mode: 'update' | 'snapshot',
): ReadonlySet<string> {
  const meta = decodeImportBlobMeta(bytes, true);
  if (meta.mode !== mode)
    throw new CRDTActorBindingError(`Loro ${mode} required, not ${meta.mode}`);
  const start = meta.partialStartVersionVector.toJSON();
  const peers = new Set<string>();
  for (const [peer, end] of meta.partialEndVersionVector.toJSON())
    if (end > (start.get(peer) ?? 0)) peers.add(peer);
  return peers;
}

/** Peer IDs are 64-bit values derived from the signer and an instance nonce. */
export const loroActorBinding: CRDTActorBinding<LoroDoc, Uint8Array> = {
  actorFromDigest(digest) {
    let peer = 0n;
    for (let index = 0; index < 8; index++)
      peer = (peer << 8n) | BigInt(digest[index]!);
    return (peer % PEER_ID_RANGE).toString();
  },
  localActor: (document) => document.peerIdStr,
  setLocalActor(document, actor) {
    document.setPeerId(BigInt(actor));
    return document;
  },
  changeActors: (changes) => importedPeers(changes, 'update'),
  stateActors: (state) => importedPeers(state, 'snapshot'),
  attach: attachCRDTActorPrefix,
  detach: detachCRDTActorPrefix,
};
