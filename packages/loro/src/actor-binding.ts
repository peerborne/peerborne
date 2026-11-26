import { LoroDoc, decodeImportBlobMeta } from 'loro-crdt';
import {
  attachCRDTActorPrefix,
  detachCRDTActorPrefix,
  type CRDTActorBinding,
} from '@peerborne/core';

const PEER_ID_RANGE = (1n << 64n) - 1n;

function importedPeers(bytes: Uint8Array): ReadonlySet<string> {
  const meta = decodeImportBlobMeta(bytes, true);
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
  changeActors: importedPeers,
  stateActors: importedPeers,
  attach: attachCRDTActorPrefix,
  detach: detachCRDTActorPrefix,
};
