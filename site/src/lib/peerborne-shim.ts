// Minimal re-export of the light @peerborne/core modules needed in the
// browser bundle. The package's full barrel pulls in libp2p/Helia (and their
// ESM-only dependencies), which the landing page doesn't need — the sync demo
// only exercises the CRDT serialization and crypto providers. The site's Vite
// config aliases bare `@peerborne/core` imports to this module.
export {
  describeValue,
  serializeChangeNodeForJSON,
  deserializeChangeNodeFromJSON,
  JSONSerializer,
  validateChangeBlockMetadata,
  LRUCache,
  TIPS_HASH_LENGTH,
  SubtleCrypto,
} from '@peerborne/core/browser-primitives';
