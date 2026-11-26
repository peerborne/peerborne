/** @type {Record<string, Array<{ edges: string[], nodes?: string[], note: string }>>} */
export const flowRoutes = {
  sync: [
    {
      edges: ['app-admission', 'admission-replica', 'replica-app'],
      note: 'The SDK applies the local CRDT edit. The editor can show it before persistence or publication finishes.',
    },
    {
      edges: ['admission-crypto', 'crypto-storage'],
      note: 'The sender stores an encrypted change block by CID and seals a separate sync envelope.',
    },
    {
      edges: ['crypto-gossip', 'gossip-peer', 'storage-blocks', 'blocks-peer'],
      note: 'GossipSub announces the update. Peers fetch referenced blocks through Helia as needed.',
    },
    {
      edges: [
        '-gossip-peer',
        '-crypto-gossip',
        '-admission-crypto',
        'admission-replica',
      ],
      note: 'The receiver opens the envelope, checks current writer authorization when signing is enabled, and merges the admitted history.',
    },
  ],
  membership: [
    {
      edges: ['trust-admission'],
      note: 'The application authenticates the invitation issuer and keeps the receiving identity’s private keys on its device.',
    },
    {
      edges: ['admission-crypto', 'crypto-streams', 'streams-peer'],
      note: 'An invitation binds the offer and request to the intended recipient. The Welcome is sealed for that recipient.',
    },
    {
      edges: [
        '-streams-peer',
        '-crypto-streams',
        '-admission-crypto',
        'trust-admission',
      ],
      note: 'The receiver authenticates the writer and classifies the signed PathUpdate by generation and digest.',
    },
    {
      edges: ['admission-crypto'],
      nodes: ['peer'],
      note: 'An accepted next-epoch update can install new key material. Agreement across every replica’s ACL, load, and restart path remains open.',
    },
  ],
  coordinated: [
    {
      edges: ['trust-admission'],
      nodes: ['crypto'],
      note: 'Pinned genesis binds the signed authority history to the configured group-security provider.',
    },
    {
      edges: ['app-admission', '-admission-crypto'],
      nodes: ['replica'],
      note: 'Admission binds the signed change to its document and author’s history, then checks the CRDT targets against granted field scopes.',
    },
    {
      edges: ['admission-replica'],
      note: 'The CRDT stages changes in a detached session. The commit gate rechecks live context and authorization.',
    },
    {
      edges: ['replica-storage'],
      note: 'When journaling is enabled, accepted state and configured outbound publication records are retained for recovery.',
    },
  ],
  loading: [
    {
      edges: ['trust-admission'],
      note: 'Initial loading starts from independently trusted writer keys and security commitments.',
    },
    {
      edges: ['-streams-peer', '-crypto-streams', '-admission-crypto'],
      note: 'Peers return signed V4 responses over libp2p request streams. Quorum counts each eligible signing authority once.',
    },
    {
      edges: [
        '-blocks-peer',
        '-storage-blocks',
        '-crypto-storage',
        '-admission-crypto',
      ],
      note: 'The loader checks the complete response manifest against the agreed digest and fetches missing blocks by CID.',
    },
    {
      edges: ['admission-replica', 'replica-app'],
      note: 'The selected CRDT adapter applies the admitted history and exposes the local replica.',
    },
  ],
  'beekem-restart': [
    {
      edges: ['replica-storage'],
      nodes: ['crypto'],
      note: 'The SDK exports a signed checkpoint, sealed under an application AES-GCM key. It holds document keys; the application stores it and never transmits it.',
    },
    {
      edges: [],
      nodes: ['trust'],
      note: 'For opt-in rollback protection, keep the current checkpoint commitment in storage independent of the checkpoint.',
    },
    {
      edges: ['-crypto-storage', '-admission-crypto', 'trust-admission'],
      note: 'Restore checks the checkpoint signature and requires the exact expected commitment when a pin is supplied.',
    },
    {
      edges: ['admission-replica', 'replica-app'],
      note: 'A fresh document can continue from the restored state and epoch. Revocation continuity across replicas remains open.',
    },
  ],
  restart: [
    {
      edges: ['trust-admission'],
      note: 'Startup needs the retained device key and the application’s pinned genesis.',
    },
    {
      edges: ['-crypto-storage', 'trust-admission'],
      note: 'Journal recovery compares the authenticated checkpoint with the independent rollback anchor.',
    },
    {
      edges: [
        '-crypto-storage',
        '-admission-crypto',
        'admission-replica',
        'replica-app',
      ],
      note: 'Startup replays admissible entries and checks the anchor again before exposing recovered state.',
    },
    {
      edges: ['-crypto-storage'],
      note: 'If configured, publication resumes from retained outbound records. Delivery depends on the transport.',
    },
  ],
  operations: [
    {
      edges: ['replica-storage'],
      note: 'Cleanup rechecks a live, unpinned lease before deleting an eligible block.',
    },
    {
      edges: [
        'admission-replica',
        'crypto-storage',
        'gossip-peer',
        'blocks-peer',
      ],
      note: 'Measure CRDT work, cryptography, storage, and transport separately for the chosen browser workload.',
    },
    {
      edges: [],
      note: 'CI verifies contracts and counterexample controls. Release validation audits packed dependencies outside this replica topology.',
    },
  ],
};
