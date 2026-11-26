export const evidenceLabels = {
  proved: 'Proved contract',
  tested: 'Runtime evidence',
  assumed: 'Trust assumption',
  open: 'Open guarantee',
};

export const claims = [
  {
    id: 'trust',
    label: 'Pinned identity',
    title: 'Provision a trusted identity',
    rule: 'Keep signing and KEM private keys on the device. Pin the issuer or authority through an authenticated channel before accepting state.',
    limit:
      'The application owns key custody and the initial trust binding. A libp2p Peer ID carries no document role.',
    source: 'docs/coordinated-document-security.md',
    state: 'assumed',
  },
  {
    id: 'legacy-content',
    label: 'Sync integrity',
    title: 'Encrypt and authorize BeeKEM sync',
    rule: 'Store serialized changes as encrypted CID blocks. Publish a separate encrypted envelope and check its signature against current local writers when signing is enabled.',
    limit:
      'Signing defaults on, with a legacy opt-out. A local edit may become visible before persistence or publication succeeds.',
    source: 'packages/core/src/peerborne-document.ts',
    tests: ['packages/core/src/peerborne-document-sync-context.test.ts'],
  },
  {
    id: 'gossip-receive',
    label: 'Inbound limits',
    title: 'Reserve capacity before handling a gossip frame',
    rule: 'Share capacity between the ordinary listener and topic validator. Charge a work item and its ciphertext bytes before copying, decrypting, decoding, or queuing it. Keep the most recently arrived skipped frame of each of up to eight senders and process it when a credit frees.',
    checked:
      'The budget policy preserves count and byte bounds across finite histories. Runtime tests check the shared budgets, cutoff on close, and batches of up to four signature checks per verification.',
    limit:
      'Limits account for admitted frames; kept frames, bounded by sender count and the local byte budget, are outside the credits. Native heap and wall time need measurement. Other skipped frames rely on the retained frame carrying their changes, or on later synchronization.',
    proof: [
      'packages/core/src/policy/document-admission.ts',
      'documentAdmission_all_histories',
    ],
    source: 'packages/core/src/gossip-receive-admission.ts',
    tests: [
      'packages/core/src/gossip-receive-admission-properties.test.ts',
      'packages/core/src/gossip-receive-admission.test.ts',
      'packages/core/src/peerborne-document-gossip-admission.test.ts',
    ],
  },
  {
    id: 'invitation',
    label: 'Invitation binding',
    title: 'Keep an invitation bound to its recipient',
    rule: 'Authenticate the offer, request and acceptance. Bind a consumed acceptance to its original request and retire replay entries only after expiry.',
    checked:
      'Accepted bindings survive every finite ledger history until expiration. Expired offers cannot be revived.',
    limit:
      'The model starts with authenticated requests and a process-local ledger. Authenticated bearer-link delivery and durable replay protection need separate evidence.',
    proof: [
      'packages/core/src/policy/replay-admission.ts',
      'invitationReplayHistory_all_histories',
    ],
    tests: ['packages/core/src/invitation-replay-properties.test.ts'],
  },
  {
    id: 'beekem-generation',
    label: 'Epoch order',
    title: 'Classify a BeeKEM transition',
    rule: 'Advance only one generation. Ignore exact redelivery. For a same-generation conflict, check its predecessor and public tree commitment. Grow the tree by at most one leaf.',
    checked:
      'For validated counters and a supplied digest match, the classifier recognizes exactly stale, duplicate, fork, next and gap. It enforces the configured leaf capacity.',
    limit:
      'Sender authentication and secret distribution need separate evidence.',
    proof: [
      'packages/core/src/policy/beekem-transition.ts',
      'classifyBeeKEMGeneration_ensures',
      'isAppendOnlyLeafCount_ensures',
    ],
    tests: [
      'packages/core/src/beekem/transactional-state.test.ts',
      'packages/core/src/beekem/off-path-snapshot.test.ts',
    ],
  },
  {
    id: 'beekem-continuation',
    label: 'Pinned continuation',
    title: 'Keep a BeeKEM epoch current through restore',
    rule: 'Commit a signed PathUpdate only while its parent and writer set are current. An application may pin the exported checkpoint’s SHA-256 commitment in independent storage and supply it on restart.',
    checked:
      'The guard admits the exact next generation only with current parent and writer inputs. A blanked leaf slot cannot be reused. Finite histories preserve both guarantees across restart when the authenticated checkpoint matches an independently trusted current pin.',
    limit:
      'The application must protect checkpoint contents and keep the independent pin fresh. Peerborne Note and the password-manager example omit the SDK pin. Browser-app rollback protection and group-wide exclusion remain open.',
    proof: [
      'packages/core/src/policy/beekem-transition.ts',
      'canCommitBeeKEMPathUpdate_ensures',
      'checkpointCommitmentPermitsRestore_ensures',
      'beekemContinuation_all_histories',
      'beekemContinuation_domain',
      'beeKEMLeafTransitionAllowed_ensures',
      'beekemLeaf_nonReactivation',
      'beekemLeaf_domain',
    ],
    source: 'packages/core/src/document-checkpoint.ts',
    tests: [
      'examples/password-manager/src/document-checkpoint.test.ts',
      'packages/core/src/beekem/local-state.test.ts',
      'packages/core/src/peerborne-document-beekem-current.test.ts',
    ],
  },
  {
    id: 'beekem-fork',
    label: 'Competing epochs',
    title: 'Stop a replica that observes competing BeeKEM successors',
    rule: 'After checking the current writers, stop the document on a signed claim at the current generation for the last accepted predecessor and a different validated public tree.',
    checked:
      'The competing-epoch predicate requires all three conditions. Runtime properties exercise independently generated successors, signed competing removals, and a restored predecessor commitment.',
    limit:
      'Each document instance stops on observed evidence. The signed public tree alone gives no guarantee that the competing private epoch is usable. Automatic branch selection and old-document convergence remain open.',
    proof: [
      'packages/core/src/policy/beekem-transition.ts',
      'isCompetingBeeKEMEpoch_ensures',
    ],
    source: 'packages/core/src/peerborne-document.ts',
    tests: [
      'packages/core/src/beekem/local-state.test.ts',
      'examples/password-manager/src/document-checkpoint.test.ts',
    ],
  },
  {
    id: 'beekem-durable-fork',
    label: 'Durable quarantine',
    title: 'Keep a stopped BeeKEM document fenced across restart',
    rule: 'When configured, persist a session lease before exposing the document. Quarantine after an authenticated fork. A remaining lease blocks restart if the write is interrupted.',
    checked:
      'Finite histories preserve a quarantined record and prevent release by a stale or foreign lease. Runtime tests exercise restart after acknowledged and interrupted writes.',
    limit:
      'The application provides independent durable storage and an exact atomic compare-and-swap. An unclean shutdown can require explicit recovery onto a fresh path.',
    proof: [
      'packages/core/src/policy/beekem-fork-anchor.ts',
      'canAdvanceBeeKEMForkAnchor_ensures',
      'beeKEMForkAnchor_allHistories',
      'beeKEMForkAnchor_nonOwnerHistory',
    ],
    source: 'packages/core/src/beekem-fork-quarantine.ts',
    tests: [
      'packages/core/src/beekem-fork-quarantine-properties.test.ts',
      'packages/core/src/beekem-fork-quarantine-process.test.ts',
      'examples/password-manager/src/document-checkpoint.test.ts',
    ],
  },
  {
    id: 'beekem-replacement',
    label: 'Opt-in replacement',
    title: 'Activate an approved replacement with fresh keys',
    rule: 'Bind approval to the current logical locator, replacement identity and selected content. Stage the fresh document privately, then advance the application locator atomically.',
    checked:
      'Modeled activation histories permit at most one successor for the pinned base. An exact retry after activation confirms the same receipt.',
    limit:
      'The application owns the recovery authority, private staging, recipient enrollment and independently protected atomic locator. This flow creates a new document path.',
    proof: [
      'packages/core/src/policy/document-recovery.ts',
      'classifyDocumentRecovery_ensures',
      'canPublishDocumentRecovery_ensures',
      'documentRecovery_all_histories',
    ],
    tests: [
      'packages/core/src/document-recovery-properties.test.ts',
      'examples/password-manager/src/document-checkpoint.test.ts',
    ],
  },
  {
    id: 'beekem-removal',
    label: 'Removal continuity',
    title: 'Carry a BeeKEM removal through every authority boundary',
    rule: 'After an authenticated removal, a current replica should use the matching tree, key epoch and writer set together. Restart should preserve that decision.',
    limit:
      'Pinned founder restarts and new-epoch encryption have runtime coverage. The group-wide guarantee across tree transition, reader and writer ACLs, and loading remains open. Independently replicated ACLs can temporarily disagree.',
    source: 'packages/core/src/peerborne-document.ts',
    tests: [
      'packages/core/src/peerborne-document-role-transitions.test.ts',
      'packages/core/src/beekem/local-state.test.ts',
      'examples/password-manager/src/document-checkpoint.test.ts',
    ],
    state: 'open',
  },
  {
    id: 'coordinated-roster',
    label: 'Revocation membership',
    title: 'Bind signed document roles to decrypting membership',
    rule: 'In the strict coordinated profile, verify that the signed roles and the provider’s authenticated member list match before exposing the document or accepting new content.',
    checked:
      'The roster policy accepts equal lists within the size bound. An ID absent from an admitted authority roster is also absent from the matched provider roster.',
    limit:
      'The provider reports its actual decrypting membership. Replicas enforce the new roles after they receive both authenticated updates. Offline replicas can retain earlier keys and content.',
    proof: [
      'packages/core/src/policy/document-authority.ts',
      'exactDocumentMemberRoster',
      'exactRoster_excludesUnlisted',
    ],
    source: 'packages/core/src/coordinated-document.ts',
    tests: [
      'packages/core/src/document-authority-properties.test.ts',
      'verification/mls-provider/document-tests.ts',
    ],
  },
  {
    id: 'key-secrecy',
    label: 'Key secrecy',
    title: 'Limit exposure across key epochs',
    rule: 'Surviving members need fresh key material after removal. Previously shared keys and plaintext remain readable to the members who had them.',
    limit:
      'Forward secrecy, post-compromise security and exclusion across every key-distribution path remain open. Native cryptography and provider behavior are trust boundaries.',
    source: 'packages/core/src/auth-subtlecrypto.ts',
    tests: [
      'packages/core/src/crypto-properties.test.ts',
      'packages/core/src/beekem/beekem-branches.test.ts',
    ],
    state: 'open',
  },
  {
    id: 'load-quorum',
    label: 'Load quorum',
    title: 'Load state from independently trusted authorities',
    rule: 'Bind a V4 response to the challenge, document, trusted security context and complete response manifest. Count each eligible signing authority once.',
    checked:
      'The tally counts the first eligible vote for each identity. Two distinct digests cannot both reach strict majority in the counted votes.',
    limit:
      'The tally assumes verified vote eligibility. Provisioning trusted commitments, peer availability and partial mutation on later I/O failure remain runtime boundaries.',
    proof: [
      'packages/core/src/policy/quorum.ts',
      'quorumTally_majority',
      'firstEligiblePeerIndices',
    ],
    tests: [
      'packages/core/src/quorum-boundary-properties.test.ts',
      'packages/core/src/peerborne-document-load-boundaries.test.ts',
    ],
  },
  {
    id: 'control',
    label: 'Control chain',
    title: 'Extend an authenticated control head',
    rule: 'Check the group context, parent head and action-specific epoch before applying a control transition. Reject a stale or mismatched base.',
    checked:
      'The append policy checks the supplied parent, context and action-specific epoch. Accepted transitions preserve the epoch rule through finite histories.',
    limit:
      'A pinned controller and the group provider must authenticate the policy inputs. Recovery from an authenticated fork depends on explicit application authority.',
    proof: [
      'packages/core/src/policy/control-chain.ts',
      'classifyControlAppend_ensures',
      'controlChain_epoch_history',
    ],
    tests: [
      'packages/core/src/control-chain-properties.test.ts',
      'packages/core/src/group-security-coordinator-forks.test.ts',
    ],
  },
  {
    id: 'authority',
    label: 'Role history',
    title: 'Preserve signed role history',
    rule: 'Bind each fresh control head to one controller. Later records must preserve the old head-to-controller bindings and advance the signed role history.',
    checked:
      'Finite histories preserve old head-to-controller bindings and exclude heads introduced only by unsigned attempts.',
    limit:
      'The history model assumes current-controller authentication. The role log and provider’s decrypting roster must stay in agreement through provisioning and group transitions.',
    proof: [
      'packages/core/src/policy/document-authority.ts',
      'controllerBindings_all_histories',
      'unsignedAuthorityHeads_excluded',
    ],
    tests: ['packages/core/src/authority-history-properties.test.ts'],
  },
  {
    id: 'content-binding',
    label: 'Content binding',
    title: 'Bind every coordinated change to its document',
    rule: 'Verify the content signature and AEAD context before admission. The signed sequence and parent hash connect the change to its author’s accepted history.',
    checked:
      'Accepted finite histories extend each author’s hash and sequence prefix. Gaps, duplicates and conflicting parents do not extend it.',
    limit:
      'The model assumes validated context, signatures and author bindings. Provision a separate cryptographic group per document for confidentiality isolation.',
    proof: [
      'packages/core/src/policy/document-content.ts',
      'contentPrefix_all_histories',
    ],
    tests: [
      'packages/core/src/coordinated-document-properties.test.ts',
      'packages/core/src/document-wire-properties.test.ts',
    ],
  },
  {
    id: 'field-scope',
    label: 'Field scopes',
    title: 'Authorize native CRDT targets before apply',
    rule: 'A restricted writer may touch only targets inside a granted segment path. Ancestor replacement requires an ancestor grant. A reader cannot author an accepted mutation.',
    checked:
      'Accepted finite target histories cannot overlap a protected path disjoint from every grant.',
    limit:
      'The model assumes faithful target extraction. Generated properties exercise the bundled Automerge and Yjs adapters, including changes invisible in the rendered document.',
    proof: [
      'packages/core/src/policy/field-authorization.ts',
      'field_grants_attenuate',
      'field_all_histories',
    ],
    tests: [
      'packages/core/src/field-authorization-properties.test.ts',
      'packages/automerge/src/field-authorization-properties.test.ts',
      'packages/yjs/src/field-authorization-properties.test.ts',
    ],
  },
  {
    id: 'staged-commit',
    label: 'Staged commit',
    title: 'Bind prepared changes to the current state',
    rule: 'Prepare CRDT changes in a detached session. Reserve count and bytes, then check live authority and context at commit. A prepared change can commit at most once.',
    checked:
      'Finite histories keep reservations within their count and byte bounds. At most one completion can commit a prepared change with matching context and authorization.',
    limit:
      'The model receives reservation and completion events. Native staging, cancellation and JavaScript scheduling require runtime checks.',
    proof: [
      'packages/core/src/policy/document-admission.ts',
      'documentAdmission_all_histories',
      'preparedChange_all_histories',
    ],
    tests: [
      'packages/core/src/document-admission-properties.test.ts',
      'packages/automerge/src/document-session-properties.test.ts',
      'packages/yjs/src/document-session-properties.test.ts',
    ],
  },
  {
    id: 'block-reassembly',
    label: 'Bounded block recovery',
    title: 'Reassemble encrypted UnixFS files within read limits',
    rule: 'Bound traversal and accumulated ciphertext. Check the complete ciphertext before deserializing changes.',
    checked:
      'The reservation policy charges the exact admitted prefix and stops at the first byte or count rejection. A Chromium profile relaunch restores and edits a document with at least 50 MiB of encoded history.',
    limit:
      'The browser fixture restores an application-held checkpoint and supplies the signed missing history. Renderer memory and latency depend on the workload and device.',
    proof: [
      'packages/core/src/policy/document-admission.ts',
      'canReserveDocumentOperation_ensures',
      'AdmittedBlockChunks',
    ],
    source: 'packages/core/src/document-block-reader.ts',
    tests: [
      'packages/core/src/document-block-reader-properties.test.ts',
      'verification/browser/technical.spec.ts',
    ],
  },
  {
    id: 'journal-restart',
    label: 'Journal recovery',
    title: 'Restore coordinated state against a durable anchor',
    rule: 'Authenticate the checkpoint, replay admissible entries, and recheck the independent rollback anchor. Expose the recovered document after activation verifies its signing identity and current authority.',
    checked:
      'The exposure guard checks freshness at the final anchor observation and requires an authenticated current checkpoint or exact next checkpoint with a matching parent. Built-in IndexedDB recovery uses at most 147 logical journal row reads, excluding anchor-provider I/O.',
    limit:
      'The device key and independent anchor must survive restart. An in-memory anchor cannot detect rollback across process loss.',
    proof: [
      'packages/core/src/policy/document-journal.ts',
      'journalRecovery_all_histories',
      'journalRecovery_exposure',
      'journalRecovery_read_costs',
    ],
    tests: [
      'packages/core/src/document-journal-properties.test.ts',
      'packages/core/src/journal-recovery-io-properties.test.ts',
    ],
  },
  {
    id: 'coordinated-catch-up',
    label: 'Authenticated catch-up',
    title: 'Merge a controller checkpoint into retained local state',
    rule: 'Match current strict roles and epoch. Verify the controller’s response for the current document and the receiver’s request, then publish the native merge after journal acceptance.',
    checked:
      'Receipt admission preserves existing heads and prevents a peer from seeding the requester’s sequence. Native scenarios exercise current-epoch recovery and restart.',
    limit:
      'The application retains identity and trust, supplies authenticated control and role delivery, and relays the messages. The snapshot payload is limited to 512 KiB and conflicting receipt prefixes require ordered redelivery.',
    proof: [
      'packages/core/src/policy/document-catch-up.ts',
      'admitDocumentCatchUpReceipt_ensures',
      'CatchUpReceiptHistory',
    ],
    source: 'packages/core/src/coordinated-document.ts',
    tests: [
      'packages/core/src/document-catch-up-properties.test.ts',
      'verification/mls-provider/document-tests.ts',
    ],
  },
  {
    id: 'publication',
    label: 'Outbox integrity',
    title: 'Preserve accepted publication through journal updates',
    rule: 'Retain publication entries bound to the accepted frame and checkpoint token. A failed or stale store update must preserve accepted entries.',
    checked:
      'Finite store histories preserve accepted entries on failed or stale attempts. Publication count and byte totals stay within the configured bounds.',
    limit:
      'Platform storage and retry execution determine durability and delivery. This journal belongs to coordinated mode.',
    proof: [
      'packages/core/src/policy/journal-store.ts',
      'journalStore_all_histories',
    ],
    tests: [
      'packages/core/src/journal-transition-properties.test.ts',
      'packages/core/src/document-publication-ledger-properties.test.ts',
    ],
  },
  {
    id: 'wire-budget',
    label: 'Work bounds',
    title: 'Bound admitted parsing and response work',
    rule: 'Check framed offsets and byte limits before copies. Bound graph admission and retain only live, authenticated sync-response requests within the replay budget.',
    checked:
      'Offsets and retained chunks fit the frame budget. Work reservations cannot exceed their cap. Sync admission retains at most 46 replay entries in the checked history model.',
    limit:
      'The sync replay ledger belongs to a live BeeKEM document instance. Total heap, crypto cost and event-loop delay need separate measurement.',
    proof: [
      'packages/core/src/policy/frame-layout.ts',
      'boundedFieldEnd_ensures',
      'frameLayout_chunks',
    ],
    related: [
      [
        'packages/core/src/policy/sync-request.ts',
        'syncResponseHistory_all_histories',
        'syncResponseWindow_bound',
      ],
      ['packages/core/src/policy/work-budget.ts', 'consumeWorkBudget_ensures'],
    ],
    tests: [
      'packages/core/src/frame-boundary-properties.test.ts',
      'packages/core/src/sync-response-properties.test.ts',
    ],
  },
  {
    id: 'retention',
    label: 'Block retention',
    title: 'Keep retained and pinned blocks live',
    rule: 'Select only deletable candidates, recheck a live unpinned lease before deletion and enter deletion at most once per attempt.',
    checked:
      'Finite sweeps preserve initially protected blocks under fixed guards. A live unpinned lease is required to enter deletion, at most once per attempt.',
    limit:
      'The model assumes truthful protection and lease observations. Browser quotas, whole-history compaction and late-join availability require further evidence.',
    proof: [
      'packages/core/src/policy/retention.ts',
      'retention_all_sweeps',
      'blockGc_all_histories',
    ],
    tests: [
      'packages/core/src/live-gc-properties.test.ts',
      'packages/core/src/compaction-retention-properties.test.ts',
    ],
  },
  {
    id: 'transport',
    label: 'Relay path',
    title: 'Exchange encrypted artifacts over peer links',
    rule: 'GossipSub carries update envelopes and Helia serves encrypted blocks. The cross-NAT browser suite exercises a configured Circuit Relay path with distinct identities.',
    limit:
      'Transport identities, coordination metadata, timing and sizes remain visible. Delivery guarantees, mesh saturation and metadata anonymity remain open.',
    source: 'packages/core/src/peerborne-document.ts',
    tests: ['e2e/peerborne-nat.spec.ts', 'verification/advanced/NETWORK.md'],
  },
  {
    id: 'convergence',
    label: 'CRDT merge',
    title: 'Apply admitted changes through the selected CRDT',
    rule: 'Replicas with the same admissible native operations should converge according to their adapter’s merge rules.',
    limit:
      'Seeded adapter properties exercise generated histories. Convergence of a partitioned live group through membership changes and missing history remains open.',
    source: 'docs/feature-audit.md',
    tests: [
      'packages/core/src/coordinated-document-properties.test.ts',
      'packages/automerge/src/provider-properties.test.ts',
      'packages/yjs/src/provider-properties.test.ts',
    ],
  },
  {
    id: 'availability',
    label: 'Storage loss',
    title: 'Recover after device storage loss',
    rule: 'Secure recovery after eviction requires independently available identity, trust commitments and authenticated document state.',
    limit:
      'The browser scenario exercises storage eviction. Product-wide encrypted recovery following identity or anchor loss remains open. The application may install an explicit recovery authority.',
    source: 'verification/advanced/EXECUTION.md',
    tests: ['verification/advanced/browser/eviction.spec.ts'],
    state: 'open',
  },
  {
    id: 'performance',
    label: 'Browser latency',
    title: 'Measure usable latency under load',
    rule: 'Measure CRDT work, cryptography, transport and disk I/O separately with the workload, device and browser recorded.',
    limit:
      'Chromium records time to first edit after a 50 MiB restart. A main-thread frame budget, progressive hydration and scalable mesh fallback remain open.',
    source: 'docs/feature-audit.md',
    tests: [
      'verification/advanced/EXECUTION.md',
      'verification/advanced/NETWORK.md',
    ],
    state: 'open',
  },
  {
    id: 'release',
    label: 'Release gates',
    title: 'Require executable evidence before release',
    rule: 'CI verifies the selected contracts and counterexample controls. The release workflow tests packed consumers and checks dependencies before publication.',
    limit:
      'The workflows provide evidence for the examined revision, dependencies and platforms. Release clearance requires a current successful audit and the applicable approval.',
    source: '.github/workflows/release.yml',
    tests: [
      '.github/workflows/ci.yml',
      'verification/release/audit.mjs',
      'RELEASING.md',
    ],
  },
];

export const flows = [
  {
    id: 'sync',
    title: 'Edit & sync',
    description:
      'Default BeeKEM document · The sender emits two encrypted artifacts.',
    stages: [
      ['Sender device', 'Apply local edit', 'legacy-content'],
      [
        'Sender device',
        'Seal envelope and CID block',
        'legacy-content',
        'wire-budget',
      ],
      ['Network boundary', 'Gossip update and fetch blocks', 'transport'],
      [
        'Recipient device',
        'Check local writers and merge',
        'legacy-content',
        'gossip-receive',
        'convergence',
      ],
    ],
  },
  {
    id: 'membership',
    title: 'Invite & revoke',
    description:
      'Default BeeKEM document · Membership and key distribution have their own messages.',
    stages: [
      ['Application trust', 'Pin issuer and enroll identity', 'trust'],
      ['Sender device', 'Bind offer, request and Welcome', 'invitation'],
      ['Recipient device', 'Classify signed PathUpdate', 'beekem-generation', 'beekem-fork'],
      [
        'Across replicas',
        'Apply removal and next epoch',
        'beekem-continuation',
        'beekem-removal',
        'beekem-replacement',
        'key-secrecy',
      ],
    ],
  },
  {
    id: 'coordinated',
    title: 'Coordinated write',
    description:
      'Opt-in document · The provider and signed authority log share a pinned trust root.',
    stages: [
      [
        'Application trust',
        'Pin genesis and advance authority',
        'trust',
        'control',
        'authority',
        'coordinated-roster',
      ],
      [
        'Client device',
        'Bind frame and check native targets',
        'content-binding',
        'field-scope',
      ],
      ['Client device', 'Stage against live context', 'staged-commit'],
      ['Persistence boundary', 'Commit and record publication', 'publication'],
    ],
  },
  {
    id: 'loading',
    title: 'Load & catch up',
    description:
      'Default BeeKEM document · A challenge binds the response to the current load.',
    stages: [
      ['Application trust', 'Resolve trusted writer commitments', 'trust'],
      [
        'Network boundary',
        'Collect signed V4 responses',
        'load-quorum',
        'transport',
      ],
      [
        'Client device',
        'Check manifest and fetch missing blocks',
        'load-quorum',
        'wire-budget',
        'block-reassembly',
      ],
      ['Client device', 'Apply admitted history', 'convergence'],
    ],
  },
  {
    id: 'beekem-restart',
    title: 'Restore BeeKEM',
    description:
      'Default BeeKEM document · An optional commitment pins exact checkpoint bytes.',
    stages: [
      [
        'Client device',
        'Export signed local checkpoint',
        'beekem-continuation',
      ],
      [
        'Application trust',
        'Preserve identity and current pin',
        'trust',
        'availability',
      ],
      [
        'Client device',
        'Authenticate checkpoint and compare pin',
        'beekem-continuation',
        'beekem-fork',
        'beekem-durable-fork',
      ],
      [
        'Across replicas',
        'Continue from restored epoch',
        'beekem-removal',
        'load-quorum',
      ],
    ],
  },
  {
    id: 'restart',
    title: 'Restore journal',
    description:
      'Coordinated journal · The rollback anchor sits outside the store it protects.',
    stages: [
      [
        'Application trust',
        'Restore identity and pinned genesis',
        'trust',
        'availability',
      ],
      [
        'Persistence boundary',
        'Compare journal and trusted anchor',
        'journal-restart',
      ],
      [
        'Client device',
        'Authenticate and replay retained state',
        'journal-restart',
        'authority',
      ],
      ['Network boundary', 'Resume catch-up and publication', 'coordinated-catch-up', 'publication'],
    ],
  },
  {
    id: 'operations',
    title: 'Storage & release',
    description:
      'Operational checks · Logical bounds, browser measurements and release gates answer different questions.',
    stages: [
      [
        'Persistence boundary',
        'Protect live blocks during cleanup',
        'retention',
      ],
      [
        'Browser & network',
        'Measure resource and latency costs',
        'performance',
        'transport',
      ],
      [
        'Release boundary',
        'Check contracts, packages and advisories',
        'release',
      ],
    ],
  },
];
