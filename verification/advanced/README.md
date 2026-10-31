# Advanced security and performance verification

This catalog adds adversarial probes to the existing [technical suite](../README.md).
Each result states its attacker model, execution boundary, measurements and
unmet guarantees. No product security mechanism is supplied by these tests.
The [security model](../../site/src/content/docs/concepts/security.md) and
[feature audit](../../docs/feature-audit.md) remain the capability baseline.

```sh
yarn install --immutable
yarn verify:advanced
yarn verify:advanced:browser
node verification/advanced/collect.mjs --profile smoke
```

Use `--profile full` for Node stress sizes and
`PEERBORNE_VERIFY_PROFILE=full` for browser stress sizes. `--seed` and
`PEERBORNE_VERIFY_SEED` default to 9420. Actor IDs, generated synthetic workloads,
boundary vectors and delivery schedules repeat; real crypto entropy, native
network delivery, timing and memory measurements vary.

```sh
node verification/advanced/run.mjs --list
yarn verify:advanced --category crypto --profile full
yarn verify:advanced --scenario document-replay --strict
PEERBORNE_VERIFY_STRICT=1 yarn verify:advanced:browser --grep traffic-metadata
node verification/advanced/collect.mjs --profile full --strict
```

Catalog files register scenarios independently, so later PRs can add categories
without editing the runner. `--category` and `--scenario` may be repeated. Node
workers have a 15-minute deadline (`--timeout-ms` overrides it), use isolated
processes and temporary files, and suppress library console output. Browser
tests have one worker, no retries and a 15-minute timeout. Traces, screenshots,
video, raw frame dumps, SDP dumps and key dumps are disabled.

Reports persist under `verification/results/advanced/<profile>/`, outside the
per-run Playwright scratch directory. The existing results ignore rule covers
them. A worker/process failure or violated safety assertion fails diagnostic
mode. Missing guarantees produce `gap`; unexecuted browser scenarios produce
`not-run`. Strict mode fails on either. A green diagnostic job is not complete
security certification. CI runs both Node and browser smoke catalogs, collects
the reports and uploads the existing verification artifact. Manual workflow
dispatch selects full workloads.

## Crypto and access control probes

| ID                 | Workload and safety assertions                                                                                                                                                                                                                                                  | Evidence boundary                                                                                                                                                                                |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `epoch-fork`       | Three BeeKEM members partition; two partitions independently revoke the third. Rejected sibling transitions preserve both roots. Subsequent signed document frames are tested against the divergent keys. Fuzz 48/512 invalid v2 wire values and runtime generation boundaries. | Rejection alone is not explicit fork identification or graceful resolution. No automatic epoch-DAG recovery is invented.                                                                         |
| `key-compromise`   | Compare a sole AES epoch-key leak, a retained historical keychain, and a complete cloned member ratchet. Other-member updates remain readable by the compromised member; test whether that member's own fresh ratchet excludes the clone.                                       | Legacy BeeKEM component evidence, not MLS or durable erasure. Same-epoch historical ciphertext and retained historical keys remain distinct attack surfaces.                                     |
| `document-replay`  | Two documents share a signing authority and encryption material. Reinject exact ciphertext, rebind document IDs, alter parents, switch signature contexts, and fuzz 32/512 bit flips plus truncated header/tag boundaries.                                                      | Signed routing rejection is reported separately from AEAD decryption binding.                                                                                                                    |
| `traffic-metadata` | Deliver an actual encrypted document frame over native ordered RTC. Search for synthetic document/operation/signer canaries; inspect the epoch prefix, publication routing label and native signaling structure.                                                                | Pubsub publication is inspected before Noise; SDP is inspected before signaling encryption. This is not a packet capture of the complete shipped libp2p path. Only counts/booleans are reported. |

The crypto probes use native Web Crypto and production BeeKEM, wire codecs,
document signing, encryption and ingress. Document fixtures substitute peer
discovery/transport and share a synthetic signing authority where stated.
Do not promote a fixture's delivery policy, key restoration or error handling
into a product guarantee.
