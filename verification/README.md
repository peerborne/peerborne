# Technical verification and stress scenarios

This suite covers the eleven edge cases in the technical verification brief.
It tests the current source workspaces; the packages do not need to be published.
No production implementation, wire format, or persistence format is changed.
Use the [feature audit](../docs/feature-audit.md) and
[limitations](../site/src/content/docs/concepts/limitations.md) for the broader
capability boundaries.

## Run

Use Node **22.19.0**, Corepack, and Yarn **4.5.0**:

```sh
corepack enable
yarn install --immutable
yarn verify:technical
yarn exec playwright install chromium
yarn verify:technical:browser
```

The default `smoke` profile is deliberately small. Run the requested stress
sizes explicitly:

```sh
yarn verify:technical --profile full
PEERBORNE_VERIFY_PROFILE=full yarn verify:technical:browser
```

A full mesh of 50 peers needs 1,225 links / 2,450 native `RTCPeerConnection`
objects in the single-renderer harness. Chromium may refuse that many
connections. That is a failed workload, not a successful fallback. Compare a
bounded-degree graph explicitly:

```sh
PEERBORNE_VERIFY_PROFILE=full PEERBORNE_VERIFY_TOPOLOGY=ring yarn verify:technical:browser --grep webrtc
```

The `ring` graph connects each peer to its two nearest neighbors in each
direction. The harness supplies routing, duplicate suppression, backpressure,
and signaling. Neither configuration proves the product's libp2p/GossipSub
scalability or an automatic topology fallback.

Target an individual scenario or change the deterministic delivery schedule:

```sh
yarn verify:technical --scenario schema --scenario epoch-race --seed 123
yarn verify:technical --scenario offline --profile full --budget-ms 16
PEERBORNE_VERIFY_PROFILE=full yarn verify:technical:browser --grep cold
node verification/run.mjs --list
```

After a build, `node --expose-gc verification/run.mjs` runs the Node scenarios
without rebuilding. This runner is independent of `yarn benchmark:all`, whose
existing module mismatch is outside this change.

## Results and acceptance

Node results are saved to `verification/results/node-report.json`; use
`--output <path>` to preserve separate runs. Browser reports are saved in the
individual test directories under
`verification/results/reports/<profile>/<topology>/` and attached to Playwright.
The relay report uses `reports/full/nat/`. Playwright's per-run scratch output
is under `results/browser-<profile>-<topology>/` or `results/nat/`.
The results directory is ignored and separate from the default Playwright
output, so running the repository's smoke suites does not erase these reports.
No credentials, keys, private document payloads, or console state are included.
Only synthetic workloads are used. Traces, videos, and screenshots are disabled
to avoid recording synthetic security state during browser calls.

Statuses distinguish executable observations from the requested guarantee:

| Status    | Meaning                                                                        |
| --------- | ------------------------------------------------------------------------------ |
| `passed`  | Assertions pass within the explicitly reported scope.                          |
| `gap`     | The probe completed but a requested guarantee is missing or outside its scope. |
| `failed`  | A workload/assertion failed or a worker exceeded its deadline.                 |
| `not-run` | A separate browser/Docker runner is required.                                  |

The default is **diagnostic**: assertion/workload failures exit nonzero, while
known capability gaps remain in the JSON. To use this as an acceptance gate:

```sh
yarn verify:technical --profile full --strict
PEERBORNE_VERIFY_PROFILE=full PEERBORNE_VERIFY_STRICT=1 yarn verify:technical:browser
```

Strict mode currently fails: the alpha does not supply all requested guarantees.
A green diagnostic run must not be described as passing all eleven requirements.
The Node report explicitly marks the four separately executed browser/NAT cases
`not-run`. An aggregate report can combine their artifacts:

```sh
node verification/collect.mjs --profile full
node verification/collect.mjs --profile full --strict
```

Measurements vary with the machine, cryptographic entropy, GC, and load. Fixed
actor/client IDs, seeded synthetic data and permutations, explicit partitions,
and bounded completion conditions make the workloads and semantic assertions
repeatable. Real cryptographic randomness is never replaced. Node workers run
in separate processes with `--expose-gc` and a 15-minute per-scenario deadline;
override it with `--timeout-ms`. Browser tests have a 15-minute deadline, no
retries, and one worker.

`--budget-ms` (default 50 ms) reports timer/local-mutation budget violations as
gaps in the membership and offline probes. Browser reports include timer gaps
and Long Task durations; Node reports include process CPU, heap, external
memory, ArrayBuffers and RSS. These are measurements, not portable performance
thresholds. The renderer CPU metric is nullable when CDP does not expose it.

## CI

The [CI workflow](../.github/workflows/ci.yml) runs the `smoke` Node and Chromium
profiles on pull requests and pushes to `main`. The existing `peerborne-cross-nat`
job also runs the relay profiling scenario after its bounded readiness checks.
Both jobs upload `verification/results/` as artifacts even on failure.

Use the workflow's manual **Run workflow** inputs to select `full` workloads
and either `mesh` or `ring`. The full single-renderer mesh is expected to fail
on Chromium's connection limit; the ring is an explicit comparison, not an
automatic product fallback. The Node/Chromium artifact marks `relay` as
`not-run` because its report is uploaded separately by the NAT job.

CI uses diagnostic mode: broken assertions and incomplete workloads fail the
job, while capability gaps remain explicit in the JSON reports. A green CI
run does not certify all eleven requested guarantees. Strict acceptance and
the unimplemented or unverified behavior listed below remain outstanding.

## Coverage

| Requirement / ID            | Full workload and assertions                                                                                                                                                                                                                                                                             | Evidence boundary / gaps                                                                                                                                                                                                                                                                                                                           |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema conflict / `schema`  | Both adapters migrate `user.name` to an object while another offline peer writes a string. Opposite and seeded duplicate deliveries converge to the expected fixed-actor winner; subsequent edits work. Automerge retains both conflicts.                                                                | Adapter simulation. Applications need union-aware readers during rolling schema migration; CRDT convergence cannot make arbitrary application code schema-safe.                                                                                                                                                                                    |
| Tombstones / `history`      | 50,000 cursor assignments plus 50,000 deletions through real `PeerborneDocument.change()`. Automatic snapshots/pruning/GC are invoked at fixed counts; measure retained blocks/bytes, CIDs, and memory at five checkpoints. A late replica applies the signed snapshot/tail and a new edit.              | Real document/UnixFS in memory. GC success is counted at actual block deletions, not calls. The current Helia `NotFoundError` on unpinned blocks prevents deletion; CID metadata also remains unbounded. No destructive-GC recovery claim is made when deletion fails.                                                                             |
| Missing context / `causal`  | Reorder 2,048 descendants before their ancestor for each adapter; require eventual recovery and replay idempotence. Reject 2,048 unsigned frames before history growth; send 2,048 signed independent orphans and measure pending bytes/CIDs.                                                            | Authentication rejection is separate from aggregate resource bounds. No count/byte/TTL limit for authorized orphans is established.                                                                                                                                                                                                                |
| Group scale / `group`       | Legacy BeeKEM groups at 2, 4, 8, 16, 32, 64, 100 peers. Time invitation, Welcome, survivor application, and revocation; assert root convergence and removed-peer AEAD failure. Record concurrent independent local mutation latency, process CPU and timer gaps.                                         | Primitive benchmark, not MLS or the live public document membership APIs. Setup/key generation precedes the measured final invitation. Timer gaps measure responsiveness; total fanout time does not equal blocking time.                                                                                                                          |
| Epoch race / `epoch-race`   | Deliver real ciphertext through the installed pubsub listener before installing epoch N, then install the key. Observe automatic replay; explicit retransmission must recover; tampered ciphertext must fail closed.                                                                                     | Currently ignored without replay. Key installation is scheduled by the fixture, not a live membership transport.                                                                                                                                                                                                                                   |
| Offline resync / `offline`  | Generate 500 real v2 transitions while a member is offline. Reject an ancestor skip without advancing state, replay every wire-encoded transition, compare roots, decrypt current state, and replay the last generation idempotently.                                                                    | Harness supplies the backlog. No automatic retrieval, persistent BeeKEM restart recovery, or browser UI guarantee is implied.                                                                                                                                                                                                                      |
| Topology / `webrtc`         | 50 active independent documents make four commits each over real native RTC channels. Verify every operation on every peer, count frames/bytes, queue pressure, delivery latency, CPU, and timer/Long Task delays. Mesh and ring comparison modes.                                                       | One renderer, shared synthetic signing identity; fixture transport replaces libp2p. Browser connection limits can fail the full mesh before writes begin.                                                                                                                                                                                          |
| NAT / `relay`               | Two NAT-isolated Chromium processes, ICE servers removed, actual `/p2p-circuit/` connection required, 64 KiB document load verified, WebSocket bytes and load latency reported.                                                                                                                          | Circuit Relay v2, not TURN or a zero-knowledge proof. Isolation is not a symmetric NAT mapping/filtering emulator; automatic fallback and matched direct-versus-relay overhead remain gaps.                                                                                                                                                        |
| Delta calculation / `delta` | Two partitions of two replicas each make 300 independent changes. Rejoin through signed production sync, assert convergence/replay safety, and verify exactly the missing CIDs are selected. Compare encrypted/JSON envelope, missing payload, snapshot and hypothetical deflate sizes.                  | Common ancestors are filtered on receipt but still serialized in the sender's envelope. Hypothetical deflate is not a shipped compressed cryptographic delta protocol.                                                                                                                                                                             |
| IndexedDB / `idb`           | Paste 20,000 words; compare 2,000 sequential commits with 2,000 queued mutations in one explicit transaction. Instrument native IndexedDB transactions and `put/add` calls, verify text/state, and require fewer writes for batching.                                                                    | Real browser storage with substituted transport. Explicit batching works; no automatic WAL/coalescing guarantee is supplied.                                                                                                                                                                                                                       |
| Cold boot / `cold`          | Persist at least 50 MiB of encoded Yjs historical updates (800 overwritten 64 KiB strings plus list insert/delete edits; source GC disabled). Close Chromium, restart using the same profile, then read/decrypt/reconstruct and measure initial document paint/input timing separately from shell paint. | Manifest restores a CID/CryptoKey out of band. Production `_getBlock()` fails on chunked UnixFS files; a labeled diagnostic `UnixFS.cat()` continuation measures hydration. Production TTI is `null` when that path fails. Hydration completes before document rendering. Not a full Peerborne/keychain reopen proof or a cold OS disk-cache test. |

## NAT topology lifecycle

This runner is separate from the no-Docker Chromium suite. It uses the existing
[cross-NAT Compose topology](../docker-compose.peerborne-nat.yaml) and the
`peerborne-cross-nat` job's exact bounded endpoint waits and teardown in
[CI](../.github/workflows/ci.yml). On a host with Docker, Compose, Bash, and the repository Node toolchain installed:

```sh
bash verification/run-nat.sh
```

The script owns its Compose topology and deletes its ephemeral volumes on exit.
Do not run it against a topology whose data you intend to keep. To run against
an already prepared topology, perform its readiness checks first, then use
`yarn verify:technical:nat`. `BROWSER_A_WS` and `BROWSER_B_WS` can override the
default remote Playwright endpoints at ports 3101 and 3102. Remote browsers must
reach the apps through the topology's localhost proxy. No existing pages are
reused or inspected.
