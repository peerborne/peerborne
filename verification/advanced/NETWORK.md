# Network scaling and duplicate resistance

Requires the [advanced runner foundation](README.md). Catalog entries are
included automatically in its Node/Chromium CI steps.

```sh
yarn verify:advanced --category network
yarn verify:advanced:browser --grep 'mesh-saturation|slow-peer'
yarn verify:advanced --category network --profile full
PEERBORNE_VERIFY_PROFILE=full yarn verify:advanced:browser --grep 'mesh-saturation|slow-peer'
bash verification/advanced/run-kernel-loss.sh
```

`mesh-saturation` grows a native ordered RTC mesh from 5 through 6 peers in
smoke mode, and through every population up to 50 in full mode. Five browser
contexts distribute up to ten document peers per page, keeping a single page's
connection cap distinct from session population. Existing links remain open
as each peer joins. Each stage resets the synthetic document bootstrap, then
all peers mutate concurrently with real signing, encryption and CRDT ingress.
Every frame must drain and state must converge before the next stage.

Reports include logical links, native connection/channel endpoints, ICE UDP
candidate and selected-pair counts, descriptor counts when permitted, Chromium
task/script duration deltas, heap usage, decoder cost, encrypted bytes and
convergence percentiles. The first observed p95 above
`max(100ms, 3 * five-peer p95)` is reported as degradation. A native connection
or convergence deadline records the first capacity failure and highest completed
population. These thresholds describe this machine/workload, not a universal
Peerborne limit. Candidate entries are not exact OS UDP socket counts; contexts
may share browser processes. A missing measurement is `null`.

`duplicate-echo` uses four real libp2p TCP/Noise/Yamux/GossipSub nodes in a diamond.
Both forwarders hold their real outbound RPC until both paths are ready, then
release identical publications to D. No harness seen-cache is installed. Actual
GossipSub pre-validation receipt, application dispatch, decryption, CRDT sync,
outbound forwarding and seen-cache growth are counted. Eight/128 publications
must each reach D through both branches but enter application crypto exactly
once. Gossip settings require both links and disable peer exchange; this is
dependency/ingress evidence, not default discovery or WebRTC routing evidence.

`oversized-frames` joins a founder and an invited reader through a loopback
WebSocket Circuit Relay with production GossipSub, topic validators and
Bitswap. Twelve (full: 24) 300 KB edits must reach the reader while every
frame stays under the 4 MiB RPC limit and reaches a peer, and the founder must
compact. A reader removal right after a 1.2 MB edit must succeed. A change
larger than one frame must be refused with `GossipFrameLimitError` without a
publish, and the retired instance must refuse the next change.

`author-offline-frames` runs three replicas of one writer identity over real
TCP GossipSub. Fixture replicas cannot fetch blocks from one another. A writes
large values and ten edits while C drops its traffic, then A stops. Within one
compaction window C must converge from B's next frames alone, without reading
a block. Beyond it, A's older changes are pruned, and B's frames must still
apply without stalling. Slow links, relay data limits and browser transports
remain outside both scenarios.

`slow-peer` places one replica in a separate CDP target and makes the other
three mutate concurrently over ordered SCTP channels. A no-loss baseline and
100% blackout control precede 80% WebRTC packet-loss emulation. The control
must stop probe delivery before loss enforcement can be claimed. A CDP success
response alone is insufficient; unsupported/ineffective throttling produces a
gap. Healthy replicas have their own bounded convergence deadline. Reports
include slow-peer progress, buffered bytes and timing relative to baseline.
Native loss is stochastic; a fixed workload seed does not seed Chromium's
packet-loss generator or reveal exact SCTP retransmission counters.

On Linux, `run-kernel-loss.sh` runs the slow-peer test in a new, unnamed network
namespace. It requires passwordless sudo, iproute2, iptables, `unshare` and `setpriv`.
The IPv4 namespace has loopback and a synthetic veth pair with a default route;
its interfaces and packet filters are separate from the host. The test classifies only the slow replica's
actual UDP candidate ports into a kernel packet filter that passes one of every five datagrams, in both
directions. The workload seed chooses the initial position in that fixed pattern. A 100% blackout must suppress probe delivery and actual kernel
drop counters must increase before the workload runs at 80% loss. The CI job
runs this variant after the portable Chromium probes and collects its report.
`PEERBORNE_VERIFY_PROFILE=full` also selects the full kernel-loss workload.
The namespace disappears after its processes stop. Native packet arrival
schedules still vary; a fixed kernel packet-drop pattern is not a bit-for-bit network
replay. Kernel UDP drops do not count SCTP's internal retransmissions.
Loopback ICE candidates are explicitly allowed for this isolated fixture.

The mesh and slow-peer transports, signaling, shared fixture bootstrap and
direct per-channel publication are explicit harness components. They do not
prove shipped libp2p queue isolation, topology selection or automatic tree/relay
fallback. No synthetic automatic fallback is presented as a product feature.
Strict acceptance rejects those evidence gaps. Raw SDP, addresses, keys and
encrypted/private frame contents are never written to reports or traces.
