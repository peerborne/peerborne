# Main-thread and storage-eviction probes

Requires the [advanced runner foundation](README.md). The existing Chromium
CI step discovers both scenarios.

```sh
yarn verify:advanced:browser --grep 'crypto-jitter|storage-eviction'
PEERBORNE_VERIFY_PROFILE=full yarn verify:advanced:browser --grep 'crypto-jitter|storage-eviction'
PEERBORNE_VERIFY_STRICT=1 yarn verify:advanced:browser --grep crypto-jitter
```

`crypto-jitter` pre-generates 64/2,048 individual, valid signed AES-GCM Yjs
deltas with 1/4 KiB synthetic payloads. This controls incoming load rather
than adding an unrelated growing-sender-DAG benchmark. Native ordered RTC
delivers the unchanged encrypted envelopes to the real document pubsub
handler. Actual synchronous decoder/adapter calls and crypto dispatch spans
are measured on the window thread. Reports distinguish Web Crypto invocation
cost from promise settlement time; neither identifies its internal executor.

Worker construction is instrumented before application modules load. Render
intervals, baseline timing, long tasks, timer gaps and the measured JavaScript
work per render interval are reported. The 16ms work budget is separate from
nominal 60Hz frame spacing (about 16.67ms). Measured spans are not all browser
main-thread work. Main-thread decoding remains a gap even if this finite
workload meets the timing budget. Hardware, native crypto and network timing
vary; input generation and delivery batches repeat with the workload seed.

`storage-eviction` uses a temporary persistent Chromium profile and the shipped
Peerborne Note non-extractable identity store. A separate browser context
retains authoritative state. The victim first receives an actual signed,
encrypted snapshot and its encrypted content-addressed blocks over native
RTC. It persists a fixture boot manifest, then closes/reopens the browser
profile and must restore both identity and document state before eviction.

Next it goes offline, closes storage handles, clears all origin IndexedDB
through CDP, verifies no databases remain, closes the browser and restarts
the same profile. The authoritative peer sends another encrypted snapshot.
The test never re-injects the lost identity or document keys after eviction.
Opening empty state must fail closed. Reports distinguish loss of the shipped
identity store, a replacement identity, missing local state and inability to
decrypt an otherwise available authoritative snapshot. No independent secure
vault or synthetic automatic re-enrollment is supplied.

The boot manifest, explicit initial enrollment, signaling and RTC block
carrier are fixtures. This is not the complete shipped discovery, invitation
or recovery UI, and no automatic recovery claim follows from a preserved
authoritative replica. Chromium's programmatic origin eviction does not
prove iOS Safari's OS-triggered policy. All temporary profiles are removed;
keys, raw frames, manifests, browser profiles and private payloads are excluded
from committed files and reports. Tracing, screenshots and video stay off.
