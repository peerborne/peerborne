/**
 * libp2p v3 stream adapter shims.
 *
 * libp2p v3 replaced the v2 `{ source, sink }` duplex-stream shape (consumed
 * by `it-pipe`) with an event-driven `MessageStream`/`Stream` interface whose
 * read side is an `AsyncIterable<Uint8Array | Uint8ArrayList>` and whose write
 * side is a `.send()` method (with an `onDrain()` for backpressure).
 *
 * The peerborne protocol handlers and `_sendLoadRequestAndSync` helpers all
 * predate v3 and are written against the legacy `{ source, sink }` shape. To
 * avoid a big-bang rewrite during this migration, we expose a thin adapter
 * that wraps a v3 `Stream` and presents the v2 duplex shape on top of it.
 *
 * This file is intentionally narrow in scope -- it captures only the subset
 * of v2 stream behaviour peerborne actually uses (`source`, `sink`,
 * `close`). Once all call sites are ported to the native v3 API (push/pull
 * via `send()`/iterator), this shim can be removed.
 */

import type { Stream } from '@libp2p/interface';
import type { Uint8ArrayList } from 'uint8arraylist';

/**
 * Legacy v2-style duplex stream shape. Several call sites in
 * `peerborne-document.ts` and `peerborne.ts` consume streams via this
 * shape (typically through `it-pipe`). `wrapStream` produces values matching
 * this shape from v3 `Stream`s.
 */
export interface DuplexStream {
  source: AsyncIterable<Uint8Array | Uint8ArrayList>;
  sink: (data: Iterable<Uint8Array> | AsyncIterable<Uint8Array>) => Promise<void>;
  close: () => Promise<void>;
}

/**
 * Wrap a libp2p v3 `Stream` so it satisfies the v2 `{ source, sink }` duplex
 * shape used throughout peerborne's protocol handlers.
 *
 * - `source` is the underlying stream's async iterator (v3 `MessageStream`
 *   extends `AsyncIterable`, so we can forward as-is).
 * - `sink` writes each chunk via the new `send()` method, awaiting
 *   `onDrain()` whenever the underlying transport signals backpressure.
 *   After all chunks are sent, it half-closes the writable end so the
 *   remote peer can detect end-of-request in request/response patterns.
 * - `close` defers to the v3 stream's half-close (it flushes any pending
 *   writes and closes the writable end only; the readable end stays open).
 *
 * Half-close semantics (important):
 *
 *   In libp2p v3, `Stream.close()` is a *write-side* half-close, not a full
 *   bidirectional close. From the `@libp2p/interface` Stream docs:
 *
 *     "Close stream for writing and return a promise that resolves once any
 *      pending data has been passed to the underlying transport. Note that
 *      the stream itself will remain readable until the remote end also
 *      closes its writable end."
 *
 *   v3 intentionally does not expose a separate `closeWrite()` method --
 *   `close()` *is* the write-side close. Read-side close is `closeRead()`,
 *   and full teardown is `abort(err)`.
 *
 *   This is what makes the sink-then-read request/response pattern in
 *   `_sendLoadRequestAndSync` work: after `pipe([request], stream.sink)`
 *   resolves, the writable end is closed (signalling end-of-request to the
 *   peer) but `stream.source` remains open so we can still read the peer's
 *   response.
 */
export function wrapStream(stream: Stream): DuplexStream {
  return {
    source: stream,
    sink: async (data) => {
      for await (const chunk of data) {
        const ok = stream.send(chunk);
        if (!ok) {
          // Backpressure: wait for the underlying transport to drain its
          // write buffer before sending any further chunks.
          await stream.onDrain();
        }
      }
      // Half-close the writable end so the remote can detect end-of-request.
      // The readable end remains open; callers can still consume response
      // data from `stream.source` afterwards (see `_sendLoadRequestAndSync`).
      // In libp2p v3, `Stream.close()` is the write-side close -- there is
      // no separate `closeWrite()` method.
      await stream.close();
    },
    close: () => stream.close(),
  };
}
