import type { Stream } from '@libp2p/interface';

export type ProtocolWriteStream = Pick<Stream, 'send' | 'onDrain' | 'close'>;

/** Flush a response with backpressure, then close only the writable side. */
export async function writeStream(
  stream: ProtocolWriteStream,
  data: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
): Promise<void> {
  for await (const chunk of data) {
    if (!stream.send(chunk)) await stream.onDrain();
  }
  await stream.close();
}
