import type { Uint8ArrayList } from 'uint8arraylist';

const INVITATION_FRAME_HEADER_BYTES = 4;

/** @internal Prefix one invitation protocol message with its uint32 length. */
export function encodeInvitationProtocolFrame(
  payload: Uint8Array,
  maxPayloadBytes: number,
): Uint8Array {
  assertFrameLimit(maxPayloadBytes);
  if (!(payload instanceof Uint8Array) || payload.byteLength === 0) {
    throw new Error('Invitation protocol frame payload must not be empty');
  }
  if (payload.byteLength > maxPayloadBytes) {
    throw new RangeError(
      `Invitation protocol frame exceeds ${maxPayloadBytes} bytes`,
    );
  }
  const frame = new Uint8Array(
    INVITATION_FRAME_HEADER_BYTES + payload.byteLength,
  );
  new DataView(frame.buffer).setUint32(0, payload.byteLength, false);
  frame.set(payload, INVITATION_FRAME_HEADER_BYTES);
  return frame;
}

/** @internal Read exactly one bounded invitation frame without reparsing chunks. */
export async function readInvitationProtocolFrame(
  source: AsyncIterable<Uint8Array | Uint8ArrayList>,
  maxPayloadBytes: number,
): Promise<Uint8Array> {
  assertFrameLimit(maxPayloadBytes);
  const header = new Uint8Array(INVITATION_FRAME_HEADER_BYTES);
  let headerLength = 0;
  let payload: Uint8Array | undefined;
  let payloadLength = 0;

  for await (const chunk of source) {
    const bytes =
      chunk instanceof Uint8Array ? chunk : chunk.subarray();
    let offset = 0;
    while (offset < bytes.byteLength) {
      if (headerLength < INVITATION_FRAME_HEADER_BYTES) {
        const copied = Math.min(
          INVITATION_FRAME_HEADER_BYTES - headerLength,
          bytes.byteLength - offset,
        );
        header.set(bytes.subarray(offset, offset + copied), headerLength);
        headerLength += copied;
        offset += copied;
        if (headerLength < INVITATION_FRAME_HEADER_BYTES) continue;

        const declaredLength = new DataView(
          header.buffer,
          header.byteOffset,
          header.byteLength,
        ).getUint32(0, false);
        if (declaredLength === 0) {
          throw new Error('Invitation protocol frame payload must not be empty');
        }
        if (declaredLength > maxPayloadBytes) {
          throw new RangeError(
            `Invitation protocol frame exceeds ${maxPayloadBytes} bytes`,
          );
        }
        payload = new Uint8Array(declaredLength);
      }

      const copied = Math.min(
        payload!.byteLength - payloadLength,
        bytes.byteLength - offset,
      );
      payload!.set(bytes.subarray(offset, offset + copied), payloadLength);
      payloadLength += copied;
      offset += copied;
      if (payloadLength === payload!.byteLength) {
        if (offset !== bytes.byteLength) {
          throw new Error('Invitation protocol frame has trailing bytes');
        }
        return payload!;
      }
    }
  }

  if (headerLength < INVITATION_FRAME_HEADER_BYTES) {
    throw new Error('Invitation protocol frame header is truncated');
  }
  throw new Error('Invitation protocol frame payload is truncated');
}

/** @internal Read and decode one complete invitation frame exactly once. */
export async function readInvitationProtocolMessage<T>(
  source: AsyncIterable<Uint8Array | Uint8ArrayList>,
  deserialize: (payload: Uint8Array) => T,
  maxPayloadBytes: number,
): Promise<T> {
  return deserialize(
    await readInvitationProtocolFrame(source, maxPayloadBytes),
  );
}

function assertFrameLimit(maxPayloadBytes: number): void {
  if (
    !Number.isSafeInteger(maxPayloadBytes) ||
    maxPayloadBytes < 1 ||
    maxPayloadBytes > 0xffff_ffff
  ) {
    throw new RangeError(
      'Invitation protocol frame limit must be a positive uint32',
    );
  }
}
