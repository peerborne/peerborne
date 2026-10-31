import assert from 'node:assert/strict';
import test from 'node:test';
import fc from 'fast-check';
import { Uint8ArrayList } from 'uint8arraylist';
import {
  encodeInvitationProtocolFrame,
  readInvitationProtocolFrame,
  readInvitationProtocolMessage,
} from './invitation-framing.ts';

test('decodes once across arbitrary empty, aliased, offset and native list chunks and closes the source', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ minLength: 1, maxLength: 512 }),
      fc.array(fc.nat({ max: 64 }), { maxLength: 80 }),
      fc.boolean(),
      async (payload, sizes, lists) => {
        const frame = encodeInvitationProtocolFrame(payload, 512);
        let closed = false;
        let decoded = 0;
        async function* source() {
          try {
            let offset = 0;
            for (const size of [...sizes, frame.length]) {
              if (offset === frame.length) break;
              const length = Math.min(size, frame.length - offset);
              const storage = new Uint8Array(length + 6).fill(0xff);
              const view = storage.subarray(3, 3 + length);
              view.set(frame.subarray(offset, offset + length));
              yield lists
                ? new Uint8ArrayList(
                    view.subarray(0, length >> 1),
                    view.subarray(length >> 1),
                  )
                : view;
              view.fill(0xaa);
              offset += length;
            }
          } finally {
            closed = true;
          }
        }
        const result = await readInvitationProtocolMessage(
          source(),
          (bytes) => {
            decoded++;
            return bytes;
          },
          512,
        );
        assert.deepEqual(result, payload);
        assert.equal(decoded, 1);
        assert.equal(closed, true);
        const truncated = (async function* () {
          yield frame.subarray(0, frame.length - 1);
        })();
        await assert.rejects(
          readInvitationProtocolFrame(truncated, 512),
          /truncated/,
        );
        const trailing = new Uint8Array(frame.length + 1);
        trailing.set(frame);
        await assert.rejects(
          readInvitationProtocolFrame(
            (async function* () {
              yield trailing;
            })(),
            512,
          ),
          /trailing/,
        );
      },
    ),
    { seed: 9706, numRuns: 300 },
  );
});
