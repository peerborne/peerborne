import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import test from 'node:test';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { generateKeyPair } from '@libp2p/crypto/keys';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';
import { webSockets } from '@libp2p/websockets';
import { multiaddr } from '@multiformats/multiaddr';
import { createLibp2p } from 'libp2p';
import { captureConnectOptions, connectWithRetry } from './connection.ts';

function options(listen = []) {
  return {
    addresses: { listen },
    transports: [webSockets()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
  };
}

test('native Noise rejects an unexpected peer without retrying authentication', async () => {
  const server = await createLibp2p(options(['/ip4/127.0.0.1/tcp/0/ws']));
  const client = await createLibp2p(options());
  try {
    const unexpected = peerIdFromPrivateKey(await generateKeyPair('Ed25519'));
    const target = multiaddr(
      server
        .getMultiaddrs()[0]
        .toString()
        .replace(/\/p2p\/[^/]+$/u, `/p2p/${unexpected}`),
    );
    const events = [];
    let attempts = 0;
    await assert.rejects(
      connectWithRetry(
        (attempt, onProgress) => {
          attempts++;
          return client.dial(target, { onProgress, force: attempt > 1 });
        },
        captureConnectOptions({
          maxAttempts: 3,
          retryDelayMs: 0,
          onProgress: (event) => {
            events.push(event);
          },
        }),
        0,
        1,
      ),
      (error) => {
        assert.equal(error.name, 'EncryptionFailedError');
        return true;
      },
    );
    assert.equal(attempts, 1);
    assert.equal(events.at(-1).errorType, 'EncryptionFailedError');
    assert.equal(events.at(-1).stage, 'secure-channel');
    assert.equal(
      events.some((event) => event.type === 'retrying'),
      false,
    );
  } finally {
    await Promise.all([client.stop(), server.stop()]);
  }
});

test('caller cancellation interrupts a native active WebSocket dial without retrying', async () => {
  const sockets = new Set();
  const controller = new AbortController();
  const reason = new DOMException(
    'Cancelled native connection test',
    'AbortError',
  );
  let accepted = false;
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    accepted = true;
    controller.abort(reason);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const client = await createLibp2p(options());
  const events = [];
  let attempts = 0;
  const deadline = setTimeout(() => controller.abort(reason), 5000);
  try {
    const target = multiaddr(`/ip4/127.0.0.1/tcp/${server.address().port}/ws`);
    await assert.rejects(
      connectWithRetry(
        (attempt, onProgress) => {
          attempts++;
          return client.dial(target, {
            signal: controller.signal,
            onProgress,
            force: attempt > 1,
          });
        },
        captureConnectOptions({
          signal: controller.signal,
          maxAttempts: 3,
          retryDelayMs: 0,
          onProgress: (event) => {
            events.push(event);
          },
        }),
        0,
        1,
      ),
      (error) => {
        assert.equal(error, reason);
        return true;
      },
    );
    assert.equal(accepted, true);
    assert.equal(attempts, 1);
    assert.equal(events.at(-1).aborted, true);
    assert.equal(events.at(-1).errorType, 'AbortError');
    assert.equal(events.at(-1).stage, 'transport');
    assert.equal(
      events.some((event) => event.type === 'retrying'),
      false,
    );
  } finally {
    clearTimeout(deadline);
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    await client.stop();
  }
});
