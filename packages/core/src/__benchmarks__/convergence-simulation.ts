/**
 * Benchmark: Convergence Simulation
 *
 * Simulates N peers making concurrent edits and measures:
 * - Time to converge to a consistent state
 * - Message count per peer
 * - Bandwidth (bytes) per peer
 *
 * This is a simulated benchmark that models the message-passing behavior
 * without requiring actual network connections. Each "peer" maintains its own
 * document state and applies changes through the serialization pipeline.
 */
import { PaperBenchmarkRunner, BenchmarkSuiteResult } from './benchmark-runner.js';
import { SubtleCrypto } from '../auth-subtlecrypto.js';
import { JSONSerializer } from '../json-serializer.js';
import {
  generateSigningKeyPair,
  generateEncryptionKey,
} from './crypto-setup.js';

const PEER_COUNTS = [2, 4, 8, 16, 32];
const EDITS_PER_PEER = 10;

interface SimulatedPeer {
  id: number;
  keyPair: CryptoKeyPair;
  document: Record<string, string>;
  messagesSent: number;
  messagesReceived: number;
  bytesSent: number;
  bytesReceived: number;
}

/**
 * Run convergence simulation benchmarks measuring peer-to-peer synchronization.
 *
 * Simulates N peers (2 to 32) making concurrent edits through the full
 * sign-encrypt-broadcast-decrypt-verify pipeline, then measures:
 * - Total convergence time for all peers to apply all changes
 * - Message generation rate per peer
 * - Bandwidth estimates per peer
 *
 * @param iterations - Number of iterations per benchmark (default 20)
 * @returns A {@link BenchmarkSuiteResult} with timing statistics for each peer count
 */
export async function runConvergenceSimulationBenchmarks(
  iterations: number = 20,
): Promise<BenchmarkSuiteResult> {
  const runner = new PaperBenchmarkRunner('convergence-simulation');
  const auth = new SubtleCrypto();
  const serializer = new JSONSerializer<string>();

  for (const peerCount of PEER_COUNTS) {
    // Pre-generate keys for all peers (not timed)
    const peerKeys: CryptoKeyPair[] = [];
    for (let i = 0; i < peerCount; i++) {
      peerKeys.push(await generateSigningKeyPair());
    }
    const documentKey = await generateEncryptionKey();

    // --- Convergence time: all peers produce edits, then apply all to all ---
    await runner.run(`convergence-${peerCount}-peers`, async () => {
      const peers: SimulatedPeer[] = peerKeys.map((keyPair, i) => ({
        id: i,
        keyPair,
        document: {},
        messagesSent: 0,
        messagesReceived: 0,
        bytesSent: 0,
        bytesReceived: 0,
      }));

      // Phase 1: Each peer generates local changes
      const allMessages: Array<{
        fromPeer: number;
        encryptedPayload: Uint8Array;
        nonce: Uint8Array;
        signature: Uint8Array;
        byteSize: number;
      }> = [];

      for (const peer of peers) {
        for (let e = 0; e < EDITS_PER_PEER; e++) {
          const changeData = `peer-${peer.id}-edit-${e}`;
          const changeBytes = serializer.serializeChanges(changeData);

          // Sign the serialized changes
          const signature = await auth.sign(changeBytes, peer.keyPair.privateKey);

          // Encrypt the serialized changes
          const encrypted = await auth.encrypt(changeBytes, documentKey);

          const byteSize = signature.length + encrypted.data.length + encrypted.nonce.length;

          // Apply locally before broadcast -- each peer must have its own edits
          peer.document[`peer-${peer.id}-${changeData}`] = 'applied';

          peer.messagesSent++;
          peer.bytesSent += byteSize;
          allMessages.push({
            fromPeer: peer.id,
            encryptedPayload: encrypted.data,
            nonce: encrypted.nonce,
            signature,
            byteSize,
          });
        }
      }

      // Phase 2: Each peer receives and processes all other peers' messages
      for (const peer of peers) {
        for (const msg of allMessages) {
          if (msg.fromPeer === peer.id) continue; // skip own messages

          // Decrypt
          const decrypted = await auth.decrypt(msg.encryptedPayload, documentKey, msg.nonce);

          // Verify the decrypted payload
          const senderKey = peerKeys[msg.fromPeer].publicKey;
          const valid = await auth.verify(decrypted, senderKey, msg.signature);
          if (!valid) {
            throw new Error(`Signature verification failed for message from peer ${msg.fromPeer}`);
          }

          // Deserialize from verified/decrypted bytes and apply
          const decryptedChanges = serializer.deserializeChanges(decrypted);
          peer.document[`peer-${msg.fromPeer}-${decryptedChanges}`] = 'applied';

          peer.messagesReceived++;
          peer.bytesReceived += msg.byteSize;
        }
      }

      // Assert all peers converged to the same document state
      const referenceKeys = Object.keys(peers[0].document).sort();
      const referenceJoined = referenceKeys.join(',');
      for (let i = 1; i < peers.length; i++) {
        const peerKeys2 = Object.keys(peers[i].document).sort();
        if (peerKeys2.join(',') !== referenceJoined) {
          throw new Error(
            `Peer ${peers[i].id} did not converge with peer 0: expected ${referenceKeys.length} keys, got ${peerKeys2.length} keys`,
          );
        }
      }
    }, iterations);

    // --- Message count per peer ---
    const expectedMsgsSent = EDITS_PER_PEER;
    const expectedMsgsReceived = (peerCount - 1) * EDITS_PER_PEER;

    await runner.run(`msg-generation-per-peer-${peerCount}-peers`, async () => {
      const peer = { keyPair: peerKeys[0], document: {} };
      for (let e = 0; e < EDITS_PER_PEER; e++) {
        const changeData = `peer-0-edit-${e}`;
        const changeBytes = serializer.serializeChanges(changeData);
        const signature = await auth.sign(changeBytes, peer.keyPair.privateKey);
        const encrypted = await auth.encrypt(changeBytes, documentKey);
        // Simulate broadcast
        void signature.length;
        void encrypted.data.length;
      }
    }, iterations);

    // --- Bandwidth: measure serialized message sizes ---
    const sampleChange = `sample-edit-peer-0`;
    const sampleBytes = serializer.serializeChanges(sampleChange);
    const sampleSig = await auth.sign(sampleBytes, peerKeys[0].privateKey);
    const sampleEnc = await auth.encrypt(sampleBytes, documentKey);
    const singleMsgBytes = sampleSig.length + sampleEnc.data.length + sampleEnc.nonce.length;

    const sentBytesPerPeer = expectedMsgsSent * singleMsgBytes;
    const recvBytesPerPeer = expectedMsgsReceived * singleMsgBytes;
    // Log bandwidth stats (not timed, but recorded as metadata)
    console.log(`  [${peerCount} peers] msgs/peer: sent=${expectedMsgsSent}, recv=${expectedMsgsReceived}`);
    console.log(`  [${peerCount} peers] bytes/msg: ~${singleMsgBytes}, sent/peer: ~${sentBytesPerPeer}, recv/peer: ~${recvBytesPerPeer}, total/peer: ~${sentBytesPerPeer + recvBytesPerPeer}`);
  }

  return runner.toSuiteResult();
}
