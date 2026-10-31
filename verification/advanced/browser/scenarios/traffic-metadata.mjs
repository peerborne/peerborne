import {
  documentFixture,
  replicaOf,
  receiveEncrypted,
} from '../../../fixtures.mjs';
import { assert, pair, contains, deadline } from '../support.mjs';

export const id = 'traffic-metadata';
export async function run({ seed }) {
  const documentPath = `/advanced/traffic-private-document-${seed}`;
  const canary = `synthetic-private-operation-${seed}-never-cleartext`;
  const source = await documentFixture({ path: documentPath });
  let target;
  const resources = [];
  try {
    target = await replicaOf(source, 2);
    const connection = await pair(resources);
    const frames = [];
    const topics = [];
    let applied;
    const delivered = new Promise((resolve, reject) => {
      applied = { resolve, reject };
    });
    connection.right.onmessage = async ({ data }) => {
      try {
        const bytes = new Uint8Array(data);
        assert(
          await receiveEncrypted(target, bytes),
          'Native RTC ciphertext must authenticate and apply',
        );
        applied.resolve();
      } catch (error) {
        applied.reject(error);
      }
    };
    source.setPublish(async (topic, bytes) => {
      topics.push(topic);
      frames.push(bytes.slice());
      connection.left.send(bytes);
    });
    await source.document.change((doc) =>
      doc.getMap('root').set('privateField', canary),
    );
    await deadline(delivered);
    const frame = frames[0];
    const [epochId] = await source.document._keychain.current();
    const signer = await source.auth.serializePublicKey(
      source.identity.publicKey,
    );
    assert(
      !contains(frame, documentPath) &&
        !contains(frame, canary) &&
        !contains(frame, signer),
      'Encrypted frame cannot expose document, operation or signer canaries',
    );
    const metadata = {
      clearDocumentCanaryInCiphertext: contains(frame, documentPath),
      clearOperationCanaryInCiphertext: contains(frame, canary),
      clearSigningIdentityInCiphertext: contains(frame, signer),
      routingLabelContainsDocumentPath: topics.some((topic) =>
        topic.includes(documentPath),
      ),
      visibleEpochIdentifierBytes: frame
        .slice(0, epochId.length)
        .every((value, index) => value === epochId[index])
        ? epochId.length
        : 0,
      signalingFingerprintLines: connection.signaling.reduce(
        (sum, sdp) => sum + (sdp.match(/^a=fingerprint:/gm)?.length ?? 0),
        0,
      ),
      signalingContainsDocumentCanary: connection.signaling.some((sdp) =>
        sdp.includes(documentPath),
      ),
      candidateCount: connection.signaling.reduce(
        (sum, sdp) => sum + (sdp.match(/^a=candidate:/gm)?.length ?? 0),
        0,
      ),
      encryptedFrameBytes: frame.byteLength,
      nativeRTCTransferApplied:
        target.document.document.getMap('root').get('privateField') === canary,
    };
    assert(
      metadata.nativeRTCTransferApplied,
      'Transferred state must match the synthetic operation',
    );
    return {
      scope:
        'Native ordered RTC carries the unchanged production encrypted envelope. Pubsub topic observed at the document publication boundary before libp2p Noise; native SDP observed before signaling encryption. Not a packet capture of shipped libp2p/WebRTC signaling.',
      metrics: metadata,
      gaps: [
        ...(metadata.routingLabelContainsDocumentPath
          ? [
              'The publication routing label contains the document path outside the group-encrypted envelope. Noise may protect it in transit, but this label is visible at the pubsub/relay boundary.',
            ]
          : []),
        ...(metadata.visibleEpochIdentifierBytes
          ? [
              'The clear epoch identifier links frames from the same epoch. Fully opaque transaction framing is not established.',
            ]
          : []),
        'Native signaling exposes transport fingerprints/candidates. The complete shipped signaling pipeline and passive on-wire anonymity are not established by this carrier-level probe.',
      ],
    };
  } finally {
    for (const pc of resources) pc.close();
    await target?.close();
    await source.close();
  }
}
