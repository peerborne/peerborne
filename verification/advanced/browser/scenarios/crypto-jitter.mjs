import {
  documentFixture,
  replicaOf,
  syntheticText,
} from '../../../fixtures.mjs';
import {
  assert,
  pair,
  until,
  paint,
  measure,
  distribution,
} from '../support.mjs';

export const id = 'crypto-jitter';
export async function run({ full, seed }) {
  const source = await documentFixture();
  let target;
  const resources = [];
  let sampling = true;
  let frameWork = 0;
  const perFrameWork = [];
  try {
    target = await replicaOf(source, 2);
    const link = await pair(resources);
    const frames = [];
    const count = full ? 2048 : 64;
    const payloadBytes = full ? 4096 : 1024;
    let rawDocument = source.provider.newDocument();
    rawDocument.clientID = 9000;
    const [epoch, key] = await source.document._keychain.current();
    // Generate a bounded stream of individual, valid signed CRDT deltas.
    // This controls incoming load, rather than benchmarking growing sender DAGs.
    for (let i = 0; i < count; i++) {
      let delta;
      [rawDocument, delta] = source.provider.localChange(
        rawDocument,
        '',
        (doc) => {
          doc.getMap('root').set('streamCounter', i);
          doc
            .getMap('root')
            .set('streamPayload', syntheticText(payloadBytes, seed + i));
        },
      );
      const message = {
        documentId: source.document.documentPath,
        signatureContext: 'ordinary-sync-v1',
        changeId: await source.document._putBlock(delta),
        changes: { kind: 'document', change: delta },
      };
      message.signature = await source.document._signAsWriter(message);
      const encrypted = await source.auth.encrypt(
        source.serializer.serializeSyncMessage(message),
        key,
      );
      const bytes = new Uint8Array(
        epoch.length + encrypted.nonce.length + encrypted.data.length,
      );
      bytes.set(epoch);
      bytes.set(encrypted.nonce, epoch.length);
      bytes.set(encrypted.data, epoch.length + encrypted.nonce.length);
      frames.push(bytes);
    }
    rawDocument.destroy();
    const workerConstructionsBefore =
      window.advancedWorkerConstructions ?? null;
    const spans = {
      deserialize: [],
      apply: [],
      cryptoDispatch: [],
      cryptoSettled: [],
    };
    const wrap = (object, method, collection) => {
      const original = object[method].bind(object);
      object[method] = (...args) => {
        const start = performance.now();
        try {
          return original(...args);
        } finally {
          const elapsed = performance.now() - start;
          collection.push(elapsed);
          frameWork += elapsed;
        }
      };
    };
    wrap(target.serializer, 'deserializeSyncMessage', spans.deserialize);
    wrap(target.provider, 'remoteChange', spans.apply);
    const decrypt = target.auth.decrypt.bind(target.auth);
    target.auth.decrypt = (...args) => {
      const start = performance.now();
      const pending = decrypt(...args);
      const elapsed = performance.now() - start;
      spans.cryptoDispatch.push(elapsed);
      frameWork += elapsed;
      return pending.finally(() =>
        spans.cryptoSettled.push(performance.now() - start),
      );
    };
    let received = 0;
    link.right.onmessage = ({ data }) => {
      received++;
      target.document._pubsubHandler(
        new CustomEvent('message', {
          detail: { topic: target.document._topic, data: new Uint8Array(data) },
        }),
      );
    };
    const baseline = await measure(
      () => new Promise((resolve) => setTimeout(resolve, 200)),
    );
    const sample = () => {
      if (!sampling) return;
      perFrameWork.push(frameWork);
      frameWork = 0;
      requestAnimationFrame(sample);
    };
    requestAnimationFrame(sample);
    const started = performance.now();
    const timing = await measure(async () => {
      for (let offset = 0; offset < frames.length; offset += 8) {
        await paint();
        for (const bytes of frames.slice(offset, offset + 8)) {
          assert(
            bytes.length <= link.a.sctp.maxMessageSize,
            'jitter load frame must fit the native RTC message limit',
          );
          link.left.send(bytes);
        }
        document.querySelector('#state').textContent = String(offset);
      }
      await until(
        () =>
          target.document.document.getMap('root').get('streamCounter') ===
            count - 1 && received === count,
        60000,
        'streamed encrypted deltas did not converge',
      );
    });
    assert(
      spans.deserialize.length === count,
      'each authenticated frame must enter the actual deserializer',
    );
    assert(
      spans.apply.length === count,
      'each incoming delta must enter the actual CRDT adapter',
    );
    assert(
      target.document.document.getMap('root').get('streamPayload') ===
        syntheticText(payloadBytes, seed + count - 1),
      'stream state must match its final payload',
    );
    const { value, ...performanceMetrics } = timing;
    const observedWorkOver16ms = perFrameWork.filter(
      (duration) => duration > 16,
    ).length;
    return {
      scope:
        'Pre-generated, individual signed AES-GCM CRDT deltas delivered through native RTC to the real document pubsub handler, decoder and Yjs adapter. The controlled sender envelope is a fixture. Worker construction is instrumented before app load; Web Crypto internal execution threads are opaque.',
      metrics: {
        count,
        payloadBytes,
        ciphertextBytes: frames.reduce((sum, frame) => sum + frame.length, 0),
        elapsedStreamMs: performance.now() - started,
        baselineAnimationFrameGapMs: baseline.animationFrameGapMs,
        ...performanceMetrics,
        observedMainThreadDeserializeCalls: spans.deserialize.length,
        observedMainThreadApplyCalls: spans.apply.length,
        mainThreadDeserializeMs: distribution(spans.deserialize),
        mainThreadApplyMs: distribution(spans.apply),
        cryptoDispatchMs: distribution(spans.cryptoDispatch),
        cryptoPromiseSettlementMs: distribution(spans.cryptoSettled),
        instrumentedWorkPerRenderFrameMs: distribution(perFrameWork),
        observedWorkOver16ms,
        workerConstructionsBefore,
        workerConstructionsAfter: window.advancedWorkerConstructions ?? null,
        converged: true,
      },
      gaps: [
        'Actual raw deserialization and CRDT application run on the window thread in this path. Dedicated Web Worker offload is not established, even when a finite workload stays responsive.',
        ...(observedWorkOver16ms
          ? [
              'Instrumented JavaScript work exceeded the requested 16ms budget in at least one render interval.',
            ]
          : []),
        'Instrumented work covers the measured decoder/adapter/crypto-dispatch spans, not all main-thread work. Native Web Crypto dispatch/settlement does not reveal the browser crypto executor thread. Hardware-dependent frame timing is a measurement, not a universal 60 FPS guarantee.',
      ],
    };
  } finally {
    sampling = false;
    for (const pc of resources) pc.close();
    await target?.close();
    await source.close();
  }
}
