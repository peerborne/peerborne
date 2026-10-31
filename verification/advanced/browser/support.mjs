export const assert = (condition, label) => {
  if (!condition) throw new Error(label);
};
export const turn = () => new Promise((resolve) => setTimeout(resolve, 0));
export const paint = () =>
  new Promise((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(resolve)),
  );
export function deadline(
  promise,
  ms = 15000,
  label = 'Bounded browser operation exceeded its deadline',
) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}
export async function until(predicate, ms = 15000, label) {
  return deadline(
    (async () => {
      while (!predicate()) await turn();
    })(),
    ms,
    label,
  );
}
export function distribution(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return {
    count: values.length,
    p50: sorted.length ? sorted[Math.ceil(sorted.length * 0.5) - 1] : null,
    p95: sorted.length ? sorted[Math.ceil(sorted.length * 0.95) - 1] : null,
    p99: sorted.length ? sorted[Math.ceil(sorted.length * 0.99) - 1] : null,
    max: sorted.at(-1) ?? null,
  };
}
export async function measure(operation) {
  const frames = [];
  const timers = [];
  const longTasks = [];
  let frameAt = performance.now();
  let timerAt = frameAt;
  let running = true;
  const raf = () => {
    if (!running) return;
    const now = performance.now();
    frames.push(now - frameAt);
    frameAt = now;
    requestAnimationFrame(raf);
  };
  const observer = new PerformanceObserver((list) =>
    longTasks.push(...list.getEntries().map(({ duration }) => duration)),
  );
  observer.observe({ entryTypes: ['longtask'] });
  requestAnimationFrame(raf);
  const timer = setInterval(() => {
    const now = performance.now();
    timers.push(now - timerAt);
    timerAt = now;
  }, 1);
  const start = performance.now();
  try {
    const value = await operation();
    await paint();
    longTasks.push(...observer.takeRecords().map(({ duration }) => duration));
    return {
      value,
      elapsedMs: performance.now() - start,
      animationFrameGapMs: distribution(frames),
      timerGapMs: distribution(timers),
      longTasksMs: distribution(longTasks),
      jsHeapUsedBytes: performance.memory?.usedJSHeapSize ?? null,
    };
  } finally {
    running = false;
    clearInterval(timer);
    observer.disconnect();
  }
}

export async function pair(resources) {
  const a = new RTCPeerConnection({ iceServers: [] });
  resources.push(a);
  const b = new RTCPeerConnection({ iceServers: [] });
  resources.push(b);
  const ca = [];
  const cb = [];
  a.onicecandidate = ({ candidate }) => {
    if (candidate) ca.push(candidate);
  };
  b.onicecandidate = ({ candidate }) => {
    if (candidate) cb.push(candidate);
  };
  const left = a.createDataChannel('peerborne-advanced', { ordered: true });
  left.binaryType = 'arraybuffer';
  const gotRight = new Promise((resolve) => {
    b.ondatachannel = ({ channel }) => {
      channel.binaryType = 'arraybuffer';
      resolve(channel);
    };
  });
  await a.setLocalDescription(await a.createOffer());
  await b.setRemoteDescription(a.localDescription);
  await b.setLocalDescription(await b.createAnswer());
  await a.setRemoteDescription(b.localDescription);
  const gather = (pc) =>
    pc.iceGatheringState === 'complete'
      ? Promise.resolve()
      : new Promise((resolve) =>
          pc.addEventListener('icegatheringstatechange', () => {
            if (pc.iceGatheringState === 'complete') resolve();
          }),
        );
  await deadline(Promise.all([gather(a), gather(b)]));
  await Promise.all([
    ...ca.map((candidate) => b.addIceCandidate(candidate)),
    ...cb.map((candidate) => a.addIceCandidate(candidate)),
  ]);
  const right = await deadline(gotRight);
  const open = (channel) =>
    channel.readyState === 'open'
      ? Promise.resolve()
      : new Promise((resolve, reject) => {
          channel.onopen = resolve;
          channel.onerror = () =>
            reject(new Error('Native RTC channel failed'));
        });
  await deadline(Promise.all([open(left), open(right)]));
  return {
    left,
    right,
    a,
    b,
    signaling: [a.localDescription.sdp, b.localDescription.sdp],
  };
}

export function contains(bytes, marker) {
  const target =
    typeof marker === 'string' ? new TextEncoder().encode(marker) : marker;
  outer: for (
    let offset = 0;
    offset <= bytes.length - target.length;
    offset++
  ) {
    for (let i = 0; i < target.length; i++)
      if (bytes[offset + i] !== target[i]) continue outer;
    return true;
  }
  return false;
}
