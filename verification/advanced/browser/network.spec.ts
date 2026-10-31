import {
  test,
  expect,
  type Page,
  type Browser,
  type BrowserContext,
  type TestInfo,
  type CDPSession,
} from '@playwright/test';
import { mkdir, writeFile, readdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { catalog, options } from '../catalog.mjs';

const settings = options();
const definitions = (await catalog()).filter(
  (item) => item.driver === 'network',
);
const execute = promisify(execFile);
async function kernelLoss(page: Page) {
  const own = await execute('sudo', ['-n', 'readlink', '/proc/self/ns/net']);
  const initial = await execute('sudo', ['-n', 'readlink', '/proc/1/ns/net']);
  if (
    process.platform !== 'linux' ||
    own.stdout.trim() === initial.stdout.trim()
  )
    throw new Error(
      'Kernel loss requires the private namespace created by run-netem.sh',
    );
  await execute('ip', ['link', 'show', 'pbverify0']);
  const ports: number[] = await call(page, 'candidatePorts');
  expect(
    ports.length,
    'slow peer must expose actual native UDP candidate ports',
  ).toBeGreaterThan(0);
  for (const port of ports) {
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      throw new Error('Invalid native UDP port');
    for (const direction of ['sport', 'dport'])
      await execute('sudo', [
        '-n',
        'tc',
        'filter',
        'add',
        'dev',
        'lo',
        'protocol',
        'ip',
        'parent',
        '1:',
        'prio',
        '1',
        'u32',
        'match',
        'ip',
        'protocol',
        '17',
        '0xff',
        'match',
        'ip',
        direction,
        String(port),
        '0xffff',
        'flowid',
        '1:3',
      ]);
  }
  return {
    portCount: ports.length,
    async set(percent: number) {
      await execute('sudo', [
        '-n',
        'tc',
        'qdisc',
        'change',
        'dev',
        'lo',
        'parent',
        '1:3',
        'handle',
        '30:',
        'netem',
        'loss',
        'random',
        `${percent}%`,
        'seed',
        String(settings.seed),
      ]);
    },
    async stats() {
      const { stdout } = await execute('sudo', [
        'tc',
        '-j',
        '-s',
        'qdisc',
        'show',
        'dev',
        'lo',
      ]);
      const queue = JSON.parse(stdout).find(
        (entry: any) => entry.kind === 'netem',
      );
      return {
        packets: queue?.packets ?? null,
        dropped: queue?.drops ?? null,
        backlogBytes: queue?.backlog ?? null,
      };
    },
  };
}
const call = (page: Page, method: string, args: any[] = []): Promise<any> =>
  page.evaluate(
    async ({ method, args }) => {
      const path = '/network.mjs';
      const module = await import(path);
      return module[method](...args);
    },
    { method, args },
  );
const percentile = (values: number[], fraction: number) =>
  [...values].sort((a, b) => a - b)[Math.ceil(values.length * fraction) - 1] ??
  null;
async function save(info: TestInfo, definition: any, observation: any) {
  const path = resolve(
    info.config.rootDir,
    '../../results/advanced',
    settings.profile,
    `${definition.id}-report.json`,
  );
  const result = {
    ...definition,
    ...settings,
    ...observation,
    status: observation.status ?? (observation.gaps.length ? 'gap' : 'passed'),
  };
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(result, null, 2)}\n`);
  await info.attach(`${definition.id}-report.json`, {
    path,
    contentType: 'application/json',
  });
  if (settings.strict)
    expect(
      observation.gaps,
      'strict acceptance rejects missing guarantees',
    ).toEqual([]);
}
async function cluster(browser: Browser, count: number) {
  const contexts: BrowserContext[] = [];
  const pages: Page[] = [];
  const sessions: CDPSession[] = [];
  for (let i = 0; i < count; i++) {
    const context = await browser.newContext({
      baseURL: 'http://127.0.0.1:4188',
    });
    contexts.push(context);
    const page = await context.newPage();
    pages.push(page);
    await page.goto('/');
    const session = await context.newCDPSession(page);
    sessions.push(session);
    await session.send('Performance.enable');
  }
  return {
    pages,
    sessions,
    async close() {
      await Promise.allSettled(pages.map((page) => call(page, 'close')));
      await Promise.all(contexts.map((context) => context.close()));
    },
  };
}
async function connect(
  pages: Page[],
  owner: (index: number) => number,
  a: number,
  b: number,
) {
  const offer = await call(pages[owner(a)], 'offer', [a, b]);
  const answer = await call(pages[owner(b)], 'answer', [b, a, offer]);
  await call(pages[owner(a)], 'accept', [a, b, answer]);
  await Promise.all([
    call(pages[owner(a)], 'opened', [a, b]),
    call(pages[owner(b)], 'opened', [b, a]),
  ]);
}
async function cpu(sessions: CDPSession[]) {
  return Promise.all(
    sessions.map(async (session) => {
      const { metrics } = await session.send('Performance.getMetrics');
      const values = Object.fromEntries(
        metrics.map(({ name, value }) => [name, value]),
      );
      return {
        taskSeconds: values.TaskDuration ?? null,
        scriptSeconds: values.ScriptDuration ?? null,
        heapBytes: values.JSHeapUsedSize ?? null,
      };
    }),
  );
}
async function descriptors(browser: Browser) {
  const session = await browser.newBrowserCDPSession();
  try {
    const { processInfo } = await session.send('SystemInfo.getProcessInfo');
    const counts = await Promise.all(
      processInfo.map(async ({ id, type }) => {
        let openFileDescriptors: number | null = null;
        try {
          if (process.platform === 'linux')
            openFileDescriptors = (await readdir(`/proc/${id}/fd`)).length;
          else if (process.platform === 'darwin') {
            const { stdout } = await execute(
              '/usr/sbin/lsof',
              ['-a', '-p', String(id), '-Ff'],
              { timeout: 5000, maxBuffer: 1024 * 1024 },
            );
            openFileDescriptors = stdout
              .split('\n')
              .filter((line) => /^f\d/.test(line)).length;
          }
        } catch {}
        return { type, openFileDescriptors };
      }),
    );
    return {
      processCount: counts.length,
      observedOpenFileDescriptors: counts.some(
        (item) => item.openFileDescriptors !== null,
      )
        ? counts.reduce((sum, item) => sum + (item.openFileDescriptors ?? 0), 0)
        : null,
      processes: counts,
    };
  } finally {
    await session.detach();
  }
}
async function waitForState(
  pages: Page[],
  expected: number,
  ids?: number[],
  timeout = 30000,
  drain = false,
) {
  const stop = performance.now() + timeout;
  while (true) {
    const nodes = (
      await Promise.all(pages.map((page) => call(page, 'status')))
    ).flat();
    expect(
      nodes.reduce((sum, node) => sum + node.receiveFailures, 0),
      'authenticated receive failures',
    ).toBe(0);
    if (
      nodes
        .filter((node) => !ids || ids.includes(node.id))
        .every((node) => node.operations === expected) &&
      (!drain ||
        nodes.reduce((sum, node) => sum + node.receivedFrames, 0) ===
          nodes.reduce((sum, node) => sum + node.sentFrames, 0))
    )
      return nodes;
    if (performance.now() >= stop) return null;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

async function mesh(browser: Browser) {
  const group = await cluster(browser, 5);
  const owner = (id: number) => id % group.pages.length;
  const stages: any[] = [];
  let capacityFailure: any = null;
  let baseline: number | null = null;
  let firstLatencyDegradation: number | null = null;
  const maximum = settings.full ? 50 : 6;
  try {
    for (let count = 5; count <= maximum; count++) {
      const rounds = settings.full ? 2 : 1;
      const bootstrap = await call(group.pages[0], 'seed', [settings]);
      await Promise.all(
        group.pages.map((page, shard) =>
          call(page, 'reset', [
            bootstrap,
            Array.from({ length: count }, (_, id) => id).filter(
              (id) => owner(id) === shard,
            ),
            count * rounds,
          ]),
        ),
      );
      const links: [number, number][] = [];
      if (count === 5) {
        for (let a = 0; a < count; a++)
          for (let b = a + 1; b < count; b++) links.push([a, b]);
      } else for (let a = 0; a < count - 1; a++) links.push([a, count - 1]);
      try {
        for (let offset = 0; offset < links.length; offset += 8)
          await Promise.all(
            links
              .slice(offset, offset + 8)
              .map(([a, b]) => connect(group.pages, owner, a, b)),
          );
      } catch {
        capacityFailure = {
          peers: count,
          stage: 'connection-setup',
          intendedUndirectedLinks: (count * (count - 1)) / 2,
        };
        break;
      }
      const before = await cpu(group.sessions);
      const started = Date.now();
      await Promise.all(
        group.pages.map((page, shard) =>
          call(page, 'mutate', [
            rounds,
            Array.from({ length: count }, (_, id) => id).filter(
              (id) => owner(id) === shard,
            ),
          ]),
        ),
      );
      const nodes = await waitForState(
        group.pages,
        count * rounds,
        undefined,
        60000,
        true,
      );
      if (!nodes) {
        capacityFailure = {
          peers: count,
          stage: 'convergence-deadline',
          intendedUndirectedLinks: (count * (count - 1)) / 2,
        };
        break;
      }
      const durations = nodes.map((node) =>
        Math.max(0, node.completedAt - started),
      );
      const after = await cpu(group.sessions);
      const native = await Promise.all(
        group.pages.map((page) => call(page, 'stats')),
      );
      const p95 = percentile(durations, 0.95);
      if (baseline === null) baseline = p95;
      const budget = Math.max(100, (baseline ?? 0) * 3);
      if (p95 !== null && p95 > budget && firstLatencyDegradation === null)
        firstLatencyDegradation = count;
      const stage = {
        peers: count,
        rounds,
        undirectedLinks: (count * (count - 1)) / 2,
        sentFrames: nodes.reduce((sum, node) => sum + node.sentFrames, 0),
        receivedFrames: nodes.reduce(
          (sum, node) => sum + node.receivedFrames,
          0,
        ),
        ciphertextBytes: nodes.reduce((sum, node) => sum + node.sentBytes, 0),
        convergenceLatencyMs: {
          p50: percentile(durations, 0.5),
          p95,
          max: Math.max(...durations),
        },
        degradationBudgetMs: budget,
        rendererTaskMs: after.reduce(
          (sum, value, index) =>
            sum + 1000 * (value.taskSeconds - before[index].taskSeconds),
          0,
        ),
        rendererScriptMs: after.reduce(
          (sum, value, index) =>
            sum + 1000 * (value.scriptSeconds - before[index].scriptSeconds),
          0,
        ),
        rendererHeapBytes: after.reduce(
          (sum, value) => sum + value.heapBytes,
          0,
        ),
        decoderCalls: nodes.reduce((sum, node) => sum + node.codecCalls, 0),
        decoderCpuMs: nodes.reduce((sum, node) => sum + node.codecMs, 0),
        maxDecoderMs: Math.max(...nodes.map((node) => node.maxCodecMs)),
        nativePeerConnectionEndpoints: native.reduce(
          (sum, value) => sum + value.nativePeerConnectionEndpoints,
          0,
        ),
        nativeDataChannelsOpened: native.reduce(
          (sum, value) => sum + value.nativeDataChannelsOpened,
          0,
        ),
        udpCandidateEntries: native.reduce(
          (sum, value) => sum + value.udpCandidateEntries,
          0,
        ),
        selectedCandidatePairs: native.reduce(
          (sum, value) => sum + value.selectedCandidatePairs,
          0,
        ),
        fileDescriptors: await descriptors(browser),
        converged: true,
      };
      expect(stage.sentFrames).toBe(count * (count - 1) * rounds);
      expect(stage.receivedFrames).toBe(stage.sentFrames);
      stages.push(stage);
      process.stdout.write(
        `mesh-saturation: ${count} peers, p95 ${p95?.toFixed(1)} ms\n`,
      );
    }
    expect(
      stages.length,
      'the initial five-peer workload must complete',
    ).toBeGreaterThan(0);
    return {
      scope:
        'Native ordered RTC endpoints distributed across five browser contexts (up to ten document peers per renderer), actual Peerborne encryption/signing/CRDT ingress. Full mode adds each population from 5 through 50. The explicit mesh, signaling and bootstrap are fixture code.',
      metrics: {
        requestedPeers: maximum,
        highestConvergedPopulation: stages.at(-1)?.peers,
        firstLatencyDegradation,
        capacityFailure,
        thresholdRule:
          'First observed stage exceeding max(100ms, 3x five-peer p95), under this runner and workload; not a universal product threshold.',
        stages,
      },
      gaps: [
        ...(capacityFailure
          ? [
              'The native carrier hit a measured connection/convergence limit; full target population did not complete.',
            ]
          : []),
        'Shipped libp2p topology selection and automatic tree/relay fallback are not exercised. No automatic fallback is supplied by the fixture. UDP candidate counts are not exact OS socket counts, and unavailable descriptor measurements remain null. Browser contexts may share OS processes.',
      ],
    };
  } finally {
    await group.close();
  }
}

async function slowPeer(browser: Browser) {
  const group = await cluster(browser, 2);
  const owner = (id: number) => (id === 0 ? 0 : 1);
  const ids = [[0], [1, 2, 3]];
  const rounds = settings.full ? 32 : 8;
  const expected = 3 * rounds;
  let emulationAccepted = false;
  let kernel: Awaited<ReturnType<typeof kernelLoss>> | undefined;
  try {
    const bootstrap = await call(group.pages[0], 'seed', [settings]);
    await Promise.all(
      group.pages.map((page, index) =>
        call(page, 'reset', [bootstrap, ids[index], expected]),
      ),
    );
    for (let a = 0; a < 4; a++)
      for (let b = a + 1; b < 4; b++) await connect(group.pages, owner, a, b);
    const baselineStarted = performance.now();
    await call(group.pages[1], 'mutate', [rounds, ids[1]]);
    expect(
      await waitForState(group.pages, expected, undefined, 30000, true),
    ).not.toBeNull();
    const baselineMs = performance.now() - baselineStarted;
    await Promise.all(
      group.pages.map((page, index) =>
        call(page, 'reset', [bootstrap, ids[index], expected]),
      ),
    );
    await call(group.pages[0], 'probe', [0, 1, 10]);
    await expect
      .poll(async () => (await call(group.pages[1], 'status'))[0].probeReceipts)
      .toBe(10);
    const condition = {
      offline: false,
      latency: 20,
      downloadThroughput: 32768,
      uploadThroughput: 32768,
    };
    let duringBlackout = 10;
    try {
      if (process.env.PEERBORNE_VERIFY_NETEM === 'isolated') {
        kernel = await kernelLoss(group.pages[0]);
        await kernel.set(100);
      } else {
        await group.sessions[0].send('Network.enable');
        await group.sessions[0].send('Network.emulateNetworkConditionsByRule', {
          offline: false,
          matchedNetworkConditions: [
            { ...condition, urlPattern: '', packetLoss: 100 },
          ],
        });
      }
      emulationAccepted = true;
      await call(group.pages[0], 'probe', [0, 1, 10]);
      await new Promise((resolve) => setTimeout(resolve, 1000));
      duringBlackout =
        (await call(group.pages[1], 'status'))[0].probeReceipts - 10;
      if (kernel) await kernel.set(80);
      else
        await group.sessions[0].send('Network.emulateNetworkConditionsByRule', {
          offline: false,
          matchedNetworkConditions: [
            { ...condition, urlPattern: '', packetLoss: 80 },
          ],
        });
    } catch (error) {
      if (process.env.PEERBORNE_VERIFY_NETEM === 'isolated') throw error;
    }
    const before = await cpu(group.sessions);
    const started = performance.now();
    await call(group.pages[1], 'mutate', [rounds, ids[1]]);
    const healthy = await waitForState(group.pages, expected, ids[1], 30000);
    const elapsedMs = performance.now() - started;
    expect(
      healthy,
      'healthy peers must converge within their independent deadline',
    ).not.toBeNull();
    const native = await Promise.all(
      group.pages.map((page) => call(page, 'stats')),
    );
    const after = await cpu(group.sessions);
    const lossEnforcementObserved = emulationAccepted && duringBlackout === 0;
    const kernelCounters = kernel ? await kernel.stats() : null;
    if (kernel) {
      expect(
        lossEnforcementObserved,
        'kernel blackout must stop native SCTP probe delivery',
      ).toBe(true);
      expect(
        kernelCounters?.dropped,
        'kernel must count actual dropped datagrams',
      ).toBeGreaterThan(0);
    }
    return {
      scope:
        'Four actual document replicas over native ordered SCTP channels. The slow peer occupies a separate browser context/CDP target; three healthy peers make independent mutations. Native loss emulation is checked with a 100% blackout control before configuring 80%. Fixture sends directly per channel; this does not prove shipped libp2p queue isolation.',
      metrics: {
        peers: 4,
        rounds,
        ordered: true,
        configuredPacketLossPercent: emulationAccepted ? 80 : null,
        baselineProbeReceipts: 10,
        blackoutProbeReceipts: duringBlackout,
        lossEnforcementObserved,
        lossBackend: kernel
          ? 'Linux netem in a private network namespace'
          : 'Chromium CDP global P2P rule',
        kernelCounters,
        classifiedNativeUdpPorts: kernel?.portCount ?? null,
        baselineConvergenceMs: baselineMs,
        healthyConvergenceMs: elapsedMs,
        healthyToBaselineRatio: elapsedMs / baselineMs,
        healthyConverged: true,
        slowOperations: native[0].peers[0].operations,
        expectedOperations: expected,
        maxSlowBufferedBytes: Math.max(
          ...native[1].peers.map((node: any) => node.maxBufferedBytes),
        ),
        native,
        rendererTaskMs: after.reduce(
          (sum, value, index) =>
            sum + 1000 * (value.taskSeconds - before[index].taskSeconds),
          0,
        ),
      },
      gaps: [
        ...(!lossEnforcementObserved
          ? [
              'CDP packet-loss enforcement was not observed in the blackout control. Results cannot establish SCTP behavior under real 80% packet loss.',
            ]
          : []),
        'The fixture uses direct per-channel sends; no production libp2p backpressure or slow-peer isolation policy is established. Browser SCTP retransmission/loss counters and a seeded native loss schedule are unavailable; accepted CDP configuration is not an exact measured packet-loss percentage.',
      ],
    };
  } finally {
    if (kernel) await kernel.set(0);
    try {
      await group.sessions[0].send('Network.emulateNetworkConditionsByRule', {
        offline: false,
        matchedNetworkConditions: [],
      });
    } catch {}
    await group.close();
  }
}

for (const definition of definitions)
  test(`${definition.id}: ${definition.name}`, async ({ browser }, info) => {
    let observation;
    try {
      observation =
        definition.id === 'mesh-saturation'
          ? await mesh(browser)
          : await slowPeer(browser);
    } catch (error) {
      await save(info, definition, {
        scope: 'Browser transport workload did not complete.',
        metrics: {},
        gaps: [],
        status: 'failed',
      });
      throw error;
    }
    await save(info, definition, observation);
  });
