import {
  chromium,
  expect,
  test,
  type Browser,
  type Page,
  type TestInfo,
} from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const endpoints = [
  process.env.BROWSER_A_WS ?? 'ws://127.0.0.1:3101/',
  process.env.BROWSER_B_WS ?? 'ws://127.0.0.1:3102/',
];
let reported = false;
const reportPath = (info: TestInfo) =>
  resolve(info.config.rootDir, '../results/reports/full/nat/relay-report.json');

test.afterEach(async ({}, info) => {
  if (info.status === info.expectedStatus || reported) return;
  const file = reportPath(info);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(
    file,
    JSON.stringify(
      {
        id: 'relay',
        status: 'failed',
        profile: 'full',
        error: 'NAT workload did not complete; see Playwright failure.',
      },
      null,
      2,
    ),
  );
});

async function traffic(page: Page) {
  return page.evaluate(() => ({ ...(window as any).__TECHNICAL_TRAFFIC__ }));
}

test('STUN-disabled cross-NAT encrypted document load profiles Circuit Relay traffic', async ({}, info) => {
  const browsers: Browser[] = [];
  try {
    browsers.push(await chromium.connect(endpoints[0]));
    browsers.push(await chromium.connect(endpoints[1]));
    const contexts = await Promise.all(
      browsers.map((browser) => browser.newContext()),
    );
    const pages = await Promise.all(
      contexts.map((context) => context.newPage()),
    );
    const pageErrors = [0, 0];
    pages.forEach((page, index) =>
      page.on('pageerror', () => {
        pageErrors[index]++;
      }),
    );
    await Promise.all(
      pages.map((page) =>
        page.addInitScript(() => {
          // The example's Redux logger dumps state, including keychain state.
          // Keep that test-only state out of the remote browser console.
          for (const level of [
            'log',
            'debug',
            'info',
            'warn',
            'error',
          ] as const) {
            console[level] = () => {};
          }
          const counters = {
            sentBytes: 0,
            receivedBytes: 0,
            sentFrames: 0,
            receivedFrames: 0,
            rtcConstructions: 0,
          };
          (window as any).__TECHNICAL_TRAFFIC__ = counters;
          const byteLength = (data: any) =>
            typeof data === 'string'
              ? new TextEncoder().encode(data).byteLength
              : (data.byteLength ?? data.size ?? 0);
          const Socket = WebSocket;
          class MeteredSocket extends Socket {
            constructor(...args: ConstructorParameters<typeof WebSocket>) {
              super(...args);
              this.addEventListener('message', ({ data }) => {
                counters.receivedBytes += byteLength(data);
                counters.receivedFrames++;
              });
            }
            send(data: string | ArrayBufferLike | Blob | ArrayBufferView) {
              counters.sentBytes += byteLength(data);
              counters.sentFrames++;
              return super.send(data);
            }
          }
          window.WebSocket = MeteredSocket;
          const RTC = RTCPeerConnection;
          window.RTCPeerConnection = class extends RTC {
            constructor(configuration?: RTCConfiguration) {
              // Remove STUN and TURN configuration in every transport construction.
              const blocked = { ...configuration, iceServers: [] };
              super(blocked);
              counters.rtcConstructions++;
              this.setConfiguration = (config) =>
                RTC.prototype.setConfiguration.call(this, {
                  ...config,
                  iceServers: [],
                });
            }
          };
        }),
      ),
    );
    await Promise.all(
      pages.map(async (page) => {
        await page.goto('http://localhost:8080');
        await page.waitForFunction(
          () => Boolean((window as any).__PEERBORNE_TEST__?.state().node),
          undefined,
          { timeout: 90_000 },
        );
      }),
    );
    const fingerprints = await Promise.all(
      pages.map((page) =>
        page.evaluate(() =>
          (window as any).__PEERBORNE_TEST__.identityFingerprint(),
        ),
      ),
    );
    expect(fingerprints[0]).not.toBe(fingerprints[1]);
    await Promise.all(
      pages.map((page) =>
        expect
          .poll(
            () =>
              page.evaluate(() =>
                (window as any).__PEERBORNE_TEST__.circuitAddress(),
              ),
            { timeout: 90_000, intervals: [250, 500, 1000] },
          )
          .not.toBeUndefined(),
      ),
    );
    const address = await pages[0].evaluate(() =>
      (window as any).__PEERBORNE_TEST__.circuitAddress(),
    );
    expect(address).toContain('/p2p-circuit/');
    await Promise.all(
      pages.map((page) =>
        page.evaluate(() => {
          const libp2p = (window as any).__PEERBORNE_TEST__.state().node.libp2p;
          const routes: any[] = [];
          (window as any).__TECHNICAL_ROUTES__ = routes;
          const observe = (connection: any) =>
            routes.push({
              direct: connection.direct,
              circuitAddress: connection.remoteAddr
                .toString()
                .includes('/p2p-circuit/'),
              protocols: connection.remoteAddr
                .getComponents()
                .map((component: any) => component.name),
            });
          for (const connection of libp2p.getConnections()) observe(connection);
          libp2p.addEventListener('connection:open', (event: any) =>
            observe(event.detail),
          );
        }),
      ),
    );
    await expect
      .poll(
        () =>
          pages[1].evaluate(async (target) => {
            try {
              await (window as any).__PEERBORNE_TEST__.connect([target]);
              return true;
            } catch {
              return false;
            }
          }, address),
        { timeout: 90_000, intervals: [500, 1000] },
      )
      .toBe(true);

    const payloadBytes = 64 * 1024;
    const path = '/technical-relay-profile';
    // Synthetic and deterministic; no application document data is exported.
    await pages[0].evaluate(
      async ([documentPath, length]) => {
        const api = (window as any).__PEERBORNE_TEST__;
        await api.create(documentPath);
        await api.change(
          documentPath,
          'payload',
          'relay-probe-'.repeat(Math.ceil(length / 12)).slice(0, length),
        );
      },
      [path, payloadBytes] as const,
    );
    const offer = await pages[0].evaluate(
      (documentPath) =>
        (window as any).__PEERBORNE_TEST__.createInvitation(documentPath),
      path,
    );
    const before = await Promise.all(pages.map(traffic));
    const started = performance.now();
    await pages[1].evaluate(
      (encodedOffer) =>
        (window as any).__PEERBORNE_TEST__.acceptInvitation(encodedOffer),
      offer,
    );
    await expect
      .poll(
        () =>
          pages[1].evaluate(
            ([documentPath, length]) =>
              (window as any).__PEERBORNE_TEST__.state().documents[documentPath]
                ?.document?.payload ===
              'relay-probe-'.repeat(Math.ceil(length / 12)).slice(0, length),
            [path, payloadBytes] as const,
          ),
        { timeout: 60_000 },
      )
      .toBe(true);
    const elapsedMs = performance.now() - started;
    const after = await Promise.all(pages.map(traffic));
    const routes = await Promise.all(
      pages.map((page) =>
        page.evaluate(() => (window as any).__TECHNICAL_ROUTES__),
      ),
    );
    await info.attach('route-observations.json', {
      body: Buffer.from(JSON.stringify(routes)),
      contentType: 'application/json',
    });
    expect(
      routes
        .flat()
        .some((route: any) => route.circuitAddress || route.direct === false),
      'actual relayed connection must be observed, including short-lived connections',
    ).toBe(true);
    expect(pageErrors).toEqual([0, 0]);
    const gaps = [
      'Circuit Relay v2 is exercised; this is not a TURN deployment or proof of a zero-knowledge architecture.',
      'Docker network isolation plus disabled ICE servers forces a relayed route, not an emulation of symmetric NAT mapping/filtering behavior or automatic fallback after STUN timeout.',
      'A matched direct-path baseline is absent. Measured load latency and WebSocket bytes include protocol overhead and background traffic, so relay-only overhead cannot be isolated.',
    ];
    const result = {
      id: 'relay',
      status: 'gap',
      profile: 'full',
      scope:
        'Real Peerborne/Automerge load between two NAT-isolated Chromium processes. Distinct synthetic identities join through the public authenticated invitation API.',
      metrics: {
        payloadBytes,
        invitationWireBytes: offer.length,
        documentLoadMs: elapsedMs,
        latencyOverheadVsDirectMs: null,
        bytesScope:
          'Browser WebSocket bytes at both endpoints, including protocol/background traffic; not IP packet capture.',
        peers: after.map((value, index) => ({
          sentBytes: value.sentBytes - before[index].sentBytes,
          receivedBytes: value.receivedBytes - before[index].receivedBytes,
          sentFrames: value.sentFrames - before[index].sentFrames,
          receivedFrames: value.receivedFrames - before[index].receivedFrames,
          rtcConstructions: value.rtcConstructions,
        })),
        circuitConnectionObserved: true,
        routeObservations: routes,
      },
      gaps,
    };
    const file = reportPath(info);
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify(result, null, 2));
    await info.attach('relay-report.json', {
      path: file,
      contentType: 'application/json',
    });
    reported = true;
    for (const gap of gaps)
      info.annotations.push({ type: 'capability-gap', description: gap });
    if (process.env.PEERBORNE_VERIFY_STRICT === '1') expect(gaps).toEqual([]);
  } finally {
    await Promise.all(browsers.map((browser) => browser.close()));
  }
});
