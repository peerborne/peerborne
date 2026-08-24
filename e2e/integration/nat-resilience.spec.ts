/**
 * NAT Traversal Resilience Tests (issue #184)
 *
 * Exercises failure-recovery scenarios for Peerborne peers communicating across
 * isolated NAT-simulated Docker networks. Builds on the topology established
 * by `docker-compose.nat-test.yaml`:
 *
 *   nat-a: [test-app-a (3001), test-app-c (3003), relay]
 *   nat-b: [test-app-b (3002), relay]
 *
 * Cross-NAT traffic between test-app-a and test-app-b MUST flow through the
 * relay. These tests verify that the system tolerates:
 *
 *   1. Relay container restart mid-sync (container churn, recovers via
 *      bootstrap re-dial + fresh config fetch).
 *   2. Browser-side reconnection (page reload on the cross-NAT peer).
 *   3. Browser-side network toggle (Playwright `context.setOffline(true)`
 *      then `setOffline(false)` to simulate a transient network drop).
 *   4. Rapid, concurrent cross-NAT edits without message loss.
 *
 * Many of these scenarios are inherently flaky in CI because GossipSub mesh
 * re-formation through a single relay takes time (10s+) and depends on
 * libp2p's discovery cadence. We use generous timeouts and, where useful,
 * a minimum-success-rate threshold instead of strict equality so the suite
 * stays meaningful without becoming noise.
 *
 * CI gating strategy
 * ------------------
 * To balance signal vs. noise the four scenarios above are gated as follows:
 *
 *   1. Relay restart   — opt-in via `RUN_NAT_RESTART=1`. Restarts docker
 *      services and rebuilds the gossipsub mesh from scratch; the slowest
 *      and most volatile scenario, so it does not run in CI by default.
 *   2. Page reload     — RUNS IN CI. Single-peer reload + cross-NAT message
 *      round-trip; the most stable resilience scenario and the one CI
 *      assertion this suite contributes.
 *   3. Network toggle  — CI-skip. `context.setOffline()` cycling depends on
 *      transport-level reconnection timing through the relay, which has
 *      historically been flaky on shared CI runners.
 *   4. Rapid concurrent — CI-skip. 10-message bidirectional burst with a 60%
 *      delivery threshold; deliberately stress-shaped, expected to be flaky
 *      on shared CI runners.
 *
 * Skipped scenarios run locally with `yarn test:nat` (and `RUN_NAT_RESTART=1
 * yarn test:nat` for the relay restart).
 *
 * Shared helpers (`initPage`, `trackConsole`, etc.) live in
 * `./helpers/nat-helpers.ts` and are also used by `nat-traversal.spec.ts`.
 */
import { execSync } from 'node:child_process';
import { test, expect, type Page } from '@playwright/test';
import {
  initPage,
  rebindConsoleTracker,
  refreshPeerId,
  waitForMesh,
  waitForPeerConnection,
  type PageHandle,
} from './helpers/nat-helpers';

const APP_A_URL = 'http://localhost:3001';
const APP_B_URL = 'http://localhost:3002';

const COMPOSE_FILE = 'docker-compose.nat-test.yaml';

/**
 * Shape of the `messages` array stored on `window` by `e2e/test-app/app.js`.
 * Each entry is a single pubsub-delivered message that the test app rendered.
 */
interface TestAppMessage {
  text: string;
  // Other fields (id, ts, from, etc.) may be present but aren't asserted on.
  [key: string]: unknown;
}

/**
 * Subset of the test-app's window globals consumed by these tests.
 * Declaring these explicitly avoids `(window as any)` casts when calling
 * `page.evaluate(...)` and gives us proper typing for `__messages`.
 */
interface TestAppWindow extends Window {
  __messages: TestAppMessage[];
  // `__libp2p` is also exposed by the test app but is opaque to these tests.
  __libp2p?: unknown;
}

/**
 * Narrowed shape of execSync's thrown error. The Node typings declare
 * `stdout`/`stderr` as `string | Buffer | undefined`; with `encoding: 'utf8'`
 * they are typically strings, but we keep the union to stay safe.
 */
interface ExecError {
  message: string;
  stdout?: string | Buffer;
  stderr?: string | Buffer;
}

function isExecError(err: unknown): err is ExecError {
  return typeof err === 'object' && err !== null && 'message' in err;
}

function decode(buf: string | Buffer | undefined): string {
  if (buf === undefined) return '';
  return typeof buf === 'string' ? buf : buf.toString('utf8');
}

/**
 * Run a docker compose subcommand against the NAT-test compose file.
 * Failures are surfaced via thrown Error so the test fails loudly.
 */
function compose(args: string): string {
  const fullCommand = `docker compose -f ${COMPOSE_FILE} ${args}`;
  try {
    return execSync(fullCommand, {
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      timeout: 120_000,
    });
  } catch (err: unknown) {
    const message = isExecError(err) ? err.message : String(err);
    const stdout = isExecError(err) ? decode(err.stdout) : '';
    const stderr = isExecError(err) ? decode(err.stderr) : '';
    throw new Error(
      `\`${fullCommand}\` failed: ${message}\n` +
      `stdout: ${stdout}\n` +
      `stderr: ${stderr}`,
    );
  }
}

/**
 * Poll an HTTP URL until it responds with 2xx or `timeoutMs` elapses.
 * Used after restarting test-app containers to wait for `serve` to come back.
 */
async function waitForUrl(page: Page, url: string, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await page.request.get(url, { timeout: 2000 });
      if (resp.ok()) return;
    } catch {
      // ignore and retry
    }
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`Timed out waiting for ${url} to respond after ${timeoutMs}ms`);
}

/**
 * Read the relay's `/shared/relay-info.json` from inside the relay container.
 * Returns null while the file is missing or unparseable (e.g., mid-write).
 */
function readRelayInfo(): { peerId: string } | null {
  try {
    const raw = execSync(`docker compose -f ${COMPOSE_FILE} exec -T relay cat /shared/relay-info.json`, {
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      timeout: 10_000,
    });
    const parsed = JSON.parse(raw);
    if (typeof parsed?.peerId === 'string' && parsed.peerId.length > 0) {
      return { peerId: parsed.peerId };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * After restarting the relay, the relay container rewrites
 * `/shared/relay-info.json` with a fresh peer ID. The `test-app-*` entrypoint
 * only waits for the file to *exist*, so if we restart `test-app-*` before
 * the relay has written the new info, they will re-publish `config.json`
 * with the *old* peer ID. Poll until the file's `peerId` differs from
 * `previousPeerId` so callers can sequence the restart deterministically.
 */
async function waitForRelayInfoChange(previousPeerId: string, timeoutMs = 60_000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const info = readRelayInfo();
    if (info && info.peerId !== previousPeerId) return info.peerId;
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(
    `Timed out (${timeoutMs}ms) waiting for relay-info.json peerId to change from ${previousPeerId}`,
  );
}

// ---------------------------------------------------------------------------
// Test suites
// ---------------------------------------------------------------------------

test.describe('NAT Relay Failure Recovery', () => {
  test.setTimeout(360_000);

  // The relay container generates a fresh peer ID on every start, so a true
  // restart cycle invalidates the config.json that test-app containers baked
  // in via their entrypoint script. We therefore restart relay + both
  // test-app containers and reload browser pages so they pick up the new
  // relay info. The end-state assertion is that cross-NAT sync resumes.
  //
  // Opt-in only when `RUN_NAT_RESTART=1` is explicitly set, regardless of
  // whether we're in CI. Any other value (unset, "0", "false", "true", etc.)
  // skips this slow/flaky scenario.
  test.skip(
    process.env.RUN_NAT_RESTART !== '1',
    'Relay restart cycle is opt-in (set RUN_NAT_RESTART=1 to enable)',
  );

  test('cross-NAT sync resumes after relay container restart', async ({ browser }) => {
    // Declare with definite-assignment so the `try` body sees a non-nullable
    // type. Assigning inside `try` ensures that if the second `initPage`
    // throws, the first context is still closed by the `finally` (which
    // guards with optional chaining against partial init).
    let a!: PageHandle;
    let b!: PageHandle;
    try {
      a = await initPage(browser, APP_A_URL);
      b = await initPage(browser, APP_B_URL);
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
      ]);
      await waitForMesh(a.page);

      // Establish working baseline: A -> B over relay.
      const preMsg = b.track.waitFor('PUBSUB_MESSAGE:', 45_000);
      await a.page.fill('#message-input', 'pre-restart');
      await a.page.click('#send-btn');
      await preMsg;

      // Confirm the pre-restart message was received on B before we tear
      // anything down. The post-restart assertion below snapshots the new
      // page's message buffer length right after reload and verifies it
      // grows once the post-restart send round-trips.
      const preMessagesB = await b.page.evaluate(
        () => (window as unknown as TestAppWindow).__messages,
      );
      expect(preMessagesB.some((m) => m.text === 'pre-restart')).toBe(true);

      // Capture the pre-restart relay peer ID so we can detect when the
      // restarted relay has rewritten /shared/relay-info.json.
      const preRestartInfo = readRelayInfo();
      if (!preRestartInfo) {
        throw new Error('Could not read pre-restart relay-info.json from the relay container');
      }

      // Restart the relay. We also restart the test-app containers so their
      // entrypoint script picks up the new relay-info.json and rewrites
      // config.json with the new peer ID. Browsers will be reloaded next.
      compose('restart relay');

      // The test-app entrypoint only waits for the file to *exist*, not for
      // it to change, so we must explicitly wait for the new peer ID to land
      // in /shared/relay-info.json before restarting the test-apps —
      // otherwise they may rewrite config.json with the stale peer ID.
      await waitForRelayInfoChange(preRestartInfo.peerId, 90_000);

      compose('restart test-app-a test-app-b');

      // Wait for the test-app HTTP servers to come back online before reload.
      await waitForUrl(a.page, APP_A_URL, 90_000);
      await waitForUrl(b.page, APP_B_URL, 90_000);

      // Close stale browser contexts (the existing libp2p instances are
      // pinned to the old relay peer ID and will not be able to recover).
      await a.context.close();
      await b.context.close();

      // Re-open both pages. They will fetch the new config.json (new relay
      // peer ID & multiaddr) and re-bootstrap.
      a = await initPage(browser, APP_A_URL);
      b = await initPage(browser, APP_B_URL);

      await Promise.all([
        waitForPeerConnection(a.track, 120_000),
        waitForPeerConnection(b.track, 120_000),
      ]);
      await waitForMesh(a.page, 15_000);

      // Snapshot B's message buffer right after reload (before the post-
      // restart send) so we can verify the buffer actually grows as a result
      // of new cross-NAT traffic, not just because the assertion happens to
      // match a stale entry.
      const baselineMessagesB = await b.page.evaluate(
        () => (window as unknown as TestAppWindow).__messages,
      );
      const baselineMessageCountB = baselineMessagesB.length;

      // Verify cross-NAT sync works again post-restart.
      const postMsg = b.track.waitFor('PUBSUB_MESSAGE:', 60_000);
      await a.page.fill('#message-input', 'post-restart');
      await a.page.click('#send-btn');
      await postMsg;

      const postMessagesB = await b.page.evaluate(
        () => (window as unknown as TestAppWindow).__messages,
      );
      expect(postMessagesB.some((m) => m.text === 'post-restart')).toBe(true);
      // Confirm the message buffer actually grew after the post-restart send,
      // proving we observed new traffic on this fresh page (not a stale
      // match against the buffer's initial contents).
      expect(postMessagesB.length).toBeGreaterThan(baselineMessageCountB);
    } finally {
      await a?.context.close().catch(() => {});
      await b?.context.close().catch(() => {});
    }
  });
});

// This describe block is intentionally kept enabled on CI. It is the most
// stable resilience scenario in this suite (no docker churn, no stress
// thresholds — just a single page reload plus a cross-NAT round-trip) and
// provides the CI assertion that this PR contributes to the nat-traversal
// job. If this scenario starts flaking on CI, prefer fixing the underlying
// instability over re-adding a CI-skip — opt out only as a last resort.
test.describe('NAT Browser Page Reload', () => {
  test.setTimeout(300_000);

  test('cross-NAT peer catches up after page reload', async ({ browser }) => {
    // See test 1 for the rationale on definite-assignment + assign-in-try.
    let a!: PageHandle;
    let b!: PageHandle;
    try {
      a = await initPage(browser, APP_A_URL);
      b = await initPage(browser, APP_B_URL);
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
      ]);
      await waitForMesh(a.page);

      // Send a baseline message before reload to confirm sync is healthy.
      const preReload = b.track.waitFor('PUBSUB_MESSAGE:', 45_000);
      await a.page.fill('#message-input', 'before-reload');
      await a.page.click('#send-btn');
      await preReload;

      // Reload B (simulates the cross-NAT browser dropping & coming back).
      // The test app spins up a fresh libp2p node on reload, so we must
      // refresh `b.peerId` to match — the prior value is stale.
      b = rebindConsoleTracker(b);
      await b.page.reload();
      await b.track.waitFor('INIT_COMPLETE', 90_000);
      b = await refreshPeerId(b);
      await b.track.waitFor('PEER_CONNECTED:', 120_000);
      await waitForMesh(b.page, 12_000);

      // Send a fresh message from A; B should receive it after reconnecting.
      const postReload = b.track.waitFor('PUBSUB_MESSAGE:', 60_000);
      await a.page.fill('#message-input', 'after-reload');
      await a.page.click('#send-btn');
      await postReload;

      const messagesB = await b.page.evaluate(
        () => (window as unknown as TestAppWindow).__messages,
      );
      expect(messagesB.some((m) => m.text === 'after-reload')).toBe(true);
    } finally {
      await a?.context.close().catch(() => {});
      await b?.context.close().catch(() => {});
    }
  });
});

test.describe('NAT Browser Network Toggle', () => {
  test.setTimeout(300_000);

  // `context.setOffline()` cycling depends on transport-level reconnection
  // timing through the relay, which has historically been flaky on shared CI
  // runners. Keep CI-skip; run with `yarn test:nat` locally.
  test.skip(!!process.env.CI, 'Cross-NAT setOffline toggle is flaky on CI mesh re-formation; run with `yarn test:nat` locally');

  test('cross-NAT peer can send after context.setOffline offline/online cycle', async ({ browser }) => {
    // See test 1 for the rationale on definite-assignment + assign-in-try.
    let a!: PageHandle;
    let b!: PageHandle;
    try {
      a = await initPage(browser, APP_A_URL);
      b = await initPage(browser, APP_B_URL);
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
      ]);
      await waitForMesh(a.page);

      // Sanity check: bi-directional baseline.
      const baseline = b.track.waitFor('PUBSUB_MESSAGE:', 45_000);
      await a.page.fill('#message-input', 'pre-offline');
      await a.page.click('#send-btn');
      await baseline;

      // Simulate B losing connectivity for a few seconds.
      await b.context.setOffline(true);
      await b.page.waitForTimeout(5_000);
      await b.context.setOffline(false);

      // Give libp2p time to re-establish (transports must reconnect through relay).
      await waitForMesh(b.page, 20_000);

      // After coming back online, B should be able to send a message that A
      // receives. We don't require A's send to reach B (depends on whether
      // the relay also dropped the connection), but B sending to A is a
      // stronger indicator that the browser end recovered.
      const aReceives = a.track.waitFor('PUBSUB_MESSAGE:', 60_000);
      await b.page.fill('#message-input', 'post-offline-from-b');
      await b.page.click('#send-btn');
      await aReceives;

      const messagesA = await a.page.evaluate(
        () => (window as unknown as TestAppWindow).__messages,
      );
      expect(messagesA.some((m) => m.text === 'post-offline-from-b')).toBe(true);
    } finally {
      await a?.context.close().catch(() => {});
      await b?.context.close().catch(() => {});
    }
  });
});

test.describe('NAT Rapid Concurrent Edits', () => {
  test.setTimeout(240_000);

  // Volume test for cross-NAT sync. We require at least 60% delivery on each
  // side (out of 10 messages from each peer). Higher than the existing 50%
  // threshold in nat-traversal.spec.ts since this is a focused stress test.
  test.skip(!!process.env.CI, 'Rapid cross-NAT concurrent edits are flaky on CI; run with `yarn test:nat` locally');

  test('both peers converge after rapid bidirectional cross-NAT messages', async ({ browser }) => {
    // See test 1 for the rationale on definite-assignment + assign-in-try.
    let a!: PageHandle;
    let b!: PageHandle;
    try {
      a = await initPage(browser, APP_A_URL);
      b = await initPage(browser, APP_B_URL);
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
      ]);
      await waitForMesh(a.page);

      // Warmup to ensure mesh is settled.
      const warmup = b.track.waitFor('PUBSUB_MESSAGE:', 60_000);
      await a.page.fill('#message-input', 'warmup');
      await a.page.click('#send-btn');
      await warmup;

      const count = 10;
      // Interleave sends from both sides as fast as possible, with tiny
      // pauses so gossipsub has a chance to forward each one. The point of
      // this test is high cross-NAT throughput, not back-pressure handling.
      for (let i = 0; i < count; i++) {
        await a.page.fill('#message-input', `A-edit-${i}`);
        await a.page.click('#send-btn');
        await b.page.fill('#message-input', `B-edit-${i}`);
        await b.page.click('#send-btn');
        await a.page.waitForTimeout(150);
      }

      // Wait for both sides to receive at least 60% of the other's messages.
      const target = Math.ceil(count * 0.6);
      await Promise.all([
        a.page.waitForFunction(
          (n) =>
            ((window as unknown as TestAppWindow).__messages ?? [])
              .filter((m) => m.text.startsWith('B-edit-')).length >= n,
          target,
          { timeout: 90_000 },
        ),
        b.page.waitForFunction(
          (n) =>
            ((window as unknown as TestAppWindow).__messages ?? [])
              .filter((m) => m.text.startsWith('A-edit-')).length >= n,
          target,
          { timeout: 90_000 },
        ),
      ]);

      const messagesA = await a.page.evaluate(
        () => (window as unknown as TestAppWindow).__messages,
      );
      const messagesB = await b.page.evaluate(
        () => (window as unknown as TestAppWindow).__messages,
      );

      // Each side should always have all of its own messages.
      for (let i = 0; i < count; i++) {
        expect(messagesA.some((m) => m.text === `A-edit-${i}`)).toBe(true);
        expect(messagesB.some((m) => m.text === `B-edit-${i}`)).toBe(true);
      }

      const aFromB = messagesA.filter((m) => m.text.startsWith('B-edit-')).length;
      const bFromA = messagesB.filter((m) => m.text.startsWith('A-edit-')).length;
      console.log(`Cross-NAT rapid delivery: A<-B ${aFromB}/${count}, B<-A ${bFromA}/${count}`);

      expect(aFromB).toBeGreaterThanOrEqual(target);
      expect(bFromA).toBeGreaterThanOrEqual(target);
    } finally {
      await a?.context.close().catch(() => {});
      await b?.context.close().catch(() => {});
    }
  });
});
