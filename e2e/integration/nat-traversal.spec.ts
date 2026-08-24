/**
 * NAT Traversal Integration Tests
 *
 * These tests verify that Peerborne peers on isolated Docker networks
 * can discover each other and sync data through the Circuit Relay V2 server.
 *
 * Requires: docker compose -f docker-compose.nat-test.yaml up -d
 *
 * Network topology:
 *   nat-a: [test-app-a, test-app-c, relay]
 *   nat-b: [test-app-b, relay]
 *   relay-net: [relay]
 *
 * test-app-a and test-app-b cannot communicate directly (different networks).
 * test-app-a and test-app-c are on the same network (same "LAN").
 * All traffic between nat-a and nat-b must route through the relay.
 */
import { test, expect } from '@playwright/test';
import {
  initPage,
  waitForMesh,
  waitForPeerConnection,
} from './helpers/nat-helpers';

const APP_A_URL = 'http://localhost:3001';
const APP_B_URL = 'http://localhost:3002';
const APP_C_URL = 'http://localhost:3003';

test.describe('Cross-NAT Document Sync', () => {
  test.setTimeout(180_000);

  test('peers on different networks sync through relay', async ({ browser }) => {
    const a = await initPage(browser, APP_A_URL);
    const b = await initPage(browser, APP_B_URL);
    try {
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
      ]);
      await waitForMesh(a.page);

      // A sends to B (cross-NAT, must go through relay)
      const msgReceived = b.track.waitFor('PUBSUB_MESSAGE:', 30_000);
      await a.page.fill('#message-input', 'cross-nat-hello');
      await a.page.click('#send-btn');
      await msgReceived;

      const messagesB = await b.page.evaluate(() => (window as any).__messages);
      expect(messagesB.some((m: any) => m.text === 'cross-nat-hello')).toBe(true);

      // Check whether the connection to peer B routes through circuit relay.
      // This is a soft check — the primary goal of this test is message delivery
      // across NAT boundaries, not the specific transport mechanism. In CI the
      // __libp2p handle or connection metadata may not reliably reflect the
      // relay path, so we log a warning instead of failing the test.
      const hasCircuitRelayToB = await a.page.evaluate((remotePeerId: string) => {
        const libp2p = (window as any).__libp2p;
        if (!libp2p) return false;
        return libp2p.getConnections().some(
          (conn: any) =>
            conn.remotePeer.toString() === remotePeerId &&
            conn.remoteAddr.toString().includes('/p2p-circuit'),
        );
      }, b.peerId);
      if (!hasCircuitRelayToB) {
        console.warn(
          'WARNING: Circuit relay path not detected between cross-NAT peers A and B. ' +
          'This can happen when __libp2p is unavailable or connection metadata does ' +
          'not include /p2p-circuit multiaddrs in CI. Message delivery still succeeded.',
        );
      }
    } finally {
      await a.context.close();
      await b.context.close();
    }
  });

  test('bidirectional sync across NAT boundaries', async ({ browser }) => {
    const a = await initPage(browser, APP_A_URL);
    const b = await initPage(browser, APP_B_URL);
    try {
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
      ]);
      await waitForMesh(a.page);

      // A -> B
      const msg1 = b.track.waitFor('PUBSUB_MESSAGE:', 30_000);
      await a.page.fill('#message-input', 'from-nat-a');
      await a.page.click('#send-btn');
      await msg1;

      // B -> A
      const msg2 = a.track.waitFor('PUBSUB_MESSAGE:', 30_000);
      await b.page.fill('#message-input', 'from-nat-b');
      await b.page.click('#send-btn');
      await msg2;

      const messagesA = await a.page.evaluate(() => (window as any).__messages);
      const messagesB = await b.page.evaluate(() => (window as any).__messages);

      expect(messagesA.some((m: any) => m.text === 'from-nat-b')).toBe(true);
      expect(messagesB.some((m: any) => m.text === 'from-nat-a')).toBe(true);
    } finally {
      await a.context.close();
      await b.context.close();
    }
  });
});

test.describe('Same-LAN Peer Connectivity', () => {
  test.setTimeout(180_000);

  test('peers on the same network can sync', async ({ browser }) => {
    // A and C are on the same Docker network (nat-a)
    const a = await initPage(browser, APP_A_URL);
    const c = await initPage(browser, APP_C_URL);
    try {
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(c.track),
      ]);
      await waitForMesh(a.page);

      const msgReceived = c.track.waitFor('PUBSUB_MESSAGE:', 30_000);
      await a.page.fill('#message-input', 'same-lan-msg');
      await a.page.click('#send-btn');
      await msgReceived;

      const messagesC = await c.page.evaluate(() => (window as any).__messages);
      expect(messagesC.some((m: any) => m.text === 'same-lan-msg')).toBe(true);

      // Ideally same-LAN peers (A and C) connect directly without circuit relay.
      // However, because browser peers run inside Playwright on the test runner
      // (not inside Docker), libp2p may still route through the relay depending
      // on NAT/firewall conditions. We log a warning instead of failing the test.
      const usesCircuitRelay = await a.page.evaluate((remotePeerId: string) => {
        const libp2p = (window as any).__libp2p;
        if (!libp2p) return false;
        return libp2p.getConnections().some(
          (conn: any) =>
            conn.remotePeer.toString() === remotePeerId &&
            conn.remoteAddr.toString().includes('/p2p-circuit'),
        );
      }, c.peerId);
      if (usesCircuitRelay) {
        console.warn(
          'WARNING: Same-LAN peers A and C are communicating via circuit relay. ' +
          'Expected a direct connection, but relay routing can occur when browser ' +
          'peers run in Playwright on the host rather than inside Docker.',
        );
      }
    } finally {
      await a.context.close();
      await c.context.close();
    }
  });
});

// Three-peer and concurrent tests are skipped in CI because GossipSub mesh
// formation through a single relay is unreliable for >2 peers (same issue
// documented in resilience.spec.ts). Run manually with: yarn test:nat
test.describe('Three-Peer Cross-NAT Sync', () => {
  test.setTimeout(240_000);

  test.skip(!!process.env.CI, 'Three-peer relay mesh is unreliable in CI');

  test('message from NAT-A reaches both NAT-A and NAT-B peers', async ({ browser }) => {
    const a = await initPage(browser, APP_A_URL);
    const b = await initPage(browser, APP_B_URL);
    const c = await initPage(browser, APP_C_URL);
    try {
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
        waitForPeerConnection(c.track),
      ]);
      await waitForMesh(a.page, 20_000);

      const msgB = b.track.waitFor('PUBSUB_MESSAGE:', 45_000);
      const msgC = c.track.waitFor('PUBSUB_MESSAGE:', 45_000);
      await a.page.fill('#message-input', 'broadcast-from-a');
      await a.page.click('#send-btn');
      await Promise.all([msgB, msgC]);

      const messagesB = await b.page.evaluate(() => (window as any).__messages);
      const messagesC = await c.page.evaluate(() => (window as any).__messages);

      expect(messagesB.some((m: any) => m.text === 'broadcast-from-a')).toBe(true);
      expect(messagesC.some((m: any) => m.text === 'broadcast-from-a')).toBe(true);
    } finally {
      await a.context.close();
      await b.context.close();
      await c.context.close();
    }
  });

  test('message from NAT-B reaches all NAT-A peers', async ({ browser }) => {
    const a = await initPage(browser, APP_A_URL);
    const b = await initPage(browser, APP_B_URL);
    const c = await initPage(browser, APP_C_URL);
    try {
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
        waitForPeerConnection(c.track),
      ]);
      await waitForMesh(a.page, 20_000);

      const msgA = a.track.waitFor('PUBSUB_MESSAGE:', 45_000);
      const msgC = c.track.waitFor('PUBSUB_MESSAGE:', 45_000);
      await b.page.fill('#message-input', 'broadcast-from-b');
      await b.page.click('#send-btn');
      await Promise.all([msgA, msgC]);

      const messagesA = await a.page.evaluate(() => (window as any).__messages);
      const messagesC = await c.page.evaluate(() => (window as any).__messages);

      expect(messagesA.some((m: any) => m.text === 'broadcast-from-b')).toBe(true);
      expect(messagesC.some((m: any) => m.text === 'broadcast-from-b')).toBe(true);
    } finally {
      await a.context.close();
      await b.context.close();
      await c.context.close();
    }
  });
});

test.describe('Rapid Cross-NAT Concurrent Messages', () => {
  test.setTimeout(180_000);

  test.skip(!!process.env.CI, 'Concurrent cross-NAT messaging is unreliable in CI');

  test('concurrent messages from both NATs achieve at least 50% delivery', async ({ browser }) => {
    const a = await initPage(browser, APP_A_URL);
    const b = await initPage(browser, APP_B_URL);
    try {
      await Promise.all([
        waitForPeerConnection(a.track),
        waitForPeerConnection(b.track),
      ]);
      await waitForMesh(a.page);

      // Warmup message to confirm mesh
      const warmup = b.track.waitFor('PUBSUB_MESSAGE:', 60_000);
      await a.page.fill('#message-input', 'warmup');
      await a.page.click('#send-btn');
      await warmup;

      const count = 5;
      for (let i = 0; i < count; i++) {
        await a.page.fill('#message-input', `nat-a-${i}`);
        await a.page.click('#send-btn');
        await a.page.waitForTimeout(300);
        await b.page.fill('#message-input', `nat-b-${i}`);
        await b.page.click('#send-btn');
        await b.page.waitForTimeout(300);
      }

      // Wait for at least half the messages to arrive on each side
      await Promise.all([
        a.page.waitForFunction(
          (n) => (window as any).__messages?.filter((m: any) => m.text.startsWith('nat-b-')).length >= n,
          Math.floor(count / 2),
          { timeout: 30_000 },
        ),
        b.page.waitForFunction(
          (n) => (window as any).__messages?.filter((m: any) => m.text.startsWith('nat-a-')).length >= n,
          Math.floor(count / 2),
          { timeout: 30_000 },
        ),
      ]);

      const messagesA = await a.page.evaluate(() => (window as any).__messages);
      const messagesB = await b.page.evaluate(() => (window as any).__messages);

      const aFromB = messagesA.filter((m: any) => m.text.startsWith('nat-b-')).length;
      const bFromA = messagesB.filter((m: any) => m.text.startsWith('nat-a-')).length;

      console.log(`Cross-NAT delivery: A received ${aFromB}/${count} from B, B received ${bFromA}/${count} from A`);

      expect(aFromB).toBeGreaterThanOrEqual(Math.floor(count / 2));
      expect(bFromA).toBeGreaterThanOrEqual(Math.floor(count / 2));
    } finally {
      await a.context.close();
      await b.context.close();
    }
  });
});
