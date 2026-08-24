import { describe, expect, test } from '@jest/globals';
import { NetworkStats } from './network-stats.js';

describe('NetworkStats', () => {
  test('initial snapshot has all zero counters', () => {
    const stats = new NetworkStats();
    expect(stats.snapshot()).toEqual({
      messagesSent: 0,
      messagesReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      documentsOpened: 0,
      documentsClosed: 0,
      peersConnected: 0,
      peersDisconnected: 0,
    });
  });

  test('recordSent increments message count and byte total', () => {
    const stats = new NetworkStats();
    stats.recordSent(100);
    stats.recordSent(200);
    const snap = stats.snapshot();
    expect(snap.messagesSent).toBe(2);
    expect(snap.bytesSent).toBe(300);
  });

  test('recordReceived increments message count and byte total', () => {
    const stats = new NetworkStats();
    stats.recordReceived(50);
    const snap = stats.snapshot();
    expect(snap.messagesReceived).toBe(1);
    expect(snap.bytesReceived).toBe(50);
  });

  test('recordDocumentOpen/Close increments counters', () => {
    const stats = new NetworkStats();
    stats.recordDocumentOpen();
    stats.recordDocumentOpen();
    stats.recordDocumentClose();
    const snap = stats.snapshot();
    expect(snap.documentsOpened).toBe(2);
    expect(snap.documentsClosed).toBe(1);
  });

  test('recordPeerConnect/Disconnect increments counters', () => {
    const stats = new NetworkStats();
    stats.recordPeerConnect();
    stats.recordPeerConnect();
    stats.recordPeerDisconnect();
    const snap = stats.snapshot();
    expect(snap.peersConnected).toBe(2);
    expect(snap.peersDisconnected).toBe(1);
  });

  test('reset clears all counters', () => {
    const stats = new NetworkStats();
    stats.recordSent(100);
    stats.recordReceived(50);
    stats.recordDocumentOpen();
    stats.recordPeerConnect();
    stats.reset();
    const snap = stats.snapshot();
    expect(snap.messagesSent).toBe(0);
    expect(snap.messagesReceived).toBe(0);
    expect(snap.bytesSent).toBe(0);
    expect(snap.bytesReceived).toBe(0);
    expect(snap.documentsOpened).toBe(0);
    expect(snap.peersConnected).toBe(0);
  });

  test('snapshot returns a copy, not a live reference', () => {
    const stats = new NetworkStats();
    const snap1 = stats.snapshot();
    stats.recordSent(100);
    const snap2 = stats.snapshot();
    expect(snap1.messagesSent).toBe(0);
    expect(snap2.messagesSent).toBe(1);
  });

  test('negative/NaN/Infinity bytes are clamped to 0', () => {
    const stats = new NetworkStats();
    stats.recordSent(-10);
    stats.recordSent(NaN);
    stats.recordSent(Infinity);
    stats.recordReceived(-5);
    const snap = stats.snapshot();
    expect(snap.bytesSent).toBe(0);
    expect(snap.bytesReceived).toBe(0);
    expect(snap.messagesSent).toBe(3);
    expect(snap.messagesReceived).toBe(1);
  });
});
