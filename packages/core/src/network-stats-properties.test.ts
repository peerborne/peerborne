import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { NetworkStats } from './network-stats.js';

const event = fc.record({
  kind: fc.constantFrom(
    'sent',
    'received',
    'open',
    'close',
    'connect',
    'disconnect',
    'reset',
  ),
  bytes: fc.oneof(
    fc.double({ min: 0, max: 1000000, noNaN: true }),
    fc.constantFrom(-1, NaN, Infinity),
  ),
});
describe('generated network-statistics histories', () => {
  test('reports exact event aggregates since the most recent reset and returns detached snapshots', () => {
    fc.assert(
      fc.property(fc.array(event, { maxLength: 100 }), (program) => {
        const stats = new NetworkStats();
        for (const value of program) {
          if (value.kind === 'sent') stats.recordSent(value.bytes);
          if (value.kind === 'received') stats.recordReceived(value.bytes);
          if (value.kind === 'open') stats.recordDocumentOpen();
          if (value.kind === 'close') stats.recordDocumentClose();
          if (value.kind === 'connect') stats.recordPeerConnect();
          if (value.kind === 'disconnect') stats.recordPeerDisconnect();
          if (value.kind === 'reset') stats.reset();
        }
        const lastReset = program
          .map((value) => value.kind)
          .lastIndexOf('reset');
        const suffix = program.slice(lastReset + 1);
        const count = (kind: string) =>
          suffix.filter((value) => value.kind === kind).length;
        const bytes = (kind: string) =>
          suffix
            .filter((value) => value.kind === kind)
            .map((value) =>
              Number.isFinite(value.bytes) && value.bytes >= 0
                ? value.bytes
                : 0,
            )
            .reduce((a, b) => a + b, 0);
        const expected = {
          messagesSent: count('sent'),
          messagesReceived: count('received'),
          bytesSent: bytes('sent'),
          bytesReceived: bytes('received'),
          documentsOpened: count('open'),
          documentsClosed: count('close'),
          peersConnected: count('connect'),
          peersDisconnected: count('disconnect'),
        };
        const snapshot = stats.snapshot();
        expect(snapshot).toEqual(expected);
        snapshot.messagesSent = -1;
        expect(stats.snapshot()).toEqual(expected);
      }),
      { seed: 9544, numRuns: 300 },
    );
  });
});
