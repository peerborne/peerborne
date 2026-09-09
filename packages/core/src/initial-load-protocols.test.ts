import { describe, expect, test } from '@jest/globals';
import {
  initialLoadProtocols,
  shouldServeInitialLoadProtocol,
} from './initial-load-protocols.js';
import {
  documentLoadV3,
  documentLoadV4,
  securityAdvertiseV1,
  snapshotLoadV3,
  snapshotLoadV4,
  tipAdvertiseV1,
} from './wire-protocols.js';

describe('initialLoadProtocols', () => {
  test('selects the complete legacy family', () => {
    expect(initialLoadProtocols(false)).toEqual({
      documentLoad: documentLoadV3,
      snapshotLoad: snapshotLoadV3,
      advertise: tipAdvertiseV1,
      securityAware: false,
    });
  });

  test('selects the complete security-aware family without downgrade IDs', () => {
    const protocols = initialLoadProtocols(true);
    expect(protocols).toEqual({
      documentLoad: documentLoadV4,
      snapshotLoad: snapshotLoadV4,
      advertise: securityAdvertiseV1,
      securityAware: true,
    });
    expect(Object.values(protocols)).not.toContain(documentLoadV3);
    expect(Object.values(protocols)).not.toContain(snapshotLoadV3);
    expect(Object.values(protocols)).not.toContain(tipAdvertiseV1);
  });

  test('strict protocol selection declines every legacy handler family', () => {
    expect(shouldServeInitialLoadProtocol(true, false)).toBe(false);
    expect(shouldServeInitialLoadProtocol(true, true)).toBe(true);
    expect(shouldServeInitialLoadProtocol(false, false)).toBe(true);
  });
});
