import { describe, expect, test } from '@jest/globals';

import * as wireProtocols from './wire-protocols';

describe('wire protocol constant verification', () => {
  const allConstants = Object.entries(wireProtocols).filter(
    ([, v]) => typeof v === 'string',
  ) as [string, string][];

  test('all constants match a supported namespace/{name}/{semver} convention', () => {
    const pattern = /^\/(?:collabswarm|peerborne)\/[a-z][a-z-]+\/\d+\.\d+\.\d+$/;
    for (const [, value] of allConstants) {
      expect(value).toMatch(pattern);
    }
  });

  test('new invitation protocol uses the Peerborne namespace', () => {
    expect(wireProtocols.invitationJoinV1).toBe(
      '/peerborne/invitation-join/1.0.0',
    );
  });

  test('no duplicate protocol strings', () => {
    const values = allConstants.map(([, v]) => v);
    expect(new Set(values).size).toBe(values.length);
  });

  test('semver components are valid', () => {
    for (const [, value] of allConstants) {
      const parts = value.split('/').pop()!.split('.').map(Number);
      expect(parts[0]).toBeGreaterThanOrEqual(1);
      expect(parts[1]).toBeGreaterThanOrEqual(0);
      expect(parts[2]).toBeGreaterThanOrEqual(0);
      expect(parts.length).toBe(3);
    }
  });

  test('protocol name segments match expected purpose', () => {
    const expected: Record<string, string> = {
      bloomFilterUpdateV1: 'bloom-index',
      documentLoadV3: 'doc-load',
      documentKeyUpdateV2: 'key-update',
      snapshotLoadV3: 'snapshot-load',
      tipAdvertiseV1: 'tip-advertise',
      invitationJoinV1: 'invitation-join',
      beekemWelcomeV1: 'beekem-welcome',
      beekemPathUpdateV1: 'beekem-pathupdate',
      searchIndexAdvertiseV1: 'search-index-advertise',
      searchQueryV1: 'search-query',
    };
    for (const [name, segment] of Object.entries(expected)) {
      expect(wireProtocols[name as keyof typeof wireProtocols]).toContain(`/${segment}/`);
    }
  });

  test('major version in constant name matches value', () => {
    const nameToMajor: Record<string, number> = {
      bloomFilterUpdateV1: 1,
      documentLoadV3: 3,
      documentKeyUpdateV2: 2,
      snapshotLoadV3: 3,
      tipAdvertiseV1: 1,
      invitationJoinV1: 1,
      beekemWelcomeV1: 1,
      beekemPathUpdateV1: 1,
      searchIndexAdvertiseV1: 1,
      searchQueryV1: 1,
    };
    for (const [name, expectedMajor] of Object.entries(nameToMajor)) {
      const value = wireProtocols[name as keyof typeof wireProtocols];
      expect(value).toContain(`/${expectedMajor}.`);
    }
  });

  test('handler label matches protocol path segment', () => {
    const labelMap: Record<string, string> = {
      documentKeyUpdateV2: 'key-update',
      invitationJoinV1: 'invitation-join',
      beekemWelcomeV1: 'beekem-welcome',
      beekemPathUpdateV1: 'beekem-pathupdate',
    };
    for (const [constant, label] of Object.entries(labelMap)) {
      expect(wireProtocols[constant as keyof typeof wireProtocols]).toContain(`/${label}/`);
    }
  });
});
