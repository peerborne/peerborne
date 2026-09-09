import { describe, expect, test } from '@jest/globals';
import {
  snapshotPeerborneSecurityPolicy,
  validateSecurityConfiguration,
} from './security-config.js';
import type { PeerborneConfig } from './peerborne-config.js';

const config = (overrides: Partial<PeerborneConfig>): PeerborneConfig =>
  overrides as PeerborneConfig;

describe('validateSecurityConfiguration', () => {
  test('accepts structurally valid class-instance configs', () => {
    class Config {
      enableSigning = true;
      enableTopicValidators = true;
    }
    const instance = new Config() as PeerborneConfig;

    expect(() => validateSecurityConfiguration(instance)).not.toThrow();
    expect(snapshotPeerborneSecurityPolicy(instance)).toEqual({
      enableSigning: true,
      enableTopicValidators: true,
    });
  });

  test('public validation rejects security accessors without invoking them', () => {
    let reads = 0;
    const accessorConfig = Object.defineProperty({}, 'enableSigning', {
      enumerable: true,
      get() {
        reads++;
        return true;
      },
    }) as PeerborneConfig;

    expect(() => validateSecurityConfiguration(accessorConfig)).toThrow(
      /enableSigning must be an own data property/,
    );
    expect(reads).toBe(0);
  });

  test.each(['accessor', 'data'] as const)(
    'rejects inherited %s security fields without reading them',
    (propertyKind) => {
      let reads = 0;
      const prototype =
        propertyKind === 'accessor'
          ? Object.defineProperty({}, 'requireSecurityStateQuorum', {
              get() {
                reads++;
                return true;
              },
            })
          : Object.defineProperty({}, 'requireSecurityStateQuorum', {
              value: true,
            });
      const inheritedConfig = Object.create(prototype) as PeerborneConfig;

      expect(() => validateSecurityConfiguration(inheritedConfig)).toThrow(
        /requireSecurityStateQuorum must be an own data property/,
      );
      expect(reads).toBe(0);
    },
  );

  test.each([
    ['enableSigning', 1],
    ['enableSigning', 'true'],
    ['enableSigning', null],
    ['enableTopicValidators', 1],
    ['enableTopicValidators', 'false'],
    ['enableTopicValidators', null],
    ['allowInsecureLegacyBeeKEMPathUpdateV1', 1],
    ['allowInsecureLegacyBeeKEMPathUpdateV1', 'true'],
    ['allowInsecureLegacyBeeKEMPathUpdateV1', null],
    ['requireAuthenticatedInitialLoad', 1],
    ['requireAuthenticatedInitialLoad', 'true'],
    ['requireAuthenticatedInitialLoad', null],
    ['requireSecurityStateQuorum', 1],
    ['requireSecurityStateQuorum', 'true'],
    ['requireSecurityStateQuorum', null],
  ])('rejects non-boolean security flag %s=%p', (name, value) => {
    expect(() =>
      validateSecurityConfiguration(
        config({ [name]: value } as Partial<PeerborneConfig>),
      ),
    ).toThrow(/must be a boolean/);
  });

  test.each([
    ['resolveTrustedDocumentWriters', []],
    ['resolveLoadSecurityCommitments', {}],
    ['validateDocumentPath', true],
  ])('rejects non-function optional resolver %s', (name, value) => {
    expect(() =>
      validateSecurityConfiguration(
        config({ [name]: value } as Partial<PeerborneConfig>),
      ),
    ).toThrow(/must be a function/);
  });

  test('requires signing and pinned writers for authenticated initial load', () => {
    expect(() =>
      validateSecurityConfiguration(
        config({ requireAuthenticatedInitialLoad: true, enableSigning: false }),
      ),
    ).toThrow(/signing/);
    expect(() =>
      validateSecurityConfiguration(config({ requireAuthenticatedInitialLoad: true })),
    ).toThrow(/resolveTrustedDocumentWriters/);
  });

  test('requires the complete security-aware quorum configuration', () => {
    expect(() =>
      validateSecurityConfiguration(
        config({
          requireSecurityStateQuorum: true,
          requireAuthenticatedInitialLoad: true,
          resolveTrustedDocumentWriters: () => [],
          loadQuorumEnabled: false,
        }),
      ),
    ).toThrow(/loadQuorumEnabled/);
    expect(() =>
      validateSecurityConfiguration(
        config({
          requireSecurityStateQuorum: true,
          requireAuthenticatedInitialLoad: true,
          resolveTrustedDocumentWriters: () => [],
        }),
      ),
    ).toThrow(/resolveLoadSecurityCommitments/);
  });

  test('accepts a coherent strict configuration', () => {
    expect(() =>
      validateSecurityConfiguration(
        config({
          requireSecurityStateQuorum: true,
          requireAuthenticatedInitialLoad: true,
          resolveTrustedDocumentWriters: () => [],
          resolveLoadSecurityCommitments: () => ({
            version: 1,
            controlHead: new Uint8Array(32),
            groupId: 'group',
            epoch: 0n,
            treeHash: new Uint8Array(32),
            confirmedTranscriptHash: new Uint8Array(32),
          }),
        }),
      ),
    ).not.toThrow();
  });
});
