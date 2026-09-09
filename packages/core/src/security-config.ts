import type { PeerborneConfig } from './peerborne-config.js';

export type PeerborneSecurityPolicyConfig = Pick<
  PeerborneConfig,
  | 'enableSigning'
  | 'enableTopicValidators'
  | 'allowInsecureLegacyBeeKEMPathUpdateV1'
  | 'loadQuorumEnabled'
  | 'loadQuorumK'
  | 'loadQuorumQ'
  | 'loadQuorumTimeoutMs'
  | 'loadQuorumAllowSinglePeer'
  | 'requireAuthenticatedInitialLoad'
  | 'requireSecurityStateQuorum'
  | 'resolveTrustedDocumentWriters'
  | 'resolveLoadSecurityCommitments'
  | 'validateDocumentPath'
>;

const SECURITY_POLICY_FIELDS = [
  'enableSigning',
  'enableTopicValidators',
  'allowInsecureLegacyBeeKEMPathUpdateV1',
  'loadQuorumEnabled',
  'loadQuorumK',
  'loadQuorumQ',
  'loadQuorumTimeoutMs',
  'loadQuorumAllowSinglePeer',
  'requireAuthenticatedInitialLoad',
  'requireSecurityStateQuorum',
  'resolveTrustedDocumentWriters',
  'resolveLoadSecurityCommitments',
  'validateDocumentPath',
] as const satisfies ReadonlyArray<keyof PeerborneSecurityPolicyConfig>;

const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const reflectHas = Reflect.has;

/**
 * Capture the complete authentication/quorum policy without invoking caller
 * accessors. Validation and runtime installation must consume this same
 * detached object so a stateful config cannot present different policies at
 * the two boundaries.
 */
export function snapshotPeerborneSecurityPolicy(
  config: PeerborneConfig,
): PeerborneSecurityPolicyConfig {
  if (config === null || typeof config !== 'object') {
    throw new TypeError('Peerborne config must be an object');
  }

  const snapshot: Partial<PeerborneSecurityPolicyConfig> = {};
  for (const field of SECURITY_POLICY_FIELDS) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = objectGetOwnPropertyDescriptor(config, field);
    } catch {
      throw new TypeError(
        `Peerborne security policy ${field} must be an own data property`,
      );
    }
    if (descriptor === undefined) {
      let inherited = false;
      try {
        inherited = reflectHas(config, field);
      } catch {
        throw new TypeError(
          `Peerborne security policy ${field} must be an own data property`,
        );
      }
      if (inherited) {
        throw new TypeError(
          `Peerborne security policy ${field} must be an own data property`,
        );
      }
      continue;
    }
    if (!('value' in descriptor)) {
      throw new TypeError(
        `Peerborne security policy ${field} must be an own data property`,
      );
    }
    Object.defineProperty(snapshot, field, {
      value: descriptor.value,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(snapshot) as PeerborneSecurityPolicyConfig;
}

export function validateSecurityConfiguration(
  config: PeerborneConfig,
): void {
  // Apply the same own-data-property snapshot used by `initialize()` so the
  // public validator cannot invoke accessors or approve a policy shape that
  // initialization would reject.
  config = snapshotPeerborneSecurityPolicy(config) as PeerborneConfig;
  if (
    config.enableSigning !== undefined &&
    typeof config.enableSigning !== 'boolean'
  ) {
    throw new TypeError('enableSigning must be a boolean');
  }
  if (
    config.enableTopicValidators !== undefined &&
    typeof config.enableTopicValidators !== 'boolean'
  ) {
    throw new TypeError('enableTopicValidators must be a boolean');
  }
  if (
    config.allowInsecureLegacyBeeKEMPathUpdateV1 !== undefined &&
    typeof config.allowInsecureLegacyBeeKEMPathUpdateV1 !== 'boolean'
  ) {
    throw new TypeError(
      'allowInsecureLegacyBeeKEMPathUpdateV1 must be a boolean',
    );
  }
  if (
    config.requireAuthenticatedInitialLoad !== undefined &&
    typeof config.requireAuthenticatedInitialLoad !== 'boolean'
  ) {
    throw new TypeError('requireAuthenticatedInitialLoad must be a boolean');
  }
  if (
    config.requireSecurityStateQuorum !== undefined &&
    typeof config.requireSecurityStateQuorum !== 'boolean'
  ) {
    throw new TypeError('requireSecurityStateQuorum must be a boolean');
  }
  if (
    config.resolveTrustedDocumentWriters !== undefined &&
    typeof config.resolveTrustedDocumentWriters !== 'function'
  ) {
    throw new TypeError('resolveTrustedDocumentWriters must be a function');
  }
  if (
    config.resolveLoadSecurityCommitments !== undefined &&
    typeof config.resolveLoadSecurityCommitments !== 'function'
  ) {
    throw new TypeError('resolveLoadSecurityCommitments must be a function');
  }
  if (
    config.validateDocumentPath !== undefined &&
    typeof config.validateDocumentPath !== 'function'
  ) {
    throw new TypeError('validateDocumentPath must be a function');
  }
  if (config.requireAuthenticatedInitialLoad === true) {
    if (config.enableSigning === false) {
      throw new Error(
        'requireAuthenticatedInitialLoad requires application-level signing',
      );
    }
    if (!config.resolveTrustedDocumentWriters) {
      throw new Error(
        'requireAuthenticatedInitialLoad requires resolveTrustedDocumentWriters',
      );
    }
  }
  if (config.requireSecurityStateQuorum === true) {
    if (config.loadQuorumEnabled === false) {
      throw new Error('requireSecurityStateQuorum requires loadQuorumEnabled');
    }
    if (config.requireAuthenticatedInitialLoad !== true) {
      throw new Error(
        'requireSecurityStateQuorum requires requireAuthenticatedInitialLoad',
      );
    }
    if (!config.resolveLoadSecurityCommitments) {
      throw new Error(
        'requireSecurityStateQuorum requires resolveLoadSecurityCommitments',
      );
    }
  }
}
