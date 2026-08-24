/**
 * Lightweight UCAN (User Controlled Authorization Networks) implementation
 * for Peerborne's decentralized authorization.
 *
 * UCANs are self-contained authorization tokens that support:
 * - Delegation chains: authority flows from document creator through intermediaries
 * - Attenuation: delegated permissions can only be narrowed, never broadened
 * - Offline verification: no authority lookup needed
 * - Revocation: revoking a token invalidates all downstream delegations
 */

import { capabilityImplies } from './capabilities.js';

/**
 * A UCAN token for Peerborne document authorization.
 */
export interface UCAN {
  /** Version of the UCAN spec */
  version: '0.1.0';

  /** Issuer's public key (who is granting this capability), Base64-encoded */
  issuer: string;

  /** Audience's public key (who receives this capability), Base64-encoded */
  audience: string;

  /** Capabilities being granted */
  capabilities: UCANCapability[];

  /** Expiration timestamp (seconds since epoch), or null for no expiration */
  expiration: number | null;

  /** Not-before timestamp (seconds since epoch), or null */
  notBefore: number | null;

  /** Nonce for uniqueness */
  nonce: string;

  /** Optional proof chain (parent UCANs that authorize this delegation) */
  proofs: string[]; // Base64-encoded parent UCANs

  /** Signature of the token payload by the issuer */
  signature: string;
}

/**
 * A capability granted by a UCAN.
 */
export interface UCANCapability {
  /** The resource (document ID) */
  resource: string;
  /** The capability (e.g., "/doc/write") */
  ability: string;
}

/**
 * Payload of a UCAN (everything except the signature).
 */
export type UCANPayload = Omit<UCAN, 'signature'>;

/**
 * Create a new UCAN token.
 */
export async function createUCAN(
  issuerPrivateKey: CryptoKey,
  issuerPublicKeyBase64: string,
  audiencePublicKeyBase64: string,
  capabilities: UCANCapability[],
  proofs: string[] = [],
  options?: {
    expiration?: number | null;
    notBefore?: number | null;
  }
): Promise<UCAN> {
  const payload: UCANPayload = {
    version: '0.1.0',
    issuer: issuerPublicKeyBase64,
    audience: audiencePublicKeyBase64,
    capabilities,
    expiration: options?.expiration ?? null,
    notBefore: options?.notBefore ?? null,
    nonce: generateNonce(),
    proofs,
  };

  const payloadBytes = new TextEncoder().encode(canonicalPayloadString(payload));
  const signatureBytes = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-384' } },
    issuerPrivateKey,
    payloadBytes
  );

  return {
    ...payload,
    signature: uint8ArrayToBase64(new Uint8Array(signatureBytes)),
  };
}

/**
 * Verify a UCAN token's signature.
 *
 * Note: Uses SHA-384 to match ECDSA P-384 curve strength (not SHA-256,
 * which is used in epoch.ts for HKDF -- different purpose).
 */
export async function verifyUCANSignature(
  ucan: UCAN,
  issuerPublicKey: CryptoKey,
): Promise<boolean> {
  const { signature, ...payload } = ucan;
  const payloadBytes = new TextEncoder().encode(canonicalPayloadString(payload));
  const signatureBytes = base64ToUint8Array(signature);

  return crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-384' } },
    issuerPublicKey,
    signatureBytes.buffer as ArrayBuffer,
    payloadBytes
  );
}

/**
 * Validate a UCAN delegation chain.
 * Checks that each UCAN in the chain:
 * 1. Has a valid signature
 * 2. The audience of each proof matches the issuer of the next
 * 3. Capabilities are properly attenuated (only narrowed, never broadened)
 * 4. The token is not expired
 * 5. The chain does not exceed maxDepth or contain circular delegations
 */
export async function validateUCANChain(
  ucan: UCAN,
  rootPublicKey: CryptoKey,
  resolvePublicKey: (base64Key: string) => Promise<CryptoKey>,
  maxDepth: number = 10,
  visited: Set<string> = new Set(),
): Promise<{ valid: boolean; error?: string }> {
  if (maxDepth <= 0) {
    return { valid: false, error: 'UCAN chain exceeds maximum depth' };
  }

  // Detect circular delegations using the serialized UCAN as fingerprint
  const fingerprint = serializeUCAN(ucan);
  if (visited.has(fingerprint)) {
    return { valid: false, error: 'Circular delegation detected in UCAN chain' };
  }
  visited.add(fingerprint);

  // Check expiration
  if (ucan.expiration !== null && Date.now() / 1000 > ucan.expiration) {
    return { valid: false, error: 'UCAN has expired' };
  }

  // Check not-before
  if (ucan.notBefore !== null && Date.now() / 1000 < ucan.notBefore) {
    return { valid: false, error: 'UCAN is not yet valid' };
  }

  // Verify signature
  const issuerKey = await resolvePublicKey(ucan.issuer);
  if (!await verifyUCANSignature(ucan, issuerKey)) {
    return { valid: false, error: 'Invalid UCAN signature' };
  }

  // If no proofs, the issuer must be the root (document creator)
  if (ucan.proofs.length === 0) {
    // Verify issuer is the root authority
    const rootKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', rootPublicKey));
    const issuerKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', issuerKey));
    if (!arraysEqual(rootKeyBytes, issuerKeyBytes)) {
      return { valid: false, error: 'Root UCAN must be issued by document creator' };
    }
    return { valid: true };
  }

  // Validate proof chain
  for (const proofStr of ucan.proofs) {
    const proof = deserializeUCAN(proofStr);

    // The proof's audience must be this UCAN's issuer
    if (proof.audience !== ucan.issuer) {
      return { valid: false, error: 'Proof audience does not match UCAN issuer' };
    }

    // Check attenuation: this UCAN's capabilities must be subset of proof's
    for (const cap of ucan.capabilities) {
      const proofHasCap = proof.capabilities.some(
        proofCap => proofCap.resource === cap.resource && capabilityImplies(proofCap.ability, cap.ability)
      );
      if (!proofHasCap) {
        return { valid: false, error: `Capability ${cap.ability} on ${cap.resource} not authorized by proof` };
      }
    }

    // Recursively validate proof with decremented depth and shared visited set
    const proofResult = await validateUCANChain(proof, rootPublicKey, resolvePublicKey, maxDepth - 1, visited);
    if (!proofResult.valid) {
      return proofResult;
    }
  }

  return { valid: true };
}

/**
 * Serialize a UCAN to a Base64 string using deterministic key ordering.
 * Header fields come first (version), then payload fields alphabetically,
 * then signature last. This ensures identical UCANs always produce the
 * same serialized output regardless of object key insertion order.
 */
export function serializeUCAN(ucan: UCAN): string {
  return uint8ArrayToBase64(new TextEncoder().encode(deterministicStringify(ucan)));
}

/**
 * Canonical JSON serialization of a UCAN payload (without signature).
 * Used for both signing and verification to ensure deterministic byte
 * representation regardless of JS object key insertion order.
 */
function canonicalPayloadString(payload: UCANPayload): string {
  const ordered: Record<string, unknown> = {
    version: payload.version,
    audience: payload.audience,
    capabilities: payload.capabilities,
    expiration: payload.expiration,
    issuer: payload.issuer,
    nonce: payload.nonce,
    notBefore: payload.notBefore,
    proofs: payload.proofs,
  };
  return JSON.stringify(ordered);
}

/**
 * Deterministic JSON serialization for UCAN tokens (including signature).
 * Serializes fields in a fixed order: version (header), then payload
 * fields alphabetically, then signature.
 */
function deterministicStringify(ucan: UCAN): string {
  const ordered: Record<string, unknown> = {
    version: ucan.version,
    audience: ucan.audience,
    capabilities: ucan.capabilities,
    expiration: ucan.expiration,
    issuer: ucan.issuer,
    nonce: ucan.nonce,
    notBefore: ucan.notBefore,
    proofs: ucan.proofs,
    signature: ucan.signature,
  };
  return JSON.stringify(ordered);
}

/**
 * Deserialize a UCAN from a Base64 string.
 */
export function deserializeUCAN(encoded: string): UCAN {
  return JSON.parse(new TextDecoder().decode(base64ToUint8Array(encoded)));
}

// Helper functions
function generateNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  // Use btoa for browser compatibility
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
