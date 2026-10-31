import {
  validateInitialLoadSignerAuthority,
  type InitialLoadSignerLookup,
} from './initial-load-trust.js';
import {
  copyUnsharedUint8Array,
  unsharedUint8ArrayByteLength,
} from './utils.js';
import { consumeWorkBudget } from './policy/work-budget.js';

export const MAX_INITIAL_LOAD_AUTHENTICATION_PAYLOAD_BYTES = 64 * 1024 * 1024;
export const MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES = 8192;
export const MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS = 256;
export const MAX_INITIAL_LOAD_AUTHENTICATION_WORK_BYTES = 256 * 1024 * 1024;

/** Shared by all probes and response verification in one captured load session. */
export class InitialLoadAuthenticationBudget {
  #attempts = 0;
  #bytes = 0;

  reserve(payloadBytes: number): boolean {
    if (!Number.isSafeInteger(payloadBytes) || payloadBytes < 0) return false;
    const attempts = consumeWorkBudget(
      this.#attempts,
      1,
      MAX_INITIAL_LOAD_AUTHENTICATION_ATTEMPTS,
    );
    const bytes = consumeWorkBudget(
      this.#bytes,
      payloadBytes,
      MAX_INITIAL_LOAD_AUTHENTICATION_WORK_BYTES,
    );
    if (attempts === -1 || bytes === -1) return false;
    this.#attempts = attempts;
    this.#bytes = bytes;
    return true;
  }
}

export interface InitialLoadAuthenticationOptions<PublicKey> {
  payload: Uint8Array;
  signature?: Uint8Array;
  signerAuthority?: string;
  trustedSigners: InitialLoadSignerLookup<PublicKey>;
  budget: InitialLoadAuthenticationBudget;
  signal?: AbortSignal;
  verify: (
    payload: Uint8Array,
    publicKey: PublicKey,
    signature: Uint8Array,
  ) => Promise<boolean>;
}

export interface IdentifiedInitialLoadSigner<PublicKey> {
  readonly publicKey: PublicKey;
  readonly keyIndex: number;
}

/**
 * Authenticate one explicitly claimed authority from the captured local trust
 * index. The envelope signature must cover signerAuthority. An untrusted claim
 * selects a candidate; it never adds a key to the trust set.
 */
export async function identifyInitialLoadSigner<PublicKey>(
  options: InitialLoadAuthenticationOptions<PublicKey>,
): Promise<IdentifiedInitialLoadSigner<PublicKey> | null> {
  try {
    const { signerAuthority, trustedSigners, budget, signal, verify } = options;
    if (signal?.aborted || typeof verify !== 'function') return null;
    validateInitialLoadSignerAuthority(signerAuthority);
    const signer = trustedSigners(signerAuthority);
    if (signer === undefined || signer.authorityId !== signerAuthority)
      return null;
    const { publicKey, keyIndex } = signer;
    const payloadValue = options.payload;
    const signatureValue = options.signature;
    const payloadBytes = unsharedUint8ArrayByteLength(
      payloadValue,
      1,
      MAX_INITIAL_LOAD_AUTHENTICATION_PAYLOAD_BYTES,
      'initial-load authentication payload',
    );
    unsharedUint8ArrayByteLength(
      signatureValue,
      1,
      MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES,
      'initial-load authentication signature',
    );
    if (!budget.reserve(payloadBytes)) return null;
    const payload = copyUnsharedUint8Array(
      payloadValue,
      payloadBytes,
      payloadBytes,
      'initial-load authentication payload',
    );
    const signature = copyUnsharedUint8Array(
      signatureValue,
      1,
      MAX_INITIAL_LOAD_AUTHENTICATION_SIGNATURE_BYTES,
      'initial-load authentication signature',
    );
    const verified = await verify(payload, publicKey, signature);
    return verified === true && !signal?.aborted
      ? { publicKey, keyIndex }
      : null;
  } catch {
    return null;
  }
}

/** Verify one writer-bound initial-load envelope using only locally trusted keys. */
export async function verifyInitialLoadAuthentication<PublicKey>(
  options: InitialLoadAuthenticationOptions<PublicKey>,
): Promise<boolean> {
  return (await identifyInitialLoadSigner(options)) !== null;
}
