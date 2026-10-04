import type { InitialLoadSignerAuthority } from '../initial-load-trust.js';
import type { LoadSecurityCommitments } from '../load-security-state.js';

export type InitialLoadSession<PublicKey> = {
  readonly challenge: Uint8Array;
  readonly authorities: readonly InitialLoadSignerAuthority<PublicKey>[];
  readonly writerVersion: number;
  readonly bootstrap: boolean;
} & (
  | {
      readonly context: 'load-response-v4';
      readonly commitments: LoadSecurityCommitments;
    }
  | { readonly context: 'invitation-catch-up-v1' }
);
