import type {
  InitialLoadSignerAuthority,
  InitialLoadSignerLookup,
} from '../initial-load-trust.js';
import type { InitialLoadAuthenticationBudget } from '../initial-load-auth.js';
import type { LoadSecurityCommitments } from '../load-security-state.js';

export type InitialLoadSession<PublicKey> = {
  readonly challenge: Uint8Array;
  readonly authorities: readonly InitialLoadSignerAuthority<PublicKey>[];
  readonly trustedSigners: InitialLoadSignerLookup<PublicKey>;
  readonly authenticationBudget: InitialLoadAuthenticationBudget;
  readonly writerVersion: number;
  readonly bootstrap: boolean;
} & (
  | {
      readonly context: 'load-response-v4';
      readonly commitments: LoadSecurityCommitments;
    }
  | { readonly context: 'invitation-catch-up-v1' }
);
