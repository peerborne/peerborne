import type {
  InitialLoadSignerAuthority,
  InitialLoadSignerLookup,
} from '../initial-load-trust.js';
import type { InitialLoadAuthenticationBudget } from '../initial-load-auth.js';
import type { LoadSecurityCommitments } from '../load-security-state.js';

export type InitialLoadSessionBase<PublicKey> = {
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

/** A load session addressed to one responder with its own fresh challenge. */
export type InitialLoadSession<PublicKey> = InitialLoadSessionBase<PublicKey> & {
  readonly responder: string;
  readonly challenge: Uint8Array;
};
