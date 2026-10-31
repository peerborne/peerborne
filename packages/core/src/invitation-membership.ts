import {
  classifyAcceptedMembership,
  classifyInitialMembership,
} from './policy/string-collections.js';
import {
  crdtReaderChangeNode,
  crdtWriterChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
import { collectBoundedChangeTree } from './change-tree-walk.js';
import type { InvitationRole } from './invitation-wire.js';

export interface InitialInvitationMembershipState {
  readonly createdLocally: boolean;
  readonly founder: string;
  readonly recipient: string;
  readonly readers: readonly string[];
  readonly writers: readonly string[];
}

export type InitialInvitationMembershipPhase = 'preflight' | 'ready-to-attest';

export interface AcceptedInvitationMembershipState {
  readonly issuer: string;
  readonly recipient: string;
  readonly readers: readonly string[];
  readonly writers: readonly string[];
}

/** @internal Require the exact signed founder-plus-one ACL after bootstrap. */
export function assertAcceptedInvitationMembershipTopology(
  state: AcceptedInvitationMembershipState,
  role: InvitationRole,
): void {
  const disposition = classifyAcceptedMembership(
    state.issuer,
    state.recipient,
    state.readers,
    state.writers,
    role === 'editor',
  );
  if (disposition === 'valid') return;
  const messages = {
    sameIdentity: 'Invitation recipient must use a distinct identity',
    duplicates:
      'Invitation bootstrap membership contains duplicate canonical identities',
    readers: 'Invitation bootstrap readers do not match the signed recipient',
    writers:
      'Invitation bootstrap writers do not match the signed issuer and role',
  };
  throw new Error(messages[disposition]);
}

/** @internal Admit one invitation exactly at its first state mutation. */
export function createInvitationMutationAdmission(
  assertCanMutate?: () => void,
): () => void {
  let admitted = false;
  return () => {
    if (admitted) return;
    assertCanMutate?.();
    admitted = true;
  };
}

/** @internal Validate the founder-plus-one topology using canonical identities. */
export function assertInitialInvitationMembershipTopology(
  state: InitialInvitationMembershipState,
  role: InvitationRole,
  phase: InitialInvitationMembershipPhase,
): void {
  const disposition = classifyInitialMembership(
    state.createdLocally,
    state.founder,
    state.recipient,
    state.readers,
    state.writers,
    role === 'editor',
    phase === 'ready-to-attest',
  );
  if (disposition === 'valid') return;
  const messages = {
    notFounder:
      'Invitation acceptance is limited to the founder process that created the document',
    sameIdentity: 'Invitation recipient must use a distinct identity',
    duplicates: 'Invitation membership contains duplicate canonical identities',
    founderMissing: 'Invitation founder is no longer an authorized writer',
    unrelatedReader: 'Invitation membership contains an unrelated reader',
    unrelatedWriter: 'Invitation membership contains an unrelated writer',
    readerMissing: 'Invitation recipient is not the document reader',
    roleMissing: 'Invitation recipient does not have the requested role',
  };
  throw new Error(messages[disposition]);
}

/** @internal One non-poisoning FIFO for invitation-sensitive state writers. */
export class InvitationMembershipQueue {
  private _tail: Promise<void> = Promise.resolve();

  public async run<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this._tail;
    let release!: () => void;
    this._tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

/** @internal Detect inline or deferred reader/writer ACL nodes. */
export function changeTreeContainsMembershipChange<ChangesType>(
  node: CRDTChangeNode<ChangesType>,
): boolean {
  return collectBoundedChangeTree(undefined, node).some(
    ({ kind }) =>
      kind === crdtReaderChangeNode || kind === crdtWriterChangeNode,
  );
}

interface PrepareInitialInvitationMembershipOptions<Welcome> {
  readonly role: InvitationRole;
  readonly getState: () => Promise<InitialInvitationMembershipState>;
  readonly addReader: () => Promise<Welcome>;
  readonly addWriter: () => Promise<void>;
}

/** @internal Onboard one exact recipient before bootstrap attestation. */
export async function prepareInitialInvitationMembership<Welcome>(
  options: PrepareInitialInvitationMembershipOptions<Welcome>,
): Promise<Welcome> {
  assertInitialInvitationMembershipTopology(
    await options.getState(),
    options.role,
    'preflight',
  );

  const welcome = await options.addReader();
  if (options.role === 'editor') await options.addWriter();

  assertInitialInvitationMembershipTopology(
    await options.getState(),
    options.role,
    'ready-to-attest',
  );
  return welcome;
}
