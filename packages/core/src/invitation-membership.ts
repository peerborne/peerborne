import {
  crdtChangeNodeDeferred,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
  type CRDTChangeNode,
} from './crdt-change-node.js';
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
  if (state.issuer === state.recipient) {
    throw new Error('Invitation recipient must use a distinct identity');
  }

  const readers = new Set(state.readers);
  const writers = new Set(state.writers);
  if (
    readers.size !== state.readers.length ||
    writers.size !== state.writers.length
  ) {
    throw new Error(
      'Invitation bootstrap membership contains duplicate canonical identities',
    );
  }
  if (readers.size !== 1 || !readers.has(state.recipient)) {
    throw new Error(
      'Invitation bootstrap readers do not match the signed recipient',
    );
  }

  const expectedWriters = new Set([state.issuer]);
  if (role === 'editor') expectedWriters.add(state.recipient);
  if (
    writers.size !== expectedWriters.size ||
    [...expectedWriters].some((identity) => !writers.has(identity))
  ) {
    throw new Error(
      'Invitation bootstrap writers do not match the signed issuer and role',
    );
  }
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
  if (!state.createdLocally) {
    throw new Error(
      'Invitation acceptance is limited to the founder process that created the document',
    );
  }
  if (state.founder === state.recipient) {
    throw new Error('Invitation recipient must use a distinct identity');
  }

  const readers = new Set(state.readers);
  const writers = new Set(state.writers);
  if (
    readers.size !== state.readers.length ||
    writers.size !== state.writers.length
  ) {
    throw new Error(
      'Invitation membership contains duplicate canonical identities',
    );
  }
  if (!writers.has(state.founder)) {
    throw new Error('Invitation founder is no longer an authorized writer');
  }
  if ([...readers].some((identity) => identity !== state.recipient)) {
    throw new Error('Invitation membership contains an unrelated reader');
  }

  const allowedWriters = new Set([state.founder]);
  if (role === 'editor') allowedWriters.add(state.recipient);
  if ([...writers].some((identity) => !allowedWriters.has(identity))) {
    throw new Error('Invitation membership contains an unrelated writer');
  }

  if (phase === 'ready-to-attest') {
    if (readers.size !== 1 || !readers.has(state.recipient)) {
      throw new Error('Invitation recipient is not the document reader');
    }
    const expectedWriterCount = role === 'editor' ? 2 : 1;
    if (
      writers.size !== expectedWriterCount ||
      (role === 'editor' && !writers.has(state.recipient))
    ) {
      throw new Error('Invitation recipient does not have the requested role');
    }
  }
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
  if (
    node.kind === crdtReaderChangeNode ||
    node.kind === crdtWriterChangeNode
  ) {
    return true;
  }
  if (node.children === undefined || node.children === crdtChangeNodeDeferred) {
    return false;
  }
  return Object.values(node.children).some((child) =>
    changeTreeContainsMembershipChange(child),
  );
}

interface PrepareInitialInvitationMembershipOptions<Welcome> {
  readonly role: InvitationRole;
  readonly getState: () => Promise<InitialInvitationMembershipState>;
  readonly addReader: () => Promise<Welcome>;
  readonly addWriter: () => Promise<void>;
  readonly repairReaders: () => Promise<void>;
  readonly repairWriters: () => Promise<void>;
}

/** @internal Onboard or repair one exact recipient before bootstrap attestation. */
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

  // ACL providers mutate before publication completes. Re-publish both full
  // snapshots on every attempt so a retry repairs either missing DAG node.
  await options.repairReaders();
  await options.repairWriters();
  return welcome;
}
