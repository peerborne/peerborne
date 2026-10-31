import * as mls from 'ts-mls';
import { makeKeyPackageRef, verifyKeyPackage } from 'ts-mls/keyPackage.js';
import { verifyLeafNodeSignatureKeyPackage } from 'ts-mls/leafNode.js';
import { validateRatchetTree } from 'ts-mls/clientState.js';
import { getHpkePublicKey } from 'ts-mls/ratchetTree.js';
import {
  EncryptedGroupState,
  EncryptedKeyPackageState,
  copyUnsharedUint8Array,
  type AppliedGroupMembershipChange,
  type CreateGroupCommitInput,
  type CreateGroupInput,
  type CreateKeyPackageInput,
  type GroupKeyPackage,
  type GroupSecurityCommit,
  type GroupSecurityCommitResult,
  type GroupSecurityPublicState,
  type GroupStateProtector,
  type GroupWelcome,
} from '@peerborne/core/browser-primitives';

const encoder = new TextEncoder();
const PROTOCOL = Object.freeze({
  id: 'peerborne/mls-provider-spike',
  version: 1,
});
const SUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
const MAX_WIRE = 4 * 1024 * 1024;
const MAX_STATE = 16 * 1024 * 1024;
const MAX_PENDING = 64;
const MAX_MEMBERS = 256;
type SignatureKeys = Awaited<
  ReturnType<mls.CiphersuiteImpl['signature']['keygen']>
>;
export type CredentialPolicy = (binding: {
  memberId: Uint8Array;
  signingKey: Uint8Array;
  credential: Uint8Array;
}) => Promise<boolean>;
type Pending = {
  publicValue: GroupKeyPackage;
  privateValue: mls.PrivateKeyPackage;
  envelopes: Map<string, EncryptedKeyPackageState>;
};

function fail(): never {
  throw new Error('MLS provider rejected the operation');
}
function requireValue(condition: unknown): asserts condition {
  if (!condition) fail();
}
function bytes(input: Uint8Array, max = MAX_WIRE, min = 0): Uint8Array {
  return copyUnsharedUint8Array(input, min, max);
}
function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function key(value: Uint8Array): string {
  return Array.from(value, (value) => value.toString(16).padStart(2, '0')).join(
    '',
  );
}
function capture<T>(input: T): T {
  let remaining = MAX_WIRE + 65536,
    nodes = 2048;
  const seen = new Set<object>();
  function copy(value: unknown): unknown {
    requireValue(--nodes >= 0);
    if (ArrayBuffer.isView(value)) {
      const result = copyUnsharedUint8Array(value, 0, Math.max(0, remaining));
      remaining -= result.length;
      return result;
    }
    if (
      value === undefined ||
      value === null ||
      typeof value === 'boolean' ||
      typeof value === 'bigint'
    )
      return value;
    if (typeof value === 'number') {
      requireValue(Number.isFinite(value));
      return value;
    }
    if (typeof value === 'string') {
      requireValue(value.length <= 16384);
      return value;
    }
    requireValue(typeof value === 'object' && !seen.has(value));
    seen.add(value);
    if (value instanceof Map) {
      requireValue(value.size <= 64);
      return new Map([...value].map(([k, v]) => [copy(k), copy(v)]));
    }
    const prototype = Object.getPrototypeOf(value);
    requireValue(
      Array.isArray(value) ||
        prototype === Object.prototype ||
        prototype === null,
    );
    const descriptors = Object.getOwnPropertyDescriptors(value),
      result: Record<string, unknown> = {};
    requireValue(Reflect.ownKeys(descriptors).length <= 1024);
    if (Array.isArray(value)) {
      requireValue(value.length <= 256);
      return Array.from({ length: value.length }, (_, i) => {
        const descriptor = descriptors[String(i)];
        requireValue(descriptor && 'value' in descriptor);
        return copy(descriptor.value);
      });
    }
    for (const [name, descriptor] of Object.entries(descriptors)) {
      requireValue('value' in descriptor && name !== '__proto__');
      result[name] = copy(descriptor.value);
    }
    return result;
  }
  return copy(input) as T;
}
function frame(domain: string, fields: Uint8Array[]): Uint8Array {
  const prefix = encoder.encode(domain + '\0');
  const result = new Uint8Array(
    prefix.length + fields.reduce((size, field) => size + 4 + field.length, 0),
  );
  result.set(prefix);
  const view = new DataView(result.buffer);
  let offset = prefix.length;
  for (const field of fields) {
    view.setUint32(offset, field.length);
    offset += 4;
    result.set(field, offset);
    offset += field.length;
  }
  return result;
}
function unframe(
  input: Uint8Array,
  domain: string,
  limits: number[],
): Uint8Array[] {
  const value = bytes(input, MAX_STATE, 1);
  const prefix = encoder.encode(domain + '\0');
  requireValue(same(value.subarray(0, prefix.length), prefix));
  const view = new DataView(value.buffer);
  let offset = prefix.length;
  const fields: Uint8Array[] = [];
  try {
    for (const limit of limits) {
      requireValue(offset + 4 <= value.length);
      const length = view.getUint32(offset);
      offset += 4;
      requireValue(length <= limit && offset + length <= value.length);
      fields.push(value.slice(offset, offset + length));
      offset += length;
    }
    requireValue(offset === value.length);
    return fields;
  } catch {
    wipe(fields);
    fail();
  } finally {
    value.fill(0);
  }
}
function wipe(value: unknown): void {
  if (value instanceof Uint8Array) {
    value.fill(0);
    return;
  }
  if (value instanceof Map) {
    for (const item of value.values()) wipe(item);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) wipe(item);
    return;
  }
  if (value && typeof value === 'object')
    for (const item of Object.values(value)) wipe(item);
}

/** Experimental adapter; terminal removal and self-update need coordinator contracts. */
export class MlsProviderSpike {
  readonly protocol = PROTOCOL;
  readonly lifecycleIdentity = {};
  readonly #member: Uint8Array;
  readonly #controller: Uint8Array;
  readonly #authenticate: CredentialPolicy;
  readonly #suite: mls.CiphersuiteImpl;
  #signing: SignatureKeys;
  #state?: mls.ClientState;
  #scope?: Uint8Array;
  #retired = false;
  #obsoletePathsErased = 0;
  #pending = new Map<string, Pending>();
  #consumed = new Set<string>();
  #tail: Promise<unknown> = Promise.resolve();

  private constructor(
    member: Uint8Array,
    controller: Uint8Array,
    policy: CredentialPolicy,
    suite: mls.CiphersuiteImpl,
    signing: SignatureKeys,
  ) {
    this.#member = member;
    this.#controller = controller;
    this.#authenticate = policy;
    this.#suite = suite;
    this.#signing = signing;
  }
  static async initialize(
    memberId: Uint8Array,
    controllerId: Uint8Array,
    authenticate: CredentialPolicy,
  ): Promise<MlsProviderSpike> {
    const member = bytes(memberId, 512, 1),
      controller = bytes(controllerId, 512, 1);
    requireValue(typeof authenticate === 'function');
    const suite = await mls.getCiphersuiteImpl(
      mls.getCiphersuiteFromName(SUITE),
    );
    return new MlsProviderSpike(
      member,
      controller,
      authenticate,
      suite,
      await suite.signature.keygen(),
    );
  }
  get credentialSigningKey(): Uint8Array {
    const own = this.#state?.ratchetTree[this.#state.privatePath.leafIndex * 2];
    return own?.nodeType === 'leaf'
      ? own.leaf.signaturePublicKey.slice()
      : this.#signing.publicKey.slice();
  }
  get obsoletePathsErased(): number {
    return this.#obsoletePathsErased;
  }
  async hasActiveGroup(): Promise<boolean> {
    await this.#tail;
    return this.#state !== undefined && !this.#retired;
  }
  #run<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#tail.then(async () => {
      requireValue(!this.#retired);
      return operation();
    });
    this.#tail = result.catch(() => undefined);
    return result;
  }
  #config(): mls.ClientConfig {
    return {
      authService: {
        validateCredential: async (credential, signingKey) => {
          if (credential.credentialType !== 'basic') return false;
          try {
            const binding = this.#binding(credential.identity);
            return (
              (await this.#authenticate({
                memberId: binding.member.slice(),
                signingKey: signingKey.slice(),
                credential: binding.proof.slice(),
              })) === true
            );
          } catch {
            return false;
          }
        },
      },
      keyRetentionConfig: {
        retainKeysForGenerations: 0,
        retainKeysForEpochs: 0,
        maximumForwardRatchetSteps: 32,
      },
      lifetimeConfig: mls.defaultLifetimeConfig,
      keyPackageEqualityConfig: mls.defaultKeyPackageEqualityConfig,
      paddingConfig: mls.defaultPaddingConfig,
    };
  }
  #binding(credential: Uint8Array) {
    const [group, member, request, proof] = unframe(
      credential,
      'peerborne/mls-credential-spike/1',
      [32, 512, 32, 16 * 1024],
    );
    requireValue(
      group.length === 32 &&
        member.length > 0 &&
        request.length === 32 &&
        this.#scope &&
        same(group, this.#scope),
    );
    return { group, member, request, proof };
  }
  #decode(
    input: Uint8Array,
    wireformat: mls.MLSMessage['wireformat'],
  ): mls.MLSMessage {
    const value = bytes(input, MAX_WIRE, 1);
    const decoded = mls.decodeMlsMessage(value, 0);
    requireValue(
      decoded &&
        decoded[1] === value.length &&
        decoded[0].version === 'mls10' &&
        decoded[0].wireformat === wireformat,
    );
    return decoded[0];
  }
  #setScope(group: Uint8Array): void {
    requireValue(group.length === 32);
    if (this.#state)
      requireValue(same(group, this.#state.groupContext.groupId));
    for (const pending of this.#pending.values())
      requireValue(same(group, pending.publicValue.groupId));
    this.#scope = group.slice();
  }
  async #package(value: GroupKeyPackage) {
    requireValue(
      value.protocol.id === PROTOCOL.id &&
        value.protocol.version === PROTOCOL.version,
    );
    this.#setScope(bytes(value.groupId, 32, 32));
    const message = this.#decode(value.payload, 'mls_key_package');
    requireValue(message.wireformat === 'mls_key_package');
    const kp = message.keyPackage;
    requireValue(
      kp.version === 'mls10' &&
        kp.cipherSuite === SUITE &&
        kp.initKey.length === 32 &&
        kp.leafNode.hpkePublicKey.length === 32 &&
        kp.leafNode.signaturePublicKey.length === 32 &&
        !same(kp.initKey, kp.leafNode.hpkePublicKey),
    );
    const now = BigInt(Math.floor(Date.now() / 1000));
    requireValue(
      kp.leafNode.lifetime.notBefore <= now &&
        now <= kp.leafNode.lifetime.notAfter,
    );
    requireValue(
      (await verifyKeyPackage(kp, this.#suite.signature)) &&
        (await verifyLeafNodeSignatureKeyPackage(
          kp.leafNode,
          this.#suite.signature,
        )),
    );
    requireValue(
      same(await makeKeyPackageRef(kp, this.#suite.hash), value.reference),
    );
    requireValue(
      await this.#config().authService.validateCredential(
        kp.leafNode.credential,
        kp.leafNode.signaturePublicKey,
      ),
    );
    requireValue(kp.leafNode.credential.credentialType === 'basic');
    return { kp, ...this.#binding(kp.leafNode.credential.identity) };
  }
  async #newPackage(
    group: Uint8Array,
    credential: Uint8Array,
    request: Uint8Array,
  ): Promise<Pending> {
    this.#setScope(group);
    const identity = frame('peerborne/mls-credential-spike/1', [
      group,
      this.#member,
      request,
      credential,
    ]);
    const generated = await mls.generateKeyPackageWithKey(
      { credentialType: 'basic', identity },
      mls.defaultCapabilities(),
      mls.defaultLifetime,
      [],
      {
        publicKey: this.#signing.publicKey.slice(),
        signKey: this.#signing.signKey.slice(),
      },
      this.#suite,
    );
    const publicValue: GroupKeyPackage = {
      protocol: PROTOCOL,
      groupId: group.slice(),
      reference: await makeKeyPackageRef(
        generated.publicPackage,
        this.#suite.hash,
      ),
      payload: mls.encodeMlsMessage({
        version: 'mls10',
        wireformat: 'mls_key_package',
        keyPackage: generated.publicPackage,
      }),
    };
    try {
      await this.#package(publicValue);
    } catch {
      wipe(generated.privatePackage);
      fail();
    }
    return {
      publicValue,
      privateValue: generated.privatePackage,
      envelopes: new Map(),
    };
  }
  createKeyPackage(input: CreateKeyPackageInput): Promise<GroupKeyPackage> {
    const value = capture(input);
    return this.#run(async () => {
      requireValue(
        !this.#state &&
          !value.extensions?.size &&
          same(value.memberId, this.#member) &&
          this.#pending.size < MAX_PENDING,
      );
      const pending = await this.#newPackage(
        bytes(value.groupId, 32, 32),
        bytes(value.credential, 16 * 1024),
        bytes(value.requestCommitment, 32, 32),
      );
      const id = key(pending.publicValue.reference);
      requireValue(!this.#consumed.has(id));
      this.#pending.set(id, pending);
      return structuredClone(pending.publicValue);
    });
  }
  authenticateKeyPackageMember(value: GroupKeyPackage): Promise<Uint8Array> {
    const snapshot = capture(value);
    return this.#run(async () =>
      (await this.#package(snapshot)).member.slice(),
    );
  }
  authenticateKeyPackageRequestCommitment(
    value: GroupKeyPackage,
  ): Promise<Uint8Array> {
    const snapshot = capture(value);
    return this.#run(async () =>
      (await this.#package(snapshot)).request.slice(),
    );
  }
  exportEncryptedKeyPackage(
    reference: Uint8Array,
    protector: GroupStateProtector,
  ): Promise<EncryptedKeyPackageState> {
    const ref = bytes(reference, 32, 32);
    return this.#run(async () => {
      const pending = this.#pending.get(key(ref));
      requireValue(pending);
      const cacheKey = JSON.stringify([protector.algorithm, protector.keyId]);
      let envelope = pending.envelopes.get(cacheKey);
      if (!envelope) {
        const material = frame('peerborne/mls-private-package-spike/1', [
          pending.privateValue.initPrivateKey,
          pending.privateValue.hpkePrivateKey,
          pending.privateValue.signaturePrivateKey,
        ]);
        try {
          envelope = await EncryptedKeyPackageState.seal(
            pending.publicValue,
            material,
            protector,
          );
        } finally {
          material.fill(0);
        }
        pending.envelopes.set(cacheKey, envelope);
      }
      return EncryptedKeyPackageState.deserialize(envelope.serialize());
    });
  }
  importEncryptedKeyPackage(
    envelope: EncryptedKeyPackageState,
    protector: GroupStateProtector,
  ): Promise<GroupKeyPackage> {
    const serialized = envelope.serialize();
    requireValue(serialized.length <= MAX_WIRE + 8192);
    const snapshot = EncryptedKeyPackageState.deserialize(serialized);
    requireValue(snapshot.ciphertext.length <= 1024);
    return this.#run(async () => {
      const value = snapshot.keyPackage,
        id = key(value.reference);
      requireValue(
        !this.#state &&
          !this.#consumed.has(id) &&
          !this.#pending.has(id) &&
          this.#pending.size < MAX_PENDING,
      );
      const validated = await this.#package(value);
      requireValue(same(validated.member, this.#member));
      const raw = await snapshot.open(protector);
      let fields: Uint8Array[] = [];
      try {
        fields = unframe(
          raw,
          'peerborne/mls-private-package-spike/1',
          [128, 128, 128],
        );
        const [initPrivateKey, hpkePrivateKey, signaturePrivateKey] = fields;
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        requireValue(
          await this.#suite.signature.verify(
            validated.kp.leafNode.signaturePublicKey,
            challenge,
            await this.#suite.signature.sign(signaturePrivateKey, challenge),
          ),
        );
        for (const [privateKey, publicKey] of [
          [initPrivateKey, validated.kp.initKey],
          [hpkePrivateKey, validated.kp.leafNode.hpkePublicKey],
        ]) {
          const sealed = await this.#suite.hpke.seal(
            await this.#suite.hpke.importPublicKey(publicKey),
            challenge,
            challenge,
          );
          const opened = await this.#suite.hpke.open(
            await this.#suite.hpke.importPrivateKey(privateKey),
            sealed.enc,
            sealed.ct,
            challenge,
          );
          requireValue(same(opened, challenge));
          opened.fill(0);
        }
        this.#pending.set(id, {
          publicValue: value,
          privateValue: { initPrivateKey, hpkePrivateKey, signaturePrivateKey },
          envelopes: new Map([
            [JSON.stringify([snapshot.algorithm, snapshot.keyId]), snapshot],
          ]),
        });
        fields = [];
        return structuredClone(value);
      } finally {
        raw.fill(0);
        wipe(fields);
      }
    });
  }
  #clone(state: mls.ClientState): mls.ClientState {
    const encoded = mls.encodeGroupState(state);
    try {
      requireValue(encoded.length <= MAX_STATE);
      const decoded = mls.decodeGroupState(encoded, 0);
      requireValue(decoded && decoded[1] === encoded.length);
      return { ...structuredClone(decoded[0]), clientConfig: this.#config() };
    } finally {
      encoded.fill(0);
    }
  }
  async #validate(state: mls.ClientState): Promise<void> {
    requireValue(
      state.groupContext.version === 'mls10' &&
        state.groupContext.cipherSuite === SUITE &&
        state.groupActiveState.kind === 'active' &&
        state.historicalReceiverData.size === 0 &&
        Object.keys(state.unappliedProposals).length === 0,
    );
    this.#setScope(state.groupContext.groupId);
    requireValue(
      state.ratchetTree.length >= 1 &&
        state.ratchetTree.length <= MAX_MEMBERS * 2 - 1 &&
        state.ratchetTree.length % 2 === 1,
    );
    requireValue(
      (await validateRatchetTree(
        state.ratchetTree,
        state.groupContext,
        state.clientConfig.lifetimeConfig,
        state.clientConfig.authService,
        state.groupContext.treeHash,
        this.#suite,
      )) === undefined,
    );
    const members = new Set<string>();
    for (const node of state.ratchetTree) {
      if (!node || node.nodeType !== 'leaf') continue;
      requireValue(
        await state.clientConfig.authService.validateCredential(
          node.leaf.credential,
          node.leaf.signaturePublicKey,
        ),
      );
      requireValue(node.leaf.credential.credentialType === 'basic');
      const binding = this.#binding(node.leaf.credential.identity);
      requireValue(!members.has(key(binding.member)));
      members.add(key(binding.member));
    }
    requireValue(
      members.size > 0 &&
        members.size <= MAX_MEMBERS &&
        members.has(key(this.#member)) &&
        members.has(key(this.#controller)),
    );
    const own = state.ratchetTree[state.privatePath.leafIndex * 2];
    requireValue(
      own?.nodeType === 'leaf' &&
        own.leaf.credential.credentialType === 'basic' &&
        same(this.#binding(own.leaf.credential.identity).member, this.#member),
    );
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    requireValue(
      await this.#suite.signature.verify(
        own.leaf.signaturePublicKey,
        challenge,
        await this.#suite.signature.sign(state.signaturePrivateKey, challenge),
      ),
    );
    requireValue(
      state.privatePath.privateKeys[state.privatePath.leafIndex * 2],
    );
    const privateNodes = Object.entries(state.privatePath.privateKeys);
    requireValue(privateNodes.length <= 10);
    for (const [position, privateKey] of privateNodes) {
      const index = Number(position),
        node = state.ratchetTree[index];
      requireValue(Number.isSafeInteger(index) && index >= 0 && node);
      const sealed = await this.#suite.hpke.seal(
        await this.#suite.hpke.importPublicKey(getHpkePublicKey(node)),
        challenge,
        challenge,
      );
      const opened = await this.#suite.hpke.open(
        await this.#suite.hpke.importPrivateKey(privateKey),
        sealed.enc,
        sealed.ct,
        challenge,
      );
      requireValue(same(opened, challenge));
      opened.fill(0);
    }
  }
  async #validateGenerated(state: mls.ClientState): Promise<void> {
    for (const [position, privateKey] of Object.entries(
      state.privatePath.privateKeys,
    )) {
      if (state.ratchetTree[Number(position)] === undefined) {
        privateKey.fill(0);
        delete state.privatePath.privateKeys[Number(position)];
        this.#obsoletePathsErased++;
      }
    }
    await this.#validate(state);
  }
  #public(state: mls.ClientState): GroupSecurityPublicState {
    return {
      protocol: PROTOCOL,
      groupId: state.groupContext.groupId.slice(),
      epoch: state.groupContext.epoch,
      treeHash: state.groupContext.treeHash.slice(),
      confirmedTranscriptHash:
        state.groupContext.confirmedTranscriptHash.slice(),
    };
  }
  #commitState(state: mls.ClientState): void {
    const detached = this.#clone(state);
    wipe(this.#state);
    this.#state = detached;
  }
  createGroup(input: CreateGroupInput) {
    const value = capture(input);
    return this.#run(async () => {
      requireValue(
        !this.#state &&
          !value.authenticatedData &&
          same(value.creatorMemberId, this.#member) &&
          same(this.#member, this.#controller),
      );
      const pending = await this.#newPackage(
        bytes(value.groupId, 32, 32),
        bytes(value.credential, 16 * 1024),
        new Uint8Array(32),
      );
      try {
        const message = this.#decode(
          pending.publicValue.payload,
          'mls_key_package',
        );
        requireValue(message.wireformat === 'mls_key_package');
        const state = await mls.createGroup(
          value.groupId.slice(),
          message.keyPackage,
          pending.privateValue,
          [],
          this.#suite,
          this.#config(),
        );
        await this.#validateGenerated(state);
        this.#commitState(state);
        return {
          state: this.#public(state),
          authenticatedCreatorMemberId: this.#member.slice(),
        };
      } finally {
        wipe(pending.privateValue);
      }
    });
  }
  joinGroup(input: {
    welcome: GroupWelcome;
    keyPackageRef: Uint8Array;
    authenticatedData?: Uint8Array;
  }) {
    const value = capture(input);
    return this.#run(async () => {
      requireValue(
        !this.#state &&
          !value.authenticatedData &&
          value.welcome.protocol.id === PROTOCOL.id &&
          value.welcome.protocol.version === PROTOCOL.version &&
          same(value.welcome.recipientKeyPackageRef, value.keyPackageRef),
      );
      const id = key(value.keyPackageRef),
        pending = this.#pending.get(id);
      requireValue(
        pending && !this.#consumed.has(id) && this.#consumed.size < 4096,
      );
      requireValue(same(value.welcome.groupId, pending.publicValue.groupId));
      const kp = await this.#package(pending.publicValue);
      const welcome = this.#decode(value.welcome.payload, 'mls_welcome');
      requireValue(welcome.wireformat === 'mls_welcome');
      const state = await mls.joinGroup(
        welcome.welcome,
        kp.kp,
        structuredClone(pending.privateValue),
        mls.emptyPskIndex,
        this.#suite,
        undefined,
        undefined,
        this.#config(),
      );
      requireValue(
        state.groupContext.epoch === value.welcome.epoch &&
          same(state.groupContext.groupId, value.welcome.groupId),
      );
      await this.#validate(state);
      this.#commitState(state);
      this.#pending.delete(id);
      this.#consumed.add(id);
      wipe(pending.privateValue);
      return this.#public(state);
    });
  }
  getPublicState(): Promise<GroupSecurityPublicState> {
    return this.#run(async () => {
      requireValue(this.#state);
      return this.#public(this.#state);
    });
  }
  createCommit(
    input: CreateGroupCommitInput,
  ): Promise<GroupSecurityCommitResult> {
    const value = capture(input);
    return this.#run(async () => {
      requireValue(
        this.#state &&
          same(this.#member, this.#controller) &&
          value.changes.length <= 1,
      );
      const before = this.#state,
        stage = this.#clone(before);
      const proposals: mls.Proposal[] = [],
        applied: AppliedGroupMembershipChange[] = [];
      let addRef: Uint8Array | undefined;
      let addedLeaf: mls.LeafNode | undefined;
      try {
        for (const change of value.changes) {
          if (change.kind === 'add') {
            const kp = await this.#package(change.keyPackage);
            requireValue(same(kp.member, change.memberId));
            proposals.push({ proposalType: 'add', add: { keyPackage: kp.kp } });
            addedLeaf = kp.kp.leafNode;
            addRef = change.keyPackage.reference.slice();
            applied.push({
              kind: 'add',
              memberId: kp.member.slice(),
              keyPackageRef: addRef,
            });
          } else if (change.kind === 'remove') {
            requireValue(!same(change.memberId, this.#controller));
            const index = this.#memberIndex(stage, change.memberId);
            requireValue(index !== undefined);
            proposals.push({
              proposalType: 'remove',
              remove: { removed: index },
            });
            applied.push({ kind: 'remove', memberId: change.memberId.slice() });
          } else {
            fail();
          }
        }
        const result = await mls.createCommit(
          { state: stage, cipherSuite: this.#suite },
          {
            wireAsPublicMessage: true,
            ratchetTreeExtension: true,
            extraProposals: proposals,
            authenticatedData: value.authenticatedData,
          },
        );
        await this.#validateGenerated(result.newState);
        requireValue(
          result.newState.groupContext.epoch === before.groupContext.epoch + 1n,
        );
        this.#checkApplied(before, result.newState, applied, addedLeaf);
        const state = this.#public(result.newState);
        const commit: GroupSecurityCommit = {
          protocol: PROTOCOL,
          groupId: state.groupId.slice(),
          priorEpoch: before.groupContext.epoch,
          epoch: state.epoch,
          payload: mls.encodeMlsMessage(result.commit),
        };
        requireValue(commit.payload.length <= MAX_WIRE);
        const welcomes: GroupWelcome[] =
          result.welcome && addRef
            ? [
                {
                  protocol: PROTOCOL,
                  groupId: state.groupId.slice(),
                  epoch: state.epoch,
                  recipientKeyPackageRef: addRef.slice(),
                  payload: mls.encodeMlsMessage({
                    version: 'mls10',
                    wireformat: 'mls_welcome',
                    welcome: result.welcome,
                  }),
                },
              ]
            : [];
        requireValue(
          welcomes.every((welcome) => welcome.payload.length <= MAX_WIRE),
        );
        requireValue(
          result.consumed.every((secret) => secret instanceof Uint8Array),
        );
        this.#commitState(result.newState);
        result.consumed.forEach((secret) => secret.fill(0));
        return {
          commit,
          welcomes,
          state,
          appliedMembership: { changes: applied },
        };
      } finally {
        wipe(stage);
      }
    });
  }
  #memberIndex(state: mls.ClientState, member: Uint8Array): number | undefined {
    for (let index = 0; index < state.ratchetTree.length; index += 2) {
      const node = state.ratchetTree[index];
      if (
        node?.nodeType === 'leaf' &&
        node.leaf.credential.credentialType === 'basic' &&
        same(this.#binding(node.leaf.credential.identity).member, member)
      )
        return index / 2;
    }
    return undefined;
  }
  #checkApplied(
    before: mls.ClientState,
    after: mls.ClientState,
    applied: AppliedGroupMembershipChange[],
    expectedLeaf?: mls.LeafNode,
  ): void {
    const roster = (state: mls.ClientState) => {
      const result = new Map<string, mls.LeafNode>();
      for (const node of state.ratchetTree) {
        if (!node || node.nodeType !== 'leaf') continue;
        requireValue(node.leaf.credential.credentialType === 'basic');
        const id = key(this.#binding(node.leaf.credential.identity).member);
        requireValue(!result.has(id));
        result.set(id, node.leaf);
      }
      return result;
    };
    const oldRoster = roster(before),
      newRoster = roster(after);
    const added = [...newRoster.keys()].filter((id) => !oldRoster.has(id));
    const removed = [...oldRoster.keys()].filter((id) => !newRoster.has(id));
    requireValue(applied.length <= 1);
    const change = applied[0];
    if (!change) {
      requireValue(added.length === 0 && removed.length === 0);
      const controller = key(this.#controller),
        oldLeaf = oldRoster.get(controller),
        newLeaf = newRoster.get(controller);
      requireValue(
        oldLeaf &&
          newLeaf &&
          !same(oldLeaf.hpkePublicKey, newLeaf.hpkePublicKey),
      );
    } else if (change.kind === 'add') {
      requireValue(
        added.length === 1 &&
          removed.length === 0 &&
          added[0] === key(change.memberId) &&
          expectedLeaf,
      );
      const actual = newRoster.get(added[0])!;
      requireValue(
        actual.credential.credentialType === 'basic' &&
          expectedLeaf.credential.credentialType === 'basic' &&
          same(actual.hpkePublicKey, expectedLeaf.hpkePublicKey) &&
          same(actual.signaturePublicKey, expectedLeaf.signaturePublicKey) &&
          same(actual.credential.identity, expectedLeaf.credential.identity),
      );
    } else {
      requireValue(
        change.kind === 'remove' &&
          added.length === 0 &&
          removed.length === 1 &&
          removed[0] === key(change.memberId),
      );
    }
    for (const [id, oldLeaf] of oldRoster) {
      const newLeaf = newRoster.get(id);
      if (!newLeaf) continue;
      requireValue(
        oldLeaf.credential.credentialType === 'basic' &&
          newLeaf.credential.credentialType === 'basic' &&
          same(oldLeaf.credential.identity, newLeaf.credential.identity) &&
          same(oldLeaf.signaturePublicKey, newLeaf.signaturePublicKey),
      );
    }
  }
  applyCommit(input: GroupSecurityCommit) {
    const value = capture(input);
    return this.#run(async () => {
      requireValue(
        this.#state &&
          value.protocol.id === PROTOCOL.id &&
          value.protocol.version === PROTOCOL.version &&
          same(value.groupId, this.#state.groupContext.groupId) &&
          value.priorEpoch === this.#state.groupContext.epoch &&
          value.epoch === value.priorEpoch + 1n,
      );
      const stage = this.#clone(this.#state),
        applied: AppliedGroupMembershipChange[] = [];
      let addedLeaf: mls.LeafNode | undefined;
      try {
        const decoded = this.#decode(value.payload, 'mls_public_message');
        requireValue(decoded.wireformat === 'mls_public_message');
        requireValue(
          decoded.publicMessage.content.contentType === 'commit' &&
            decoded.publicMessage.content.epoch === value.priorEpoch,
        );
        const proposals = decoded.publicMessage.content.commit.proposals;
        requireValue(
          proposals.length <= 1 &&
            proposals.every(
              (proposal) => proposal.proposalOrRefType === 'proposal',
            ),
        );
        for (const item of proposals) {
          requireValue(item.proposalOrRefType === 'proposal');
          const proposal = item.proposal;
          if (proposal.proposalType === 'add') {
            const kp = proposal.add.keyPackage;
            addedLeaf = kp.leafNode;
            const ref = await makeKeyPackageRef(kp, this.#suite.hash);
            const bound = await this.#package({
              protocol: PROTOCOL,
              groupId: value.groupId,
              reference: ref,
              payload: mls.encodeMlsMessage({
                version: 'mls10',
                wireformat: 'mls_key_package',
                keyPackage: kp,
              }),
            });
            applied.push({
              kind: 'add',
              memberId: bound.member.slice(),
              keyPackageRef: ref,
            });
          } else if (proposal.proposalType === 'remove') {
            const node = stage.ratchetTree[proposal.remove.removed * 2];
            requireValue(
              node?.nodeType === 'leaf' &&
                node.leaf.credential.credentialType === 'basic',
            );
            const member = this.#binding(node.leaf.credential.identity).member;
            requireValue(!same(member, this.#controller));
            applied.push({ kind: 'remove', memberId: member.slice() });
          } else {
            fail();
          }
        }
        const result = await mls.processPublicMessage(
          stage,
          decoded.publicMessage,
          mls.emptyPskIndex,
          this.#suite,
          (incoming) => {
            if (
              incoming.kind !== 'commit' ||
              incoming.senderLeafIndex === undefined
            )
              return 'reject';
            return this.#memberIndex(stage, this.#controller) ===
              incoming.senderLeafIndex
              ? 'accept'
              : 'reject';
          },
        );
        requireValue(result.actionTaken === 'accept');
        this.#checkApplied(stage, result.newState, applied, addedLeaf);
        if (result.newState.groupActiveState.kind === 'removedFromGroup') {
          wipe(this.#state);
          this.#state = undefined;
          this.#retired = true;
          wipe(this.#signing);
          wipe(this.#pending);
          this.#pending.clear();
          return { status: 'removed' as const, memberId: this.#member.slice() };
        }
        await this.#validateGenerated(result.newState);
        requireValue(result.newState.groupContext.epoch === value.epoch);
        requireValue(
          result.consumed.every((secret) => secret instanceof Uint8Array),
        );
        this.#commitState(result.newState);
        result.consumed.forEach((secret) => secret.fill(0));
        return {
          status: 'applied' as const,
          state: this.#public(result.newState),
          appliedMembership: { changes: applied },
        };
      } finally {
        wipe(stage);
      }
    });
  }
  exportSecret(input: {
    label: string;
    context: Uint8Array;
    length: number;
  }): Promise<Uint8Array> {
    const value = capture(input);
    return this.#run(async () => {
      requireValue(
        this.#state &&
          value.label.length <= 128 &&
          Number.isInteger(value.length) &&
          value.length >= 1 &&
          value.length <= 64,
      );
      return mls.mlsExporter(
        this.#state.keySchedule.exporterSecret,
        value.label,
        bytes(value.context, 4096),
        value.length,
        this.#suite,
      );
    });
  }
  exportEncryptedState(
    protector: GroupStateProtector,
  ): Promise<EncryptedGroupState> {
    return this.#run(async () => {
      requireValue(this.#state);
      const encoded = mls.encodeGroupState(this.#state);
      const material = frame('peerborne/mls-group-spike/1', [
        this.#controller,
        this.#member,
        frame(
          'peerborne/mls-consumed-spike/1',
          [...this.#consumed].map((value) => encoder.encode(value)),
        ),
        encoded,
      ]);
      try {
        requireValue(material.length <= MAX_STATE);
        return await EncryptedGroupState.seal(
          this.#public(this.#state),
          material,
          protector,
        );
      } finally {
        material.fill(0);
        encoded.fill(0);
      }
    });
  }
  importEncryptedState(
    envelope: EncryptedGroupState,
    protector: GroupStateProtector,
  ): Promise<GroupSecurityPublicState> {
    const serialized = envelope.serialize();
    requireValue(serialized.length <= MAX_STATE + 4096);
    const snapshot = EncryptedGroupState.deserialize(serialized);
    return this.#run(async () => {
      const raw = await snapshot.open(protector);
      let fields: Uint8Array[] = [];
      let recovered: mls.ClientState | undefined;
      try {
        fields = unframe(raw, 'peerborne/mls-group-spike/1', [
          512,
          512,
          512 * 1024,
          MAX_STATE,
        ]);
        const [controller, member, consumed, encoded] = fields;
        requireValue(
          same(controller, this.#controller) && same(member, this.#member),
        );
        const decoded = mls.decodeGroupState(encoded, 0);
        requireValue(decoded && decoded[1] === encoded.length);
        const canonical = mls.encodeGroupState(decoded[0]);
        try {
          requireValue(same(canonical, encoded));
        } finally {
          canonical.fill(0);
        }
        const state: mls.ClientState = {
          ...structuredClone(decoded[0]),
          clientConfig: this.#config(),
        };
        recovered = state;
        const consumedCount =
          (consumed.length -
            encoder.encode('peerborne/mls-consumed-spike/1\0').length) /
          68;
        requireValue(
          Number.isInteger(consumedCount) &&
            consumedCount >= 0 &&
            consumedCount <= 4096,
        );
        const refs = unframe(
          consumed,
          'peerborne/mls-consumed-spike/1',
          Array(consumedCount).fill(64),
        );
        const ids = refs.map((ref) => {
          const value = new TextDecoder('utf-8', { fatal: true }).decode(ref);
          requireValue(/^[0-9a-f]{64}$/.test(value));
          return value;
        });
        requireValue(new Set(ids).size === ids.length);
        await this.#validate(state);
        const actual = this.#public(state),
          expected = snapshot.state;
        requireValue(
          actual.protocol.id === expected.protocol.id &&
            actual.protocol.version === expected.protocol.version &&
            actual.epoch === expected.epoch &&
            same(actual.groupId, expected.groupId) &&
            same(actual.treeHash, expected.treeHash) &&
            same(
              actual.confirmedTranscriptHash,
              expected.confirmedTranscriptHash,
            ),
        );
        this.#commitState(state);
        this.#consumed = new Set(ids);
        return actual;
      } finally {
        raw.fill(0);
        wipe(fields);
        wipe(recovered);
      }
    });
  }
  clearKeyPackageState(reference: Uint8Array): Promise<void> {
    const ref = key(bytes(reference, 32, 32));
    return this.#run(async () => {
      wipe(this.#pending.get(ref)?.privateValue);
      this.#pending.delete(ref);
    });
  }
  clearGroupState(): Promise<void> {
    return this.#run(async () => {
      wipe(this.#state);
      this.#state = undefined;
      wipe(this.#signing);
      wipe(this.#pending);
      this.#pending.clear();
      this.#retired = true;
    });
  }
}
