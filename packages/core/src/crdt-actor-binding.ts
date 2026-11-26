/**
 * Binds native CRDT actor identifiers (Yjs client IDs, Automerge actors, Loro
 * peer IDs) to the signing identity that authored their operations.
 *
 * A document instance draws a random nonce and writes under the actor derived
 * from its signer, document path and that nonce. Every document change carries
 * an authored-change envelope with the signer, the nonce and a signature over
 * the change bytes. A receiver admits a change only when the signature
 * verifies and every actor the change adds operations for is the actor its
 * envelope derives, so a writer cannot add operations under another signer's
 * actor. Each registration is also signed on its own, so replicas can remember
 * the first registration seen for each actor and carry it in snapshots and
 * checkpoints without trusting whoever relays it.
 */

/** Hooks a CRDT provider implements so documents can bind its actors to signers. */
export interface CRDTActorBinding<DocType, ChangesType> {
  /** Native actor identifier selected by a 32-byte derivation digest. */
  actorFromDigest(digest: Uint8Array): string;
  /** Native actor the document's next local change is made under. */
  localActor(document: DocType): string;
  /** Make `actor` the document's local actor. May return a new document. */
  setLocalActor(document: DocType, actor: string): DocType;
  /** Actors `changes` adds operations for, decoded without applying them. */
  changeActors(changes: ChangesType): ReadonlySet<string>;
  /** Actors with operations in a `getSnapshot()` or `getHistory()` state. */
  stateActors(state: ChangesType): ReadonlySet<string>;
  /** `changes` carrying `prefix`, an envelope or manifest. */
  attach(changes: ChangesType, prefix: Uint8Array): ChangesType;
  /** The prefix and bare changes. Throws when `changes` carries no prefix. */
  detach(changes: ChangesType): readonly [Uint8Array, ChangesType];
}

/** One actor's registration: the signer and per-instance nonce it derives from. */
export interface CRDTActorRegistration {
  readonly signer: string;
  readonly nonce: Uint8Array;
}

/** A registration with its signer's signature over the document path and nonce. */
export interface CRDTSignedActorRegistration extends CRDTActorRegistration {
  readonly registrationSignature: Uint8Array;
}

/** Authorship carried by a document change. */
export interface CRDTChangeAuthor extends CRDTSignedActorRegistration {
  readonly signature: Uint8Array;
}

/** A change or snapshot was rejected because its actors are not bound to its signer. */
export class CRDTActorBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CRDTActorBindingError';
  }
}

export const CRDT_ACTOR_NONCE_BYTES = 16;
/**
 * Bindings a replica remembers for one signer. Beyond it, the signer's least
 * recently used binding is forgotten; no registration is ever refused.
 */
export const MAX_CRDT_ACTORS_PER_SIGNER = 4096;
/** Bindings a replica remembers per document, forgetting the least recently used. */
export const MAX_CRDT_ACTOR_BINDINGS = 16384;
const MAX_SIGNER_BYTES = 1024;
const MAX_SIGNATURE_BYTES = 1024;
const MAX_MANIFEST_SIGNERS = MAX_CRDT_ACTOR_BINDINGS;
const MAX_MANIFEST_REGISTRATIONS = MAX_CRDT_ACTOR_BINDINGS;

const ACTOR_DOMAIN = 'peerborne/crdt-actor/v1\0';
const REGISTRATION_DOMAIN = 'peerborne/crdt-actor-registration/v1\0';
const SIGNATURE_DOMAIN = 'peerborne/crdt-change-author/v1\0';
const WRAP_MAGIC = [0x50, 0x42, 0x57, 0x31];
const ENVELOPE_MAGIC = [0x50, 0x42, 0x41, 0x31];
const MANIFEST_MAGIC = [0x50, 0x42, 0x4d, 0x31];

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

class Writer {
  private readonly parts: Uint8Array[] = [];
  private length = 0;
  bytes(value: Uint8Array | readonly number[]): this {
    const bytes = Uint8Array.from(value);
    this.parts.push(bytes);
    this.length += bytes.byteLength;
    return this;
  }
  u16(value: number): this {
    return this.bytes([value >>> 8, value & 0xff]);
  }
  u32(value: number): this {
    return this.bytes([
      value >>> 24,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    ]);
  }
  lengthPrefixed(value: Uint8Array): this {
    return this.u32(value.byteLength).bytes(value);
  }
  finish(): Uint8Array {
    const out = new Uint8Array(this.length);
    let offset = 0;
    for (const part of this.parts) {
      out.set(part, offset);
      offset += part.byteLength;
    }
    return out;
  }
}

class Reader {
  offset = 0;
  constructor(private readonly view: Uint8Array) {}
  take(length: number): Uint8Array {
    if (length < 0 || this.offset + length > this.view.byteLength)
      throw new CRDTActorBindingError('Truncated actor binding encoding');
    const out = this.view.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }
  u16(): number {
    const [a, b] = this.take(2);
    return (a! << 8) | b!;
  }
  u32(): number {
    const [a, b, c, d] = this.take(4);
    return ((a! << 24) >>> 0) + (b! << 16) + (c! << 8) + d!;
  }
  magic(expected: readonly number[], what: string): void {
    const actual = this.take(expected.length);
    if (actual.some((byte, index) => byte !== expected[index]))
      throw new CRDTActorBindingError(`Missing ${what}`);
  }
  end(): void {
    if (this.offset !== this.view.byteLength)
      throw new CRDTActorBindingError('Trailing actor binding bytes');
  }
}

function signerBytes(signer: string): Uint8Array {
  const bytes = encoder.encode(signer);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_SIGNER_BYTES)
    throw new CRDTActorBindingError('Invalid change signer');
  return bytes;
}

function readSigner(reader: Reader): string {
  const length = reader.u16();
  if (length === 0 || length > MAX_SIGNER_BYTES)
    throw new CRDTActorBindingError('Invalid change signer');
  try {
    return decoder.decode(reader.take(length));
  } catch {
    throw new CRDTActorBindingError('Invalid change signer');
  }
}

function assertNonce(nonce: Uint8Array): void {
  if (
    !(nonce instanceof Uint8Array) ||
    nonce.byteLength !== CRDT_ACTOR_NONCE_BYTES
  )
    throw new CRDTActorBindingError('Invalid actor nonce');
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index++) {
    if (left[index] !== right[index]) return left[index]! - right[index]!;
  }
  return left.byteLength - right.byteLength;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return compareBytes(left, right) === 0;
}

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

function readSignature(reader: Reader): Uint8Array {
  const length = reader.u16();
  if (length > MAX_SIGNATURE_BYTES)
    throw new CRDTActorBindingError('Invalid actor binding signature');
  return reader.take(length);
}

function signatureBytes(signature: Uint8Array): Uint8Array {
  if (
    !(signature instanceof Uint8Array) ||
    signature.byteLength > MAX_SIGNATURE_BYTES
  )
    throw new CRDTActorBindingError('Invalid actor binding signature');
  return signature;
}

/** Whether two registrations name the same signer and nonce. */
export function sameCRDTActorRegistration(
  left: CRDTActorRegistration,
  right: CRDTActorRegistration,
): boolean {
  return left.signer === right.signer && sameBytes(left.nonce, right.nonce);
}

/** Draw a fresh per-instance actor nonce. */
export function createCRDTActorNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(CRDT_ACTOR_NONCE_BYTES));
}

/** Derive the digest that selects a registration's native actor. */
export async function deriveCRDTActorDigest(
  documentPath: string,
  registration: CRDTActorRegistration,
): Promise<Uint8Array> {
  assertNonce(registration.nonce);
  const input = new Writer()
    .bytes(encoder.encode(ACTOR_DOMAIN))
    .lengthPrefixed(encoder.encode(documentPath))
    .lengthPrefixed(signerBytes(registration.signer))
    .bytes(registration.nonce)
    .finish();
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', input as Uint8Array<ArrayBuffer>),
  );
}

/** Bytes a signer signs to register one actor for a document. */
export function crdtActorRegistrationPayload(
  documentPath: string,
  registration: CRDTActorRegistration,
): Uint8Array {
  assertNonce(registration.nonce);
  return new Writer()
    .bytes(encoder.encode(REGISTRATION_DOMAIN))
    .lengthPrefixed(encoder.encode(documentPath))
    .lengthPrefixed(signerBytes(registration.signer))
    .bytes(registration.nonce)
    .finish();
}

/** Bytes an author signs for one document change. */
export function crdtChangeAuthorPayload(
  documentPath: string,
  registration: CRDTActorRegistration,
  changeBytes: Uint8Array,
): Uint8Array {
  assertNonce(registration.nonce);
  return new Writer()
    .bytes(encoder.encode(SIGNATURE_DOMAIN))
    .lengthPrefixed(encoder.encode(documentPath))
    .lengthPrefixed(signerBytes(registration.signer))
    .bytes(registration.nonce)
    .lengthPrefixed(changeBytes)
    .finish();
}

export function encodeCRDTChangeAuthor(author: CRDTChangeAuthor): Uint8Array {
  assertNonce(author.nonce);
  const signer = signerBytes(author.signer);
  const registrationSignature = signatureBytes(author.registrationSignature);
  const signature = signatureBytes(author.signature);
  return new Writer()
    .bytes(ENVELOPE_MAGIC)
    .u16(signer.byteLength)
    .bytes(signer)
    .bytes(author.nonce)
    .u16(registrationSignature.byteLength)
    .bytes(registrationSignature)
    .u16(signature.byteLength)
    .bytes(signature)
    .finish();
}

export function decodeCRDTChangeAuthor(bytes: Uint8Array): CRDTChangeAuthor {
  const reader = new Reader(bytes);
  reader.magic(ENVELOPE_MAGIC, 'authored-change envelope');
  const signer = readSigner(reader);
  const nonce = reader.take(CRDT_ACTOR_NONCE_BYTES);
  const registrationSignature = readSignature(reader);
  const signature = readSignature(reader);
  reader.end();
  return { signer, nonce, registrationSignature, signature };
}

/** Canonical encoding of a registration set: equal sets encode identically. */
export function encodeCRDTActorManifest(
  registrations: Iterable<CRDTSignedActorRegistration>,
): Uint8Array {
  const bySigner = new Map<string, Map<string, CRDTSignedActorRegistration>>();
  for (const registration of registrations) {
    assertNonce(registration.nonce);
    signerBytes(registration.signer);
    signatureBytes(registration.registrationSignature);
    let nonces = bySigner.get(registration.signer);
    if (nonces === undefined)
      bySigner.set(registration.signer, (nonces = new Map()));
    const key = hexOf(registration.nonce);
    if (!nonces.has(key)) nonces.set(key, registration);
  }
  const signers = [...bySigner.keys()]
    .map((signer) => [signer, encoder.encode(signer)] as const)
    .sort(([, left], [, right]) => compareBytes(left, right));
  const writer = new Writer().bytes(MANIFEST_MAGIC).u32(signers.length);
  for (const [, bytes] of signers) writer.u16(bytes.byteLength).bytes(bytes);
  const entries = signers.flatMap(([signer], index) =>
    [...bySigner.get(signer)!.values()]
      .sort((left, right) => compareBytes(left.nonce, right.nonce))
      .map((registration) => [index, registration] as const),
  );
  writer.u32(entries.length);
  for (const [index, { nonce, registrationSignature }] of entries)
    writer
      .u32(index)
      .bytes(nonce)
      .u16(registrationSignature.byteLength)
      .bytes(registrationSignature);
  return writer.finish();
}

export function decodeCRDTActorManifest(
  bytes: Uint8Array,
): CRDTSignedActorRegistration[] {
  const reader = new Reader(bytes);
  reader.magic(MANIFEST_MAGIC, 'actor manifest');
  const signerCount = reader.u32();
  if (signerCount > MAX_MANIFEST_SIGNERS)
    throw new CRDTActorBindingError('Too many manifest signers');
  const signers: string[] = [];
  let previous: Uint8Array | undefined;
  for (let index = 0; index < signerCount; index++) {
    const signer = readSigner(reader);
    const encoded = encoder.encode(signer);
    if (previous !== undefined && compareBytes(previous, encoded) >= 0)
      throw new CRDTActorBindingError('Noncanonical actor manifest');
    previous = encoded;
    signers.push(signer);
  }
  const entryCount = reader.u32();
  if (entryCount > MAX_MANIFEST_REGISTRATIONS)
    throw new CRDTActorBindingError('Too many manifest registrations');
  const registrations: CRDTSignedActorRegistration[] = [];
  let last: readonly [number, Uint8Array] | undefined;
  const used = new Set<number>();
  for (let entry = 0; entry < entryCount; entry++) {
    const index = reader.u32();
    if (index >= signers.length)
      throw new CRDTActorBindingError('Invalid manifest signer index');
    const nonce = reader.take(CRDT_ACTOR_NONCE_BYTES);
    const registrationSignature = readSignature(reader);
    if (
      last !== undefined &&
      (index < last[0] ||
        (index === last[0] && compareBytes(last[1], nonce) >= 0))
    )
      throw new CRDTActorBindingError('Noncanonical actor manifest');
    last = [index, nonce];
    used.add(index);
    registrations.push({
      signer: signers[index]!,
      nonce,
      registrationSignature,
    });
  }
  if (used.size !== signers.length)
    throw new CRDTActorBindingError('Noncanonical actor manifest');
  reader.end();
  return registrations;
}

/** Prefix `payload` with an envelope or manifest for byte-valued providers. */
export function attachCRDTActorPrefix(
  payload: Uint8Array,
  prefix: Uint8Array,
): Uint8Array {
  return new Writer()
    .bytes(WRAP_MAGIC)
    .lengthPrefixed(prefix)
    .bytes(payload)
    .finish();
}

/** Split bytes produced by {@link attachCRDTActorPrefix}. */
export function detachCRDTActorPrefix(
  bytes: Uint8Array,
): readonly [Uint8Array, Uint8Array] {
  if (!(bytes instanceof Uint8Array))
    throw new CRDTActorBindingError('Missing actor binding prefix');
  const reader = new Reader(bytes);
  reader.magic(WRAP_MAGIC, 'actor binding prefix');
  const prefix = reader.take(reader.u32());
  return [prefix, bytes.slice(reader.offset)];
}

/** Whether `bytes` begins with an envelope or manifest magic. */
export function isCRDTActorPrefix(bytes: unknown): bytes is Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 4) return false;
  const starts = (magic: readonly number[]) =>
    magic.every((byte, index) => bytes[index] === byte);
  return starts(ENVELOPE_MAGIC) || starts(MANIFEST_MAGIC);
}

/**
 * First-seen registrations for the actors a replica has admitted. A different
 * registration for a remembered actor is rejected. Memory is bounded by
 * forgetting the least recently used binding beyond
 * {@link MAX_CRDT_ACTORS_PER_SIGNER} for one signer or
 * {@link MAX_CRDT_ACTOR_BINDINGS} in all, so honest use never stops a signer
 * from registering a new actor.
 */
export class CRDTActorBindings {
  private readonly _actors = new Map<string, CRDTSignedActorRegistration>();
  private readonly _bySigner = new Map<string, Set<string>>();

  get size(): number {
    return this._actors.size;
  }

  get(actor: string): CRDTSignedActorRegistration | undefined {
    return this._actors.get(actor);
  }

  signerCount(signer: string): number {
    return this._bySigner.get(signer)?.size ?? 0;
  }

  /** Throw if any pair conflicts with a remembered binding or another pair. */
  check(entries: Iterable<readonly [string, CRDTActorRegistration]>): void {
    const pending = new Map<string, CRDTActorRegistration>();
    for (const [actor, registration] of entries) {
      const known = this._actors.get(actor) ?? pending.get(actor);
      if (
        known !== undefined &&
        !sameCRDTActorRegistration(known, registration)
      )
        throw new CRDTActorBindingError(
          'CRDT actor is already bound to another registration',
        );
      pending.set(actor, registration);
    }
  }

  /** Remember pairs, refreshing ones already known. */
  record(
    entries: Iterable<readonly [string, CRDTSignedActorRegistration]>,
  ): void {
    const list = [...entries];
    this.check(list);
    for (const [actor, registration] of list) {
      const known = this._actors.get(actor);
      this._actors.delete(actor);
      this._actors.set(
        actor,
        known ?? {
          signer: registration.signer,
          nonce: new Uint8Array(registration.nonce),
          registrationSignature: new Uint8Array(
            registration.registrationSignature,
          ),
        },
      );
      let actors = this._bySigner.get(registration.signer);
      if (actors === undefined)
        this._bySigner.set(registration.signer, (actors = new Set()));
      actors.delete(actor);
      actors.add(actor);
      if (actors.size > MAX_CRDT_ACTORS_PER_SIGNER)
        this._forget(actors.values().next().value!);
      if (this._actors.size > MAX_CRDT_ACTOR_BINDINGS)
        this._forget(this._actors.keys().next().value!);
    }
  }

  private _forget(actor: string): void {
    const registration = this._actors.get(actor);
    if (registration === undefined) return;
    this._actors.delete(actor);
    const actors = this._bySigner.get(registration.signer)!;
    actors.delete(actor);
    if (actors.size === 0) this._bySigner.delete(registration.signer);
  }

  /** Remembered registrations for `actors`, or every remembered one. */
  registrations(actors?: Iterable<string>): CRDTSignedActorRegistration[] {
    if (actors === undefined) return [...this._actors.values()];
    const selected: CRDTSignedActorRegistration[] = [];
    for (const actor of actors) {
      const registration = this._actors.get(actor);
      if (registration !== undefined) selected.push(registration);
    }
    return selected;
  }
}
