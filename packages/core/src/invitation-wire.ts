import { Base64 } from 'js-base64';

/** Wire-format version shared by the public invitation messages. */
export const INVITATION_WIRE_VERSION = 1 as const;

/** One-time identifiers and SHA-256 bindings are always 32 bytes. */
export const INVITATION_ID_LENGTH = 32;
export const INVITATION_DIGEST_LENGTH = 32;
export const INVITATION_EPOCH_ID_LENGTH = 32;

/** Raw uncompressed P-256 public key: 0x04 || X || Y. */
export const INVITATION_KEM_PUBLIC_KEY_LENGTH = 65;

/**
 * Maximum encoded envelope size. The opaque payload fields have tighter
 * individual bounds below; this cap also accounts for Base64 expansion.
 */
export const MAX_INVITATION_MESSAGE_BYTES = 4 << 20;
export const MAX_INVITATION_JOIN_REQUEST_BYTES = 32 << 10;
export const MAX_INVITATION_DOCUMENT_ID_BYTES = 4096;
export const MAX_INVITATION_IDENTITY_BYTES = 4096;
export const MAX_INVITATION_SIGNATURE_BYTES = 8192;
export const MAX_INVITATION_RENDEZVOUS_ENTRIES = 8;
export const MAX_INVITATION_RENDEZVOUS_BYTES = 2048;
export const MAX_INVITATION_OPAQUE_PAYLOAD_BYTES = 1 << 20;

/** Salt + ephemeral P-256 key + nonce + AES-GCM tag. */
export const MIN_INVITATION_SEALED_WELCOME_BYTES = 32 + 65 + 12 + 16;

/** Public offers and acceptances cannot remain usable indefinitely. */
export const MAX_INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_INVITATION_CLOCK_SKEW_MS = 60 * 1000;

const OFFER_TAG = 'peerborne.invitation.offer';
const JOIN_TAG = 'peerborne.invitation.join';
const ACCEPTANCE_TAG = 'peerborne.invitation.acceptance';

const OFFER_SIGNATURE_DOMAIN = 'peerborne/invitation/offer-signature/v1\0';
const JOIN_SIGNATURE_DOMAIN = 'peerborne/invitation/join-signature/v1\0';
const ACCEPTANCE_SIGNATURE_DOMAIN =
  'peerborne/invitation/acceptance-signature/v1\0';

export type InvitationRole = 'reader' | 'editor';

export interface InvitationOfferV1 {
  readonly version: typeof INVITATION_WIRE_VERSION;
  readonly invitationId: Uint8Array;
  readonly documentId: string;
  /** Canonical serialization of the inviter's signing public key. */
  readonly issuer: string;
  readonly role: InvitationRole;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly rendezvous: readonly string[];
  readonly signature: Uint8Array;
}

export type UnsignedInvitationOfferV1 = Omit<
  InvitationOfferV1,
  'signature'
>;

export interface InvitationJoinRequestV1 {
  readonly version: typeof INVITATION_WIRE_VERSION;
  /** SHA-256 of the complete, signed canonical offer envelope. */
  readonly offerDigest: Uint8Array;
  readonly requestId: Uint8Array;
  readonly documentId: string;
  readonly role: InvitationRole;
  /** Canonical serialization of the recipient's signing public key. */
  readonly recipient: string;
  /** Raw uncompressed P-256 ECDH public key used to seal the Welcome. */
  readonly recipientKemPublicKey: Uint8Array;
  readonly signature: Uint8Array;
}

export type UnsignedInvitationJoinRequestV1 = Omit<
  InvitationJoinRequestV1,
  'signature'
>;

export interface InvitationAcceptanceV1 {
  readonly version: typeof INVITATION_WIRE_VERSION;
  readonly acceptanceId: Uint8Array;
  /** SHA-256 of the complete, signed canonical offer envelope. */
  readonly offerDigest: Uint8Array;
  /** SHA-256 of the complete, signed canonical join-request envelope. */
  readonly requestDigest: Uint8Array;
  readonly documentId: string;
  /** Canonical serialization of the inviter's signing public key. */
  readonly issuer: string;
  /** Exact recipient signing identity copied from the join request. */
  readonly recipient: string;
  /** Exact recipient KEM public key copied from the join request. */
  readonly recipientKemPublicKey: Uint8Array;
  readonly role: InvitationRole;
  readonly welcomeEpochId: Uint8Array;
  /** Opaque ECIES ciphertext addressed to recipientKemPublicKey. */
  readonly sealedWelcome: Uint8Array;
  /** Opaque, document-key-encrypted initial document state. */
  readonly encryptedBootstrap: Uint8Array;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly signature: Uint8Array;
}

export type UnsignedInvitationAcceptanceV1 = Omit<
  InvitationAcceptanceV1,
  'signature'
>;

/** The subset of AuthProvider needed by invitation signatures. */
export interface InvitationSignatureProvider<PrivateKey, PublicKey> {
  sign(data: Uint8Array, privateKey: PrivateKey): Promise<Uint8Array>;
  verify(
    data: Uint8Array,
    publicKey: PublicKey,
    signature: Uint8Array,
  ): Promise<boolean>;
  serializePublicKey(publicKey: PublicKey): Promise<string>;
}

export type InvitationWireErrorCode =
  | 'invalid-encoding'
  | 'non-canonical-encoding'
  | 'unsupported-version'
  | 'invalid-field'
  | 'size-limit'
  | 'not-yet-valid'
  | 'expired'
  | 'identity-mismatch'
  | 'binding-mismatch'
  | 'missing-identity-serializer';

export class InvitationWireError extends Error {
  constructor(
    public readonly code: InvitationWireErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'InvitationWireError';
  }
}

export interface InvitationExpiryOptions {
  /** Permitted future clock skew for issuedAtMs. Expiry remains a hard bound. */
  readonly clockSkewMs?: number;
}

function fail(code: InvitationWireErrorCode, message: string): never {
  throw new InvitationWireError(code, message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertVersion(value: unknown): asserts value is 1 {
  if (value !== INVITATION_WIRE_VERSION) {
    fail(
      'unsupported-version',
      `unsupported invitation wire version: ${String(value)}`,
    );
  }
}

function assertBytes(
  value: unknown,
  field: string,
  minLength: number,
  maxLength: number,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    fail('invalid-field', `${field} must be a Uint8Array`);
  }
  if (value.byteLength < minLength || value.byteLength > maxLength) {
    const code = value.byteLength > maxLength ? 'size-limit' : 'invalid-field';
    fail(
      code,
      `${field} must contain ${minLength === maxLength ? `${minLength}` : `${minLength}-${maxLength}`} bytes`,
    );
  }
}

function assertWireString(
  value: unknown,
  field: string,
  maxBytes: number,
): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    fail('invalid-field', `${field} must be a non-empty string`);
  }
  if (/[\u0000-\u001f\u007f]/u.test(value)) {
    fail('invalid-field', `${field} must not contain control characters`);
  }
  const encoded = new TextEncoder().encode(value);
  if (new TextDecoder('utf-8', { fatal: true }).decode(encoded) !== value) {
    fail('invalid-field', `${field} must contain well-formed Unicode`);
  }
  if (encoded.byteLength > maxBytes) {
    fail('size-limit', `${field} exceeds ${maxBytes} UTF-8 bytes`);
  }
}

function assertRole(value: unknown, field: string): asserts value is InvitationRole {
  if (value !== 'reader' && value !== 'editor') {
    fail('invalid-field', `${field} must be "reader" or "editor"`);
  }
}

function assertTimestamp(value: unknown, field: string): asserts value is number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 0 ||
    Object.is(value, -0)
  ) {
    fail('invalid-field', `${field} must be a non-negative safe integer`);
  }
}

function assertTimeWindow(issuedAtMs: unknown, expiresAtMs: unknown): void {
  assertTimestamp(issuedAtMs, 'issuedAtMs');
  assertTimestamp(expiresAtMs, 'expiresAtMs');
  if (expiresAtMs <= issuedAtMs) {
    fail('invalid-field', 'expiresAtMs must be greater than issuedAtMs');
  }
  if (expiresAtMs - issuedAtMs > MAX_INVITATION_TTL_MS) {
    fail('size-limit', `invitation lifetime exceeds ${MAX_INVITATION_TTL_MS} ms`);
  }
}

function assertSignature(value: unknown): asserts value is Uint8Array {
  assertBytes(value, 'signature', 1, MAX_INVITATION_SIGNATURE_BYTES);
}

function assertRendezvous(
  value: unknown,
): asserts value is readonly string[] {
  if (!Array.isArray(value)) {
    fail('invalid-field', 'rendezvous must be an array');
  }
  if (value.length > MAX_INVITATION_RENDEZVOUS_ENTRIES) {
    fail(
      'size-limit',
      `rendezvous exceeds ${MAX_INVITATION_RENDEZVOUS_ENTRIES} entries`,
    );
  }
  const seen = new Set<string>();
  for (let i = 0; i < value.length; i++) {
    assertWireString(
      value[i],
      `rendezvous[${i}]`,
      MAX_INVITATION_RENDEZVOUS_BYTES,
    );
    if (seen.has(value[i])) {
      fail('invalid-field', 'rendezvous entries must be unique');
    }
    seen.add(value[i]);
  }
}

function assertOfferCore(value: unknown): asserts value is UnsignedInvitationOfferV1 {
  if (!isRecord(value)) {
    fail('invalid-field', 'invitation offer must be an object');
  }
  assertVersion(value.version);
  assertBytes(
    value.invitationId,
    'invitationId',
    INVITATION_ID_LENGTH,
    INVITATION_ID_LENGTH,
  );
  assertWireString(
    value.documentId,
    'documentId',
    MAX_INVITATION_DOCUMENT_ID_BYTES,
  );
  assertWireString(value.issuer, 'issuer', MAX_INVITATION_IDENTITY_BYTES);
  assertRole(value.role, 'role');
  assertTimeWindow(value.issuedAtMs, value.expiresAtMs);
  assertRendezvous(value.rendezvous);
}

export function assertValidInvitationOffer(
  value: unknown,
): asserts value is InvitationOfferV1 {
  assertOfferCore(value);
  assertSignature((value as unknown as Record<string, unknown>).signature);
}

function assertJoinCore(
  value: unknown,
): asserts value is UnsignedInvitationJoinRequestV1 {
  if (!isRecord(value)) {
    fail('invalid-field', 'invitation join request must be an object');
  }
  assertVersion(value.version);
  assertBytes(
    value.offerDigest,
    'offerDigest',
    INVITATION_DIGEST_LENGTH,
    INVITATION_DIGEST_LENGTH,
  );
  assertBytes(
    value.requestId,
    'requestId',
    INVITATION_ID_LENGTH,
    INVITATION_ID_LENGTH,
  );
  assertWireString(
    value.documentId,
    'documentId',
    MAX_INVITATION_DOCUMENT_ID_BYTES,
  );
  assertRole(value.role, 'role');
  assertWireString(value.recipient, 'recipient', MAX_INVITATION_IDENTITY_BYTES);
  assertBytes(
    value.recipientKemPublicKey,
    'recipientKemPublicKey',
    INVITATION_KEM_PUBLIC_KEY_LENGTH,
    INVITATION_KEM_PUBLIC_KEY_LENGTH,
  );
}

export function assertValidInvitationJoinRequest(
  value: unknown,
): asserts value is InvitationJoinRequestV1 {
  assertJoinCore(value);
  assertSignature((value as unknown as Record<string, unknown>).signature);
}

function assertAcceptanceCore(
  value: unknown,
): asserts value is UnsignedInvitationAcceptanceV1 {
  if (!isRecord(value)) {
    fail('invalid-field', 'invitation acceptance must be an object');
  }
  assertVersion(value.version);
  assertBytes(
    value.acceptanceId,
    'acceptanceId',
    INVITATION_ID_LENGTH,
    INVITATION_ID_LENGTH,
  );
  assertBytes(
    value.offerDigest,
    'offerDigest',
    INVITATION_DIGEST_LENGTH,
    INVITATION_DIGEST_LENGTH,
  );
  assertBytes(
    value.requestDigest,
    'requestDigest',
    INVITATION_DIGEST_LENGTH,
    INVITATION_DIGEST_LENGTH,
  );
  assertWireString(
    value.documentId,
    'documentId',
    MAX_INVITATION_DOCUMENT_ID_BYTES,
  );
  assertWireString(value.issuer, 'issuer', MAX_INVITATION_IDENTITY_BYTES);
  assertWireString(value.recipient, 'recipient', MAX_INVITATION_IDENTITY_BYTES);
  assertBytes(
    value.recipientKemPublicKey,
    'recipientKemPublicKey',
    INVITATION_KEM_PUBLIC_KEY_LENGTH,
    INVITATION_KEM_PUBLIC_KEY_LENGTH,
  );
  assertRole(value.role, 'role');
  assertBytes(
    value.welcomeEpochId,
    'welcomeEpochId',
    INVITATION_EPOCH_ID_LENGTH,
    INVITATION_EPOCH_ID_LENGTH,
  );
  assertBytes(
    value.sealedWelcome,
    'sealedWelcome',
    MIN_INVITATION_SEALED_WELCOME_BYTES,
    MAX_INVITATION_OPAQUE_PAYLOAD_BYTES,
  );
  assertBytes(
    value.encryptedBootstrap,
    'encryptedBootstrap',
    1,
    MAX_INVITATION_OPAQUE_PAYLOAD_BYTES,
  );
  assertTimeWindow(value.issuedAtMs, value.expiresAtMs);
}

export function assertValidInvitationAcceptance(
  value: unknown,
): asserts value is InvitationAcceptanceV1 {
  assertAcceptanceCore(value);
  assertSignature((value as unknown as Record<string, unknown>).signature);
}

function encodeBase64Url(bytes: Uint8Array): string {
  return Base64.fromUint8Array(bytes, true);
}

function decodeBase64Url(value: unknown, field: string): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    fail('invalid-encoding', `${field} must use unpadded Base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = Base64.toUint8Array(value);
  } catch {
    fail('invalid-encoding', `${field} is not valid Base64url`);
  }
  if (encodeBase64Url(decoded) !== value) {
    fail('non-canonical-encoding', `${field} is not canonical Base64url`);
  }
  return decoded;
}

function encodeJsonTuple(tuple: readonly unknown[]): Uint8Array {
  const encoded = new TextEncoder().encode(JSON.stringify(tuple));
  if (encoded.byteLength > MAX_INVITATION_MESSAGE_BYTES) {
    fail(
      'size-limit',
      `invitation envelope exceeds ${MAX_INVITATION_MESSAGE_BYTES} bytes`,
    );
  }
  return encoded;
}

function parseJsonTuple(bytes: Uint8Array): unknown[] {
  if (!(bytes instanceof Uint8Array)) {
    fail('invalid-encoding', 'invitation envelope must be a Uint8Array');
  }
  if (bytes.byteLength === 0) {
    fail('invalid-encoding', 'invitation envelope must not be empty');
  }
  if (bytes.byteLength > MAX_INVITATION_MESSAGE_BYTES) {
    fail(
      'size-limit',
      `invitation envelope exceeds ${MAX_INVITATION_MESSAGE_BYTES} bytes`,
    );
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('invalid-encoding', 'invitation envelope is not valid UTF-8');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail('invalid-encoding', 'invitation envelope is not valid JSON');
  }
  if (!Array.isArray(parsed)) {
    fail('invalid-encoding', 'invitation envelope must be a JSON tuple');
  }
  return parsed;
}

function assertCanonicalBytes(original: Uint8Array, canonical: Uint8Array): void {
  if (!equalBytes(original, canonical)) {
    fail(
      'non-canonical-encoding',
      'invitation envelope is not in canonical form',
    );
  }
}

function offerTuple(
  offer: UnsignedInvitationOfferV1,
  signature?: Uint8Array,
): readonly unknown[] {
  const tuple: unknown[] = [
    OFFER_TAG,
    INVITATION_WIRE_VERSION,
    encodeBase64Url(offer.invitationId),
    offer.documentId,
    offer.issuer,
    offer.role,
    offer.issuedAtMs,
    offer.expiresAtMs,
    Array.from(offer.rendezvous),
  ];
  if (signature !== undefined) tuple.push(encodeBase64Url(signature));
  return tuple;
}

function joinTuple(
  request: UnsignedInvitationJoinRequestV1,
  signature?: Uint8Array,
): readonly unknown[] {
  const tuple: unknown[] = [
    JOIN_TAG,
    INVITATION_WIRE_VERSION,
    encodeBase64Url(request.offerDigest),
    encodeBase64Url(request.requestId),
    request.documentId,
    request.role,
    request.recipient,
    encodeBase64Url(request.recipientKemPublicKey),
  ];
  if (signature !== undefined) tuple.push(encodeBase64Url(signature));
  return tuple;
}

function acceptanceTuple(
  acceptance: UnsignedInvitationAcceptanceV1,
  signature?: Uint8Array,
): readonly unknown[] {
  const tuple: unknown[] = [
    ACCEPTANCE_TAG,
    INVITATION_WIRE_VERSION,
    encodeBase64Url(acceptance.acceptanceId),
    encodeBase64Url(acceptance.offerDigest),
    encodeBase64Url(acceptance.requestDigest),
    acceptance.documentId,
    acceptance.issuer,
    acceptance.recipient,
    encodeBase64Url(acceptance.recipientKemPublicKey),
    acceptance.role,
    encodeBase64Url(acceptance.welcomeEpochId),
    encodeBase64Url(acceptance.sealedWelcome),
    encodeBase64Url(acceptance.encryptedBootstrap),
    acceptance.issuedAtMs,
    acceptance.expiresAtMs,
  ];
  if (signature !== undefined) tuple.push(encodeBase64Url(signature));
  return tuple;
}

export function encodeInvitationOffer(offer: InvitationOfferV1): Uint8Array {
  assertValidInvitationOffer(offer);
  return encodeJsonTuple(offerTuple(offer, offer.signature));
}

export function decodeInvitationOffer(bytes: Uint8Array): InvitationOfferV1 {
  const tuple = parseJsonTuple(bytes);
  if (tuple.length !== 10 || tuple[0] !== OFFER_TAG) {
    fail('invalid-encoding', 'invalid invitation offer tuple');
  }
  assertVersion(tuple[1]);
  const offer: InvitationOfferV1 = {
    version: INVITATION_WIRE_VERSION,
    invitationId: decodeBase64Url(tuple[2], 'invitationId'),
    documentId: tuple[3] as string,
    issuer: tuple[4] as string,
    role: tuple[5] as InvitationRole,
    issuedAtMs: tuple[6] as number,
    expiresAtMs: tuple[7] as number,
    rendezvous: tuple[8] as string[],
    signature: decodeBase64Url(tuple[9], 'signature'),
  };
  assertValidInvitationOffer(offer);
  assertCanonicalBytes(bytes, encodeInvitationOffer(offer));
  return offer;
}

export function encodeInvitationJoinRequest(
  request: InvitationJoinRequestV1,
): Uint8Array {
  assertValidInvitationJoinRequest(request);
  const encoded = encodeJsonTuple(joinTuple(request, request.signature));
  if (encoded.byteLength > MAX_INVITATION_JOIN_REQUEST_BYTES) {
    fail(
      'size-limit',
      `invitation join request exceeds ${MAX_INVITATION_JOIN_REQUEST_BYTES} bytes`,
    );
  }
  return encoded;
}

export function decodeInvitationJoinRequest(
  bytes: Uint8Array,
): InvitationJoinRequestV1 {
  const tuple = parseJsonTuple(bytes);
  if (tuple.length !== 9 || tuple[0] !== JOIN_TAG) {
    fail('invalid-encoding', 'invalid invitation join-request tuple');
  }
  assertVersion(tuple[1]);
  const request: InvitationJoinRequestV1 = {
    version: INVITATION_WIRE_VERSION,
    offerDigest: decodeBase64Url(tuple[2], 'offerDigest'),
    requestId: decodeBase64Url(tuple[3], 'requestId'),
    documentId: tuple[4] as string,
    role: tuple[5] as InvitationRole,
    recipient: tuple[6] as string,
    recipientKemPublicKey: decodeBase64Url(
      tuple[7],
      'recipientKemPublicKey',
    ),
    signature: decodeBase64Url(tuple[8], 'signature'),
  };
  assertValidInvitationJoinRequest(request);
  assertCanonicalBytes(bytes, encodeInvitationJoinRequest(request));
  return request;
}

export function encodeInvitationAcceptance(
  acceptance: InvitationAcceptanceV1,
): Uint8Array {
  assertValidInvitationAcceptance(acceptance);
  return encodeJsonTuple(acceptanceTuple(acceptance, acceptance.signature));
}

export function decodeInvitationAcceptance(
  bytes: Uint8Array,
): InvitationAcceptanceV1 {
  const tuple = parseJsonTuple(bytes);
  if (tuple.length !== 16 || tuple[0] !== ACCEPTANCE_TAG) {
    fail('invalid-encoding', 'invalid invitation acceptance tuple');
  }
  assertVersion(tuple[1]);
  const acceptance: InvitationAcceptanceV1 = {
    version: INVITATION_WIRE_VERSION,
    acceptanceId: decodeBase64Url(tuple[2], 'acceptanceId'),
    offerDigest: decodeBase64Url(tuple[3], 'offerDigest'),
    requestDigest: decodeBase64Url(tuple[4], 'requestDigest'),
    documentId: tuple[5] as string,
    issuer: tuple[6] as string,
    recipient: tuple[7] as string,
    recipientKemPublicKey: decodeBase64Url(
      tuple[8],
      'recipientKemPublicKey',
    ),
    role: tuple[9] as InvitationRole,
    welcomeEpochId: decodeBase64Url(tuple[10], 'welcomeEpochId'),
    sealedWelcome: decodeBase64Url(tuple[11], 'sealedWelcome'),
    encryptedBootstrap: decodeBase64Url(tuple[12], 'encryptedBootstrap'),
    issuedAtMs: tuple[13] as number,
    expiresAtMs: tuple[14] as number,
    signature: decodeBase64Url(tuple[15], 'signature'),
  };
  assertValidInvitationAcceptance(acceptance);
  assertCanonicalBytes(bytes, encodeInvitationAcceptance(acceptance));
  return acceptance;
}

function domainSeparated(domain: string, payload: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(domain);
  const bytes = new Uint8Array(prefix.byteLength + payload.byteLength);
  bytes.set(prefix, 0);
  bytes.set(payload, prefix.byteLength);
  return bytes;
}

export function invitationOfferSigningBytes(
  offer: UnsignedInvitationOfferV1 | InvitationOfferV1,
): Uint8Array {
  assertOfferCore(offer);
  return domainSeparated(
    OFFER_SIGNATURE_DOMAIN,
    encodeJsonTuple(offerTuple(offer)),
  );
}

export function invitationJoinRequestSigningBytes(
  request: UnsignedInvitationJoinRequestV1 | InvitationJoinRequestV1,
): Uint8Array {
  assertJoinCore(request);
  return domainSeparated(JOIN_SIGNATURE_DOMAIN, encodeJsonTuple(joinTuple(request)));
}

export function invitationAcceptanceSigningBytes(
  acceptance: UnsignedInvitationAcceptanceV1 | InvitationAcceptanceV1,
): Uint8Array {
  assertAcceptanceCore(acceptance);
  return domainSeparated(
    ACCEPTANCE_SIGNATURE_DOMAIN,
    encodeJsonTuple(acceptanceTuple(acceptance)),
  );
}

function requireIdentitySerializer<PrivateKey, PublicKey>(
  provider: InvitationSignatureProvider<PrivateKey, PublicKey>,
): (publicKey: PublicKey) => Promise<string> {
  if (typeof provider.serializePublicKey !== 'function') {
    fail(
      'missing-identity-serializer',
      'public invitation signatures require serializePublicKey',
    );
  }
  return provider.serializePublicKey.bind(provider);
}

async function assertSigningIdentity<PrivateKey, PublicKey>(
  expected: string,
  publicKey: PublicKey,
  provider: InvitationSignatureProvider<PrivateKey, PublicKey>,
): Promise<void> {
  const serialize = requireIdentitySerializer(provider);
  if ((await serialize(publicKey)) !== expected) {
    fail(
      'identity-mismatch',
      'signing public key does not match the invitation wire identity',
    );
  }
}

export async function signInvitationOffer<PrivateKey, PublicKey>(
  offer: UnsignedInvitationOfferV1,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  provider: InvitationSignatureProvider<PrivateKey, PublicKey>,
): Promise<InvitationOfferV1> {
  const snapshot = snapshotUnsignedOffer(offer);
  assertOfferCore(snapshot);
  await assertSigningIdentity(snapshot.issuer, publicKey, provider);
  const signature = await provider.sign(
    invitationOfferSigningBytes(snapshot),
    privateKey,
  );
  const signed = copyOffer(snapshot, signature);
  encodeInvitationOffer(signed);
  return signed;
}

export async function verifyInvitationOffer<PrivateKey, PublicKey>(
  offer: InvitationOfferV1,
  publicKey: PublicKey,
  provider: InvitationSignatureProvider<PrivateKey, PublicKey>,
): Promise<boolean> {
  const serialize = requireIdentitySerializer(provider);
  try {
    const snapshot = snapshotOffer(offer);
    if ((await serialize(publicKey)) !== snapshot.issuer) return false;
    return (
      (await provider.verify(
        invitationOfferSigningBytes(snapshot),
        publicKey,
        snapshot.signature,
      )) === true
    );
  } catch {
    return false;
  }
}

export async function signInvitationJoinRequest<PrivateKey, PublicKey>(
  request: UnsignedInvitationJoinRequestV1,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  provider: InvitationSignatureProvider<PrivateKey, PublicKey>,
): Promise<InvitationJoinRequestV1> {
  const snapshot = snapshotUnsignedJoinRequest(request);
  assertJoinCore(snapshot);
  await assertSigningIdentity(snapshot.recipient, publicKey, provider);
  const signature = await provider.sign(
    invitationJoinRequestSigningBytes(snapshot),
    privateKey,
  );
  const signed = copyJoinRequest(snapshot, signature);
  encodeInvitationJoinRequest(signed);
  return signed;
}

export async function verifyInvitationJoinRequest<PrivateKey, PublicKey>(
  request: InvitationJoinRequestV1,
  publicKey: PublicKey,
  provider: InvitationSignatureProvider<PrivateKey, PublicKey>,
): Promise<boolean> {
  const serialize = requireIdentitySerializer(provider);
  try {
    const snapshot = snapshotJoinRequest(request);
    if ((await serialize(publicKey)) !== snapshot.recipient) return false;
    return (
      (await provider.verify(
        invitationJoinRequestSigningBytes(snapshot),
        publicKey,
        snapshot.signature,
      )) === true
    );
  } catch {
    return false;
  }
}

export async function signInvitationAcceptance<PrivateKey, PublicKey>(
  acceptance: UnsignedInvitationAcceptanceV1,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  provider: InvitationSignatureProvider<PrivateKey, PublicKey>,
): Promise<InvitationAcceptanceV1> {
  const snapshot = snapshotUnsignedAcceptance(acceptance);
  assertAcceptanceCore(snapshot);
  await assertSigningIdentity(snapshot.issuer, publicKey, provider);
  const signature = await provider.sign(
    invitationAcceptanceSigningBytes(snapshot),
    privateKey,
  );
  const signed = copyAcceptance(snapshot, signature);
  encodeInvitationAcceptance(signed);
  return signed;
}

export async function verifyInvitationAcceptance<PrivateKey, PublicKey>(
  acceptance: InvitationAcceptanceV1,
  publicKey: PublicKey,
  provider: InvitationSignatureProvider<PrivateKey, PublicKey>,
): Promise<boolean> {
  const serialize = requireIdentitySerializer(provider);
  try {
    const snapshot = snapshotAcceptance(acceptance);
    if ((await serialize(publicKey)) !== snapshot.issuer) return false;
    return (
      (await provider.verify(
        invitationAcceptanceSigningBytes(snapshot),
        publicKey,
        snapshot.signature,
      )) === true
    );
  } catch {
    return false;
  }
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      bytes as Uint8Array<ArrayBuffer>,
    ),
  );
}

export function digestInvitationOffer(
  offer: InvitationOfferV1,
): Promise<Uint8Array> {
  return sha256(encodeInvitationOffer(offer));
}

export function digestInvitationJoinRequest(
  request: InvitationJoinRequestV1,
): Promise<Uint8Array> {
  return sha256(encodeInvitationJoinRequest(request));
}

export function digestInvitationAcceptance(
  acceptance: InvitationAcceptanceV1,
): Promise<Uint8Array> {
  return sha256(encodeInvitationAcceptance(acceptance));
}

function assertUsableWindow(
  issuedAtMs: number,
  expiresAtMs: number,
  nowMs: number,
  options: InvitationExpiryOptions,
): void {
  assertTimeWindow(issuedAtMs, expiresAtMs);
  assertTimestamp(nowMs, 'nowMs');
  const clockSkewMs = options.clockSkewMs ?? DEFAULT_INVITATION_CLOCK_SKEW_MS;
  if (
    !Number.isSafeInteger(clockSkewMs) ||
    clockSkewMs < 0 ||
    clockSkewMs > MAX_INVITATION_TTL_MS
  ) {
    fail(
      'invalid-field',
      `clockSkewMs must be an integer from 0 to ${MAX_INVITATION_TTL_MS}`,
    );
  }
  if (nowMs + clockSkewMs < issuedAtMs) {
    fail('not-yet-valid', 'invitation is not yet valid');
  }
  if (nowMs >= expiresAtMs) {
    fail('expired', 'invitation has expired');
  }
}

export function assertInvitationOfferUsable(
  offer: InvitationOfferV1,
  nowMs = Date.now(),
  options: InvitationExpiryOptions = {},
): void {
  assertValidInvitationOffer(offer);
  assertUsableWindow(offer.issuedAtMs, offer.expiresAtMs, nowMs, options);
}

export function assertInvitationAcceptanceUsable(
  acceptance: InvitationAcceptanceV1,
  nowMs = Date.now(),
  options: InvitationExpiryOptions = {},
): void {
  assertValidInvitationAcceptance(acceptance);
  assertUsableWindow(
    acceptance.issuedAtMs,
    acceptance.expiresAtMs,
    nowMs,
    options,
  );
}

export async function assertInvitationJoinMatchesOffer(
  request: InvitationJoinRequestV1,
  offer: InvitationOfferV1,
): Promise<void> {
  const requestSnapshot = snapshotJoinRequest(request);
  const offerSnapshot = snapshotOffer(offer);
  await assertInvitationJoinSnapshotsMatchOffer(
    requestSnapshot,
    offerSnapshot,
  );
}

async function assertInvitationJoinSnapshotsMatchOffer(
  request: InvitationJoinRequestV1,
  offer: InvitationOfferV1,
): Promise<void> {
  const expectedOfferDigest = await digestInvitationOffer(offer);
  if (!equalBytes(request.offerDigest, expectedOfferDigest)) {
    fail('binding-mismatch', 'join request does not bind to this offer');
  }
  if (request.documentId !== offer.documentId || request.role !== offer.role) {
    fail(
      'binding-mismatch',
      'join request document or role does not match the offer',
    );
  }
}

export async function assertInvitationAcceptanceMatches(
  acceptance: InvitationAcceptanceV1,
  offer: InvitationOfferV1,
  request: InvitationJoinRequestV1,
): Promise<void> {
  const acceptanceSnapshot = snapshotAcceptance(acceptance);
  const offerSnapshot = snapshotOffer(offer);
  const requestSnapshot = snapshotJoinRequest(request);
  await assertInvitationJoinSnapshotsMatchOffer(
    requestSnapshot,
    offerSnapshot,
  );
  const [expectedOfferDigest, expectedRequestDigest] = await Promise.all([
    digestInvitationOffer(offerSnapshot),
    digestInvitationJoinRequest(requestSnapshot),
  ]);
  if (
    !equalBytes(acceptanceSnapshot.offerDigest, expectedOfferDigest) ||
    !equalBytes(acceptanceSnapshot.requestDigest, expectedRequestDigest)
  ) {
    fail(
      'binding-mismatch',
      'acceptance does not bind to this offer and join request',
    );
  }
  if (
    acceptanceSnapshot.documentId !== offerSnapshot.documentId ||
    acceptanceSnapshot.issuer !== offerSnapshot.issuer ||
    acceptanceSnapshot.role !== requestSnapshot.role ||
    acceptanceSnapshot.recipient !== requestSnapshot.recipient ||
    !equalBytes(
      acceptanceSnapshot.recipientKemPublicKey,
      requestSnapshot.recipientKemPublicKey,
    )
  ) {
    fail(
      'binding-mismatch',
      'acceptance recipient, KEM key, document, issuer, or role is mismatched',
    );
  }
  if (
    acceptanceSnapshot.issuedAtMs < offerSnapshot.issuedAtMs ||
    acceptanceSnapshot.expiresAtMs > offerSnapshot.expiresAtMs
  ) {
    fail('binding-mismatch', 'acceptance lifetime exceeds the offer lifetime');
  }
}

export function equalInvitationBytes(a: Uint8Array, b: Uint8Array): boolean {
  return equalBytes(a, b);
}

/** @internal Bind the encrypted bootstrap header to the signed Welcome epoch. */
export function assertInvitationBootstrapEpochBinding(
  welcomeEpochId: Uint8Array,
  bootstrapKeyId: Uint8Array,
): void {
  if (!equalBytes(welcomeEpochId, bootstrapKeyId)) {
    throw new Error(
      'Invitation encrypted bootstrap epoch does not match its signed acceptance',
    );
  }
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < a.byteLength; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

function snapshotUnsignedOffer(
  offer: UnsignedInvitationOfferV1,
): UnsignedInvitationOfferV1 {
  assertOfferCore(offer);
  return {
    version: offer.version,
    invitationId: offer.invitationId.slice(),
    documentId: offer.documentId,
    issuer: offer.issuer,
    role: offer.role,
    issuedAtMs: offer.issuedAtMs,
    expiresAtMs: offer.expiresAtMs,
    rendezvous: Array.from(offer.rendezvous),
  };
}

function snapshotUnsignedJoinRequest(
  request: UnsignedInvitationJoinRequestV1,
): UnsignedInvitationJoinRequestV1 {
  assertJoinCore(request);
  return {
    version: request.version,
    offerDigest: request.offerDigest.slice(),
    requestId: request.requestId.slice(),
    documentId: request.documentId,
    role: request.role,
    recipient: request.recipient,
    recipientKemPublicKey: request.recipientKemPublicKey.slice(),
  };
}

function snapshotUnsignedAcceptance(
  acceptance: UnsignedInvitationAcceptanceV1,
): UnsignedInvitationAcceptanceV1 {
  assertAcceptanceCore(acceptance);
  return {
    version: acceptance.version,
    acceptanceId: acceptance.acceptanceId.slice(),
    offerDigest: acceptance.offerDigest.slice(),
    requestDigest: acceptance.requestDigest.slice(),
    documentId: acceptance.documentId,
    issuer: acceptance.issuer,
    recipient: acceptance.recipient,
    recipientKemPublicKey: acceptance.recipientKemPublicKey.slice(),
    role: acceptance.role,
    welcomeEpochId: acceptance.welcomeEpochId.slice(),
    sealedWelcome: acceptance.sealedWelcome.slice(),
    encryptedBootstrap: acceptance.encryptedBootstrap.slice(),
    issuedAtMs: acceptance.issuedAtMs,
    expiresAtMs: acceptance.expiresAtMs,
  };
}

function snapshotOffer(offer: InvitationOfferV1): InvitationOfferV1 {
  return decodeInvitationOffer(encodeInvitationOffer(offer));
}

function snapshotJoinRequest(
  request: InvitationJoinRequestV1,
): InvitationJoinRequestV1 {
  return decodeInvitationJoinRequest(encodeInvitationJoinRequest(request));
}

function snapshotAcceptance(
  acceptance: InvitationAcceptanceV1,
): InvitationAcceptanceV1 {
  return decodeInvitationAcceptance(encodeInvitationAcceptance(acceptance));
}

function copyOffer(
  offer: UnsignedInvitationOfferV1,
  signature: Uint8Array,
): InvitationOfferV1 {
  return {
    ...offer,
    invitationId: offer.invitationId.slice(),
    rendezvous: Array.from(offer.rendezvous),
    signature: signature.slice(),
  };
}

function copyJoinRequest(
  request: UnsignedInvitationJoinRequestV1,
  signature: Uint8Array,
): InvitationJoinRequestV1 {
  return {
    ...request,
    offerDigest: request.offerDigest.slice(),
    requestId: request.requestId.slice(),
    recipientKemPublicKey: request.recipientKemPublicKey.slice(),
    signature: signature.slice(),
  };
}

function copyAcceptance(
  acceptance: UnsignedInvitationAcceptanceV1,
  signature: Uint8Array,
): InvitationAcceptanceV1 {
  return {
    ...acceptance,
    acceptanceId: acceptance.acceptanceId.slice(),
    offerDigest: acceptance.offerDigest.slice(),
    requestDigest: acceptance.requestDigest.slice(),
    recipientKemPublicKey: acceptance.recipientKemPublicKey.slice(),
    welcomeEpochId: acceptance.welcomeEpochId.slice(),
    sealedWelcome: acceptance.sealedWelcome.slice(),
    encryptedBootstrap: acceptance.encryptedBootstrap.slice(),
    signature: signature.slice(),
  };
}
