import {
  assertBoundedUtf8,
  encodeUtf8,
} from './internal/canonical-encoding.js';
import {
  canPublishDocumentRecovery,
  classifyDocumentRecovery,
} from './policy/document-recovery.js';
import {
  copyUnsharedUint8Array,
  snapshotEnumerableOwnDataObject,
} from './utils.js';

const MAX_TEXT_BYTES = 4096;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const RECOVERY_DOMAIN = 'peerborne/document-replacement/v1';

export interface DocumentRecoveryLocator {
  readonly revision: number;
  readonly documentPath: string;
  /** Application-selected commitment to the document's security context. */
  readonly context: string;
  /** Digest of the approving recovery operation, or null for an initial locator. */
  readonly receipt: string | null;
}

export interface DocumentRecoveryApproval {
  readonly logicalDocumentId: string;
  readonly base: DocumentRecoveryLocator;
  readonly replacementPath: string;
  readonly replacementContext: string;
  /** Lowercase hexadecimal SHA-256 of the exact selected application content. */
  readonly contentDigest: string;
}

/** The application supplies a locator protected independently of document storage. */
export interface DurableDocumentRecoveryLocator {
  load(logicalDocumentId: string): Promise<DocumentRecoveryLocator | undefined>;
  /** Compare every expected field and persist the update atomically before returning true. */
  compareAndSwap(
    logicalDocumentId: string,
    expected: DocumentRecoveryLocator,
    next: DocumentRecoveryLocator,
  ): Promise<boolean>;
}

export interface DocumentRecoveryOptions {
  readonly locator: DurableDocumentRecoveryLocator;
  /** Authorize the exact detached approval using application trust. */
  authorize(approval: DocumentRecoveryApproval): Promise<boolean> | boolean;
  /**
   * Durably prepare the replacement using only the selected content and fresh
   * key state. Return true after the artifact is ready. Stage privately and
   * idempotently by the full locator, including the receipt. Resolve live reads
   * through the CAS locator so a losing stage cannot shadow an accepted one.
   */
  stage(
    next: DocumentRecoveryLocator,
    selectedContent: Uint8Array,
  ): Promise<boolean>;
}

export interface DocumentRecoveryResult {
  readonly status: 'activated' | 'already-active';
  readonly locator: DocumentRecoveryLocator;
}

function assertDigest(value: unknown, field: string): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length !== 64 ||
    !SHA256_HEX.test(value)
  )
    throw new TypeError(`${field} must be a lowercase SHA-256 digest`);
}

function captureLocator(value: unknown): DocumentRecoveryLocator {
  const record = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    value,
    'Document recovery locator',
    { maxProperties: 4, maxKeyBytes: 80 },
  );
  const { revision, documentPath, context, receipt } = record;
  if (
    Object.keys(record).length !== 4 ||
    typeof revision !== 'number' ||
    !Number.isSafeInteger(revision) ||
    revision < 0 ||
    Object.is(revision, -0)
  )
    throw new TypeError('Invalid document recovery locator');
  assertBoundedUtf8(documentPath, MAX_TEXT_BYTES, 'Recovery document path');
  assertDigest(context, 'Recovery context');
  if (receipt !== null) assertDigest(receipt, 'Recovery receipt');
  return Object.freeze({ revision, documentPath, context, receipt });
}

function captureApproval(
  input: DocumentRecoveryApproval,
): DocumentRecoveryApproval {
  const record = snapshotEnumerableOwnDataObject<Record<string, unknown>>(
    input,
    'Document recovery approval',
    { maxProperties: 5, maxKeyBytes: 160 },
  );
  const {
    logicalDocumentId,
    replacementPath,
    replacementContext,
    contentDigest,
  } = record;
  if (Object.keys(record).length !== 5)
    throw new TypeError('Invalid document recovery approval');
  assertBoundedUtf8(logicalDocumentId, MAX_TEXT_BYTES, 'Logical document ID');
  assertBoundedUtf8(replacementPath, MAX_TEXT_BYTES, 'Replacement path');
  assertDigest(replacementContext, 'Replacement context');
  assertDigest(contentDigest, 'Recovery content digest');
  const base = captureLocator(record.base);
  if (
    base.revision === Number.MAX_SAFE_INTEGER ||
    base.documentPath === replacementPath ||
    base.context === replacementContext
  )
    throw new Error(
      'Recovery requires a fresh path, context and locator revision',
    );
  return Object.freeze({
    logicalDocumentId,
    base,
    replacementPath,
    replacementContext,
    contentDigest,
  });
}

function sameLocator(
  left: DocumentRecoveryLocator,
  right: DocumentRecoveryLocator,
): boolean {
  return (
    left.revision === right.revision &&
    left.documentPath === right.documentPath &&
    left.context === right.context &&
    left.receipt === right.receipt
  );
}

async function hashBytes(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

/** Commit to up to 16 MiB of application content selected for recovery. */
export async function documentRecoveryContentDigest(
  content: Uint8Array,
): Promise<string> {
  return hashBytes(
    copyUnsharedUint8Array(content, 0, MAX_CONTENT_BYTES, 'Recovery content'),
  );
}

/**
 * Activate an explicitly approved fresh replacement through an application-owned
 * durable locator. Exact retries confirm the accepted receipt without staging
 * or publishing again. Keep failed or interrupted staging private.
 */
export async function activateDocumentReplacement(
  input: DocumentRecoveryApproval,
  content: Uint8Array,
  options: DocumentRecoveryOptions,
): Promise<DocumentRecoveryResult> {
  const approval = captureApproval(input);
  const selected = copyUnsharedUint8Array(
    content,
    0,
    MAX_CONTENT_BYTES,
    'Recovery content',
  );
  const authorize = options.authorize.bind(options);
  const stage = options.stage.bind(options);
  const store = options.locator;
  const load = store.load.bind(store);
  const compareAndSwap = store.compareAndSwap.bind(store);

  if ((await authorize(approval)) !== true)
    throw new Error('Document recovery is unauthorized');
  if ((await hashBytes(selected)) !== approval.contentDigest)
    throw new Error('Document recovery content digest mismatch');

  const { logicalDocumentId, base } = approval;
  const receipt = await hashBytes(
    encodeUtf8(
      JSON.stringify([
        RECOVERY_DOMAIN,
        logicalDocumentId,
        base.revision,
        base.documentPath,
        base.context,
        base.receipt,
        approval.replacementPath,
        approval.replacementContext,
        approval.contentDigest,
      ]),
    ),
  );
  const next = Object.freeze({
    revision: base.revision + 1,
    documentPath: approval.replacementPath,
    context: approval.replacementContext,
    receipt,
  });
  const observed = await load(logicalDocumentId);
  if (observed === undefined) throw new Error('Recovery locator is missing');
  const current = captureLocator(observed);
  const disposition = classifyDocumentRecovery(
    base.revision,
    current.revision,
    sameLocator(current, base),
    sameLocator(current, next),
  );
  if (disposition === 'already-active')
    return { status: 'already-active', locator: next };
  if (disposition !== 'ready') throw new Error('Recovery locator changed');

  const staged = (await stage(next, selected)) === true;
  if (!canPublishDocumentRecovery(disposition, staged))
    throw new Error('Replacement document was not staged');

  const published =
    (await compareAndSwap(logicalDocumentId, base, next)) === true;
  const visible = await load(logicalDocumentId);
  if (visible === undefined || !sameLocator(captureLocator(visible), next))
    throw new Error('Recovery locator changed during publication');
  return { status: published ? 'activated' : 'already-active', locator: next };
}
