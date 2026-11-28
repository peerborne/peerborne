import { DocumentBinaryWriter } from './internal/document-binary.js';

/** What an encrypted document payload is, bound into its associated data. */
export type DocumentPayloadKind =
  'block' | 'frame' | 'response' | 'invitation-bootstrap';

const KINDS: ReadonlySet<string> = new Set<DocumentPayloadKind>([
  'block',
  'frame',
  'response',
  'invitation-bootstrap',
]);

const DOMAIN = Uint8Array.from('peerborne/document-payload/v1\0', (value) =>
  value.charCodeAt(0),
);

const MAX_PATH = 64 * 1024;
const MAX_KEY_ID = 1024;

/**
 * Associated data for a payload encrypted under a document key: a versioned
 * domain, the document path, the key ID written before the nonce, and the
 * payload kind, each length-prefixed. A ciphertext then authenticates only as
 * the same kind of payload of the same document under the same key ID.
 */
export function documentPayloadAAD(
  documentPath: string,
  keyId: Uint8Array,
  kind: DocumentPayloadKind,
): Uint8Array {
  if (!KINDS.has(kind)) throw new TypeError('Invalid document payload kind');
  return new DocumentBinaryWriter(2 * MAX_PATH)
    .fixed(DOMAIN)
    .text(documentPath, MAX_PATH)
    .bytes(keyId, MAX_KEY_ID)
    .text(kind, 32)
    .finish();
}
