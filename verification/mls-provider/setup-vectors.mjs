import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';

const revision = '2034fe72e0c805a683ba76165660c834f2a8142a';
const digest =
  'b24949fdf857bf79d511f57504a8bdc7ce3247eb199684745e439c11b1a1da21';
const url = `https://raw.githubusercontent.com/mlswg/mls-implementations/${revision}/test-vectors/passive-client-handling-commit.json`;
const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
if (!response.ok) throw new Error('MLS reference vector download failed');
const raw = new Uint8Array(await response.arrayBuffer());
if (
  raw.length > 2 * 1024 * 1024 ||
  createHash('sha256').update(raw).digest('hex') !== digest
)
  throw new Error('MLS reference vector integrity check failed');
const cases = JSON.parse(new TextDecoder().decode(raw)).filter(
  (value) => value.cipher_suite === 1,
);
if (cases.length !== 13) throw new Error('MLS reference case count changed');
await mkdir(new URL('./vectors/', import.meta.url), { recursive: true });
await writeFile(
  new URL('./vectors/passive-client.json', import.meta.url),
  JSON.stringify({ source: url, revision, sha256: digest, cases }),
);
console.log('Pinned 13 suite-1 MLS Working Group passive-client cases.');
