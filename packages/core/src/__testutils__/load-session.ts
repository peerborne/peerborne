import type { InitialLoadSession } from '../internal/initial-load-session.js';
import type { LoadSecurityCommitments } from '../load-security-state.js';
import { loadAdvertisementHash } from '../load-advertisement-hash.js';
import { tipsHashToHex } from '../tips-hash.js';
import { computeServedFrontier } from '../merkle-cross-links.js';

export const fixtureLoadChallenge = () => new Uint8Array(32).fill(17);
export const fixtureLoadCommitments = (): LoadSecurityCommitments => ({
  version: 1,
  controlHead: new Uint8Array(32).fill(1),
  groupId: 'fixture-group',
  epoch: 1n,
  treeHash: new Uint8Array(32).fill(2),
  confirmedTranscriptHash: new Uint8Array(32).fill(3),
});
export const fixtureSerializeChanges = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value));

export function currentLoadResponse(
  message: any,
  context = 'load-response-v4',
): any {
  const descriptors = Object.getOwnPropertyDescriptors(message);
  let tips: string[] = [];
  try {
    tips = computeServedFrontier(
      descriptors.changeId?.value,
      descriptors.changes?.value,
      descriptors.snapshot?.value?.lastChangeNodeCID,
    );
  } catch {
    /* malformed state is exercised by the receiver */
  }
  return Object.create(Object.getPrototypeOf(message), {
    ...Object.getOwnPropertyDescriptors({
      signatureContext: context,
      ...(context !== 'security-advertisement-v1' ? { tips } : {}),
      ...(context === 'load-response-v4' ||
      context === 'security-advertisement-v1'
        ? { loadSecurityState: fixtureLoadCommitments() }
        : {}),
      ...(context !== 'invitation-bootstrap-v1'
        ? { loadChallenge: fixtureLoadChallenge() }
        : {}),
    }),
    ...descriptors,
  });
}

export function fixedLoadSession(
  document: any,
  issuer?: string,
): InitialLoadSession<any> {
  const common = {
    challenge: fixtureLoadChallenge(),
    authorities: [
      {
        authorityId: issuer ?? 'fixture-writer',
        publicKey: issuer ?? 'writer',
      },
    ],
    writerVersion: document._writerKeysVersion ?? 0,
    bootstrap: false,
  };
  return issuer === undefined
    ? {
        ...common,
        context: 'load-response-v4',
        commitments: fixtureLoadCommitments(),
      }
    : { ...common, context: 'invitation-catch-up-v1' };
}

export async function loadSessionFixture(
  document: any,
  issuer?: string,
): Promise<InitialLoadSession<any>> {
  const session = fixedLoadSession(document, issuer);
  const keys =
    issuer === undefined
      ? document._writers || Object.hasOwn(document, '_getWriterKeys')
        ? await document._getWriterKeys()
        : ['writer']
      : [issuer];
  const authorities = keys.length > 0 ? keys : ['bootstrap-writer'];
  if (issuer !== undefined && document._fixtureLoadResponse) {
    document._fixtureLoadResponse.signatureContext = 'invitation-catch-up-v1';
    delete document._fixtureLoadResponse.loadSecurityState;
  }
  return {
    ...session,
    bootstrap: keys.length === 0,
    authorities: authorities.map((publicKey: any, index: number) => ({
      authorityId: `fixture-writer-${index}`,
      publicKey,
    })),
  };
}

export async function fixtureLoadDigest(
  document: any,
  frontier: string[],
): Promise<string> {
  return tipsHashToHex(
    await loadAdvertisementHash(
      document.documentPath,
      frontier,
      fixtureLoadCommitments(),
      await document._loadResponseManifestHash(document._fixtureLoadResponse),
    ),
  );
}
