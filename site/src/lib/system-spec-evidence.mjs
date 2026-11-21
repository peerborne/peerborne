import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evidenceLabels, claims, flows } from './system-spec.mjs';

const manifestPath = 'verification/formal/manifest.json';
const root = [
  fileURLToPath(new URL('../../../', import.meta.url)),
  process.cwd(),
  resolve('..'),
].find((directory) => existsSync(resolve(directory, manifestPath)));
if (!root)
  throw new Error('Could not locate the Peerborne verification manifest');
const revision = process.env.GITHUB_SHA;
const ref = revision && /^[a-f0-9]{40}$/.test(revision) ? revision : 'main';
const repository = `https://github.com/Peerborne/peerborne/blob/${ref}/`;
const manifest = JSON.parse(read(manifestPath));
const units = new Map(manifest.sources.map((unit) => [unit.path, unit]));

function read(path) {
  return readFileSync(resolve(root, path), 'utf8');
}

function fileLink(path) {
  read(path);
  return { label: path.split('/').at(-1), href: repository + path };
}

function proofLinks([source, ...obligations]) {
  const unit = units.get(source);
  if (!unit || !obligations.length) {
    throw new Error(`Missing proof registration or obligations for ${source}`);
  }
  const path = `verification/formal/proofs/${source.replace(/\.ts$/, '.dfy')}`;
  const lines = read(path).split('\n');
  const link = (name) => {
    const declaration = new RegExp(
      `^\\s*(?:ghost\\s+)?(?:lemma|method|function|predicate)\\s+${name}\\b`,
    );
    const index = lines.findIndex((line) => declaration.test(line));
    if (index < 0) throw new Error(`Missing obligation ${name} in ${path}`);
    return { label: name, href: `${repository}${path}#L${index + 1}` };
  };

  return {
    production: fileLink(source),
    consumers: unit.consumers.map(fileLink),
    obligations: obligations.map((name) => {
      if (!unit.verifiedTargets.includes(name)) {
        throw new Error(`Unregistered verification target ${source}:${name}`);
      }
      return link(name);
    }),
    witness: link(unit.witness),
  };
}

export const ledger = claims.map((claim) => {
  const state = claim.state ?? (claim.proof ? 'proved' : 'tested');
  if (
    !(state in evidenceLabels) ||
    (state === 'proved' && (!claim.proof || !claim.checked))
  ) {
    throw new Error(`Invalid evidence state for ${claim.id}`);
  }
  const proofs = [claim.proof, ...(claim.related ?? [])]
    .filter(Boolean)
    .map(proofLinks);
  return {
    ...claim,
    state,
    proofs,
    code: claim.source ? fileLink(claim.source) : undefined,
    runtime: (claim.tests ?? []).map(fileLink),
  };
});

const byId = new Map(ledger.map((claim) => [claim.id, claim]));
if (
  byId.size !== ledger.length ||
  new Set(flows.map(({ id }) => id)).size !== flows.length
) {
  throw new Error('Duplicate system specification ID');
}

const diagramClaims = new Set();
export const architectureFlows = flows.map((flow) => ({
  ...flow,
  stages: flow.stages.map(([boundary, title, ...ids]) => ({
    boundary,
    title,
    claims: ids.map((id) => {
      const claim = byId.get(id);
      if (!claim) throw new Error(`Unknown claim ${id} in flow ${flow.id}`);
      diagramClaims.add(id);
      return claim;
    }),
  })),
}));

if (diagramClaims.size !== byId.size) {
  throw new Error(
    'System specification contains claims absent from the architecture',
  );
}

export const evidenceReference = {
  manifest: fileLink('verification/formal/manifest.json'),
  strategy: fileLink('verification/strategy.json'),
  runner: fileLink('verification/formal/README.md'),
};
