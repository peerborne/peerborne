# Releasing

The six `@peerborne/*` library packages are not yet published to npm. The first release is a bootstrap operation; a successful artifact-validation run does not prove npm authorization or provenance will succeed.

## Release allowlist and versioning

Releases contain exactly these packages, in dependency-first order:

1. `@peerborne/core`
2. `@peerborne/automerge`
3. `@peerborne/yjs`
4. `@peerborne/react`
5. `@peerborne/redux`
6. `@peerborne/index`

Set one strict SemVer across the allowlist and update the Yarn lockfile:

```sh
corepack enable
yarn install --immutable
yarn version:set 0.1.0
yarn install --immutable
yarn test:release
yarn build
yarn test
```

Land the version and release changes through a reviewed pull request. On a clean, synchronized `main`, create an annotated tag:

```sh
git switch main
git pull --ff-only origin main
scripts/tag-release.sh --push
```

Use `scripts/tag-release.sh` without `--push` to create the tag locally for inspection. Do not then rerun the script; push the created tag with `git push origin refs/tags/v0.1.0`. Both forms reject an existing local or remote tag. A stable version promotes to `latest`; a prerelease promotes to `next`.

## Secretless artifact validation

Pull requests, manual workflow dispatches, and `v*` tag pushes install, build, test, pack, inspect, and exercise the exact tarballs in a clean ESM, TypeScript NodeNext, and Vite consumer. Pull requests and manual dispatches have no npm environment, npm token, or OIDC permission and can never publish. A tag must exactly match the six package versions, use strict SemVer, and point to a commit contained in `origin/main`.

To reproduce artifact validation locally:

```sh
ARTIFACT_DIR="$(mktemp -d)"
yarn build
yarn release:prepare "$ARTIFACT_DIR"
yarn release:validate-consumer "$ARTIFACT_DIR" "$(dirname "$ARTIFACT_DIR")"
```

`release-manifest.json` records package order, filenames, contents, versions, and SHA-512 integrity. Remove the temporary artifact directory afterward.

## Required first-release setup

Before pushing the first tag:

1. Confirm the npm `@peerborne` scope is owned and all maintainers use 2FA.
2. Create a short-lived granular npm token with only the organization/package write access needed for bootstrap publication and dist-tag changes.
3. Create a protected GitHub environment named `npm-publish`; store the token only as its `NPM_TOKEN` environment secret.
4. Require designated reviewers for that environment, restrict deployment branches/tags to the intended `v*` release tags, and disable administrator bypass. These controls are mandatory because a tag push is the publication approval boundary.
5. Create the repository variable `NPM_PUBLISH_ENABLED` with value `true` only when publication is operationally enabled. Missing or any other value leaves tag runs in validation-only mode.

The publish job fails when `NPM_TOKEN` is empty and runs `npm whoami` before registry changes. It has only `contents: read` and `id-token: write`; the latter is used for npm provenance. Validation jobs do not receive that permission.

## Publishing and recovery

The tag workflow always validates first. It then publishes each tarball under a unique temporary staging dist-tag. For every package/version it:

1. Reads the registry integrity.
2. Skips an already-published artifact only when its integrity exactly matches the validated tarball.
3. Fails without promotion when the same version has different integrity.
4. Publishes missing artifacts under the temporary staging tag.
5. Verifies all six registry integrities.
6. Promotes all six to `latest` or `next` only after all versions exist and match.

Registry publication and dist-tag updates are not atomic. A failure can leave a subset under the staging tag or a subset of final dist-tags promoted. Rerunning the same tag workflow is safe for matching artifacts and resumes promotion; never replace a published version. Investigate any integrity mismatch rather than retrying around it.

After publication, verify each package/version and final dist-tag with `npm view`, install all six into a fresh consumer, and compare registry integrity with `release-manifest.json`. Remove obsolete temporary staging tags after verification if desired.

## Trusted publishing migration

The bootstrap token remains necessary for the first publication and for current dist-tag promotion. After all six packages exist, configure npm trusted publishing for this repository, `release.yml`, and the `npm-publish` environment. Tokenless package publication can then be evaluated, but do not remove authenticated dist-tag handling until the workflow has a tested replacement. Rotate or revoke the bootstrap token promptly.

## Release notes

The workflow does not create a GitHub Release and does not generate release notes. Create the GitHub Release and write/review its notes manually after npm verification. Keep release-PR body and release-note automation as separate future work; do not imply that npm publication is atomic.
