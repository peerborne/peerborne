# Formal policy verification

The production policy functions in `packages/core/src/policy/` are compiled
from their actual TypeScript implementations to Dafny by LemmaScript. The
runtime imports those same functions; there is no parallel executable model.
See the [assessment and scope](../../docs/formal-verification.md).

```sh
yarn verify:formal:setup
yarn verify:formal
yarn verify:formal:controls
yarn verify:formal:inventory
```

Setup installs tools locally under `.tools/`, without changing global settings
or application dependencies. LemmaScript is pinned to a Git revision and its
npm lockfile; Dafny 4.11.0 archives have pinned SHA-256 digests. Linux x64 and
macOS arm64/x64 are supported. `PEERBORNE_FORMAL_TOOLS` selects another cache
directory. Setup requires network access, Git, npm and unzip. Normal verification
uses the installed tools without downloads. CI can run the Node commands
directly without installing Peerborne's browser/transport dependencies.

`verify:formal` requires every manifest function to be selected and every
policy file to be registered. It rejects missing proof files, generated-file
drift, unverified declarations, partial verification, proof escape annotations,
and a missing domain witness. Dafny's assumption audit must report zero
findings, including no body-less declarations or unproved imported contracts.

The manifest names the actual verified obligations because Dafny need not
emit a separate verification task for a straight-line function whose body has
no well-formedness obligations. Its generated `_ensures` lemma proves the
functional contract. Loop methods carry contracts directly. Witness methods
call the generated functions with valid boundary inputs; a contradictory
precondition cannot make the verification green vacuously.

## Editing production code or contracts

```sh
yarn verify:formal:regen
yarn verify:formal
yarn verify:formal:controls
```

`.dfy.gen` files are generated and must not be edited. `.dfy` files contain
the generated program plus proof additions and domain witnesses. The
additions-only check prevents changing the program inside its proof. Use
`regen` to preserve proof additions after a source edit. Do not delete the
proof files to make regeneration succeed. Recovery files `.dfy.base` and
`.dfy.merged` are ignored and should be handled using the pinned tool's
[regen guidance](https://github.com/midspiral/LemmaScript/blob/f245e9878aa23a3c4a2d3f75ade4a44cebd545dc/AGENTS.md).

The control runner copies only policy sources and proofs into temporary
directories. It checks accepted originals, semantic mutations, stale generated
code, contradictory preconditions, `assume false`, body-less lemmas and
unproved imports. Semantic mutations must reach the verifier and fail an
obligation; a parser error or a drift-only rejection is insufficient.

Reports, source/proof digests, tool versions, per-member verification results,
assumption audits and control results go under `verification/results/formal/`.
The `Formal policy verification` CI job uploads them. These reports contain
source metadata and synthetic proof cases, never live keys or document data.

## Proof domain

Numbers are mathematical integers in this toolchain. Contracts bound production
arithmetic to safe integer ranges; runtime adapters supply counts, validated
uint32 generations and capacities. Strings explicitly use JavaScript UTF-16
semantics. Local maps contain opaque strings and do not escape through aliased
input mutations. Runtime parsing, callback authentication, scheduling, I/O,
cryptographic primitives, side channels and browser resource limits are outside
these proofs. The generated inventory is a scope inventory, not a security
coverage percentage or an end-to-end verification claim.
