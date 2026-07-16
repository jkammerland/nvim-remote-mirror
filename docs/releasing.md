# Publishing signed native agents

> [!WARNING]
> The release automation is work in progress. Use the unsigned dry run to test
> native builders and assembly; do not treat its output as a trusted registry.

The signed-agent workflow publishes one immutable release containing six native
`nrm-agent` executables, the exact manifest bytes, and detached Ed25519
signatures. It is intentionally manual: an operator starts the workflow for an
existing version tag, and the protected `release` environment gates access to
signing material.

The manifest signature is the client trust boundary. GitHub build provenance
attestations and GitHub's immutable-release attestation are useful independent
evidence, but they do not replace manifest verification.

## One-time repository setup

Before the first release:

1. Enable **release immutability** in the repository or owning organization.
   GitHub applies immutability only to releases published after the policy is
   enabled. The workflow checks the policy before creating a draft and checks
   `isImmutable` after publication.
2. Protect version tags against force updates, then create a GitHub Actions
   environment named `release`. Require reviewers and restrict deployment tags
   so an unreviewed ref cannot reach its secrets.
3. Add the environment secret `NRM_REGISTRY_SIGNING_KEYS_JSON`. Its value is a
   strict JSON object mapping distinct key IDs to standard-base64-encoded,
   32-byte Ed25519 seeds. Never store this value in the repository, an Actions
   variable, a workflow input, or a release asset.
4. Add the environment variable `NRM_REGISTRY_TRUSTED_PUBLIC_KEYS_JSON`. Its
   value is a strict JSON object whose key IDs are the exact expected signer set
   for the release, mapped to matching standard-base64-encoded, 32-byte Ed25519
   public keys. It is public data, but the release gate requires its key-ID set
   to equal the detached signature key-ID set and verifies every signature.
5. Add the environment secret `NRM_RELEASE_POLICY_TOKEN`. Use a fine-grained
   token limited to this repository with read-only **Administration** access.
   The workflow exposes it only to the immutable-release policy check; release
   creation uses the narrower workflow `GITHUB_TOKEN` instead.

The workflows checksum-pin the Linux x64 GitHub CLI archive and verify its
release, attestation, and immutable-release commands in the initial identity
job. This makes an unavailable or incompatible CLI fail before the six native
builders start instead of depending on the mutable runner-image copy.

See GitHub's documentation for [enabling immutable
releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
and [artifact
attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Release procedure

1. Set the workspace version to the intended SemVer value and complete the
   normal release review and quality gates.
2. Create and push an exact version tag such as `v0.1.3`. Once pushed, never
   move or reuse a version tag; if its source needs changes, increment the
   version.
3. Dispatch **Signed agent release** from that exact tag and enter the same tag
   as its input. For example, use
   `gh workflow run release.yml --ref v0.1.3 -f tag=v0.1.3`. The workflow
   requires its invocation commit and the peeled tag commit to match so GitHub
   provenance identifies the bytes' actual source. Approve the protected
   `release` environment only after reviewing the tag and workflow changes.
4. Retain the workflow run and release URL as release evidence.

The workflow relies on Cargo's SemVer parser and rejects unsafe tag spellings, a
tag/package version mismatch, a non-40-character source commit, and ambiguous
protocol constant declarations. SemVer prereleases are published as GitHub
prereleases rather than being marked latest. Each release is tied to one tag,
package version, protocol version, and source commit.

Every target uses a native GitHub-hosted runner:

| Platform | Runner | Rust target |
| --- | --- | --- |
| Linux x64 | `ubuntu-24.04` | `x86_64-unknown-linux-musl` |
| Linux ARM64 | `ubuntu-24.04-arm` | `aarch64-unknown-linux-musl` |
| macOS x64 | `macos-15-intel` | `x86_64-apple-darwin` |
| macOS ARM64 | `macos-15` | `aarch64-apple-darwin` |
| Windows x64 | `windows-2025` | `x86_64-pc-windows-msvc` |
| Windows ARM64 | `windows-11-arm` | `aarch64-pc-windows-msvc` |

No target is optional and no matrix entry permits failure. An unavailable ARM64
runner leaves the required job unsatisfied and prevents signing and publishing.
GitHub currently labels `ubuntu-24.04-arm` and `windows-11-arm` as public
preview, so those labels have no hosted runner availability SLA; this workflow
intentionally fails instead of omitting either target when its runner is
unavailable.
Each runner executes the protocol, agent, and sidecar tests for its native
target, builds the release agent, and executes `nrm-agent --version`. This puts
the POSIX and PowerShell installer/rollback planners under native x64 and ARM64
coverage even though only `nrm-agent` is published. Linux jobs additionally
reject binaries with a dynamic program interpreter, keeping the published musl
executables static.

Only after all six jobs pass does the protected `sign` job:

1. verify each downloaded binary's GitHub build provenance against the exact
   release workflow, tag, and source commit;
2. require exactly the six expected regular files, validate each ELF64,
   thin Mach-O, or PE32+ machine header, reject Linux program interpreters and
   duplicate digests, and independently assemble the canonical target-sorted
   manifest; and
3. strictly parse the protected signing and trust maps, derive each Ed25519
   public key from its seed, require exact key-ID and public-key equality, then
   sign and locally verify the exact manifest bytes.

The secret-bearing job intentionally performs no checkout, Cargo invocation,
repository script, or executable produced by the release tag. It uses only
checksum-pinned GitHub CLI, pinned official artifact actions, and the runner's
Python/OpenSSL to reduce the signing seed's exposure to a small reviewable
step. The signed candidate is then handed to a separate job that has no access
to the seed. That job:

1. checks out the exact source commit, tests and builds the release verifier,
   and strictly verifies all six executable formats, hashes, manifest fields,
   signer IDs, and signatures;
2. attests the manifest and signature document;
3. creates a draft release and uploads exactly eight assets;
4. re-downloads the complete draft, compares every byte to the local output,
   and runs `nrm-registry-release verify` over the downloaded files; and
5. publishes the draft, verifies GitHub's immutable-release attestation, and
   re-resolves the now-locked tag to the signed source commit.

A hardware-backed or external KMS signer remains the preferred future
replacement for the exported seed JSON. The isolated job limits exposure but
does not turn an environment secret into non-exportable key material.

The six production build artifacts and isolated signed candidate are retained
for 30 days so protected environment review does not normally outlive them. If
a run fails after draft creation, the workflow deletes only the exact release
ID it created, and only while that release is still an unpublished, mutable
draft. If cleanup cannot prove all of those conditions, inspect the draft
manually before rerunning.
Draft creation and asset population are separate steps. The creation step
captures the release ID directly from GitHub's create response, so a later
upload or verification failure cannot hide the identity needed by cleanup.
An inline failure trap covers validation or output errors inside the creation
step itself and applies the same exact-ID, draft, publication, and mutability
checks before deleting anything.
The workflow refuses to replace any existing draft or release. A published
release must never be edited, replaced, or recreated under the same version.
After publication it allows up to five minutes for immutable-release and
attestation verification to converge; a timeout message explicitly warns when
the release is already immutable and must not be rerun or replaced.

## GitHub unsigned release dry run

The manually dispatched **UNSIGNED six-target release dry run** workflow
validates the native build and assembly path without accessing the protected
`release` environment, signing keys, or release-write permissions. Run it from
the exact branch or tag commit to test:

```sh
gh workflow run release-dry-run.yml --ref master
```

The workflow pins its source identity to the dispatched commit, then uses the
same six native runner/target pairs listed above. Each target runs the protocol
agent, and sidecar tests, builds and executes `nrm-agent --version`, and records
GitHub build provenance. Linux additionally rejects a dynamic program
interpreter.
The aggregate job verifies all six attestations against the exact source
commit, requires exactly the expected target set, runs the release-tool tests,
and assembles a deterministic manifest.

The only combined output is a seven-file Actions artifact named
`UNSIGNED-TEST-ONLY-agent-release-<source-commit>`, retained for seven days. It
contains the six native binaries and
`UNSIGNED-nrm-agent-manifest-v1.json`. Individual per-target build artifacts are
retained for seven days so delayed preview ARM64 capacity cannot expire early
matrix outputs before aggregation. The workflow deliberately does not create a
detached signature, GitHub Release, tag, or trusted registry endpoint.
Consequently its bundle cannot satisfy client registry verification and must
not be renamed or published as a production release. It is useful for runner
availability, native execution, provenance, format/architecture checks,
deterministic assembly, and downstream test-fixture experiments that explicitly
treat the bytes as unsigned.

Preview ARM64 runner unavailability is a dry-run failure, just as it is for the
production workflow. Monitor every matrix job rather than interpreting the
aggregate bundle job alone.

## Local release-tool dry run

Place exactly the six correctly named native agent executables in `artifacts/`.
The tool validates their thin executable formats and exact CPU types; a script,
universal Mach-O, wrong-architecture PE/ELF, dynamic-interpreter Linux binary,
or repeated digest is rejected. Keep the manifest and signature outputs outside
that directory because the tool rejects unexpected artifact-directory entries.

```sh
cargo build -p nrm-registry --bin nrm-registry-release --release --locked

tool=target/release/nrm-registry-release
version=0.1.3
protocol_version=8
source_commit="$(git rev-parse HEAD)"

"$tool" assemble \
  --artifacts-dir artifacts \
  --version "$version" \
  --protocol-version "$protocol_version" \
  --source-commit "$source_commit" \
  --output nrm-agent-manifest-v1.json

NRM_REGISTRY_SIGNING_KEYS_JSON="$SIGNING_KEYS_JSON" \
  "$tool" sign \
  --manifest nrm-agent-manifest-v1.json \
  --output nrm-agent-manifest-v1.json.sig \
  --expected-version "$version" \
  --expected-protocol-version "$protocol_version" \
  --expected-source-commit "$source_commit"

NRM_REGISTRY_TRUSTED_PUBLIC_KEYS_JSON="$PUBLIC_KEYS_JSON" \
  "$tool" verify \
  --manifest nrm-agent-manifest-v1.json \
  --signatures nrm-agent-manifest-v1.json.sig \
  --artifacts-dir artifacts \
  --expected-version "$version" \
  --expected-protocol-version "$protocol_version" \
  --expected-source-commit "$source_commit"
```

Use disposable test seeds for a dry run. Shell environment variables are
visible to their child processes and may be observable to privileged local
users, so production seeds belong only in the protected Actions environment.

## Key rotation

With the default client threshold of one, rotate with an overlap:

1. Generate the new seed in the protected release system. Distribute the new
   key ID and public key to clients through the existing out-of-band trust
   channel before relying on it.
2. Add the new seed and public key to the protected environment while retaining
   the old entries. The deterministic signer orders key IDs and emits one
   distinct signature per configured key.
3. Publish overlap releases signed by both keys. The release gate requires the
   exact protected public-key ID set in the detached document and verifies all
   of them, so an omitted, unknown, or invalid overlap signature blocks
   publication.
4. After supported clients trust the new key, remove the old seed and the old
   public key from the protected release environment together. Continue
   accepting the old public key in client configuration for the documented
   migration period, then remove it from clients. The release gate's exact set
   is deliberately separate from each client's rollout-specific trust set and
   threshold.

Raising the client threshold is a separate migration. First distribute enough
trusted public keys, then publish enough overlapping valid signatures, and only
then raise the configured threshold. Reversing that order intentionally makes
install and update fail closed.

For a suspected compromise, remove the affected key from client trust through
the out-of-band channel, remove its seed and public key from the exact release
environment signer set, rotate the environment credentials and policy token,
and publish only with unaffected keys. Do not treat a new key served alongside
registry content as trusted. Cached manifests are checked against the client's
current trust set, so old cache entries signed only by a removed key cease to
verify.

The registry threat model and client-side cache rules are described in
[Signed agent registry operations](agent-registry.md).
