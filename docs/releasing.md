# Publishing signed native agents

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

See GitHub's documentation for [enabling immutable
releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
and [artifact
attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Release procedure

1. Set the workspace version to the intended SemVer value and complete the
   normal release review and quality gates.
2. Create and push an exact version tag such as `v0.1.0`. Moving or reusing a
   tag associated with a published immutable release is unsupported.
3. Dispatch **Signed agent release** from that exact tag and enter the same tag
   as its input. For example, use
   `gh workflow run release.yml --ref v0.1.0 -f tag=v0.1.0`. The workflow
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
Each runner executes the protocol and agent tests for its target, builds the
release agent, and executes `nrm-agent --version`. Linux jobs additionally
reject binaries with a dynamic program interpreter, keeping the published
musl executables static.

Only after all six jobs pass does the protected job:

1. verify each downloaded binary's GitHub build provenance against the exact
   release workflow, tag, and source commit;
2. validate each thin ELF, Mach-O, or PE executable header against its target,
   reject dynamic-interpreter Linux binaries and duplicate artifact digests,
   and assemble the canonical target-sorted manifest;
3. sign its unmodified bytes with every configured seed;
4. require the detached signer IDs to equal the protected release public-key
   policy and verify every artifact and expected signature locally;
5. attest the manifest and signature document;
6. create a draft release and upload exactly eight assets;
7. re-download the complete draft, compare every byte to the local output, and
   run `nrm-registry-release verify` over the downloaded files; and
8. publish the draft, verify GitHub's immutable-release attestation, and
   re-resolve the now-locked tag to the signed source commit.

If a run fails after draft creation, inspect the failure and delete only that
unpublished draft before rerunning. The workflow refuses to replace any
existing draft or release. A published release must never be edited, replaced,
or recreated under the same version.

## Local release-tool dry run

Place exactly the six correctly named native agent executables in `artifacts/`.
The tool validates their thin executable formats and exact CPU types; a script,
universal Mach-O, wrong-architecture PE/ELF, dynamic-interpreter Linux binary,
or repeated digest is rejected. Keep the manifest and signature outputs outside
that directory because the tool rejects unexpected artifact-directory entries.

```sh
cargo build -p nrm-registry --bin nrm-registry-release --release --locked

tool=target/release/nrm-registry-release
version=0.1.0
protocol_version=7
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
