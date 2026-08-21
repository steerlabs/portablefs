# Release identity

Status: **enforced release contract; a release is authoritative only after its
immutable tag completes the whole workflow successfully**

The shipped client release identity is offline: a validated git tag, a version
string stamped into the binaries and re-proved by the installer, and two
independent cryptographic trust chains — Sigstore artifact attestations for the
Linux archives, and Apple Developer ID notarization for the macOS app.

The optional hosted foundation additionally reports runtime identity. The
manager exposes its exact stamp at `GET /v1/release`; authenticated cell
observations record separate manager-plan, cell-agent, and root-helper release
stamps. `scripts/build-hosted-linux-release.sh` builds manager, agent, helper,
authority, launcher, and the Linux client from one clean commit, stamps every
executable with one `pfs-hosted-YYYYMMDD-<commit>` identity, and emits an
exact-member SHA-256 bundle. The client in this bundle is the input to a matched
managed-sandbox image. The hosted activator verifies every hash and executable
identity before installing the immutable release and atomically swapping the
one runtime root.
These operator artifacts remain intentionally separate from the frozen
two-binary end-user Linux archive and macOS app identity described below.

Everything below is enforced by `.github/workflows/release.yml`,
`.goreleaser.yaml`, `scripts/install.sh`, and the two policy checkers
`scripts/check-install-release-trust.mjs` and `scripts/check-workflow-pins.mjs`,
which run in both `release.yml` and `ci.yml`.

## The tag and checked-in version are one identity

Releases are triggered only by a pushed tag matching `v*`, and the first thing
the `validate` job does — step *"Prove an exact stable tag at this source
revision"* — is refuse anything that is not an exact stable release:

```sh
if [[ ! "$GITHUB_REF_NAME" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "release tag must be stable SemVer vMAJOR.MINOR.PATCH: $GITHUB_REF_NAME" >&2
  exit 1
fi
test "$GITHUB_REF" = "refs/tags/$GITHUB_REF_NAME"
test "$(git rev-parse "$GITHUB_REF_NAME^{commit}")" = "$GITHUB_SHA"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
version="$(cat VERSION)"
printf '%s\n' "$version" | cmp -s - VERSION
test "$GITHUB_REF_NAME" = "v$version"
```

These checks bind the stable SemVer tag, the push event's commit, the checked-out
tree, and the repository's exact newline-terminated `VERSION` file. The checkout
is `fetch-depth: 0` with `persist-credentials: false`, so the tag is resolved
against real history rather than a shallow graft.

`VERSION` is the local/Xcode authority: the production, macOS 26, and macOS 27
projects must each contain exactly four matching `MARKETING_VERSION` settings;
CI reads it directly; and the macOS packager rejects both environment overrides
and positional arguments that do not equal it. The tag is the publication
authority used by GoReleaser and artifact names. The equality gate makes these
two representations one release identity instead of allowing either to
override the other.

Publication is immutable by construction. Before uploading anything the workflow
proves no release exists for the tag — a `404` from
`/repos/$GITHUB_REPOSITORY/releases/tags/$GITHUB_REF_NAME` passes, `200` fails
with `release <tag> already exists; refusing to replace a draft, published
release, or asset`, and any other status fails as unproven. GoReleaser is
configured `draft: true` with `replace_existing_draft: false`,
`use_existing_draft: false`, and `replace_existing_artifacts: false`; the final
`publish` job asserts the release is still a draft before flipping it. The trust
checker additionally fails the build if `--clobber` appears anywhere in the
workflow.

## The version is stamped, then re-proved

GoReleaser stamps the tag into the two client binaries:

```yaml
ldflags:
  - -s -w -X main.version={{ .Version }}
```

for both the `portablefs` build (`./cmd/portablefs`) and the `portablefsd` build
(`./cmd/portablefsd`). Both packages declare `var version = "dev"`, so an
unstamped binary is self-identifying as a development build.

The installer does not take that on faith. After verifying and extracting the
archive, and *before* touching the destination, it runs the staged binaries and
requires exact agreement with the tag it resolved:

```sh
cli_version=$("$tmp/$BINARY" version)       # must equal "portablefs $version"
daemon_version=$("$tmp/$DAEMON" -version)   # must equal "$version"
```

This is what makes the version a proof rather than a label: the bytes on disk
have to say the same thing the release tag says.

## Linux: Sigstore artifact attestations

Four GitHub/Sigstore artifact attestations are produced per release, one per
Linux archive, with `actions/attest` pinned by commit SHA
(`508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4`) under `id-token: write` and
`attestations: write`:

| Step | Subject |
| --- | --- |
| Attest Linux amd64 release archive | `dist/portablefs_*_linux_amd64.tar.gz` |
| Attest Linux arm64 release archive | `dist/portablefs_*_linux_arm64.tar.gz` |
| Attest Linux server amd64 release archive | `dist/portablefs-server_*_linux_amd64.tar.gz` |
| Attest Linux server arm64 release archive | `dist/portablefs-server_*_linux_arm64.tar.gz` |

Each bundle is then published as a release asset named after its archive:

```text
portablefs_<version>_linux_amd64.tar.gz.attestation.jsonl
portablefs_<version>_linux_arm64.tar.gz.attestation.jsonl
portablefs-server_<version>_linux_amd64.tar.gz.attestation.jsonl
portablefs-server_<version>_linux_arm64.tar.gz.attestation.jsonl
```

Publishing the bundles as assets is what makes verification **offline**: the
installer never queries an attestation API, so it does not depend on a live
service being reachable or honest at install time.

`checksums.txt` (GoReleaser's default `checksum.name_template`) covers the
archives. It carries no signature of its own — it is an integrity check against
a corrupt or truncated download, and the attestation is what makes the archive
trustworthy.

### How the installer verifies

`scripts/install.sh` first verifies the archive's SHA-256 against its
`checksums.txt` entry, then bootstraps a pinned verifier: GitHub CLI 2.93.0,
downloaded by exact URL and checked against a hard-coded per-architecture
SHA-256. Its tar namespace is fully inspected before extraction — every member
must live under `gh_<version>_linux_<arch>/`, names containing `..`, `//`, or
characters outside `[A-Za-z0-9._/-]` are rejected, every entry must be a regular
file or directory, and `bin/gh` must appear exactly once — and the binary is
then streamed out with `tar -xOzf` so no attacker-chosen path is ever written.

Then, with that verifier:

```sh
"$tmp/gh" attestation verify "$tmp/$archive" \
  --hostname github.com \
  --repo "$REPO" \
  --signer-workflow "$REPO/.github/workflows/release.yml" \
  --source-ref "refs/tags/$tag" \
  --deny-self-hosted-runners \
  --bundle "$tmp/$attestation_bundle" \
  --format json \
  --jq '...'
```

Each flag removes a distinct forgery: `--repo` binds the artifact to this
repository, `--signer-workflow` binds it to this exact workflow file (not merely
some workflow in the repo), `--source-ref` binds it to the release tag rather
than a branch, `--deny-self-hosted-runners` refuses provenance from a runner the
project does not control, and `--bundle` keeps the check offline.

The `--jq` expression is a shape guard, not a formality. It requires **exactly
one attestation** carrying **exactly one subject**:

```jq
if length == 1 and (.[0].verificationResult.statement.subject | length) == 1
then "verified-single-subject" else "invalid-bundle-shape" end
```

Anything else is refused as ambiguous — a bundle that attests several artifacts,
or several attestations of varying provenance, would let a verified statement
about one file stand in for another.

**Verification happens before extraction.** `check-install-release-trust.mjs`
enforces the ordering directly, comparing the offset of `"$tmp/gh" attestation
verify` against the offset of `tar -xzf "$tmp/$archive"` and failing with
`PortableFS archive extraction can happen before provenance verification` if the
order is ever inverted.

### The exact two-binary archive contract

Also before extraction, the installer proves the archive contains exactly the
CLI and the daemon and nothing else:

```sh
tar -tzf "$tmp/$archive" | LC_ALL=C sort >"$tmp/portablefs-members.txt"
printf '%s\n' "$BINARY" "$DAEMON" | LC_ALL=C sort >"$tmp/portablefs-members.expected"
cmp ... || die "$archive does not contain exactly the PortableFS CLI/daemon pair"
```

A second pass over `tar -tvzf` requires every entry to be a regular file (`^-`),
requires every name to be `portablefs` or `portablefsd`, and requires each to
appear exactly once — otherwise `contains a link, special entry, or duplicate
binary`. The same two checks run inside `release.yml` (step *"Verify exact Linux
installer archive membership"*) against both archives, so a malformed archive
fails at build time as well as install time.

This is why `.goreleaser.yaml` splits the output into two separately named
archives — `portablefs-client` (`portablefs` + `portablefsd`) and
`portablefs-server` — with `files: [none*]` on both. Any additional build output
lands in the server archive, which the installer never fetches, so it can never
silently enter the installer's trust boundary.

## macOS: signing, notarization, and bundle identity

There is **no attestation on the macOS path.** The macOS app is not built by
GoReleaser; it comes from `scripts/package-macos-app.sh` as
`portablefs_<version>_darwin_universal_app.zip` and is not listed in
`checksums.txt`. Its identity rests on four independent things.

**A sha256 sidecar.** The packager writes `<archive>.sha256` beside the zip and
the release uploads both; the installer fetches the sidecar and refuses to
proceed without it (`refusing to install without checksum verification`).

**A proven ZIP namespace before extraction.** `ditto -x` writes paths before
`codesign` can run, so the installer inspects the archive first: no duplicate
members, every member under `PortableFS.app`, no `..`, `.`, `//`, or backslash
components, and no symlink or special entry.

**Developer ID signing, hardened runtime, and Gatekeeper.**
`codesign --verify --deep --strict` on the bundle, then for each of the app, the
`PortableFSExt.appex`, the unentitled `portablefs`, the nested
`PortableFSDService.app`, and its `portablefsd` executable:
an exact `TeamIdentifier=` line, an `Authority=Developer ID Application: `
line, and a `CodeDirectory ... flags=...runtime` line proving the hardened
runtime. Finally `spctl --assess --type execute` must accept the app, which is
what proves notarization and stapling rather than mere signing.

**An exact bundle-identity tuple.** For `steerlabs/portablefs` the expected
values are hard-coded and, by explicit policy check, *not* environment-overridable:

| Identity | Value |
| --- | --- |
| Team ID | `B47U2LLKHW` |
| Bundle identifier | `dev.portablefs.PortableFSApp` |
| App group | `B47U2LLKHW.pfsoss` |
| FSKit `fsType` | `pfs` |
| Resource scheme | `dev.portablefs.oss` |

The installer asserts the app's `Identifier=` and `TeamIdentifier=` match, that
the extension's bundle id is exactly `<bundle-id>.PortableFSExt`, that its
`EXAppExtensionAttributes` declare `FSShortName` and the personality's `FSName`
as `pfs`, that it advertises exactly one `FSSupportedSchemes` entry equal to
`dev.portablefs.oss` (a second entry is a hard failure), that
`FSSupportsGenericURLResources` is true, that the app's
`CFBundleShortVersionString` equals the release version, and that the host and
extension `PFSAppGroupIdentifier` values match. It also requires exactly one
`PortableFSDService.app` with bundle id `<bundle-id>.PortableFSDService`, an
exact background-only Info.plist, no provisioning profile, and exactly one
sealed `<bundle-id>.portablefsd.plist` whose only launch policy is the proven
RunAtLoad/KeepAlive `BundleProgram` under that service app. The host app,
extension, and nested `portablefsd` must each carry exactly one signed
`com.apple.security.application-groups` value matching that metadata identity.
The daemon service signature may carry no other entitlement, including
`get-task-allow`.
For signed development hosts, the outer host, extension, and unentitled CLI
use the explicit Apple Development identity selected by Xcode, while the
nested daemon service is independently signed with the configured
`PORTABLEFS_SERVICE_SIGN_IDENTITY`. That setting must name the exact Developer
ID Application identity; the embed phase never infers it from the keychain or
reuses the host identity. Release export subsequently requires every nested
component to prove the same Developer ID release authority.
The embedded `portablefs` CLI must carry no app-group entitlement: its shell
process wakes the exact host and uses the external private control socket, and
never enters the protected container. Packaging rejects either missing daemon
privilege or accidental CLI privilege.

**An exact service-update identity.** Before an installed host permits bundle
replacement, both the old and target nested services are bound by the service
CodeDirectory hash, full executable SHA-256, daemon version, control identity
schema, control protocol, and `pfslocal` major/minor. The owner-private durable
activation lease stores those tuples, a bounded phase/deadline, and only the
SHA-256 of a random one-use token. The plaintext token crosses only
credential-checked Unix-socket sessions and never appears in defaults, argv,
logs, or the lease. The installer keeps the exact displaced app until the
replacement has independently proved the same live identity; an acknowledged
failure is fenced before the old app may be restored.
Every host termination edge closes the owner-private update listener, removes
only the exact pinned socket inode it published, and re-proves the canonical
name absent before any acknowledgement or exit. A replaced or unsafe inode is
left in place and the durable phase stays fail-closed. If the commit reply is
lost, the installer retains the plaintext token and accepts only one of two
exact outcomes: `old-absent` plus disappearance of the authenticated prepared
host enters the normal tokenized prepublication rollback, while
`rollback-complete` additionally requires the installed old hierarchy and live
daemon full tuple. Socket-path absence or presence alone is never transaction
authority.
The long-lived listener re-proves its exact pinned inode before every accept
attempt. It retries only signal interruption and Darwin's documented
`ECONNABORTED` result for a client that abandons a queued connection; every
other accept failure stops and unpublishes the listener fail-closed.
That fence is not a system-wide PID scan. Before mutation, the host
authenticates the control peer's exact audit token, PID version, executable,
Developer ID code identity, and release CodeDirectory hash, then pins that
execution with `EVFILT_PROC`. Completion requires `NOTE_EXIT`, Service
Management `notRegistered`, and all three socket names absent. If registration
failed before an authenticated control peer was published, the host instead
proves the canonical state-singleton lock is safely pinned and free; the daemon
acquires that lock first and releases it last.
The host replaces the active phase with a durable `target-complete` or
`rollback-complete` terminal marker before acknowledging completion. A lost
activation-accept acknowledgement does not destroy the installer session: the
same in-memory token may open a new credential-checked `resume-target` or
`resume-rollback` connection only while the lease is the matching exact active
phase. The host revalidates the token hash, both old/target tuples, its sealed
release, and the registered live release before exposing the completion edge;
the resume path can neither activate nor fence a service. Loss of a readiness
reply is different: the server fences the ready release back to
`rollback-absent`, and the installer proceeds only after the authenticated
ready-host PID and listener are both absent. A lost completion reply is
accepted only after the installer proves that exact
token-bound marker, the alternate app was already durably retired, and both the
installed signed hierarchy and live daemon still prove its exact active tuple.
If the marker was not yet published and the lease remains exact-active, the
installer uses the same resume protocol and retries completion; plaintext token
material is never persisted for either recovery.
Every activation operation is admitted against one parent deadline before it
starts. The client reserves the complete worst-case work that can follow the
child request: live proof, accept reconciliation, terminal completion, and,
while the target is only ready, enough time to fence it, prove exact host/socket
absence, and run the old-release rollback activation. Every nested composition
also retains a fixed scheduling/cancellation margin outside the exact operation
budgets. A child timeout therefore
cannot consume the time needed to reconcile a host action that crossed just
after the client deadline. If the remaining budget is insufficient while a
release is still ready, the client sends the official token-bound fence and
proves `rollback-absent` plus exact process/listener absence; it never begins
Accept or another launch at the deadline edge. Persistent failure after an
exact safe-absent proof remains a fail-closed operator-recovery state rather
than discarding the token while a host action may still be running.
The terminal marker does not expire and is not deleted: a later authenticated
prepare may replace it only after the sealed, registered, and live full tuple is
re-proved. An expired nonterminal lease without its plaintext token instead
blocks normal host startup and requires explicit operator recovery; it is never
auto-removed or used as tokenless authority to mutate Service Management state.

Then it makes the three executables agree with the extension. `portablefs
lifecycle identity --json` and `portablefsd -identity-json` must report the same
`appGroup`, the same `fsType`, and the same `resourceScheme` as the appex's
metadata. That tuple is what FSKit routes on and what the sandbox permits a
socket under, so a CLI, daemon, and extension that disagree would install a
mount path that cannot work — or, worse, one that reaches a different product's
extension. A `REPO` other than `steerlabs/portablefs` must supply all five
values explicitly through `PORTABLEFS_EXPECTED_*`; there is no default.

Both platforms end the same way: the verified staged CLI performs the actual
installation (`install-linux-release` / `install-macos-app`), so path resolution,
the lifecycle guard, and the atomic activation swap are done by code that has
already been proven authentic.

## The policy that keeps it from drifting

Two dependency-free Node scripts are the enforcement. They run in `release.yml`
(job `validate`, step *"Release trust policy"*) and in `ci.yml` (job
`workflow-pins`), so a pull request cannot land a regression that only a tag
push would catch.

**`scripts/check-install-release-trust.mjs`** reads `install.sh`,
`release.yml`, and `.goreleaser.yaml` and asserts, among others:

- the pinned `gh` version and both architecture digests are unchanged;
- every one of the six `gh attestation verify` flags is still present;
- provenance verification still precedes extraction;
- the exact-membership strings and their failure messages are intact;
- the strict release-input checks are intact — the `%{url_effective}` redirect
  probe, the `https://github.com/$REPO/releases/tag/` prefix requirement, and the
  stable-SemVer tag regex;
- the macOS pre-extraction ZIP boundary checks are intact;
- the canonical Apple identity block contains all five expected values and
  contains no `PORTABLEFS_EXPECTED_` reference, failing with `canonical Apple
  identities remain environment-overridable` if it does;
- the two archive ids and name templates and the three no-replace release flags
  are unchanged;
- `release.yml` still declares `id-token: write` and `attestations: write`, still
  pins `actions/attest` by SHA, still names all four `subject-path` values and
  all four `.attestation.jsonl` asset names, still runs every validation gate
  (cross-OS builds, vet, the Go suite, the Go race suite, `sh -n
  scripts/install.sh`, both policy checkers, `govulncheck@v1.6.0`, `goreleaser
  check`, `bash scripts/test-swift-xcode.sh`) with the three
  `needs:` edges intact, and never uses `--clobber`.

It also **bans container images from the release path outright.** If
`release.yml` mentions `ghcr.io`, `docker/build-push-action`, or `Dockerfile`,
the check fails with `release workflow still publishes retired control-plane
images`. The v3 tree publishes exactly two trust chains — the Linux archives and
the notarized macOS app — and the journal-era control-plane images are gone.

**`scripts/check-workflow-pins.mjs`** governs what a workflow may execute.
Every workflow file must declare a top-level `permissions:` block and a
top-level `concurrency:` block. `runs-on:` must pin a versioned image: `latest`
or an expression is rejected. Third-party actions must be pinned to a 40-hex
commit SHA *and* carry a trailing `# vX.Y.Z` evidence comment; a SHA pin with no
comment is rejected as unreviewable. First-party `actions/*` may float on a
major tag. A `docker://` action must be digest-pinned. Local `./` composites are
allowed.

## Known gaps

State these plainly rather than reading the sections above as a description of a
working pipeline.

The release configuration now names only binaries that exist in the v3 tree.
GoReleaser builds the exact two-binary Linux client archive (`portablefs` and
`portablefsd`) plus a separate one-binary server archive containing
`portablefs-authority`; the workflow independently verifies both archive
memberships before attestation. `portablefs-mount-v3` remains a standalone
integration-harness binary rather than a published operator artifact: ordinary
Linux users mount through `portablefs`, while operators deploy the authority
from the server archive.

Tags through `v0.2.3` point at commits that predate `dba5b8f`. `v0.2.4` marks
the first tagged v3 tree but is not release authority: its draft pipeline
correctly stopped before publication when archive signing had no independently
modeled Apple Development identity. `v0.2.5` is the first releasable v3 tree.
It is accepted only when its immutable tag runs this complete workflow
successfully: exact source/version proof, Linux archive membership and
attestations, native Xcode tests, exact isolated Apple Development archive
signing, separately isolated Developer ID export, notarization, stapling, and
final publication. Developer ID export is manual and locally rooted in the
exact release identity plus the frozen FSKit direct-distribution profile; it
must never fall back to cloud-managed certificate or profile creation. A tag or
draft release alone is not release authority.
