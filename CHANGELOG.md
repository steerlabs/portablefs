# Changelog

All notable changes to PortableFS are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and immutable releases
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-release binaries, images, and auto-generated release notes are published on
the [GitHub Releases](https://github.com/steerlabs/portablefs/releases) page;
this file is the human-curated summary.

## [Unreleased]

### Added

- Writable `O_APPEND` on the stock-FUSE Linux profile, and it is exact across
  mounts. The frontend forwards the writing description's append intent and the
  authority places the payload at the object's true EOF inside the per-inode
  writer stripe, reporting the offset it assigned. Concurrent cross-mount append
  atomicity is now a demonstrated matrix case rather than a declared failure.
  Stock Linux forwards neither `RWF_APPEND` nor `RWF_NOAPPEND`, and those two
  per-call cases are disclosed deviations in `docs/portable-coherence.md` §4.3.
- The Linux write path now carries the description's `O_SYNC`/`O_DSYNC` intent to
  the authority, which the FSKit path has always honored.

### Changed

- Ship the named macOS 26 FSKit best-effort cache tier over protocol 6. One
  active Mac owns an authority-enforced compatibility writer lease; Linux peers
  remain readable but their visible mutations return `EBUSY` before storage,
  a second Mac writer is refused at activation, and clean unmount transfers
  write ownership. The product reports the measured transient-`ESTALE`
  high-rename boundary instead of hiding it behind retries or a fallback.

## [0.2.6] - 2026-08-12

### Fixed

- Make Linux archive extraction account-owned by construction. After the
  installer verifies provenance and proves the archive is exactly two regular
  files, it streams each named member into its private staging directory
  instead of materializing tar uid/gid metadata. This gives root and non-root
  installations the same fail-closed ownership contract.

## [0.2.5] - 2026-08-12

### Fixed

- Model Apple's two-stage direct-distribution signing pipeline explicitly in
  release CI: a sole Apple Development identity signs the Xcode archive and a
  separately isolated Developer ID identity signs the exported, notarized app.
  Each credential is imported into its own ephemeral keychain and validated for
  exact role, team, and cardinality before Xcode runs; neither identity can
  silently substitute for the other.
- Make Developer ID export deterministic and local: the release workflow uses
  the frozen FSKit direct-distribution profile and exact Developer ID identity,
  rather than asking Xcode to create cloud-managed signing assets.
- Verify universal release binaries one architecture at a time so the same
  packaging contract is accepted by both the Xcode 26 and Xcode 27 `lipo`
  implementations.
- Validate every GitHub Actions workflow with a version-frozen semantic parser
  in pull requests, including context-availability and shell diagnostics that
  the repository's offline pin/trust checks deliberately do not reimplement.

## [0.2.4] - 2026-08-12

First tagged release of the direct-store v3 architecture.

### Added

- **Hosted live-mount reauthorization is public at the CLI boundary.** New
  mounts return their non-secret `authorizationSessionId`, `portablefs version
  --json` advertises `hosted-mount-reauthorization-v1`, and `portablefs
  reauthorize` delivers an exact manager-issued sequence, capability, and
  renewed certificate to the existing session. Linux uses a uid-checked private
  mount-supervisor socket; macOS uses the paired `portablefsd` control socket.
  Capabilities remain environment-only at the CLI and are never written to
  mount or daemon state.
- **Hosted mounts can renew themselves under a bounded Manager enrollment.**
  An explicit `automatic_reauthorization` request creates a volume-, access-,
  generation-, and mount-key-scoped enrollment. The Linux mount supervisor and macOS
  `portablefsd` each own exactly one renewal sequence, install short-lived
  grants into the existing session, close the enrollment on exact detach, and
  fail closed before the installed grant expires. Natural tuple idempotency
  prevents lost HTTP responses from producing two proofs for one sequence
  without accumulating per-refresh response receipts; the enrollment is pinned
  as the authority session's sole reauthorization issuer.

### Removed

- **The v2 architecture, in its entirety.** The XFS authority, the `fusev3`
  kernel mount, the `portablefsd` v3 data plane, and the v3 mount CLI are now the
  only paths. Deleted: every v2 Go plane — the client core, the v2 mount wire,
  the write-back engine, the work filesystem, the mount WAL, the base-tree and
  control formats, the history and journal machinery, delegation, coherence, and
  the v2 FUSE frontend, together with the packages orphaned by the cut, the
  journal server command, and the history worker; the daemon's v2 attach path;
  and the CLI's legacy mount engine along with every command backed by the
  journal-era control plane. Deleted with them: that control plane's TypeScript
  services and workspace packages, the Railway reference deployment, the
  docker-compose stacks, the control-plane container images, and the JavaScript
  package-manager machinery.

  With the journal went the product surfaces built on it: history, branches,
  forks, snapshots, `adopt`, server-side exec and grep, and renewable access
  leases. v3 mounts carry direct credentials — an authority address, a single-use
  capability, and a mutual-TLS client identity — and a v3 volume is branchless.

  Legacy persisted attach and lease records are recognised and refused with
  remount-or-discard guidance rather than silently dropped. Module dependencies
  fall from five to three.

### Changed

- **CI and the local gate are Go and Swift only.** `scripts/verify-local.sh` is
  one bash gate: cross-OS builds, vet, the Go suite, the Go race suite, the Swift
  suite, the release-trust policy checks, and a stale-architecture scan that fails
  the build if the journal-era identifiers reappear. The release workflow no
  longer builds control-plane images and its trust check refuses their return.
- **`portablefsd` serves a real v3 authority attach**: a mutual-TLS dial with no
  mode fallback, a real coherence contract on resolve, every local operation
  routed to the v3 data plane, and an evidence-bearing detach that either delivers
  a mount-absence proof or ends fenced.
- **`portablefs mount` is v3-only on both platforms**: direct credentials, strict
  coherence by default, a shared mount engine, and a daemon-driven FSKit attach on
  macOS.
- **macOS 26 FSKit is composed end to end** as the declared compatibility cache
  policy `macos26-synchronous-vfs-repair-v1`: the namespace and live-object
  indexes are populated from every binding callback, the publication barrier is
  real, the repair gate is installed at resolve, and data invalidation is armed
  under exact one-shot provenance. Its residual race and its open live-kernel
  gates are stated in `docs/macos-26-coherence-contract.md`.
- **Strict clean detach now has one explicit cooperative-client trust boundary.**
  The authority accepts a mount-absence observation only on the authenticated
  request for that exact session. FSKit reports only after exact `getfsstat`
  absence; Linux additionally waits for the exact FUSE serving connection to
  terminate, covering lazy-unmount references. Crashes and ambiguous teardown
  still retain durable membership and require fencing before restart.

### Fixed

Each of the following carries a regression test and was verified against the
privileged XFS and kernel-FUSE suite.

- Stable-identity resolution inspected the export handle before its error, so a
  routine cross-mount `ENOENT` race nil-dereferenced and killed the whole
  authority. Absence now reports a stale-object error.
- A blocking `F_SETLKW` held the topology read guard for its whole park, so one
  queued routing writer stalled every request on the volume. Blocking waits are
  admitted through the session-routes check instead of the guard.
- Applying a routing change fenced every strict participant through silent budget
  burn. Mounts now report themselves blocked — which fences immediately — before
  revoking, and visibility control is exempt from the session-routes gate.
- One raced-away or non-portable directory entry failed a whole readdir page with
  `ESTALE`, making a directory containing a foreign FIFO permanently unlistable.
  Entries now degrade exactly as local readdir does: raced entries are skipped
  with cookie progress, and non-portable inodes list opaquely with no capability.
- Name invalidation treated a benign `ENOENT` from an evicted dentry as a repair
  failure and revoked healthy mounts on hard links, open-after-unlink, and dcache
  pressure. Absence is the invalidated state.
- Visibility targets carried the exact XFS export-handle identity while the FUSE
  frontend parsed them as device and inode, so the first strict repair on real
  XFS revoked every mount. The kernel-cache coordination facts — inode, parent
  inode, and device — now travel explicitly.
- Reclaim mutations consumed replay-slot sequences without settling the
  publication ledger, deadlocking the next visible mutation's deferred source
  completion.
- Corruption and shutdown errnos (`EUCLEAN`, `ESHUTDOWN`, `ENOTRECOVERABLE`)
  fence the volume like `EIO` and carry the storage failure class.
- A completed hard link whose local bookkeeping failed was misreported as `EIO`;
  a creation grant was permanently consumed by a transient adoption failure; and
  the coherence-matrix harness now fails loudly on a non-shared namespace and
  names declared-away cases in its verdict.
- Publish and inventory the complete signed macOS FSKit identity tuple end to
  end: filesystem type `pfs`, generic-resource scheme `dev.portablefs.oss`, and
  the app group. FSKit URL routing, lifecycle, readiness, and exact-unmount
  operations remain isolated from products embedding the shared engine under a
  different identity.
- Preserve atomic in-place upgrades from the immediately preceding signed FSKit
  identity while staged releases remain current-identity-only.
- A Linux mount attempt that joined strict membership and then failed inside
  `fusermount3` retained a durable participant forever even though it had never
  installed a kernel mount. Every Linux frontend now assigns a random source to
  each attempt; after mount creation fails, the supervisor proves that exact
  source absent from `mountinfo` and cleanly detaches the authenticated session.
  That exact cleanup verdict now also completes the CLI's failed-startup
  transaction, removing its local mount intent and closing any automatic
  enrollment; ambiguous failures retain both recovery anchors.
