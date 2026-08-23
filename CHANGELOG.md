# Changelog

All notable changes to PortableFS are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and immutable releases
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-release binaries, images, and auto-generated release notes are published on
the [GitHub Releases](https://github.com/steerlabs/portablefs/releases) page;
this file is the human-curated summary.

## [Unreleased]

### Fixed

- An uncached enumeration no longer restarts from the first entry, which made a
  single readdir pass return names the kernel had already been given. The
  uncached path introduced in the previous entry retired its buffered page at
  the next kernel callback and kept the resume cookie, but cleared the mark
  saying the stream was deliberately uncovered. `peek`'s lease guard then read a
  live cookie behind a zero lease stamp as leftovers from a dead lease and reset
  the stream to offset zero, so the next fetch re-read the directory from the
  beginning and appended a second copy of everything already delivered. Live
  staging saw stable, immutable package directories enumerate as `18 entries,
  not the 9 that were renamed into place`, 6 runs in 8 — the mount stayed up and
  served wrong data, which is strictly worse than the revocation it replaced.
  The uncovered mark is now a property of the stream rather than of one page and
  survives retirement; it is cleared only where a position is genuinely regained
  (a grant installs) or abandoned (an invalidation, or a seek to zero). Where
  that guard does have to drop a position the kernel has already read from, it
  now marks the stream invalidated so the next resume is answered with `ESTALE`
  rather than silently re-reading. `docs/portable-coherence.md` §5.4 states the
  invariant this is held to: one pass returns every stable entry exactly once,
  and the only permitted outcomes are served-exactly, `ESTALE`, or revocation.
- `deploy/opensteer/staging-qualification.sh` phase 9 can now actually run. An
  initial mount grant is single-use, so the remount could never reuse
  `PORTABLEFS_MOUNT_TOKEN` and always failed with errno 1 — meaning durability
  across unmount/remount had never once been scored. The phase now takes its own
  capability, from `--mount-token-command CMD` (preferred: a grant is short-lived
  and one minted before phase 1 can expire before phase 9) or a pre-minted
  `PORTABLEFS_REMOUNT_TOKEN`. With neither, the phase skips loudly and says the
  run did not qualify durability, instead of failing at the end of a good run.

### Changed

- Hosted automatic mount enrollment now uses a 30-minute sliding lease instead
  of an absolute enrollment lifetime. Fresh successful refreshes renew the
  lease, while exact replays, rate-limited requests, and failures leave it
  unchanged. Enrollment certificates carry only the Manager-facing identity
  and remain valid through the enrollment CA's remaining lifetime. The Manager
  wire and mount CLI no longer carry an enrollment-expiry timestamp. Clients
  advertise
  `hosted-automatic-mount-reauthorization-v2` for this contract.
- Scoped enrollment issuance now supersedes only the prior active enrollment
  for the same product issuer, renewal scope, and volume. One machine scope can
  therefore keep one active enrollment for each mounted volume; epoch advances
  still revoke every lower-epoch enrollment in that scope.
- Hosted cell declarations now carry immutable inclusive project-ID,
  service-UID, and listener-port ends. Placement admission stops before any
  lifetime-monotonic allocator crosses its declared range, including after
  prior volumes are deleted; pre-bound schema-v2 cells accept one constrained
  declaration that pins only those ends and the new exact digest.

- `.github/workflows/deploy-opensteer-staging.yml` takes the runner image as a
  required `workflow_dispatch` input instead of hardcoding a digest, and refuses
  anything not of the form `REGISTRY/PATH@sha256:<64 hex>`. The infra pin
  (`releases/staging/opensteer.json` in `opensteer-infra`) is the source of
  truth and this repository cannot read it at dispatch time, so the operator
  pastes it and the workflow validates it. The copy this workflow shipped with
  had already drifted from the pin.

### Fixed

- A Linux mount is no longer revoked when an enumeration reply carries no
  E(dir) grant. A grant on a read-side reply is a MAY, not a MUST
  (docs/portable-coherence.md §2.2), and the frontend independently declines to
  install a grant that a newer recall's grant floor, an unfinished local recall,
  or the family's cache budget has overtaken. All of those mean one thing --
  this reply is uncached -- but OPENDIR and READDIR treated them as an authority
  protocol violation and failed the mount closed. A dependency-tree install
  (per-package `rename(2)` publication into one directory) racing readers that
  enumerate that directory hits the window continuously: live staging
  qualification lost its mount in about seven seconds, three runs out of three,
  with the authority journal showing no fence and nothing to notice. The
  frontend now serves the ungranted page uncached and bounded to the kernel
  callback that fetched it, retiring the buffer at the next callback and
  resuming from the authority cookie so the verifier -- not a cache lease -- is
  what catches a mutation across the gap. A directory reply carrying no stable
  identity remains terminal: no coordinate can name it, so no recall could ever
  reach it. Covered by
  `TestDependencyTreeInstallRacingEnumeratingReadersKeepsBothMountsServing`,
  which is bounded, required, and fails on the unfixed frontend in under a
  second.

### Added

- `deploy/gcp/verify-hosted-release.sh` now asserts each released binary's Go
  VCS stamp: `vcs.revision` must equal the release's recorded `source-commit`
  and `vcs.modified` must be `false`, with an absent stamp treated as the
  failure rather than as not-applicable. That absence is exactly what a release
  built from a linked git worktree produces -- Go's `-buildvcs` support drops
  silently there -- and it shipped a provenance-stripped artifact that every
  other check in the script accepted.
- `.github/workflows/deploy-opensteer-staging.yml`: a `workflow_dispatch`
  staging deploy mirroring the production workflow against project
  `opensteer-staging`. Its required, reviewed schema-v1 inventory names the
  Manager and every cell instance and zone; the release discovers all volumes
  from the Manager rather than accepting a hand-maintained list. Its first step
  refuses, by name, an `opensteer-staging` GitHub environment whose WIF
  variables or E2B secret are not provisioned.

## [0.3.0] - 2026-08-19

This release replaces the private-kernel architecture with one that runs on a
stock Linux kernel. Every guarantee PortableFS makes is now made against
upstream FUSE 7.31+ and macOS FSKit, with no patched kernel, no private ABI,
and no capability a distribution does not already ship. Where that costs a
guarantee, the cost is written down rather than papered over.

### Added

- Protocol 6: one lease contract (N/A/D/E) over stock FUSE, replacing the
  patched-kernel publication scopes. A mount declares exactly one frontend
  profile at Attach — `LINUX_LEASES` for the Linux FUSE frontend or
  `FSKIT_SYNC_REPAIR` for the macOS synchronous-repair frontend — and the
  authority refuses any request that does not belong to the declared profile.
  There is no third, silently weaker profile.
- `portablefs mount-check --probe-mount`. It installs one real throwaway FUSE
  mount on a private temporary directory, completes the kernel INIT handshake
  with the client's own mount options, verifies the capabilities the coherence
  contract requires, and unmounts. It is the only check that a client which can
  never complete FUSE INIT cannot pass; the device node existing, the device
  opening, `CAP_SYS_ADMIN` being held, and an installed helper are all equally
  true of such a client.
- `deploy/opensteer/staging-qualification.sh`: the real-workload qualification
  corpus, run against a live mount on a staging cell. Serial and `tee -a`
  appends, a git repository created and `fsck`-verified on the mount, two
  concurrent `O_APPEND` writers on one file, several readers against a file
  another process rewrites, and a durability check across unmount and remount.
  The hot-file phase runs the rewrite twice, because only one shape of it lets
  a reader demand an all-or-nothing view: under atomic replacement a mixed read
  is wrong data and fails, while under in-place rewrite — which is not atomic
  on any POSIX filesystem — a torn read is counted rather than failed and only
  a malformed line or an invented generation fails. A stale-but-consistent
  observation passes in both: that is the documented §7.3b residual, and the
  phase reports how stale readers got instead of failing on it. The script also
  names what to watch on the authority while it runs: RecallBudget-exhaustion
  fences and uncertain-outcome revocations.
- A full mode for the local gate. `scripts/verify-local.sh --full` (or
  `VERIFY_LOCAL_FULL=1`) runs both privileged real-mount Docker suites after
  everything else.
- Writable `O_APPEND` on the stock-FUSE Linux profile, and it is exact across
  mounts. The frontend forwards the writing description's append intent and the
  authority places the payload at the object's true EOF inside the per-inode
  writer stripe, reporting the offset it assigned. Concurrent cross-mount append
  atomicity is now a demonstrated matrix case rather than a declared failure.
  Stock Linux forwards neither `RWF_APPEND` nor `RWF_NOAPPEND`, and those two
  per-call cases are disclosed deviations in `docs/portable-coherence.md` §4.3.
- The Linux write path now carries the description's `O_SYNC`/`O_DSYNC` intent to
  the authority, which the FSKit path has always honored.
- Attribute caching under the A lease, which is what the lease architecture was
  for. A path component resolved inside the daemon now publishes the attribute
  validity its held A-R lease covers instead of declaring the answer
  uncacheable, a `GETATTR` the kernel still sends is answered from the daemon's
  leased attribute record, and a changed mutation reply installs its own exact
  post-state attributes under an A-R successor grant so the mutating syscall's
  follow-up stat of the target and its parent costs no second round trip. A
  repeated 64-name path walk fell from 128 authority `GETATTR`s to zero, and one
  steady-state `git status` over 200 tracked files from 404 authority requests to
  22. Nothing is served past its lease: a coordinate under recall still misses to
  the authority.

### Fixed

- A blocking `read(2)` racing a write on another mount could stall forever. The
  window opened the moment the writing mount's recall closed the file's data
  coordinate and stayed open until the whole transaction discharged: a reader on
  any other mount passed its own local admission, reached the authority, and was
  refused with `EAGAIN` -- an errno `read(2)` may not return on a blocking
  description. This is the ordinary shape of a concurrent multi-mount workspace,
  so it was reachable in normal use, not only under contrived load. A data read
  now waits instead of being refused, and it waits for exactly the interval that
  is unsafe to observe: from the recall's reservation until the mutation has
  applied. It may not wait one step further, because the callback is holding the
  kernel folio that the same transaction's whole-file purge will need, and that
  purge runs strictly after apply -- so the wait and the purge can never be
  waiting on each other. Past apply the read is answered with the applied bytes,
  and it carries cache authority unless the reader is the very mount still
  discharging that recall. The two local refusals of the same class are gone
  with it: a buffered read is no longer refused because this mount is repairing
  the coordinate, and a read the recall caught in flight now delivers its bytes
  rather than being turned into a retry.
- Opening a file for reading could deadlock a peer mount against the write it
  raced. The frontend registers an open-for-read's page-cache publication and a
  recall's whole-file purge waits for that publication's physical reply, but the
  open itself was admitted on the metadata lane, which parks for the entire
  barrier -- so the purge waited on a reply that was waiting on the purge's own
  transaction, and the peer mount was revoked at its repair budget. Opening a
  file for reading is now admitted on the data lane, which releases at apply,
  and the publication is registered when the authority call returns rather than
  across it: a READ has to register first because its reply carries bytes the
  purge must be ordered against, and an open carries none. Opening a directory
  still takes the full barrier, and with this no recall waits on a metadata
  reply.
- A whole-file purge could run ahead of the reads it was supposed to order.
  It waited on the reply publications a coordinate still had outstanding, but
  reply preparation removes a read's data entry before the reply is physically
  written -- so a read that had been prepared and not yet written looked drained,
  and filled its folio after the purge. The wait now follows the reads the
  coordinate admitted rather than the entries preparation has already settled.
- A recall could decide there was nothing to withdraw while the kernel was still
  serving the file. Both the attribute and the data withdrawal were conditioned
  on this daemon's own cache bookkeeping, but the kernel caches an attribute from
  any reply that carried a lifetime and caches read data for any `KEEP_CACHE`
  description, neither of which requires the daemon to have retained a copy.
  Withdrawal now follows the inode. Relatedly, a read that returned end-of-file
  was treated as publishing nothing; stock zero-fills the rest of the requested
  range and marks those folios up to date, so an end-of-file read past a peer's
  truncation left real pages behind that no later withdrawal knew about.
- A buffered read registered its data publication before acquiring the mount's
  bounded bulk lane slot, while the purge that waits for those publications runs
  from a source mutation already holding one. A saturated lane could therefore
  make a purge wait on reads waiting for the lane its own mutation occupied, with
  nothing but the repair budget to break it -- and that budget revokes the mount.
  The slot is now taken for the whole callback, before the publication exists.
- A failed coherence barrier minted successor cache authority anyway. Grants were
  issued before the barrier's outcome was known, so a failure delivered them to
  the frontend and left the matching records in the authority's table with
  nothing on the wire able to discharge them. Nothing is minted on a failed
  barrier now. The same error path also dropped the source's discharge receipt
  obligation, which does not cancel the obligation -- it only guarantees the
  session is fenced once the recall budget elapses -- so the receipt now travels
  with every outcome.
- A buffered read on a mount doing its own I/O could stall forever. The frontend
  refused such a read with `EAGAIN` -- an errno `read(2)` may not return on a
  blocking description, which stock Linux hands straight to the caller and which
  permanently parks any runtime that then polls the descriptor. It was refused
  for two reasons that were not about this read at all: an unrelated file's
  in-flight `O_CREAT|O_TRUNC` on the same mount closed data publication globally,
  and a read reply that carried no successor lease was dropped even while the
  lease its handle was opened under was still live. Reads are no longer refused
  for either reason; instead every whole-file invalidation waits for the reads
  already admitted for that inode before it purges, which is the ordering the
  refusal was standing in for.

### Changed

- Two coherence residuals are now disclosed rather than implied. A mount in a
  recall audience can, between the mutation's apply and its own purge, answer a
  page-cache miss with post-apply bytes while other folios of the same inode
  still hold pre-apply ones, so a single `read(2)` spanning that boundary can
  return a mix equal to no serial state; it is bounded by one COMPLETE round trip
  plus one invalidation. And `docs/portable-coherence.md` §7.3b now states its
  real scope: it is a normal-operation residual, not only a post-terminalization
  one, serving reads through a recall raises its likelihood without changing its
  mechanism, and it has a liveness face -- stock's whole-file invalidation is an
  unbounded synchronous walk that a workload never letting an inode fall idle can
  starve, stalling the mutating mount for its whole recall budget.
- Name the three stock-kernel boundaries on the Linux range and link surfaces
  instead of leaving them as unexplained failures, each pinned by test:
  `fallocate` `COLLAPSE_RANGE`/`INSERT_RANGE`/`UNSHARE_RANGE` are refused by
  `fuse_file_fallocate` before any request exists, a `copy_file_range` spanning a
  machine-local route and the shared volume is refused as `EXDEV` and then
  completed by the kernel's own generic read/write fallback, and the first link
  of an `O_TMPFILE` uses the capability-free `/proc/self/fd` idiom because
  `linkat(AT_EMPTY_PATH)` needs `CAP_DAC_READ_SEARCH` the data plane does not
  have. `docs/portable-coherence.md` §4.4 records all three.
- Ship the named macOS 26 FSKit best-effort cache tier over protocol 6. One
  active Mac owns an authority-enforced compatibility writer lease; Linux peers
  remain readable but their visible mutations return `EBUSY` before storage,
  a second Mac writer is refused at activation, and clean unmount transfers
  write ownership. The product reports the measured transient-`ESTALE`
  high-rename boundary instead of hiding it behind retries or a fallback.

### Removed

- The retired FSKit routes barrier, in full. A routing revision was once
  delivered to mounted frontends as a two-phase visibility phase, and a
  frontend that could not adopt it answered `blocked`. Nothing drove either
  half: route changes commit only at clean mount absence, so there is no mount
  to deliver a phase to, and the authority never read the `blocked` bit off the
  wire. Gone with it: `VisibilityCoordinator.ExecuteRoutes`/`ExecuteRoutesChecked`
  and their barrier, the `Routes` member of every visibility event and the
  fairness, yield, and dispatch branches that tested it, `ReportBlocked`,
  `ErrVisibilityBlocked`, and the `routes_blocked` fence reason. The
  `AckVisibilityRequest.blocked` and `VisibilityEvent.routes` wire fields are
  reserved rather than reused, on both the authority protocol and `pfslocal`.
  Every phase a frontend is now delivered is one it repairs in place and
  acknowledges.
- The patched Linux 6.12.100 series and its private ABI, in full: the
  `kernel/linux-6.12.100-portablefs-append` patch series, its qualification
  receipts and test suite, the one-shot write path built on it, the strict
  write transaction it required, and the `LOCKLESS_EXPIRATION` and
  `PARENT_EXCLUSIVE` namespace-repair models. Nothing in the product depends on
  a kernel a distribution does not ship. The patch series is only in git
  history; the retired identifiers stay reserved in the wire schema and are
  refused everywhere else by `scripts/verify-local.sh`.
- The `mutation_order` ordering shim in the volume server and the retired
  protocol-5 FSKit qualification registry fixture. The runtime admission path
  is now the only admission path in production and in tests.

### Deploy

- The bounded read-only files gateway (`cmd/portablefs-files`, `readonlyfs/`)
  is protocol 6. It is not a mount: it holds no kernel namespace, no page
  cache, and no lease state, so it declares the synchronous-repair profile —
  the one protocol-6 contract that grants no cache leases — and discharges
  every repair phase immediately. Declaring the Linux lease profile would claim
  recall participation it cannot honor and would stall writers behind a reader
  that never caches.
- The candidate E2B template smoke now proves the shipped client can complete a
  kernel FUSE INIT handshake, and says plainly what it does and does not prove.
  It runs with no manager and no authority, so it proves nothing about the
  authority, the protocol, coherence, or any workload; full qualification is
  the staging corpus above. `docs/opensteer-production-deployment.md` carries
  the same statement.
- `scripts/build-hosted-linux-release.sh` builds every binary the systemd units
  and deploy scripts reference, including `bin/portablefs`, and its output
  membership matches `deploy/gcp/verify-hosted-release.sh` exactly.

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
