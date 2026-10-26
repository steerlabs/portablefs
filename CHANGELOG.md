# Changelog

All notable changes to PortableFS are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and immutable releases
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-release binaries, images, and auto-generated release notes are published on
the [GitHub Releases](https://github.com/steerlabs/portablefs/releases) page;
this file is the human-curated summary. Pre-launch history, including every
release before authority protocol 8, is in git history rather than here.

## [Unreleased]

The authority protocol 8 launch baseline. It replaces every earlier protocol;
there is no compatibility path, migration, or historical decoder, and
deployments are provisioned fresh. The contract, its two deployment-wide limits,
and its qualification status are in [COMPATIBILITY.md](./COMPATIBILITY.md). It
is not yet qualified.

### Changed

- Managed Linux workspaces use a conservative synchronous RTC permission
  deadline and one-second renewal cadence. Ordinary native mounts retain
  BOOTTIME admission and their three-second renewal cadence.

If host sleep overtakes cold-before-pause, the workspace retains the native protocol-8 Linux suspend limit: under the qualified RTC source bound, permission sampled after resume cannot authorize expired cache or write admission, but an operation frozen after its final permission sample, including inside an RTC read before it returns, may complete with stale state after resume, and resident kernel pages, mappings, names and attributes may remain observable until withdrawal or cache timeout; host sleep is not an atomic cache-revocation boundary.

- Authority ALPN `portablefs-authority-v8`, exact major 8. Authority feature
  strings and negotiation are gone; the major and the frontend profile fix the
  grammar and semantics, and the schema holds only current declarations.
- Frontend profiles are `FRONTEND_PROFILE_LINUX`,
  `FRONTEND_PROFILE_FSKIT_EXCLUSIVE`, and `FRONTEND_PROFILE_CACHELESS_READER`.
- macOS 26 and 27 use one exclusive-writer profile: a mounted Mac is the
  volume's only writer, Linux mounts read, and a second Mac is refused. Peer
  repair, fragmented FSKit writes, publication retraction, the cache-policy
  names, and the separately built macOS 27 native lane are removed.
- macOS 27 grants the `writeThrough` kernel cache to writers instead of
  `writeBack`, so `write(2)` returns after its callback is durable and reports
  its own error. A native Phase III quota observation on macOS 27.0.1 accepted
  every write into the kernel cache, then surfaced quota exhaustion as a
  deferred EIO at fsync and close instead of EDQUOT. macOS 26 is unchanged.
- Every successful FSKit mutation reply is durable: handle-backed mutations
  fsync their retained description and handleless mutations use syncfs on the
  volume root. A shared XFS cell is one durability-error and latency domain.
- Object versions are conservative and bounded: `0 < v <= s`, strictly greater
  on each logical change, and allowed to advance without one.
- MKDIR returns a dedicated `MkdirReply` with a kernel-evaluated search
  permission bit, which lets the daemon answer absent names in directories its
  mount created.
- Linux ordered delegated flush (window 4) and `CLOSE_BATCH` are mandatory, and
  Linux connections need `max_in_flight >= 9`.
- `pfslocal` is exactly 2.0. Daemon operational control is exactly 2 under
  `/v2/`; lifecycle v1 (`/lifecycle/v1/identity`, `inventory`, `stop-if-idle`)
  quiesces an authenticated outgoing release across versions.
- The daemon is the only authority renewal owner and attests `frontend-ready`
  from a usable initial proof, an authenticated bound frontend, and the kernel
  mount identity, with no mounted-root I/O. Normal unmount makes one unforced
  attempt, and only an explicit user `--force` ever forces one; the mount
  supervisor waits on signals and kernel mount-table notifications instead of
  probing the daemon.
- A Mac release is identified by its daemon CodeDirectory hash, executable
  SHA-256 and version. The CLI and app authenticate a daemon socket from its
  kernel audit token (canonical path, kernel CodeDirectory hash, valid
  hardened-runtime code) and take protocol numbers from the authenticated live
  daemon. With no daemon running, only the absence of `attaches.json` proves
  an empty registry for an upgrade.
- Mount membership is `mount.membership` (`PFS-MEMBERSHIP-1`) through one codec
  for the authority and the cell host. The signed cell plan is version 3; the
  daemon registry and Manager snapshot are schema 3.
- Authority flags: `--mount-membership-file` and `--mount-absence-clock-skew`
  replace the visibility-named flags. The write-staging directory, the six
  write-admission settings, the unused cache-lease settings, and the repair
  bounds are removed. Linux mount flags `--name-cache-capacity` and
  `--withdrawal-timeout` replace `--cached-name-capacity` and
  `--repair-budget`; `--coherence` is removed.
- The authority requires Linux 5.17 final or newer.

### Added

- `scripts/check-current-architecture.py`, a positive structural check of the
  current protocol, profile, schema, and wiring shape, replacing the gate's
  blacklist of retired names.
- Power-cut scenarios for the FSKit authority handler in the power-loss
  harness.
