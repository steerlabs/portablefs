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

- Authority ALPN `portablefs-authority-v8`, exact major 8. Authority feature
  strings and negotiation are gone; the major and the frontend profile fix the
  grammar and semantics, and the schema holds only current declarations.
- Frontend profiles are `FRONTEND_PROFILE_LINUX`,
  `FRONTEND_PROFILE_FSKIT_EXCLUSIVE`, and `FRONTEND_PROFILE_CACHELESS_READER`.
- macOS 26 and 27 use one exclusive-writer profile: a mounted Mac is the
  volume's only writer, Linux mounts read, and a second Mac is refused. Peer
  repair, fragmented FSKit writes, publication retraction, the cache-policy
  names, and the separately built macOS 27 native lane are removed.
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
  attempt.
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
- `vcs/bench/lantrace` and `pfs-lan-trace`, a bounded, credential-free,
  correlated diagnostic trace for LAN workload attribution.
