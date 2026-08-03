# Changelog

All notable changes to PortableFS are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches a tagged release.

Per-release binaries, images, and auto-generated release notes are published on
the [GitHub Releases](https://github.com/steerlabs/portablefs/releases) page;
this file is the human-curated summary.

## [Unreleased]

Initial open-source release preparation. No tagged release yet.

### Added

- `portablefs recovery list|resolve <mountPath>` — inspect a mount's local
  write-back recovery jobs and resolve the terminally `conflict`/`corrupt` ones
  that block `portablefs umount --force` and every attach. `list` takes no lock
  and changes nothing; `resolve` never deletes (the job's bytes are moved to
  `<store>/unreplayable/` and kept), reports exactly what was lost, and refuses
  any job it cannot prove terminal, any store a live engine owns, and any stream
  whose identity does not match. Before this the product instructed operators to
  perform an "explicit recovery resolution" that no command implemented; the only
  escape was moving the state directory by hand.

### Fixed

- A capacity refusal from the authority (`ENOSPC`/`EDQUOT` — the bounded dirty
  block pool or the journal backlog quota) no longer fences the whole mount. It
  used to park the stream terminally, which latched the engine's fail-closed
  verdict, and that verdict gates the exact-handle read/getattr/getxattr paths
  and `Truncate` — so a full store answered EIO to `ls`, `stat`, `read`, `mkdir`
  and the documented truncate remedy until remount. Writes now refuse with a
  definite `ENOSPC` while reads, metadata and releasing truncates keep working,
  exactly as documented, and the refusal clears by itself when the authority
  releases. Genuine fail-closed conditions (fence/ESTALE, typed corruption,
  out-of-subtree records) still fence.
- Every refusal in the umount / `--force` / `--discard-record` graph now names a
  command that exists and can make progress. The forced-unmount progress verdict
  no longer prescribes another `--force`, `--discard-record`'s daemon-attach
  blocker names the resolution that unblocks the force it points at, and both
  force-park call sites name `portablefs recovery resolve` when a terminal
  recovery job is what refused.
- The contained-stream verdict no longer publishes its quarantine path before
  the bytes are at it: for the whole window between the verdict and the rename —
  including an authority round trip — the only durable statement about where the
  last surviving copy lived named a path that did not exist.
- Publish and inventory the complete signed macOS FSKit identity tuple end to
  end: filesystem type `pfs`, generic-resource scheme
  `dev.portablefs.oss`, and the OSS app group. FSKit URL routing, lifecycle,
  readiness, and exact-unmount operations now remain isolated from products
  embedding the shared engine under a different identity.
- Linearize local delegation installation against concurrent authority-lane
  mutations with cancellable subtree/inode claims, including hardlink aliases
  and descendant grants, closing the same-mount acquire-to-RPC recall race
  without mount-wide head-of-line blocking. Frontend disconnects now publish
  an exposed/unacknowledged operation failure before joining blocked handlers,
  so ownership handoff cannot deadlock during FSKit timeout cleanup.
- Preserve atomic in-place upgrades from the immediately preceding signed OSS
  FSKit identity while staged releases remain current-identity-only, and keep
  the previous public Swift adapter call shapes source-compatible.
