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

### Fixed

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
