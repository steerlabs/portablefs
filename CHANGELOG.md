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

- Publish and inventory the signed macOS FSKit type `pfs` end to end, keeping
  PortableFS lifecycle, readiness, and exact-unmount operations isolated from
  other products that embed the filesystem engine under a different
  `FSShortName`.
