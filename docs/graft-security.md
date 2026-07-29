# Local-graft security verification

Machine-local graft paths are tenant-controlled input. Their host backing
directory is therefore a capability boundary: runtime code must never join a
graft path onto a host path and pass the result to an `os` or `syscall` path
operation. The implementation and threat model are described in
[architecture.md](./architecture.md#machine-local-dirs-grafts).

## Required verification

Run the capability and graft suites on the development host, including the
concurrent destination-parent symlink-swap attack under the race detector:

```bash
cd vcs
go test -race ./internal/confinedfs ./internal/localdirs -count=1
go test -race ./internal/portablefsd \
  -run '^(TestRefreshKernelFile|TestRefreshSample)' -count=3
go test ./internal/portablefsd -count=1
go test ./cmd/portablefs/internal/cli -count=1
```

On macOS, the targeted `portablefsd` suite also attacks the live-vnode
coherence refresh boundary. The authority controls the mounted path being
refreshed, so the daemon resolves it with one descriptor-relative
`openat(2)` using `O_RESOLVE_BENEATH|O_NOFOLLOW_ANY`, verifies the expected
FSItem inode and regular-file type with `fstat(2)`, and performs
`ftruncate(2)` plus `mmap(2)`/`msync(2)` on that same descriptor. The tests
cover absolute, relative, and intermediate symlinks, an ordinary-file
rename-over, and concurrent symlink and regular-file swaps while checking
outside sentinel files byte-for-byte.

Run the same confinement tests on a real Linux kernel using the repository's
pinned Go toolchain. This exercises `openat2(2)` rather than merely
cross-compiling it:

```bash
cd /path/to/portablefs
docker run --rm \
  -v "$PWD:/src:ro" \
  -w /src/vcs \
  golang:1.26-bookworm \
  go test ./internal/confinedfs ./internal/localdirs -count=1
```

The Linux suite includes both a live capability probe and an injected `ENOSYS`
case proving that unsupported or blocked `openat2` fails closed. CI obtains its
Go version from `vcs/go.mod`; release images use the same Go 1.26 toolchain
family.

Run the FSKit protocol and adapter suite on macOS:

```bash
cd swift/PortableFSKit
swift test
```

## Source audit

Before release, search the graft implementations for newly introduced host-path
operations. Expected host paths are limited to creation/opening of the trusted
backing root in `internal/confinedfs`; tenant-relative operations must be
methods on the confined capability:

```bash
rg -n 'localBackingPath|BackingPath' vcs/internal vcs/cmd
rg -n 'os\.(Open|OpenFile|Lstat|Stat|Mkdir|MkdirAll|Remove|Rename|Link|Symlink|Readlink|Chmod|Chtimes|Truncate)' \
  vcs/internal/localdirs vcs/internal/portablefsd
rg -n 'filepath\.Join\(.*mount|unix\.Truncate\(' \
  vcs/internal/portablefsd --glob '!**/*_test.go'
```

Review any match rather than blindly allowlisting it. A test may intentionally
use raw host paths to construct an attack fixture; production graft operations
may not. The final search must have no matches: mounted paths must never be
joined into a host pathname or passed to path-based `truncate(2)`.

## External certification gates

Unit tests, race tests, native Linux syscall tests, and cross-compilation do not
replace these release-environment checks:

- A Linux host with `/dev/fuse` and `fusermount3` must run the real kernel-mount
  integration/torture suite. Docker Desktop does not expose `/dev/fuse` to its
  Linux VM by default, so it cannot certify this gate.
- A production-signed and installed PortableFS FSKit extension must run the live
  macOS kernel-mount matrix. The Swift mock/live-adapter suite cannot certify
  extension activation, entitlements, signing, or kernel handoff.

Treat both as release blockers, not optional fallbacks.
