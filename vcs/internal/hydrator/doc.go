// Package hydrator is the per-volume RESTORE-phase process of the
// tiered-storage archive tier (docs/tiered-storage/restore-mode.md).
//
// It has two modes, sequenced by the helper, and they share only the sealed
// manifest:
//
//   - restore-namespace runs before the authority starts, with a read-write
//     bind of the volume data directory. It downloads and verifies the
//     manifest, materializes the complete namespace — directories, files at
//     full logical size and fully sparse, symlinks, hardlink groups, extended
//     attributes, exact modes including set-ID and sticky, and exact
//     nanosecond mtimes — and writes the manifest-entry to inode-identity
//     bindings the authority loads at restore-mode start, plus the
//     namespace-ready marker the helper observes.
//   - serve runs beside the authority with no data-directory access at all. It
//     listens on one AF_UNIX socket in the volume's state directory and answers
//     the pinned protocol: the drain order in pack order, and per-chunk fetches
//     that are ranged-GET, decompressed, and digest-verified before a byte is
//     returned. The authority owns every write to XFS; the hydrator is a
//     stateless fetch-verify-decode oracle over the sealed manifest.
//
// The rules the package is built on:
//
//   - Verified or refused. No chunk leaves the process without its manifest
//     SHA-256 having matched; a mismatch is ERR{corrupt}, which the authority
//     surfaces as RESTORE_CORRUPT rather than serving unverified bytes. A store
//     failure is ERR{blocked}, which is volume-wide and auto-clearing, and is
//     never allowed to look like corruption.
//   - Never trust a name. Entry names come from the manifest, whose decoder has
//     already proved them to be single components; the restorer validates them
//     again before any syscall and creates every node descriptor-relative from
//     the volume root descriptor into a tree it proved empty.
//   - Durability where it is defined. Files are not fsynced one by one — a
//     restore is a provisioning-time write of a tree that is entirely
//     reproducible from the sealed archive. Directories are fsynced bottom-up,
//     the volume is syncfs'd once, and only then are the bindings and the ready
//     marker written atomically and fsynced. The marker is the durability
//     boundary.
//   - Bounded and fail-closed. Frame cap, connection cap, manifest size,
//     drain-order size, and the decoded-frame cache all have explicit limits.
//
// The syscall surface lives in sys_linux.go and sys_darwin.go; the command
// (cmd/portablefs-hydrator) refuses to run anywhere but Linux.
package hydrator
