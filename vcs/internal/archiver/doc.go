// Package archiver is the per-volume ARCHIVE-phase process of the
// tiered-storage archive tier (docs/tiered-storage/restore-mode.md).
//
// It runs exactly once per ARCHIVE phase, as the volume's service identity,
// while the authority is quiesced and absent: it walks a read-only bind of the
// volume tree, builds the pack and manifest objects of
// docs/tiered-storage/pack-format.md through the shared vcs/archive format
// library, uploads them to the archive store as it builds, re-fetches and
// verifies every chunk digest and the manifest object byte-for-byte, and only
// then writes the pinned archive-sealed.json result the helper observes.
//
// Four rules run through the package:
//
//   - Fail closed. A tree containing an inode kind the authority cannot create,
//     a hardlink group with a link outside the volume, an extent map that is
//     not canonical, or a single chunk whose read-back digest disagrees with
//     the manifest fails the archive with no result record written at all. The
//     helper reports the unit failure; nothing partial is ever sealed.
//   - Never trust a path string. The walk is descriptor-relative from one open
//     root descriptor, refuses symlinked components, and never leaves the
//     volume's mount (openat2 RESOLVE_BENEATH|NO_MAGICLINKS|NO_XDEV on Linux).
//     Names are raw bytes and are never joined into a path handed to a syscall.
//   - Bound everything. The builder holds one chunk; the uploader holds one
//     multipart part; the read-back verifier holds a small number of coalesced
//     ranges. Memory does not grow with the size of the volume.
//   - Idempotent by attempt. The helper may restart a crashed unit for the same
//     attempt. A result record that already exists for this attempt is proved
//     to match the launch configuration and the run exits successfully without
//     re-uploading; a conditional-create conflict on the manifest is treated as
//     "already uploaded" only after the stored object is proved byte-identical.
//
// The syscall surface lives in sys_linux.go and sys_darwin.go behind one small
// interface, so the package compiles and its round-trip suite runs on the
// development platform while production behaviour is the Linux one. The command
// (cmd/portablefs-archiver) refuses to run anywhere but Linux.
package archiver
