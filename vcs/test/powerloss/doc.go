// Package powerloss is the crash-consistency harness for the PortableFS v3
// authority. It exists to replace one assumption in
// docs/direct-store-consensus-evaluation.md - "Successful fsync and directory
// fsync are assumptions until power-cut testing confirms them" - with evidence.
//
// The product contract under test is narrow and is asserted exactly as
// written, no wider:
//
//	A write acknowledged by the authority is present in the served XFS page
//	cache. It is durable across a power cut only once an fsync or fdatasync
//	through the mount has returned success, because that is the only call
//	that reaches unix.Fdatasync on the target descriptor
//	(xfsstore.Volume.Fsync, reached from authorityrpc's Request_Fsync).
//
// Two instruments live here, and they prove different things.
//
// The device instrument stacks dm-log-writes under the XFS the authority
// serves. Every bio the filesystem issues, and every FLUSH/FUA barrier, is
// recorded to a separate log device. Replaying that log onto a zeroed image up
// to entry N reconstructs, byte for byte, the platter state a power cut after
// the Nth bio would have left - including the reordering freedom the device is
// allowed. This is a real power-cut simulation: dirty page cache is not
// replayed, because a power cut does not write it back.
//
// The process instrument only SIGKILLs the authority. That removes the process
// but not the kernel's dirty page cache, so it is strictly weaker than a power
// cut and is labelled as such everywhere it reports. It covers the restart and
// re-attach path, which the device instrument does not exercise.
//
// What this package deliberately does NOT claim:
//
//   - It does not assert that an acknowledged but un-fsynced write survives.
//     The authority acks a write transaction once the bytes are applied to the
//     target inode (sendfile from a memfd stage into XFS); nothing has been
//     fsynced at that point, and the harness must not manufacture a stronger
//     promise than the code makes. See Expectations for the exact rule.
//   - It does not test the underlying block device's own flush honesty. Loop
//     files and dm-log-writes measure what the filesystem asked the device to
//     do, not whether a physical disk lied about its write cache.
//   - It does not cover multi-node or consensus durability. It is one
//     authority on one XFS.
//
// The parsing, replay, replay-point selection and verification logic in this
// package is pure and portable, and is unit tested on any platform. Only the
// device orchestration is Linux-and-root.
package powerloss
