// Package powerloss is the crash-consistency harness for the PortableFS v3
// authority. It turns the authority's two durability claims into evidence
// recorded at simulated power cuts, and asserts each claim exactly as the code
// makes it, no wider:
//
//	Linux mount: a write is durable across a power cut only once an fsync or
//	fdatasync through the mount has returned success, because that is the
//	call that reaches fdatasync or fsync on the authority's target
//	descriptor. write(2) returning promises nothing about a power cut.
//
//	FSKit: FSKit has no fsync callback, so every successful FSKit mutation
//	reply is durable on authority storage before it is sent or retained for
//	replay. Handle-backed mutations fsync the retained description;
//	handleless namespace and metadata mutations run syncfs on the retained
//	XFS-root description. Every acknowledged mutation must survive every
//	later cut.
//
// The device instruments stack dm-log-writes under the XFS the authority
// serves. Every bio the filesystem issues, and every FLUSH/FUA barrier, is
// recorded to a separate log device. Replaying that log onto a zeroed image up
// to entry N reconstructs, byte for byte, the platter state a power cut after
// the Nth bio would have left - including the reordering freedom the device is
// allowed. Dirty page cache is not replayed, because a power cut does not
// write it back. Workload drivers ask the root harness for a log mark after
// each durability claim (MarkChannel), so a replay can cut exactly there.
//
//   - TestFsyncedWritesSurvivePowerLoss drives a real Linux kernel FUSE mount
//     with an fsync-gated workload (Ledger, Expectations, Verify).
//   - TestFSKitAcknowledgedMutationsSurvivePowerLoss drives the real authority
//     FSKit handler directly, as portablefsd does, with no mount, daemon or
//     extension in the path (MutationLedger, MutationCutAt,
//     VerifyMutationCut).
//
// The process instrument injects only an authority SIGKILL. That removes the
// process but not the kernel's dirty page cache, so it is strictly weaker than
// a power cut and is labelled as such everywhere it reports. It covers the
// fenced restart and re-attach path, which the device instruments do not.
//
// What this package deliberately does NOT claim:
//
//   - That a Linux write accepted by write(2) but never fsynced survives. The
//     stale-data rule is the only thing asserted about it.
//   - Anything about the Mac side of FSKit: what the daemon, the extension or
//     the macOS kernel held but never delivered as a callback.
//   - That restore hydration's mtime restoration is crash-atomic. It is not,
//     and it is outside these workloads.
//   - Per-volume isolation of syncfs errors or latency. Every project on one
//     XFS cell shares one superblock writeback-error and latency domain.
//   - The underlying block device's own flush honesty. Loop files and
//     dm-log-writes measure what the filesystem asked the device to do, not
//     whether a physical disk lied about its write cache.
//   - Multi-node durability. It is one authority on one XFS.
//
// The parsing, replay, replay-point selection, ledger and verification logic
// in this package is portable and unit tested on any platform. Only the device
// orchestration is Linux-and-root.
package powerloss
