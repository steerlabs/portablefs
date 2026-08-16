# macOS FSKit coherence support boundary

Status: **macOS 26 is a supported best-effort FSKit tier; Linux remains the
exact shared-filesystem tier**

PortableFS now names these guarantees instead of pretending both operating
systems expose the same cache controls:

- Linux 6.12.100 with the strict PortableFS FUSE profile provides the exact
  protocol-5 publication and invalidation contract.
- macOS 26 uses `macos26-synchronous-vfs-repair-v2`. It provides ordinary
  mounted filesystem behavior, authenticated protocol-5 access, synchronous
  repair attempts, and fail-closed error handling. It does not claim an exact
  multi-writer cache cut that FSKit 26 cannot express.
- The macOS 27 handler remains a separate test target until its complete
  callback and invalidation behavior is qualified on the deployed SDK and OS.

This is not a hidden compatibility mode. The CLI, daemon, and extension select
one named policy, report it through diagnostics, and refuse any unknown policy.
There is no TTL downgrade, local-filesystem substitution, or protocol fallback.

## What works on macOS 26

The shipping FSKit composition is `PortableFSFileSystem.macOS26BestEffort()`.
It uses the same protocol-5 authority, replay identities, source-publication
operations, transaction staging, TLS identity checks, and terminal fencing as
the Linux client.

The following behavior has been exercised against the hosted protocol-5 stack,
including runs with a simultaneously attached Linux reader:

- create, open, read, write, positioned write, `fsync`, close, unlink, rename,
  mkdir, rmdir, hard link, symbolic link, and truncate;
- immediate Mac-to-Linux visibility and Linux-to-Mac visibility for newly
  created files;
- multi-megabyte and 64 MiB files with SHA-256 verification;
- exact refusal of unsupported writable xattrs;
- authority loss, repair refusal, and terminal-session handling that stop the
  Mac mount instead of continuing after an unproven repair.

The best-effort label has one measured namespace edge. During 100 back-to-back
Mac `fsync`+rename replacements, a Linux peer completed 2,996 of 3,000
enumerate-and-read observations and received four transient `ESTALE` results
(0.13%). It observed zero torn or mismatched generations, both mounts remained
healthy, and 1,000 subsequent observations passed. Ordinary workloads did not
produce this error. PortableFS reports the stale handle rather than concealing
it with a retry or fallback; applications that require a zero-transient-error
multi-writer namespace must use the exact Linux tier.

macOS 26 owns the volume's compatibility writer lease while it is mounted.
Linux peers may remain mounted and read Mac changes, but their visible
mutations return `EBUSY` before prepare or XFS apply. A clean Mac unmount
releases the lease; Linux can then write, and a later Mac mount starts from the
new authority state. Only one macOS 26 compatibility writer can attach at a
time; a second is refused with `EBUSY` before durable membership or runtime
activation. This explicit handoff is the intended macOS 26 operating envelope.

## The macOS 26 limit

FSKit 26 has no documented module-initiated namespace or inode-attribute cache
invalidation API. It also lacks source-result attributes for several mutation
callbacks. PortableFS 26 therefore performs authenticated synchronous repair
through its own FSKit callback lane. That mechanism can refresh ordinary
cached state, but it cannot create the exact peer cache transaction available
in the patched Linux VFS.

Qualification before the writer lease was added showed why this boundary is
needed. A Linux truncate of a file already cached by the Mac reached FSKit's
synthetic callback lane; the framework returned an error and PortableFS fenced
the Mac rather than accepting unproven state. The authority now refuses that
second writer with `EBUSY` before mutation dispatch. This keeps both mounts
healthy and makes the unsupported case predictable instead of workload-
dependent.

Two related facilities are not available through the FSKit 26 callback API:

- cross-machine advisory locks (`fcntl`/`flock`); and
- an authority-visible atomic append intent for Mac write callbacks.

Single-writer append works because the Mac kernel supplies an offset. Multiple
clients must not use the same file as a concurrent append log through a macOS
26 mount. Workloads that need exact simultaneous mutation, distributed locks,
or atomic cross-client append must use strict Linux clients with no macOS 26
writer lease active.

## Ordering retained by the best-effort tier

Even where the platform guarantee is weaker, PortableFS does not weaken its own
protocol bookkeeping:

- every visible callback owns one source-publication operation keyed by stable
  identities and namespace coordinates;
- authority responses remain retained until the physical FSKit reply,
  `PublicationAck`, duplicate-handler retirement, and resource disposition
  boundaries are complete;
- write BEGIN, DATA, COMMIT, and ABORT responses belong to the same logical
  publication lifetime;
- a terminal authority response cannot be acknowledged before the local reply
  boundary it represents;
- a definite pre-apply rejection publishes no mutation, while an assigned or
  post-apply uncertain result is terminal;
- repair refusal, malformed replies, lost transport, or missing completion
  fences the session instead of retrying through a different path.

These rules keep the daemon and authority state machine exact. The best-effort
label covers only the missing FSKit kernel cache primitive.

## Live performance snapshot

The current hosted test used an Apple M5 Max Mac, a VZ Linux 6.12.100 guest,
TLS, XFS authority storage, and an attached strict Linux peer. Five 64 MiB runs
produced:

| path | median |
| --- | ---: |
| macOS FSKit durable write (`write` + `fsync`) | 128.2 MiB/s |
| macOS FSKit `F_NOCACHE` read with SHA verification | 71.1 MiB/s |
| Linux strict durable write with Mac peer attached (pre-lease diagnostic) | 100.8 MiB/s |
| Linux strict durable write after clean Mac handoff | 120.9 MiB/s |
| Linux strict read after clean Mac handoff | 135.3 MiB/s |
| direct XFS durable write in the guest | 3033.7 MiB/s |

The matched-stack Mac durable-write runs were 29.7–144.1 MiB/s; four of five
were 117.8–144.1 MiB/s. The low run is retained rather than discarded. Linux
post-handoff write runs were 103.3–127.1 MiB/s and reads were 112.3–161.6
MiB/s, with every digest matching. Small-operation Mac medians included create 15.4 ms, `fsync` 3.6 ms, cached
stat 0.001 ms, negative lookup 1.0 ms, open/read/close 2.3 ms, rename 16.7 ms,
and unlink 16.1 ms. The ordinary Mac `write` return rate is page-cache
acceptance and is not reported as durable throughput.

Historical Archil numbers used a different machine, transport, cache policy,
and completion boundary. They remain useful context, not an exact ranking.

## Future exact macOS tier

A future FSKit release can be promoted to exact only after all of these are
available and pass a mounted two-peer matrix:

1. every mutation callback can publish the complete authoritative post-state
   for all affected items and parents;
2. the module can synchronously invalidate exact names, inode attributes, and
   retained data on a peer;
3. invalidation has a completion point that can remain inside PREPARE/COMPLETE;
4. failure is observable and terminal; and
5. source-first, peer-first, cancellation, disconnect, rename-over,
   open-unlinked, lock, append, and cached-data races pass without relying on a
   later cache miss.

Until then, macOS 26 remains useful and supported for its stated best-effort
envelope, while Linux is the exact shared-mutation client.
