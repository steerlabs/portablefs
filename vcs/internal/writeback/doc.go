// Package writeback implements the coherence-v2 client buffer. It has no FUSE,
// protocol, cgo, or platform dependency. One Buffer belongs to one attached
// mount in one Authority epoch; it is not a persistent journal.
//
// # Admission and ownership
//
// Write, Truncate, and SetAttr linearize under the admission mutex. Write copies
// the caller's bytes before publishing its accepted sequence and returning.
// Concurrent calls on an identity follow that order; callers that require a
// particular order must sequence their calls. Copying inside the fence means
// BeginRetire acquires the lock only after every in-flight admission has either
// published or left without accepting. No network call holds this mutex.
//
// Defaults are 64 MiB of retained write payload and 10,000 accepted operations.
// Accepted, applied, and visible records all count until durability. Replaced
// or truncated payload still counts: erasing an overlay is not a durability
// acknowledgment. At a cap, admission waits with context cancellation and
// schedules a flush of the accepted cut. Oversized single writes that could
// never fit the configured byte budget return ErrInvalid; frontends split them
// before admission. The stock frontend's maximum write is already 1 MiB.
// Arenas reserve operation records and at most two extent boundaries per record
// at construction. After identity initialization, uncontended Write allocates
// only its data copy. Transport coalescing uses temporary scratch, bounded by
// 1 MiB per flushing identity, in addition to the retained payload budget.
//
// An AVL extent map provides O(log n + k) reads of k intersecting dirty ranges.
// Later writes replace overlaps. Truncation removes covered data ranges and
// installs a zero mask, so truncate-then-grow cannot expose old fetched bytes.
// The tree maintains a size aggregate; Size is O(1) after identity lookup.
// Durability removes only the retiring record's surviving extents. Indexed
// heaps process cumulative visibility/durability without scanning idle files.
// Adjacent or overlapping consecutive writes coalesce at flush time within
// one cut and generation, up to MaxPayload. Truncate and SetAttr preserve their
// original position between writes; acceptance records never coalesce away.
//
// # Entry state and cuts
//
// Every record follows accepted -> applied -> visible -> durable (retired), or
// any retained state -> lost on Drop. Flush acknowledgments supply nonzero,
// nondecreasing per-identity Authority sequences. VisibleSequence advances the
// optional intermediate state. DurableSequence proves visibility as well as
// durability: integration must delay that notification until change delivery
// or subscriber horizons establish visibility through the watermark. Early,
// duplicate, and reordered cumulative notifications are safe, including ones
// delivered from inside Flusher.Flush before its reply. For a chunked write,
// all chunks must apply before the original acceptance becomes applied; the
// last chunk's sequence covers the complete write.
//
// Snapshot captures a mount-local acceptance cut, distinct from an Authority
// sequence. FlushIdentity and FlushAll wait for application of the cut, allowing
// later admissions. An already-started coalesced batch may finish past an older
// cut. Their returned sequence is a conservative per-identity high watermark
// and can include earlier flushes. Zero Cut is empty. Cuts belong to their
// originating Buffer and must not be fabricated or reused after Forget.
// Fsync snapshots one identity's obligations and waits for durability;
// WriteSync waits for the cut containing its own write. Context cancellation
// stops waiting, never rolls back an accepted operation. Barrier snapshots all
// accepted operations at call time, waits for application and durability, and
// reports whether mount loss advanced since the caller's OPENDIR observation.
// Its lost boolean must be checked even when error is nil.
//
// # Frontend and Flusher contract
//
// The frontend grants a full write delegation before admission and maps each
// local Generation to the Authority delegation id and generation. It must keep
// that mapping until the generation's entries retire. On recall, downgrade,
// release, or epoch withdrawal, call BeginRetire before draining frontend
// operations or flushing. A nil identity fences every identity, including new
// ones. Flush the returned Retirement.Cut, then acknowledge recall with the
// applied Authority sequence. Resume only after installing permission for the
// next generation; it refuses unapplied entries. A canceled flush leaves the
// retirement fence in place until a retry applies the cut or Drop discards it.
// Resume is idempotent and advances the local generation; admission waits at
// the fence rather than failing. Cap backpressure uses the same atomic
// admission boundary and cannot add operations to an already-captured cut.
//
// Flusher.Flush must respect the supplied positioned operation and generation,
// serialize its Authority application in call order per identity, and be safe
// for concurrent identities. Token is a mount/session-local idempotency key;
// retry the same token and bytes after every uncertain result. Successful
// earlier chunks are not resent. The flusher must not retain or mutate borrowed
// Data after returning and must honor context cancellation. It must arrange
// fsync-group progress independently of new admissions, including while the
// cap is full. Background transient errors retain the batch for the next timer
// or explicit retry; explicit flushes return wrapped errors. A permanent
// rejection (including stale generation) requires Drop; record its report.
// If Drop rebinds an in-flight batch before its transport returns, FlushIdentity
// returns the recorded loss (ErrLost, or a preserved capacity errno) even when
// that transport also failed: retryable transport status cannot describe data
// whose retained generation no longer exists.
// Never synchronously reenter a flush for the same identity from Flush.
//
// Drop fences results of an in-flight flush, reports retained bytes by identity,
// advances mount and identity loss, and wakes cap/durability waiters. It does
// not revoke a frontend delegation: integration must first stop or retire
// admission when permission is gone. Check IdentityLoss against each handle's
// own observation before write, close, or fsync, report EIO once, and update that
// observation. Lost/ClearLost expose a coarser identity mark without erasing
// per-handle history. A loss after a cut conservatively fails that identity's
// cut even if only later data was dropped. ClearLost does not reset mount loss.
// On epoch change, fence all admission, Drop every retained identity, stale all
// frontend handles, and replace the Buffer: Authority sequence watermarks and
// replay tokens are scoped to the old epoch. Pass the old final LossSequence
// as Options.InitialLossSequence when constructing its replacement, preserving
// the mount counter and root-directory observations across epochs. Old sequence
// callbacks must continue targeting the old Buffer, never its replacement.
//
// Read snapshots immutable dirty slices before fetching. Fetch must read from
// the coherent Authority view of the same delegation. Integration retains its
// per-identity read/publication drain and invalidates local cached read handles
// after each accepted mutation. OverlayAttributes folds explicit metadata and
// implicit write/truncate timestamps in admission order. Implicit timestamps
// stay local until the exact Authority post-attributes replace retired entries;
// integration supplies privilege-bit changes.
// Now timestamps resolve once using the client clock at acceptance. Append
// placement, lock-owner checks, access checks, handles, write flags, and wire
// encoding belong to integration; this package admits only positioned writes.
// A writethrough delegation uses immediate FlushIdentity and the integration's
// visibility wait, with WriteSync/Fsync for synchronous durability requirements.
// Namespace operations naming dirty files flush their cut before execution.
//
// For clean unmount, quiesce frontend calls, BeginRetire(nil), Barrier, then
// Stop. Stop cancels and joins background workers, rejects admissions, and keeps
// retained records for explicit inspection/drop; it does not silently lose
// data. Stop must not be called synchronously from a background Flush callback.
// Forget releases idle identity metadata only after all handles, delegation
// references, cuts, and operations have gone; clear its loss mark after
// reporting it first. Integration of these hooks is workstream F.
package writeback
