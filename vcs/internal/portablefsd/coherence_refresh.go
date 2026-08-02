package portablefsd

// Remote-change coherence for live kernel vnodes (macOS FSKit).
//
// macOS UserFS models single-writer media: a live vnode's SIZE is set when
// the kernel first materializes it and is updated only by local write and
// setattr paths — never by getattr (stat refreshes, reads stay capped at the
// stale EOF, mmap zero-fills past it), and FSKit gives the extension no
// invalidation API. The kernel also pins name->item bindings: answering
// ENOENT or ESTALE for a retired item wedges the path until remount, so
// identity rebinding is not an option either (both proven empirically).
//
// The two levers that DO work, both kernel-sanctioned and driveable by the
// unsandboxed daemon through its own mount:
//
//   - ftruncate(2) on a descriptor securely resolved beneath the mount is a
//     VNOP_SETATTR: on success the kernel adopts the new size for the vnode.
//     The daemon truncates to the AUTHORITATIVE size and its own setattr
//     handler consumes the marked request without touching the authority — a
//     pure kernel-state refresh.
//   - msync(MS_INVALIDATE) over a shared mapping is the POSIX contract for
//     "discard cached copies": it drops the stale pages so the next read
//     faults through the extension to the daemon.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// expectedTruncate marks one kernel-size refresh the daemon is issuing through
// its own mount, so the setattr handler can recognise the resulting FSKit
// upcall as coherence bookkeeping instead of an application truncate.
//
// The distinction is the whole point, and it must be a fact about PROVENANCE,
// never about elapsed time. A daemon-originated refresh and a user truncate to
// the same size are byte-identical on the wire; the only thing that separates
// them is that this process issued one of them and is still inside the
// ftruncate(2) that produced it. So the marker is PINNED for exactly that
// window (see pinned below) and is retired by the refresh that installed it.
type expectedTruncate struct {
	itemID uint64
	size   int64
	// pinned is true for the whole of the daemon's own synchronous ftruncate.
	//
	// ftruncate(2) is synchronous with its VNOP_SETATTR upcall, but the upcall
	// is not synchronous with the daemon's ANSWER to it: the request travels the
	// frontend dispatcher, where metadata-lane backpressure can pace it for up
	// to a full admission budget. A wall-clock TTL therefore decided the
	// question "is this the daemon's own refresh?" using a quantity that has
	// nothing to do with provenance — and when admission outran the TTL the
	// handler reclassified the daemon's own no-op as an APPLICATION truncate and
	// sent it to the authority, destroying every byte a concurrent local write
	// had appended past the sampled size.
	//
	// While pinned, the marker's validity is exactly "the refresh that installed
	// it has not returned yet", which is the true statement, is unforgeable by
	// anything outside applyKernelRefresh, and cannot be outrun by any amount of
	// admission latency.
	pinned bool
	// deadline bounds an UNPINNED marker only. No marker should ever be found
	// unpinned — applyKernelRefresh retires its own on every exit path — so this
	// is a sweeper for a marker that outlived its refresh through a path that
	// does not exist today, never the primary decision.
	deadline time.Time
	// seq identifies this exact marker, so the refresh that installed it retires
	// that one and not a successor installed for the same path in between.
	seq uint64
}

const (
	// refreshCoalesce absorbs a burst of remote-write invalidations for one
	// file into a single kernel refresh.
	refreshCoalesce = 25 * time.Millisecond
	// staleSampleRetries bounds how long a refresh waits for the authority
	// sample to catch up with state the daemon has already seen (see
	// refreshLocalSample). 40 × refreshCoalesce ≈ 1s, comfortably past a flush.
	staleSampleRetries = 40
)

// truncateNoteTTL is the sweeper bound on an UNPINNED marker. The pin (see
// expectedTruncate.pinned) is what actually decides whether a request is the
// daemon's own refresh; this only stops a marker that somehow outlived its
// refresh from lingering. An application truncate to the exact same (already
// current) size inside a pinned window is answered locally as a no-op — its
// only observable loss is an mtime bump the remote edit has already superseded
// — and, crucially, it does NOT consume the window: provenance belongs to the
// refresh that opened it, not to whichever request matches it first (see
// refreshWindowOpenLocked).
//
// A var so failure-shape tests can compress it and drive the case where a
// request's admission outlasts the TTL; production never changes it.
var truncateNoteTTL = 5 * time.Second

type refreshSampleOutcome uint8

const (
	refreshSampleRetry refreshSampleOutcome = iota
	// refreshSampleTerminal means the sampled name is absent. An ordinary
	// namespace-local refresh may settle that transition, but an
	// identity-required refresh must keep the barrier closed: another name
	// may still expose the exact regular-file inode whose vnode needs its
	// pages refreshed.
	refreshSampleTerminal
	// refreshSampleNonRegular means the sampled name resolved successfully
	// to the expected identity, but that identity is not a regular file.
	// Directories and symlinks have no regular-file page cache to truncate or
	// invalidate, so this is a proved, successful exact-refresh outcome.
	refreshSampleNonRegular
	// refreshSampleObsolete means the sampled name resolves to a different
	// authority inode than the frontend Item being refreshed. Its size must
	// never be applied to that Item's cached vnode.
	refreshSampleObsolete
	refreshSampleReady
)

type kernelRefreshOutcome uint8

const (
	kernelRefreshApplied kernelRefreshOutcome = iota
	// kernelRefreshObsolete means the scheduled name no longer resolves to
	// the expected regular-file identity. Namespace coherence owns that
	// transition; retrying the retired binding would be incorrect.
	kernelRefreshObsolete
	// kernelRefreshRetry means the expected binding may still be live but a
	// syscall did not complete. Ordinary convergence retries it, while an
	// exact delegation handoff fails closed before Checkin.
	kernelRefreshRetry
)

// refreshKernelItemStateComposed pushes the current composed size into the
// kernel vnode via a marked no-op truncate, then drops the vnode's cached
// pages. It reports whether the pass left the kernel on the settled state;
// false means the bounded exact transaction must run another pass. The
// refresh truncate races application writes traveling through the same
// kernel: a local write can land between the sample and the truncate — its
// own echo is invalidation-suppressed, so without the post-apply verify the
// clamp would wedge the kernel on the superseded sample forever. Verifying
// both the composed size and shared-lane authority version makes the caller
// converge on the final state instead.
func (a *attach) refreshKernelItemStateComposed(mount string, itemID uint64) bool {
	return a.refreshKernelItemStateComposedModeContext(
		context.Background(), mount, itemID, true,
	)
}

func (a *attach) refreshKernelItemStateComposedMode(
	mount string,
	itemID uint64,
	requireAuthorityIdentity bool,
) bool {
	return a.refreshKernelItemStateComposedModeContext(
		context.Background(), mount, itemID, requireAuthorityIdentity,
	)
}

func (a *attach) refreshKernelItemStateComposedModeContext(
	ctx context.Context,
	mount string,
	itemID uint64,
	requireAuthorityIdentity bool,
) bool {
	vol, eno := a.volOrErr()
	if eno != 0 {
		return false
	}
	a.mu.RLock()
	rec := a.items[itemID]
	if rec != nil {
		p := rec.path
		rec = &itemRecord{
			item: rec.item, path: p, state: rec.state, attr: rec.attr, graft: rec.graft,
		}
	}
	a.mu.RUnlock()
	if rec == nil {
		return true
	}
	p := rec.path
	var authorityIno uint64
	if rec.state != nil {
		authorityIno = rec.state.AuthorityIno()
	}
	sample := func() (int64, uint64, uint64, refreshSampleOutcome) {
		if a.localDirFor(p) != "" {
			return a.refreshGraftSample(rec)
		}
		return refreshLocalSampleAuthorityContext(ctx, vol, p, authorityIno)
	}
	size, version, generation, outcome := sample()
	switch outcome {
	case refreshSampleTerminal:
		if requireAuthorityIdentity {
			return false
		}
		if a.frontendItemMoved(rec.item, p) {
			return false
		}
		return true // gone or non-file: namespace handling owns convergence
	case refreshSampleNonRegular:
		return true
	case refreshSampleObsolete:
		// Namespace replacement owns an ordinary stale-name transition, but
		// a RelatedInos refresh is an explicit claim that this exact inode is
		// live somewhere. It cannot settle until a matching alias is known.
		return a.obsoleteRefreshSettled(rec.item, p, requireAuthorityIdentity)
	case refreshSampleRetry:
		return false
	}
	// rec.attr is the composed size this pass snapshotted BEFORE it sampled, so
	// it is the honest "nothing has been published for this item since I started"
	// baseline the arm re-checks under a.mu. Taking it from the snapshot rather
	// than re-reading the registry here is deliberate: a re-read would only prove
	// that nothing changed between two adjacent instructions.
	applyOutcome, _ := a.applyKernelRefresh(mount, p, rec, size, refreshApplyFence{
		observedSize: rec.attr.Size,
		version:      version,
		generation:   generation,
	})
	if applyOutcome != kernelRefreshApplied {
		if applyOutcome == kernelRefreshRetry {
			return false
		}
		if a.frontendItemMoved(rec.item, p) {
			return false
		}
		return true
	}
	afterSize, afterVersion, afterGeneration, afterOutcome := sample()
	switch afterOutcome {
	case refreshSampleTerminal:
		if requireAuthorityIdentity {
			return false
		}
		if a.frontendItemMoved(rec.item, p) {
			return false
		}
		return true
	case refreshSampleNonRegular:
		return true
	case refreshSampleObsolete:
		return a.obsoleteRefreshSettled(rec.item, p, requireAuthorityIdentity)
	case refreshSampleRetry:
		// Never declare a raced marked truncate settled when its verification
		// sample failed transiently. Own-write echoes may be suppressed, so
		// this worker is the only convergence trigger.
		return false
	}
	if afterSize != size {
		return false
	}
	return refreshSamplesSettled(version, generation, afterVersion, afterGeneration)
}

func (a *attach) obsoleteRefreshSettled(
	item pfslocal.Item,
	sampledPath string,
	requireAuthorityIdentity bool,
) bool {
	return !requireAuthorityIdentity && !a.frontendItemMoved(item, sampledPath)
}

// refreshGraftSample resolves an exact local-dir Item through the confined
// backing root. Grafts shadow the authority by definition, so sampling the
// remote Volume would either false-freeze on ENOENT or, worse, apply the size
// of a different shadowed inode to this vnode.
func (a *attach) refreshGraftSample(rec *itemRecord) (int64, uint64, uint64, refreshSampleOutcome) {
	if rec == nil {
		return 0, 0, 0, refreshSampleTerminal
	}
	a.mu.RLock()
	current := a.items[rec.item.ItemID]
	bound := a.paths[rec.path]
	live := current != nil &&
		current.item.ItemGeneration == rec.item.ItemGeneration &&
		bound != nil && bound.item == rec.item
	a.mu.RUnlock()
	if !live {
		return 0, 0, 0, refreshSampleTerminal
	}
	attr, eno := a.statLocal(rec.path)
	if eno != 0 {
		if eno == darwinENOENT || eno == darwinENOTDIR {
			return 0, 0, 0, refreshSampleTerminal
		}
		return 0, 0, 0, refreshSampleRetry
	}
	if attr.Kind != "file" {
		return 0, 0, 0, refreshSampleNonRegular
	}
	a.mu.RLock()
	current = a.items[rec.item.ItemID]
	bound = a.paths[rec.path]
	live = current != nil &&
		current.item.ItemGeneration == rec.item.ItemGeneration &&
		bound != nil && bound.item == rec.item
	a.mu.RUnlock()
	if !live {
		return 0, 0, 0, refreshSampleRetry
	}
	return attr.Size, 0, 0, refreshSampleReady
}

func (a *attach) frontendItemMoved(item pfslocal.Item, sampledPath string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	current := a.items[item.ItemID]
	return current != nil &&
		current.item.ItemGeneration == item.ItemGeneration &&
		current.path != sampledPath
}

func refreshSamplesSettled(version, generation, afterVersion, afterGeneration uint64) bool {
	if generation == 0 || afterGeneration == 0 {
		return generation == 0 && afterGeneration == 0
	}
	if generation != afterGeneration {
		return false
	}
	if version == 0 || afterVersion == 0 {
		return version == 0 && afterVersion == 0
	}
	return afterVersion <= version
}

// FSKit reserves inode values 0, 1, and 2 for invalid, parent-of-root, and
// root. The Swift adapter exposes every durable pfslocal item ID through the
// checked successor mapping (root 1 -> 2), so kernel-side identity proofs must
// apply the exact same boundary translation.
func fskitItemID(itemID uint64) (uint64, bool) {
	if itemID == 0 || itemID == ^uint64(0) {
		return 0, false
	}
	return itemID + 1, true
}

// refreshApplyFence is what one refresh pass must still be able to PROVE at the
// instant it opens its provenance window, and it is the answer to a sample that
// has quietly gone stale underneath the pass carrying it.
//
// A refresh is three separable steps — snapshot the item, sample the authority,
// push the sample into the kernel — and an acknowledged local write can land
// between any two of them. The push step is not a read: it installs the sampled
// size as the daemon's COMPOSED view (see armRefreshWindowLocked for why it must),
// so a pass that pushes a superseded sample overwrites newer state with older
// state and then answers the kernel from the result.
//
// The fence carries the two independent proofs that the sample has not been
// superseded, and both are checked, because each catches an interleaving the
// other cannot:
//
//   - observedSize is the composed size the pass snapshotted BEFORE it sampled.
//     Re-reading it under a.mu at the moment the window opens turns "nothing was
//     published for this item across the whole pass" into an atomic check: any
//     install — a write's post-op attributes, a getattr, an alias reconciliation —
//     goes through a.mu and moves this value. This is the one that closes the
//     race, because it is taken under the same lock that opens the window.
//   - version/generation are the authority sample's own coordinates. They catch
//     the case observedSize cannot: a write ACKNOWLEDGED and published before
//     this pass ever snapshotted, whose composed size is therefore stable at N
//     across the pass while the sample still says S. refreshLocalSample already
//     fences the sample against the version cache at sample time; this re-reads
//     that floor and refuses a sample the cache has since moved past.
//
// A zero generation is a delegated-overlay or graft sample, which has no
// authority version to order against. Its composed view is local by
// construction — it already contains every acknowledged local write — so
// observedSize is the whole proof there, and it is sufficient: the only writer
// that can move such an item is this daemon, through a.mu.
type refreshApplyFence struct {
	observedSize int64
	version      uint64
	generation   uint64
}

// errRefreshSampleSuperseded is a refresh pass refusing to push a sample it can
// no longer prove current. It is deliberately an ordinary retry outcome and not
// a failure: the item is fine, this pass's view of it is not, and the caller's
// convergence loop re-samples against the state that actually exists.
type errRefreshSampleSuperseded struct {
	path   string
	reason string
}

func (e *errRefreshSampleSuperseded) Error() string {
	return fmt.Sprintf(
		"portablefsd: kernel refresh sample for %q was superseded before it could "+
			"be applied (%s)", e.path, e.reason,
	)
}

func (a *attach) applyKernelRefresh(
	mount, p string,
	rec *itemRecord,
	size int64,
	fence refreshApplyFence,
) (kernelRefreshOutcome, error) {
	expectedKernelItemID, ok := fskitItemID(rec.item.ItemID)
	if !ok {
		return kernelRefreshRetry, fmt.Errorf(
			"portablefsd: item %d cannot be represented by FSKit",
			rec.item.ItemID,
		)
	}
	// THE CHEAP HALF OF THE FENCE, PAID BEFORE ANY SYSCALL.
	//
	// The version floor is read without a.mu — the version cache has its own
	// lock and nothing in it ever reaches back for a.mu, and nesting the two
	// here would invent a lock order the daemon does not otherwise have. It is
	// a "happened before" proof, not a race check: a publication that lands
	// after this read is caught by the observedSize arm below, which is taken
	// under the same lock that opens the window.
	if fence.generation != 0 {
		if vol, eno := a.volOrErr(); eno == 0 && vol != nil {
			gen, ver := vol.VersionCache.GenAndVersion(p)
			if gen != fence.generation || ver > fence.version {
				return kernelRefreshRetry, &errRefreshSampleSuperseded{
					path: p,
					reason: fmt.Sprintf(
						"sampled generation/version %d/%d, cache now at %d/%d",
						fence.generation, fence.version, gen, ver,
					),
				}
			}
		}
	}
	// The composed half of the fence, checked once here as well as inside the
	// arm. The arm's copy is the one that closes the race — it is taken under
	// the lock that opens the window — but a pass whose sample is ALREADY known
	// to be superseded has no business opening the file, stat-ing it, or
	// sweeping its pages, so it stops here before touching the kernel at all.
	a.mu.RLock()
	preflight := a.refreshSampleSupersededLocked(a.items[rec.item.ItemID], p, rec, fence)
	a.mu.RUnlock()
	if preflight != nil {
		return kernelRefreshRetry, preflight
	}
	refresh := refreshKernelFile
	if a.testRefreshKernelFile != nil {
		refresh = a.testRefreshKernelFile
	}
	// THE PIN IS ARMED AROUND THE FTRUNCATE, NOT AROUND THE REFRESH.
	//
	// The window's whole claim is "the daemon is inside the syscall that
	// produces this upcall". A refresh that finds the vnode size already
	// correct issues NO ftruncate at all — and used to pin a window anyway,
	// across an mmap/msync sweep that is O(file size). Every application
	// size-set matching (item, size) in that stretch was answered as daemon
	// bookkeeping for a syscall that was never made.
	//
	// So the refresh itself arms the window, exactly once, immediately before
	// unix.Ftruncate, and disarms it the instant that call returns. One
	// ftruncate, one window; no ftruncate, no window.
	var armedSeq uint64
	// settleErr is written by the disarm, which the refresh calls synchronously
	// on this goroutine the instant its ftruncate returns. It carries the
	// post-syscall verdict out to where the pass decides what it may claim.
	var settleErr error
	arm := func() (func(), error) {
		settle, seq, err := a.armRefreshWindowLocked(p, rec, size, fence)
		if err != nil {
			return nil, err
		}
		armedSeq = seq
		return func() { settleErr = settle() }, nil
	}
	outcome, err := refresh(mount, p, expectedKernelItemID, size, arm)
	// Belt and braces: the refresh disarms its own window on every path, but a
	// marker that somehow outlived it must never be left where a later
	// application truncate could match it. Identity is the sequence number, so
	// a successor installed for the same path by a concurrent pass is never
	// retired by this one. The pin goes with it, in the SAME hold, for two
	// reasons: a pin left behind a returned refresh would park every size
	// mutation on the item until their operation deadlines, and a marker left
	// standing without one is a provenance claim with nothing behind it
	// (retireRefreshWindowLocked).
	if armedSeq != 0 {
		a.mu.Lock()
		stale := a.retireRefreshWindowLocked(p, armedSeq, rec.item.ItemID, nil)
		a.mu.Unlock()
		stale.release()
	}
	if outcome == kernelRefreshApplied && settleErr != nil {
		// THE PASS MAY NOT REPORT WHAT IT CANNOT PROVE.
		//
		// The truncate went out, and by the time it returned the item was no
		// longer the one the window described. Reporting kernelRefreshApplied
		// here would end the transaction on a kernel vnode this daemon has just
		// stated it can no longer vouch for; the retry outcome re-samples and
		// runs the corrective pass under the same bounded budget.
		return kernelRefreshRetry, settleErr
	}
	if outcome != kernelRefreshApplied {
		// A failed safe-open means the name disappeared, changed identity,
		// became a symlink, or is inaccessible. Do not spin on that stale
		// binding: namespace changes publish their own invalidations and the
		// next path resolution or content invalidation schedules the current
		// FSItem. Retrying this obsolete item would be both wasteful and
		// incorrect for a permanent rename-over.
		return outcome, err
	}
	return kernelRefreshApplied, nil
}

// armRefreshWindowLocked opens one provenance window and installs the sampled
// size as the daemon's composed view, ATOMICALLY, under a.mu.
//
// ── WHY THE COMPOSED WRITE BELONGS HERE AND NOWHERE ELSE ────────────────────
//
// The write is not incidental bookkeeping, it is half the mechanism. The window
// predicate (refreshWindowClassLocked) decides Internal-versus-Ambiguous by
// asking whether the item's composed size still equals the size the window
// names, and the Internal arm answers the upcall FROM the composed attributes.
// Without the write, a refresh whose whole purpose is to install a size the
// registry does not yet hold would classify its own upcall as ambiguous, refuse
// it, and never converge.
//
// It used to run unconditionally, at the top of applyKernelRefresh, several
// steps before the window opened. That made it a FABRICATION: an acknowledged
// local write that had already published a longer composed size was silently
// rewritten back to the stale sample, which simultaneously (a) told the kernel
// the file was shorter than it is and (b) disarmed the ambiguity guard whose
// entire job is to notice that exact event.
//
// So the write is now conditional on the fence and taken under the same lock
// hold that installs the marker. Either this pass can still prove its sample is
// current — in which case installing it is an honest observation and the window
// it opens is honestly described — or it cannot, in which case there is no
// window, no ftruncate, and the caller re-samples.
// refreshSampleSupersededLocked names, in one place, everything that makes a
// refresh pass's sample no longer a statement about the object in front of it.
// Caller holds a.mu (either mode).
func (a *attach) refreshSampleSupersededLocked(
	current *itemRecord,
	p string,
	rec *itemRecord,
	fence refreshApplyFence,
) error {
	switch {
	case current == nil:
		return &errRefreshSampleSuperseded{path: p, reason: "item is no longer registered"}
	case a.sizeMutationReservedLocked(rec.item.ItemID):
		// A SIZE MUTATION IS ADMITTED AND HAS NOT FINISHED.
		//
		// This arm is earlier than the sequence arm below it, and deliberately
		// so: the sequence is opened immediately before the engine commit, which
		// is late enough that a mutation admitted a moment ago is still
		// invisible to it. The reservation is taken at pre-lock admission and
		// released only once the handler has published, so it covers the whole
		// of the interval in which that mutation can commit.
		//
		// Refusing here is what lets the pin below be an ORDER rather than
		// another check: the refresh only pins an item on which no mutation can
		// already be on its way to a commit, and any mutation that arrives after
		// the pin waits for it (refreshpin.go).
		return &errRefreshSampleSuperseded{
			path:   p,
			reason: "a size mutation has been admitted for this item and has not published",
		}
	case a.itemMutationInFlightLocked(rec.item.ItemID):
		// A SIZE MUTATION IS COMMITTED BUT NOT YET PUBLISHED.
		//
		// This arm is the one that composed size cannot answer, and it is not a
		// variant of the arm below it: the composed size has NOT moved, and that
		// is exactly the problem. A delegated write's extension is already in the
		// engine and already acknowledged to the application, while the registry
		// — which is only written by writeReplyWithAttr, later — still holds the
		// pre-write value this pass sampled. Both halves of the fence therefore
		// agree that nothing has happened, and the window this pass would open
		// would truncate the kernel's vnode back over durable bytes.
		//
		// Only the mutation sequence witnesses the gap, because only it is
		// advanced before the commit rather than after the publication. See
		// mutationseq.go.
		return &errRefreshSampleSuperseded{
			path:   p,
			reason: "a size mutation has committed but has not published its attributes",
		}
	case current.item.ItemGeneration != rec.item.ItemGeneration:
		return &errRefreshSampleSuperseded{
			path: p,
			reason: fmt.Sprintf(
				"item generation moved %d -> %d",
				rec.item.ItemGeneration, current.item.ItemGeneration,
			),
		}
	case current.path != p:
		return &errRefreshSampleSuperseded{
			path:   p,
			reason: fmt.Sprintf("item now bound to %q", current.path),
		}
	case current.attr.Size != fence.observedSize:
		return &errRefreshSampleSuperseded{
			path: p,
			reason: fmt.Sprintf(
				"composed size moved %d -> %d while the sample was in flight",
				fence.observedSize, current.attr.Size,
			),
		}
	}
	return nil
}

// armRefreshWindowLocked opens the provenance window described above, takes the
// item's size token for the syscall that follows, and returns the SETTLE that
// closes both.
//
// The settle runs at exactly the instant unix.Ftruncate(2) returns, and it is
// the PROOF that the token did its job.
//
// It asserts EXACTLY the invariant the token establishes and nothing wider: no
// LOCAL size mutation on this item was between its admission and its
// publication at any point inside the syscall. The pin makes that impossible,
// so the assertion never fires; if it ever did, the pass must report a retry
// rather than claim it applied a vnode state the daemon can no longer vouch for.
//
// It deliberately does NOT re-check the composed size. A size this daemon
// merely LEARNED during the window — a peer mount's write, discovered by a
// getattr or an invalidation and published like any other observation — moves
// that value without any local mutation being in flight, and it is neither a
// violation nor this settle's business: the pass's own post-apply verification
// sample already refuses to declare such a pass settled, and the bounded
// transaction re-runs against the state that actually exists
// (refreshKernelItemStateComposedModeContext). Widening the assertion to cover
// it would turn an ordinary remote observation into a refresh failure.
func (a *attach) armRefreshWindowLocked(
	p string,
	rec *itemRecord,
	size int64,
	fence refreshApplyFence,
) (func() error, uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	current := a.items[rec.item.ItemID]
	if err := a.refreshSampleSupersededLocked(current, p, rec, fence); err != nil {
		return nil, 0, err
	}
	if a.expectedTruncates == nil {
		a.expectedTruncates = map[string]expectedTruncate{}
	}
	a.expectedTruncateSeq++
	note := expectedTruncate{
		itemID: rec.item.ItemID, size: size,
		pinned:   true,
		deadline: time.Now().Add(truncateNoteTTL),
		seq:      a.expectedTruncateSeq,
	}
	a.expectedTruncates[p] = note
	current.attr.Size = size
	itemID := rec.item.ItemID
	pin := a.installRefreshPinLocked(itemID)
	return func() error {
		// ONE HOLD. The post-syscall verdict is read, the marker is retired and
		// the pin is removed together, so no observer can find the window's
		// provenance claim standing with nothing behind it (retireRefreshWindowLocked).
		a.mu.Lock()
		err := a.refreshWindowViolationLocked(p, itemID)
		a.retireRefreshWindowLocked(p, note.seq, itemID, pin)
		a.mu.Unlock()
		pin.release()
		if probe := a.testRefreshWindowTeardown; probe != nil {
			probe(p, itemID)
		}
		return err
	}, note.seq, nil
}

// refreshWindowViolationLocked answers whether a local size mutation was in
// flight for itemID at the instant the pass's ftruncate returned. Callers hold
// a.mu in either mode. See armRefreshWindowLocked.
func (a *attach) refreshWindowViolationLocked(p string, itemID uint64) error {
	switch {
	case a.sizeMutationReservedLocked(itemID):
		return &errRefreshSampleSuperseded{
			path:   p,
			reason: "a size mutation was admitted for this item inside the refresh truncate",
		}
	case a.itemMutationInFlightLocked(itemID):
		return &errRefreshSampleSuperseded{
			path:   p,
			reason: "a size mutation committed inside the refresh truncate",
		}
	}
	return nil
}

type frontendOperation struct {
	attach       *attach
	paths        []string
	pathEpoch    uint64
	gateActive   bool
	participants int
	suspended    int
	completed    bool
	// published records that at least one reply belonging to this logical
	// operation has been WRITTEN with PublicationAckRequired.
	//
	// ── EXPOSURE IS THE OBLIGATION; PARTICIPANT LIVENESS IS NOT ─────────────
	//
	// Everything else about a logical operation's membership of the active
	// publication set is derived from its participants: it activates when a
	// request enters, it retracts when every request has suspended or retired.
	// That derivation used participant liveness as a PROXY for "this operation
	// still owes the kernel-coherence barrier something", and the proxy is
	// simply false once a reply is on the wire. The daemon's own side of a
	// publication ends when the bytes are written; the obligation — that the
	// frontend has installed or discarded the state those bytes describe —
	// begins there and is discharged only by the PublicationAck, or by the
	// connection dying (which resolves it terminally, failing coherence
	// closed).
	//
	// So exposure PINS the operation into the active set, and the pin is
	// independent of whether any request is still running. Two doors were open
	// before it existed, and a delegation handoff walked through both:
	//
	//	1. the ALL-SUSPENDED RETRACTION. A sibling replies and retires, the
	//	   initiator suspends for its own release, and the operation now has
	//	   participants == suspended — so it was retracted from the active set
	//	   and stopped being a blocker ENTIRELY. The handoff then completed
	//	   instantly and silently, with the sibling's reply still in flight.
	//	2. the initiator's own-operation exception in publicationBlockersLocked
	//	   (see there), which reached the same state by the other route when
	//	   the release goroutine ran before the initiator suspended —
	//	   prepareReleaseLocked spawns finishRelease BEFORE its caller reaches
	//	   OnReleaseWait, so that ordering is ordinary, not exotic.
	published bool
	// fenced names the delegation scopes a handoff was permitted to cross
	// while this operation still owed an acknowledgement. See
	// publicationBlockersLocked and dischargeFrontendPublicationFence: a
	// crossing is recorded, never forgotten, and repaired the instant the
	// acknowledgement lands.
	fenced []string
	// retracted says a handoff crossed this operation, so nothing it has
	// published may be installed. Every remaining reply the operation receives
	// carries it (frontendConn.replyWithPublication), and the frontend answers
	// by discarding what it collected and failing the framework callback rather
	// than returning values the daemon no longer stands behind.
	//
	// ── WHY REFUSING TO INSTALL, AND NOT REPAIRING AFTER ────────────────────
	//
	// The mount's coherence model is version-anchored with a zero TTL: a value
	// the frontend holds is either current or it is not there. "Install it and
	// invalidate afterwards" is a TTL by another name — it names a window in
	// which an application reads a value the daemon already knows is wrong —
	// and it is the model, not the length of the window, that forbids it. A
	// value that will have to be retracted must never be installed.
	//
	// ── WHY THIS DOES NOT LIVELOCK, AND REFUSING THE MUTATION WOULD ─────────
	//
	// The alternative considered was to refuse the initiating mutation before
	// it executes and let the syscall retry. It does not terminate. The shape
	// that reaches this case is one framework callback issuing a publishing
	// request and then a mutation needing the delegation released — FSKit's
	// removeItem is exactly that. A refusal leaves the delegation in place, so
	// the retry runs the SAME callback, exposes the SAME sibling publication,
	// and is refused again, forever: the state the retry is waiting to change
	// is the state the refusal prevents from changing.
	//
	// Retraction inverts that. The handoff COMPLETES — the delegation really is
	// released — and only the crossed operation's results are thrown away. The
	// retry therefore finds nothing left to release, takes the authority lane
	// directly, never reaches this case, and converges in one attempt.
	//
	// Guarded by frontendGateMu.
	retracted bool
	// carriers counts the replies of this operation whose retraction verdict has
	// been CAPTURED and whose frame has not yet been written.
	//
	// ── WHY SAMPLING THE VERDICT IS NOT ENOUGH ──────────────────────────────
	//
	// The retraction is delivered by riding a reply, so the reply is the only
	// carrier it has, and the verdict was read a moment BEFORE the frame went
	// out. That gap is a real interleaving and it is the worst one available: a
	// non-publishing participant of an operation whose other participants are
	// all permanently suspended reads retracted==false, and before its frame
	// reaches the socket a handoff sees exactly the state
	// publicationBlockersLocked crosses (published, no runnable participant,
	// everything parked), crosses it, and sets retracted. The frame that goes
	// out is the one built before the crossing; the framework installs the
	// pre-handoff view; and the only mechanism that could have prevented the
	// install has already been used up.
	//
	// So capturing the verdict is a GATE TRANSITION, not a read: under
	// frontendGateMu the reply either observes an existing retraction, or it
	// registers itself here — and a handoff must then block on it rather than
	// cross it. The registration is released when the frame has been written, so
	// the wait is bounded by one socket write on a connection whose peer is
	// waiting for that very frame; it never becomes a wait on the acknowledgement
	// (which is the unreachable one the fence exists for). Guarded by
	// frontendGateMu.
	carriers int
}

// publicationRetracted reports whether a handoff has crossed op, so every reply
// still owed to it must tell the frontend to discard what it has collected.
//
// It is the read-only form, for a caller deciding what to DO (the initiator
// refusing its own mutation). A caller about to WRITE a frame stamped with the
// verdict must use captureRetractionCarrier instead: the answer has to be
// ordered against the crossing, not merely sampled before it.
func (a *attach) publicationRetracted(op *frontendOperation) bool {
	if op == nil || op.attach != a {
		return false
	}
	a.frontendGateMu.Lock()
	defer a.frontendGateMu.Unlock()
	return op.retracted
}

// captureRetractionCarrier is the ATOMIC GATE TRANSITION for one reply frame.
//
// Under frontendGateMu the reply either observes a retraction that has already
// happened — in which case it carries it and registers nothing, because the
// crossing it would have to block is already complete — or it commits itself
// into op.carriers, a state a future handoff must block on until the frame is
// written. Both outcomes are decided under the same lock the crossing takes, so
// there is no instant at which a reply has decided "not retracted" and a
// crossing is free to happen behind it.
//
// The returned release must be called after the frame has left, and never
// before: the whole point of the registration is that it spans the write.
func (a *attach) captureRetractionCarrier(op *frontendOperation) (retracted bool, release func()) {
	if op == nil || op.attach != a {
		return false, func() {}
	}
	a.frontendGateMu.Lock()
	if op.retracted {
		a.frontendGateMu.Unlock()
		return true, func() {}
	}
	op.carriers++
	a.frontendGateMu.Unlock()
	var once sync.Once
	return false, func() {
		once.Do(func() {
			a.frontendGateMu.Lock()
			if op.carriers > 0 {
				op.carriers--
			}
			if a.frontendGateCond != nil {
				a.frontendGateCond.Broadcast()
			}
			a.frontendGateMu.Unlock()
		})
	}
}

// ── THE PUBLICATION SETTLE VERDICT ──────────────────────────────────────────
//
// publicationSettleWindow bounds how long a delegation handoff waits for the
// active publication set to clear, measured from the last time that set made
// PROGRESS (an operation left it). It is the publication gate's analogue of the
// flusher watchdog's no-progress window, and it exists for the same reason.
//
// The wait it bounds is a wait on an event the daemon does not produce. An
// operation joins the active set when it activates and leaves it only through
// acknowledgePublication — a one-way PublicationAck the FSKit extension emits
// after its whole framework callback returns — or through connection death.
// The daemon's own side of a publication is finished the instant the reply is
// written; everything after that belongs to the kernel's scheduling of the
// rest of that callback, which the daemon can neither observe nor bound.
// startFrontendHandoff used to wait on it with the ENGINE's context (no
// deadline, no cancellation, see writeback.Engine.prepareReleaseLocked), so an
// operation whose handler had already returned but whose ack had not yet
// arrived pinned a release forever: the triggering syscall burned its whole
// operation budget and answered EIO, and — far worse — the handoff goroutine
// kept frontendHandoffs[scope] registered for the life of the mount, so every
// later request in that subtree blocked in beginFrontendPathsAtEpochContext.
// The subtree was dead until remount. Live shape: `mkdir d; touch d/f;
// rm d/f; rmdir d`, 100% reproducible.
//
// This bound applies to a wait that has a possible resolution: a FOREIGN
// operation's acknowledgement is not held up by this release, so it can and
// usually does arrive. The one case where the acknowledgement is provably
// unreachable — the release's OWN callback owes it — is not bounded here at
// all, because bounding it would only choose how long to wait before failing
// deterministically. It is handled by the crossing fence instead; see
// publicationBlockersLocked and dischargeFrontendPublicationFence.
//
// The window is measured from PROGRESS, not from the start of the wait, so it
// cannot fire on a busy-but-advancing gate: every operation that leaves the set
// rearms it. When it does fire the verdict is definite and SCOPED — the release
// attempt fails with a typed refusal that names the scope, the delegation stays
// held and draining with a recorded reason (recall semantics: a later caller
// starts a fresh attempt), the handoff registration is removed, and the attach
// is untouched. It never claims the frontend disconnected.
//
// A var so failure-shape tests can compress or stretch it; production never
// changes it.
var publicationSettleWindow = 2 * time.Second

// publicationRecheckFloor keeps a rearmed settle timer from spinning when the
// remaining window is vanishingly small.
const publicationRecheckFloor = 25 * time.Millisecond

// errPublicationUnsettled is the handoff's definite verdict when the active
// publication set did not clear within publicationSettleWindow.
//
// It is deliberately NOT the disconnect verdict. The frontend is connected; it
// has simply not acknowledged an exposed publication yet. Reporting a
// disconnect here would install a terminal attach-wide coherence failure for a
// live mount, which is exactly the misdiagnosis the live battery observed.
type errPublicationUnsettled struct {
	scope     string
	blockers  int
	live      int
	unsettled time.Duration
	// overBudget records that the RELEASE's own absolute budget ran out inside
	// this wait rather than the settle window expiring. The verdict is the same
	// shape — the frontend is alive and the scope may be released again — but
	// the reason is different and the message must say so.
	overBudget bool
}

func (e *errPublicationUnsettled) Error() string {
	scope := e.scope
	if scope == "" {
		scope = "/"
	}
	reason := fmt.Sprintf(
		"unacknowledged by a CONNECTED frontend for %s",
		e.unsettled.Round(time.Millisecond),
	)
	if e.overBudget {
		reason = fmt.Sprintf(
			"still unacknowledged by a CONNECTED frontend (last barrier progress %s ago)"+
				" when the release's own budget ran out",
			e.unsettled.Round(time.Millisecond),
		)
	}
	return fmt.Sprintf(
		"kernel publication barrier for %q did not settle: %d exposed publication(s)"+
			" (%d still executing) %s",
		scope, e.blockers, e.live, reason,
	)
}

// Unwrap ties the verdict to writeback.ErrPublicationUnsettled, the sentinel
// the release's own bounded retry (startHandoffBounded) classifies on. It is
// what makes this a TRANSIENT, scope-local refusal rather than the terminal
// disconnect verdict.
func (e *errPublicationUnsettled) Unwrap() error { return writeback.ErrPublicationUnsettled }

// PublicationUnsettled reports whether err is a bounded publication-settle
// refusal: the frontend is alive and the scope may be released again later.
func PublicationUnsettled(err error) bool {
	var unsettled *errPublicationUnsettled
	return errors.As(err, &unsettled)
}

type frontendOperationContextKey struct{}

type frontendOperationParticipant struct {
	op           *frontendOperation
	suspendDepth int
	finished     bool
	// nonpublishing marks a participant that entered the logical operation
	// permanently suspended because its request exposes no cacheable state.
	// It is accounted for (the operation is not finished while it runs) but
	// is never a member of the active publication set.
	nonpublishing bool
	// pendingPaths/pendingEpoch are an EXTENSION's own operand scopes, held
	// on the participant until the instant it activates.
	//
	// A reserved participant is suspended, so it contributes no scope to the
	// publication set and no handoff can be waiting on it. Merging its scopes
	// into op.paths at reservation time would widen an ALREADY ACTIVE
	// operation into a scope a handoff owns — the case the extension rule in
	// activationBlockedLocked holds back. So the merge is part of activation,
	// taken under the gate at the moment the operation proves no handoff owns
	// the new scopes.
	//
	// merged is true from the start for the participant that CREATED the
	// operation: its paths are the operation's paths already.
	pendingPaths []string
	pendingEpoch uint64
	merged       bool
}

// retractFromPublicationSetLocked removes op from the active publication set
// and advances the gate's progress clock. Every retraction goes through here so
// a handoff's settle verdict is measured against real progress rather than
// against elapsed time (see publicationSettleWindow). Caller holds
// frontendGateMu.
func (a *attach) retractFromPublicationSetLocked(op *frontendOperation) {
	if _, ok := a.frontendActive[op]; !ok {
		return
	}
	delete(a.frontendActive, op)
	a.frontendGateProgress++
}

// retractIdleOperationLocked applies the ONE rule by which a live logical
// operation leaves the active publication set without being finished: every
// one of its requests is suspended, so none of them can publish anything and a
// handoff has nothing to wait for.
//
// It is a single function because the rule has one exception and that
// exception must not be re-derived at each of the four call sites that used to
// spell the predicate out (suspendFrontendParticipant,
// joinFrontendOperationSuspended, finishFrontendParticipant and the resume half
// of suspendFrontendOperation). The exception is frontendOperation.published:
// an operation that has already WRITTEN an acknowledgement-required reply owes
// the kernel-coherence barrier a settlement that no amount of suspending can
// discharge, so "nobody is running" is not the same statement as "nothing is
// outstanding". Retracting it there dropped a real, unsettled publication out
// of the barrier and let a delegation handoff cross it silently.
//
// Caller holds frontendGateMu. Returns whether the operation was retracted.
func (a *attach) retractIdleOperationLocked(op *frontendOperation) bool {
	if op.completed || !op.gateActive || op.published {
		return false
	}
	if op.participants <= 0 || op.suspended != op.participants {
		return false
	}
	a.retractFromPublicationSetLocked(op)
	op.gateActive = false
	return true
}

// notePublicationExposed records that a reply belonging to op has been written
// with PublicationAckRequired, and pins op into the active publication set for
// the whole life of that obligation.
//
// It is called from frontendConn.replyWithPublication BEFORE the bytes reach
// the socket, which is the only order that works: once the reply is on the wire
// the daemon has already lost the ability to decide whether a handoff may cross
// it, so the pin has to be installed while the decision is still the daemon's
// to make.
//
// The pin re-enters the set even for an operation whose requests are all
// suspended. That looks like it contradicts the activation protocol's liveness
// rule ("a handoff never waits on a suspended participant"), and it does not:
// that rule is about REQUESTS, which can be made to wait and therefore must
// never be waited on while they hold a mirror. This is about a REPLY that has
// already left, which no lock can be holding and which no request can be asked
// to retract.
func (a *attach) notePublicationExposed(op *frontendOperation) {
	if op == nil || op.attach != a {
		return
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if !op.completed && !op.published {
		op.published = true
		if !op.gateActive {
			a.frontendActive[op] = struct{}{}
			op.gateActive = true
		}
	}
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
}

// dischargeFrontendPublicationFence repairs every publication a delegation
// handoff was permitted to cross while this operation still owed an
// acknowledgement, at the exact moment that acknowledgement lands.
//
// ── WHAT THIS IS, NOW THAT RETRACTION EXISTS ────────────────────────────────
//
// The crossing's primary answer is frontendOperation.retracted: the frontend is
// told, on a reply that provably precedes the framework install, to discard what
// the crossed operation collected. Nothing stale is installed, so there is
// nothing to repair.
//
// This is the backstop for what retraction cannot reach: cache state the crossed
// operation caused to be installed BEFORE the crossing (an earlier reply of the
// same operation whose values the framework has already taken), and any frontend
// whose retraction is partial. It runs on every crossing regardless, because a
// backstop that only runs when the daemon thinks it is needed is a backstop that
// depends on the daemon being right about the thing it just got wrong.
//
// ── WHY IT NO LONGER PUBLISHES AN EVENT AND CALLS THAT A REPAIR ─────────────
//
// It used to publish content and namespace invalidations to the attach's event
// subscribers, and that was not a repair at all on the frontend it exists for.
// pfslocal events reach a connection only after SubscribeEventsRequest, and the
// FSKit extension never sends one — the request is served (frontend.go) and
// exercised by tests, and has no production caller. So on an FSKit mount the
// entire repair was a fan-out to an empty subscriber set: the crossed value was
// installed and NOTHING ever contradicted it. "The divergence window is one
// acknowledgement round trip" described a mechanism that was not connected.
//
// What actually reaches an FSKit vnode is the daemon's own kernel refresh —
// exactKernelRefresh, which opens the file through the mount and drives the size
// and page cache itself (coherence_darwin.go). That is exactly what the authority
// invalidation watcher does for a peer change: it publishes the event AND runs
// the refresh, and treats a refresh failure as a coherence failure rather than
// as unproven visibility. The crossing repair owes the same, for the same
// reason, so it does the same.
//
// The event publication stays alongside it for frontends that DO subscribe. It
// is not the proof.
//
// ── ORDERING ────────────────────────────────────────────────────────────────
//
// This runs from the acknowledgement, which the frontend emits after its whole
// framework callback returns. So the refresh is issued strictly after any
// install that callback performed, which is the one ordering a repair must have
// and the one an event fired at crossing time could never have had.
func (a *attach) dischargeFrontendPublicationFence(op *frontendOperation) {
	if op == nil || op.attach != a {
		return
	}
	a.frontendGateMu.Lock()
	fenced := op.fenced
	op.fenced = nil
	op.retracted = false
	var paths []string
	if len(fenced) != 0 {
		paths = append(paths, op.paths...)
		if len(paths) == 0 {
			// An operation with no derived scope was treated as mount-wide by
			// the gate that crossed it, so it is repaired the same way: at the
			// root, which is the widest statement the invalidation vocabulary
			// has. frontendOperationPaths already spells the conservative scope
			// as the root path, so this only covers an operation that never
			// derived one at all.
			paths = append(paths, "")
		}
	}
	a.frontendGateMu.Unlock()
	if len(fenced) == 0 {
		return
	}
	// Content and namespace both: the daemon does not record WHICH class of
	// state the crossed reply carried (the publication classification is per
	// request kind, and one logical operation can mix lookup, getattr and read
	// over the same paths), so the repair has to cover every class the frontend
	// could have installed. Both are the same events the authority invalidation
	// path publishes, so the extension needs no new handling for them.
	a.mu.Lock()
	items := make(map[uint64]struct{}, len(paths))
	for _, p := range paths {
		a.publishContentInvalidationLocked(p, 0, 0)
		a.publishNamespaceInvalidationLocked(p, 0, 0)
		if rec := a.paths[p]; rec != nil {
			items[rec.item.ItemID] = struct{}{}
		}
	}
	a.mu.Unlock()
	a.refreshCrossedItems(items)
}

// refreshCrossedItems drives the daemon's own kernel refresh for every item a
// crossing may have left stale, and fails coherence closed if it cannot.
//
// Failing closed is the same verdict the authority invalidation watcher reaches
// for the same failure, and for the same reason: an unrefreshed vnode is a
// kernel that disagrees with the authority about a file, with no further event
// coming to correct it. Continuing to serve from that state is the one option
// that is never acceptable. It is deliberately NOT the acknowledgement's own
// error — the acknowledgement is a statement of fact about the frontend, and it
// has already been made — so this reports through the attach's terminal verdict
// rather than through any reply.
//
// The refresh runs on the ATTACH's lifetime rather than on the caller's. This is
// reached from the frontend's acknowledgement handler, whose request context is
// gone the moment that handler returns, and abandoning a coherence repair
// because the message that triggered it has been processed is how the repair
// silently stops happening.
// THE REPAIR NEVER RUNS ON ITS CALLER'S GOROUTINE.
//
// Its callers are the acknowledgement handler and the connection close. The
// acknowledgement handler IS the connection's serial frame reader
// (frontendConn.serve), so anything it waits for stalls every request and every
// further acknowledgement on that connection — including the acknowledgements
// other operations need in order to leave the publication set. A refresh that
// blocked there for its two-minute bound was a two-minute stall of the whole
// frontend, self-inflicted at the exact moment the mount was already unhappy;
// with the retry below it would never return at all.
//
// So the repair is handed to the attach's own lifetime and the caller returns
// immediately. Nothing is lost by that: the repair's ordering requirement is
// that it run AFTER the framework install, and the acknowledgement is what
// proves the install has happened — it does not have to be the thing that waits
// for the repair.
func (a *attach) refreshCrossedItems(items map[uint64]struct{}) {
	if len(items) == 0 {
		return
	}
	lifetime := a.refreshLifetimeContext()
	go func() {
		for itemID := range items {
			a.repairCrossedItem(lifetime, itemID)
		}
	}()
}

// repairCrossedItem drives one item's exact kernel refresh, RETRYING until it
// converges or the attach ends.
//
// ── WHY A RETRY AND NOT A VERDICT ───────────────────────────────────────────
//
// This used to make one attempt under a two-minute bound and hand any error to
// failCoherence, which freezes the attach permanently. That collapsed two
// completely different things into the same terminal outcome:
//
//   - "the kernel disagrees with the authority and cannot be corrected", which
//     is what failCoherence means and is genuinely terminal; and
//   - "this item is BUSY", which is not a failure at all.
//
// The second is what the live battery hit. refreshKernelItemExactMode acquires
// a refresh intent first and waits for the item's outstanding size mutations to
// drain — and on a file under continuous local write they do not drain, because
// a new writer arrives before the last one leaves. That is contention, and the
// refresh path already says so in as many words ("Reservation contention is not
// a failure to converge"); the intent exists precisely to keep the two apart.
// But the OUTER bound put them back together: a 1.5 MB/s soak on ONE file spent
// the whole two minutes queueing, reported `context deadline exceeded`, and the
// caller froze the entire mount over a file it was itself busy writing.
//
// A busy item is also the case where the repair matters LEAST. The kernel's view
// of a file this daemon is actively writing is being driven by those writes; the
// crossed publication concerned a value the daemon's own subsequent traffic
// supersedes. So waiting is not a compromise, it is the correct order.
//
// ── ROUND 16: WHY THE POINT-IN-TIME CHECK WAS NOT A YIELD ───────────────────
//
// The paragraph above was right about the principle and wrong about the
// mechanism. `if a.sizeMutationReserved(itemID) { continue }` samples the
// reservation count ONE INSTRUCTION BEFORE acquireRefreshIntent installs an
// exclusive intent, and it samples it from outside the item's arrival order. An
// ordinary write loop — open(O_APPEND), write, fsync, close, repeat — is idle in
// exactly that sense between one close and the next open. The repair wins that
// gap by construction, installs its intent, and from that instant every
// ARRIVING size mutation on the item queues behind it for the whole pass.
//
// Measured live on a fresh mount with ONE file: fsync=400.9s (uninterruptible,
// state UN), open=50.1s, fsync=300.3s, and NORMAL the instant the 10-minute
// budget expired. Round 15 turned one two-minute stall into up to ten minutes of
// them.
//
// A check cannot fix this, because the thing being checked is a property of the
// future: whether a mutation will arrive during the pass. So the repair stops
// checking and starts YIELDING.
//
// ── THE TWO WAYS THIS REPAIR NOW ENDS ───────────────────────────────────────
//
//  1. IT CONVERGES BY REFRESHING, on an item that is genuinely quiet. The pass
//     is the same exact transaction as before, and it is fast.
//
//  2. IT CONVERGES BY OBSERVING THE WRITER, on an item that is not. The pass
//     takes its intent DEFERENTIALLY (refreshintent.go): a size mutation
//     queueing behind it preempts it, it unwinds, and the application proceeds.
//     The debt is then discharged by the writer itself, and this is a proof
//     rather than a shrug:
//
//     – The caller published the item's lazy content AND namespace
//     invalidations before this repair was ever started — that is the first
//     thing noteCrossedScope and repairDisconnectedPublications do — so the
//     kernel has already been told to drop its cached pages and names for it.
//     – What the exact pass adds on top is the item's SIZE, pushed into the
//     vnode. A size mutation that reaches publishRecordAttrLocked has installed
//     this daemon's own post-op attributes for the item, which is the same
//     value from the same source arriving by the ordinary reply path.
//
//     So an attribute publication observed after the crossing supersedes
//     anything the crossed reply could have left behind, and the repair is
//     DONE — not deferred, not degraded.
//
// Preemption is therefore never counted as a failed attempt, and a busy file no
// longer walks the budget down to the give-up path. The give-up path stays
// exactly as it is, as the backstop for the case both of the above miss: an item
// that neither goes quiet nor is written for the whole budget.
//
// ── WHAT IS STILL DEFINITE ──────────────────────────────────────────────────
//
// Every attempt still ends definitely, and the debt is never dropped: it ends by
// converging, by being discharged by a publication, or on the reported give-up.
// The retry still ends when the ATTACH ends, and an attach that is going away
// takes the kernel state in question with it.
func (a *attach) repairCrossedItem(lifetime context.Context, itemID uint64) {
	a.noteCoherenceRepairing(1)
	defer a.noteCoherenceRepairing(-1)
	// The convergence witness is armed BEFORE the first attempt, so no
	// publication that happens during the repair can be missed.
	watch := a.watchRepairPublications(itemID)
	defer watch.stop()
	giveUp := time.Now().Add(crossedRepairBudget)
	backoff := crossedRepairRetryDelay
	var err error
	var yields int
	for attempt := 0; ; attempt++ {
		if lifetime.Err() != nil {
			return
		}
		if a.repairDischargedByPublication(watch, attempt, yields) {
			return
		}
		ctx, cancel := context.WithTimeout(lifetime, crossedRefreshTimeout)
		err = a.exactKernelRefreshYielding(ctx, itemID)
		cancel()
		if err == nil {
			if attempt > 0 {
				log.Printf(
					"portablefsd: attach %s: kernel coherence repair for item %d "+
						"converged after %d retries", a.ref, itemID, attempt,
				)
			}
			return
		}
		if errors.Is(err, errRefreshIntentPreempted) {
			// The application took the item. That is the outcome this repair
			// wants on a busy file, so it costs no budget commentary and — see
			// repairDischargedByPublication — the writer that took it is about to
			// discharge the debt itself.
			yields++
			if !a.waitBeforeRepairRetry(lifetime, &backoff, giveUp) {
				if lifetime.Err() != nil {
					return
				}
				if a.repairDischargedByPublication(watch, attempt, yields) {
					return
				}
				a.reportRepairGaveUp(itemID, errRepairItemStayedBusy)
				return
			}
			continue
		}
		if attempt == 0 {
			log.Printf(
				"portablefsd: attach %s: kernel coherence repair for item %d did "+
					"not converge (%v); retrying every %s until it does",
				a.ref, itemID, err, crossedRepairRetryDelay,
			)
		}
		if !a.waitBeforeRepairRetry(lifetime, &backoff, giveUp) {
			if lifetime.Err() != nil {
				// The ATTACH is going away, not the budget. It takes the kernel
				// state in question with it, and recording a sticky degraded
				// reason on the way out would be a false statement about a mount
				// that no longer exists.
				return
			}
			if a.repairDischargedByPublication(watch, attempt, yields) {
				return
			}
			a.reportRepairGaveUp(itemID, err)
			return
		}
	}
}

// repairDischargedByPublication reports whether a SIZE MUTATION has committed
// and delivered its own post-op attributes to the kernel since this repair
// began watching, and logs the discharge.
//
// A publication is only a discharge for a repair that has ALREADY yielded at
// least once. Before that the item is quiet as far as this repair knows, and a
// quiet item must be proved by the exact pass — a publication that happens to
// land during a quiet window is not a reason to skip a refresh that would have
// succeeded anyway. After a yield the situation is the opposite: the writer is
// live, its own publications are what the kernel is being driven by, and the
// exact pass has nothing to add.
//
// ── WHAT COUNTS, AND WHY IT IS NOT "ANY PUBLICATION UNDER A RESERVATION" ────
//
// The witness used to credit any attribute assignment made while any size
// reservation existed on the item, and that is not a statement about a
// mutation at all. An older getattr, already in flight and holding the locks
// the preempting write is queued behind, publishes its PRE-WRITE observation;
// the write's reservation exists, so it counted; the repair exited discharged;
// and the write was then cancelled without committing anything. The debt was
// discarded on the very value it existed to correct.
//
// watch.since() now counts only mutations that (a) held the item's reservation
// token, (b) committed and installed their post-op size into the registry, and
// (c) had that reply DELIVERED to the frontend un-retracted. See
// repairwitness.go.
func (a *attach) repairDischargedByPublication(
	watch *repairPublicationWatcher,
	attempt, yields int,
) bool {
	if yields == 0 || watch == nil {
		return false
	}
	published := watch.since()
	if published == 0 {
		return false
	}
	log.Printf(
		"portablefsd: attach %s: kernel coherence repair for item %d discharged by "+
			"%d delivered size-mutation publication(s) after %d attempt(s) and %d "+
			"yield(s) to the application", a.ref, watch.itemID, published, attempt, yields,
	)
	return true
}

// waitBeforeRepairRetry paces one retry and reports whether the loop may go
// round again. It returns false when the whole repair budget is spent, and
// backs off geometrically so a persistently busy item is polled rarely rather
// than hammered.
func (a *attach) waitBeforeRepairRetry(
	lifetime context.Context,
	backoff *time.Duration,
	giveUp time.Time,
) bool {
	if !time.Now().Before(giveUp) {
		return false
	}
	delay := *backoff
	if next := delay * 2; next < crossedRepairMaxRetryDelay {
		*backoff = next
	} else {
		*backoff = crossedRepairMaxRetryDelay
	}
	select {
	case <-lifetime.Done():
		return false
	case <-time.After(delay):
		return true
	}
}

// reportRepairGaveUp ends a repair DEFINITELY, and not by freezing.
//
// The budget exists so the retry is bounded rather than eternal and so this
// goroutine cannot outlive any plausible repair. Exhausting it is reported and
// STICKY — the attach stays degraded with this reason, which is the honest
// statement ("some kernel state here was never proven") — but it does not fail
// admissions closed. Freezing is what round 15 removed: it turned an unprovable
// CACHE ENTRY into an unusable MOUNT, and the mount's own answers were never in
// doubt.
func (a *attach) reportRepairGaveUp(itemID uint64, cause error) {
	if cause == nil {
		cause = errRepairItemStayedBusy
	}
	log.Printf(
		"portablefsd: attach %s: kernel coherence repair for item %d gave up "+
			"after %s (%v); the mount continues to serve and reports degraded",
		a.ref, itemID, crossedRepairBudget, cause,
	)
	a.mu.Lock()
	a.coherenceRepairGaveUp = true
	a.mu.Unlock()
	a.setErr(fmt.Errorf(
		"kernel coherence repair for item %d did not converge within %s: %w",
		itemID, crossedRepairBudget, cause,
	))
}

// errRepairItemStayedBusy is the give-up cause for an item that never went
// quiet. It is distinct from a refresh failure because it says nothing went
// wrong — the item was simply being written for the whole budget, and its own
// writer owns the kernel view this repair wanted to correct.
var errRepairItemStayedBusy = errors.New(
	"the item was continuously reserved by local size mutations, so the repair " +
		"never had a quiet moment to run in",
)

// crossedRepairMaxRetryDelay caps the geometric backoff. A busy item is polled
// at this rate, which is cheap and — crucially — leaves the application's own
// turnstile claims uncontended in between.
var crossedRepairMaxRetryDelay = 30 * time.Second

// crossedRepairBudget bounds the whole retry, not one attempt. It is generous
// on purpose: the case it must outlast is an item under sustained local write,
// where the refresh cannot acquire its intent until the writer pauses.
//
// A var so failure-shape tests can compress it; production never changes it.
var crossedRepairBudget = 10 * time.Minute

// crossedRepairRetryDelay paces the repair retry. It is long enough that a busy
// item is not polled hard and short enough that a repair lands promptly once the
// item goes quiet.
//
// A var so failure-shape tests can compress it; production never changes it.
var crossedRepairRetryDelay = 2 * time.Second

// noteCoherenceRepairing tracks how many kernel coherence repairs are
// outstanding, so the attach can report REPAIRING rather than either lying that
// it is healthy or freezing as if it were broken. delta is +1 on entry and -1 on
// completion.
func (a *attach) noteCoherenceRepairing(delta int) {
	a.mu.Lock()
	a.coherenceRepairs += delta
	if a.coherenceRepairs < 0 {
		a.coherenceRepairs = 0
	}
	repairing := a.coherenceRepairs > 0
	gaveUp := a.coherenceRepairGaveUp
	a.mu.Unlock()
	if gaveUp {
		// A repair that ran out of budget left a sticky reason behind. Clearing
		// it here would erase the one record that some kernel state was never
		// proven, which is the only thing an operator has to go on.
		return
	}
	if repairing {
		a.setErr(errors.New(coherenceRepairingDetail))
		return
	}
	// CLEAR ONLY WHAT THIS REPAIR SAID.
	//
	// The debt really is discharged — leaving the attach degraded after a repair
	// converged would reproduce the permanent degradation this replaces with a
	// longer fuse — but setErr(nil) clears whatever reason is currently
	// recorded, and by the time the last repair finishes that reason may belong
	// to something else entirely (a rejected credential, a drain failure). So
	// the clear is conditional on this being OUR message.
	a.mu.Lock()
	ours := a.lastErr == coherenceRepairingDetail
	a.mu.Unlock()
	if ours {
		a.setErr(nil)
	}
}

// coherenceRepairingDetail is the exact degraded reason a running repair
// publishes. It is a constant because noteCoherenceRepairing must be able to
// recognise its OWN message before clearing it.
const coherenceRepairingDetail = "kernel coherence repair in progress: " +
	"refreshing kernel state the daemon could not prove; the mount continues to serve"

// crossedRefreshTimeout bounds the backstop repair. It matches the control
// plane's own post-write refresh bound, because it is the same operation
// against the same kernel.
//
// It is no longer a bound the APPLICATION can be made to wait for: the pass it
// bounds is deferential, so a size mutation arriving at any point inside it
// preempts it (refreshintent.go). What is left is a bound on how long a pass may
// spend against a quiet item that will not settle, and the give-up path is the
// backstop for that.
//
// A var so failure-shape tests can compress it; production never changes it.
var crossedRefreshTimeout = 2 * time.Minute

// refreshLifetimeContext is the attach's own lifetime, or the background context
// for a bare test attach that never activated one.
func (a *attach) refreshLifetimeContext() context.Context {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.lifeCtx != nil {
		return a.lifeCtx
	}
	return context.Background()
}

// repairDisconnectedPublications repairs the kernel view for publications a
// frontend exposed but never acknowledged before its connection died.
//
// ── WHY THIS EXISTS INSTEAD OF A TERMINAL VERDICT ───────────────────────────
//
// A lost acknowledgement used to be the end of the mount. frontendConn.close
// found one exposed-unacknowledged publication and called failCoherence, which
// sets coherenceFailFrozen — a flag nothing ever clears — so every later request
// on the attach answered EIO forever. The reasoning was that an acknowledgement
// is a statement about a live frontend, so once the frontend is gone the
// statement can never be made.
//
// That is true and it is not the same as "the kernel cannot be corrected". The
// FSKit mount OUTLIVES the daemon connection: the extension reconnects and keeps
// every vnode it holds, so the kernel this daemon is about to go on serving is
// reachable — through the mount, by the daemon itself. exactKernelRefresh drives
// exactly that refresh, and it is what the crossing fence has used since round 9
// to repair state it could not prove any other way. The disconnect owes the same
// repair for the same reason, and the only thing that was different was the
// posture: one path repaired, the other despaired.
//
// So a lost acknowledgement is now a DEBT, not a verdict. The affected scopes are
// invalidated and refreshed, with retry (see repairCrossedItem); the attach
// reports REPAIRING while that runs and returns to attached when it converges;
// and the mount keeps serving throughout, which is correct because the daemon's
// own answers were never in doubt — only the kernel's cache was, and that is
// precisely what is being rewritten.
//
// It runs off the teardown path because it reaches the kernel through the mount
// and is unbounded in principle, while its caller is on the connection's close
// and is about to join every handler.
func (a *attach) repairDisconnectedPublications(ops []*frontendOperation) {
	if len(ops) == 0 {
		return
	}
	var paths []string
	a.frontendGateMu.Lock()
	for _, op := range ops {
		if op == nil || op.attach != a {
			continue
		}
		if len(op.paths) == 0 {
			// An operation with no derived scope published under the
			// conservative mount-wide scope, and the root path is how that scope
			// is spelled in the invalidation vocabulary.
			paths = append(paths, "")
			continue
		}
		paths = append(paths, op.paths...)
	}
	a.frontendGateMu.Unlock()
	if len(paths) == 0 {
		return
	}
	items := make(map[uint64]struct{}, len(paths))
	a.mu.Lock()
	for _, p := range paths {
		// Content and namespace both: the daemon does not record WHICH class of
		// state the unacknowledged reply carried, so the repair covers every
		// class the frontend could have installed. Same events the authority
		// invalidation path publishes, so the extension needs no new handling.
		a.publishContentInvalidationLocked(p, 0, 0)
		a.publishNamespaceInvalidationLocked(p, 0, 0)
		if rec := a.paths[p]; rec != nil {
			items[rec.item.ItemID] = struct{}{}
		}
	}
	a.mu.Unlock()
	a.refreshCrossedItems(items)
}

func (a *attach) initFrontendGateLocked() {
	if a.frontendGateCond == nil {
		a.frontendGateCond = sync.NewCond(&a.frontendGateMu)
	}
	if a.frontendActive == nil {
		a.frontendActive = map[*frontendOperation]struct{}{}
	}
	if a.frontendHandoffs == nil {
		a.frontendHandoffs = map[string]int{}
	}
}

func scopesOverlap(a, b string) bool {
	return pathWithinScope(a, b) || pathWithinScope(b, a)
}

func operationOverlapsScope(paths []string, scope string) bool {
	for _, path := range paths {
		if scopesOverlap(path, scope) {
			return true
		}
	}
	return false
}

func (a *attach) beginFrontendPaths(ctx context.Context, paths []string) (context.Context, *frontendOperation) {
	return a.beginFrontendPathsAtEpoch(ctx, paths, a.frontendPathEpoch.Load())
}

func (a *attach) beginFrontendPathsAtEpoch(
	ctx context.Context,
	paths []string,
	pathEpoch uint64,
) (context.Context, *frontendOperation) {
	op, err := a.beginFrontendPathsAtEpochContext(ctx, paths, pathEpoch)
	if err != nil {
		return ctx, nil
	}
	participant := &frontendOperationParticipant{op: op}
	return context.WithValue(ctx, frontendOperationContextKey{}, participant), op
}

func (a *attach) beginFrontendPathsAtEpochContext(
	ctx context.Context,
	paths []string,
	pathEpoch uint64,
) (*frontendOperation, error) {
	op := &frontendOperation{attach: a, paths: paths, pathEpoch: pathEpoch}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	stopWake := context.AfterFunc(ctx, func() {
		a.frontendGateMu.Lock()
		a.frontendGateCond.Broadcast()
		a.frontendGateMu.Unlock()
	})
	defer stopWake()
	for {
		if err := ctx.Err(); err != nil {
			a.frontendGateMu.Unlock()
			return nil, err
		}
		blocked := false
		for scope := range a.frontendHandoffs {
			if op.pathEpoch != a.frontendPathEpoch.Load() ||
				operationOverlapsScope(paths, scope) {
				blocked = true
				break
			}
		}
		if !blocked {
			break
		}
		a.frontendGateCond.Wait()
	}
	a.frontendActive[op] = struct{}{}
	op.gateActive = true
	op.participants = 1
	a.frontendGateMu.Unlock()
	return op, nil
}

// ── THE PUBLICATION ACTIVATION PROTOCOL ─────────────────────────────────────
//
// Membership of the active publication set is acquired in two separable steps,
// and the split is the whole point:
//
//	RESERVE   (reserveFrontendOperation / reserveFrontendExtension)
//	          The request joins its logical operation SUSPENDED. It counts as
//	          a participant — so the operation is not finished while it runs,
//	          which is what keeps a recall holding a namespace mirror from
//	          deadlocking against the operation it is waiting to publish — but
//	          it is not a member of the active set, so it blocks no handoff and
//	          waits for none. Reservation waits for NOTHING and holds NOTHING.
//	          It happens BEFORE admission, so every admission callback (in
//	          particular the delegation release that reaches OnHandoffStart)
//	          carries this operation's identity and cannot wait on it.
//
//	ACTIVATE  (tryActivateFrontendParticipant / awaitFrontendActivation)
//	          Becoming a member is ATTEMPTED, never waited for, while the
//	          frontend mirrors are held. If a handoff owns an operand scope the
//	          attempt fails, the caller drops the mirrors, waits SUSPENDED for
//	          the gate to open, and retries.
//
// The discipline both halves enforce: no gate wait is ever paid with the
// frontend serialization lock, a name stripe or a per-handle gate held. Phase 2
// used to take the mirrors and then wait — for a handoff that spans a
// delegation release's authority round trips — so a write holding the per-handle
// frontend RLock blocked the close(2) that needs it exclusively and depends on
// nothing remote. It is the same unwind discipline ErrLaneChanged already obeys,
// applied to the publication gate.
//
// Liveness: a suspended participant is never a member of the active set, so a
// handoff waiting on the active set always makes progress while a reservation
// waits. Each retry can only be defeated by a NEW handoff starting in the
// window between the wait returning and the mirrors being retaken, and the
// operation deadline (phase 0) bounds the whole loop regardless.

// reserveFrontendOperation creates a logical operation with its first
// participant already suspended. It never waits: the created operation is not
// a member of the active publication set until it activates.
func (a *attach) reserveFrontendOperation(
	paths []string,
	pathEpoch uint64,
) (*frontendOperation, *frontendOperationParticipant) {
	op := &frontendOperation{attach: a, paths: paths, pathEpoch: pathEpoch}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	op.participants = 1
	op.suspended = 1
	a.frontendGateMu.Unlock()
	return op, &frontendOperationParticipant{
		op:           op,
		suspendDepth: 1,
		// The creating participant's paths ARE the operation's paths.
		merged: true,
	}
}

// reserveFrontendExtension admits another request belonging to an already live
// logical FSKit callback, suspended and without waiting. Its operand scopes
// stay on the participant until activation merges them (see pendingPaths).
//
// It never RETRACTS the operation's existing membership. A reservation is only
// a statement about the arriving request — that IT is not yet a member — and
// says nothing about the callback, whose earlier reply may already be exposed
// and unacknowledged. Deactivating here (the rule finishFrontendParticipant and
// suspendFrontendOperation apply when an ACTIVE participant leaves the set)
// would let a delegation handoff cross that unacknowledged reply, and would
// then leave this reservation unable to activate at all, since the handoff it
// released now owns the scope. The active set is retracted only by a
// participant that was in it.
func (a *attach) reserveFrontendExtension(
	op *frontendOperation,
	paths []string,
	pathEpoch uint64,
) (*frontendOperationParticipant, error) {
	if op == nil || op.attach != a {
		return nil, fmt.Errorf("portablefsd: invalid logical frontend operation")
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if op.completed {
		a.frontendGateMu.Unlock()
		return nil, net.ErrClosed
	}
	op.participants++
	op.suspended++
	a.frontendGateMu.Unlock()
	return &frontendOperationParticipant{
		op:           op,
		suspendDepth: 1,
		pendingPaths: paths,
		pendingEpoch: pathEpoch,
	}, nil
}

// activationBlockedLocked reports whether a handoff currently owns a scope this
// participant needs. It reproduces, exactly, the two predicates the blocking
// entry points used before the split:
//
//   - an unmerged EXTENSION uses the extension rule — a handoff that already
//     waits on this operation must let its later requests through
//     (alreadyOwned), or the callback could never reach its one publication
//     acknowledgement; a handoff disjoint from the operation's original scope
//     still holds back a newly overlapping extension until ownership is stable;
//   - a merged participant (the operation's creator, or a request resuming
//     after an unwind) uses the gate-entry rule over the operation's own scopes.
func (a *attach) activationBlockedLocked(participant *frontendOperationParticipant) bool {
	op := participant.op
	currentEpoch := a.frontendPathEpoch.Load()
	for scope := range a.frontendHandoffs {
		if participant.merged {
			if op.pathEpoch != currentEpoch || operationOverlapsScope(op.paths, scope) {
				return true
			}
			continue
		}
		newOverlaps := participant.pendingEpoch != currentEpoch ||
			operationOverlapsScope(participant.pendingPaths, scope)
		alreadyOwned := op.gateActive &&
			(op.pathEpoch != currentEpoch || operationOverlapsScope(op.paths, scope))
		if newOverlaps && !alreadyOwned {
			return true
		}
	}
	return false
}

func (a *attach) mergeParticipantPathsLocked(participant *frontendOperationParticipant) {
	if participant.merged {
		return
	}
	op := participant.op
	seen := make(map[string]struct{}, len(op.paths)+len(participant.pendingPaths))
	for _, path := range op.paths {
		seen[path] = struct{}{}
	}
	for _, path := range participant.pendingPaths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		op.paths = append(op.paths, path)
	}
	if op.pathEpoch != participant.pendingEpoch {
		// Zero cannot equal a real namespace epoch, so any later handoff
		// conservatively treats this logical operation as mount-wide.
		op.pathEpoch = 0
	}
	participant.merged = true
	participant.pendingPaths = nil
}

// tryActivateFrontendParticipant attempts, WITHOUT WAITING, to make a reserved
// participant a member of the active publication set. It is the only call the
// dispatcher makes with the frontend mirrors held.
//
// ok reports membership: true means the request may proceed to its handler.
// A nonpublishing participant is permanently suspended and reports true without
// ever joining the set.
func (a *attach) tryActivateFrontendParticipant(
	participant *frontendOperationParticipant,
) (ok bool, err error) {
	if participant == nil || participant.op == nil || participant.op.attach != a {
		return true, nil
	}
	if participant.nonpublishing {
		return true, nil
	}
	op := participant.op
	a.frontendGateMu.Lock()
	defer a.frontendGateMu.Unlock()
	a.initFrontendGateLocked()
	if op.completed {
		return false, net.ErrClosed
	}
	if participant.finished || participant.suspendDepth == 0 {
		// Already active (or retired); nothing to do.
		return true, nil
	}
	if participant.suspendDepth > 1 {
		// A nested suspend inside a handler owns the outer depth; it resumes
		// through its own closure, not here.
		participant.suspendDepth--
		return true, nil
	}
	if a.activationBlockedLocked(participant) {
		return false, nil
	}
	a.mergeParticipantPathsLocked(participant)
	participant.suspendDepth = 0
	if op.suspended > 0 {
		op.suspended--
	}
	if !op.gateActive {
		a.frontendActive[op] = struct{}{}
		op.gateActive = true
	}
	a.frontendGateCond.Broadcast()
	return true, nil
}

// awaitFrontendActivation waits, holding NO frontend mirror, until this
// participant's activation could succeed. It does not activate: the caller
// retakes the mirrors and reattempts, so the window between them is covered by
// the retry rather than by holding a lock across the wait.
func (a *attach) awaitFrontendActivation(
	ctx context.Context,
	participant *frontendOperationParticipant,
) error {
	if participant == nil || participant.op == nil ||
		participant.op.attach != a || participant.nonpublishing {
		return nil
	}
	op := participant.op
	a.frontendGateMu.Lock()
	defer a.frontendGateMu.Unlock()
	a.initFrontendGateLocked()
	stopWake := context.AfterFunc(ctx, func() {
		a.frontendGateMu.Lock()
		a.frontendGateCond.Broadcast()
		a.frontendGateMu.Unlock()
	})
	defer stopWake()
	for {
		if op.completed {
			return net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if participant.finished || participant.suspendDepth == 0 {
			return nil
		}
		if !a.activationBlockedLocked(participant) {
			return nil
		}
		a.frontendGateCond.Wait()
	}
}

// enterFrontendMirrors is phase 2, once, for every request.
//
// It takes the frontend mirrors and makes this request a member of the active
// publication set, and it does so in the only order that never waits under a
// mirror:
//
//	take the mirrors (this request is SUSPENDED, so it blocks no handoff)
//	ATTEMPT activation, nonblocking
//	if blocked: drop the mirrors, wait SUSPENDED, retry
//
// Taking the mirrors first is what makes this safe. The alternative — activate
// first, then take the mirrors — puts this request in the active publication
// set while it waits for a name stripe or a handle gate, so a handoff started
// by a recall that already holds a namespace mirror waits on this request while
// this request waits on that recall. Suspended-while-holding-mirrors closes that
// cycle: a handoff never waits on a suspended participant, so it always
// completes and always lets the retry through.
//
// The returned unlock is nil only when the request takes no mirrors at all.
func (a *attach) enterFrontendMirrors(
	ctx context.Context,
	body any,
	participant *frontendOperationParticipant,
) (func(), error) {
	for {
		unlockRequest := a.lockFrontendRequest(body)
		activated, err := a.tryActivateFrontendParticipant(participant)
		if err != nil {
			if unlockRequest != nil {
				unlockRequest()
			}
			return nil, err
		}
		if activated {
			return unlockRequest, nil
		}
		if unlockRequest != nil {
			unlockRequest()
		}
		if err := a.awaitFrontendActivation(ctx, participant); err != nil {
			return nil, err
		}
	}
}

// suspendFrontendParticipant returns an ACTIVE participant to the reserved,
// suspended state. The ErrLaneChanged unwind uses it so the second pass's
// claim and delegation release are paid exactly where the first pass's were:
// holding nothing, out of the publication set.
func (a *attach) suspendFrontendParticipant(participant *frontendOperationParticipant) {
	if participant == nil || participant.op == nil ||
		participant.op.attach != a || participant.nonpublishing {
		return
	}
	op := participant.op
	a.frontendGateMu.Lock()
	if !op.completed && !participant.finished && participant.suspendDepth == 0 {
		participant.suspendDepth = 1
		op.suspended++
		a.retractIdleOperationLocked(op)
		a.frontendGateCond.Broadcast()
	}
	a.frontendGateMu.Unlock()
}

// joinFrontendOperationSuspended admits a NONPUBLISHING request into an
// already active logical FSKit callback without ever making it a member of
// the active publication set.
//
// close(2) is the motivating case. FSKit lets one framework callback issue
// several daemon requests, and the pfslocal client shares that callback's
// operation ID with every one of them — including requests that publish
// nothing. Admitting those as ordinary participants coupled them to
// delegation handoffs in both directions: they blocked handoffs while active,
// and the resume half of suspendFrontendOperation held them until every
// overlapping handoff ended. A handoff spans the release's authority round
// trips, so with a slow or dead uplink that wait is unbounded and a close(2)
// with an admitted write-back backlog stalls behind its own scope's drain.
//
// A request that cannot publish cacheable state has nothing to keep coherent,
// so it enters already suspended and stays that way for its whole lifetime.
// It still counts as a participant, which is what prevents a recall that owns
// a namespace mirror lock from deadlocking against the operation it is
// waiting to publish, and finishFrontendParticipant retires both counters.
func (a *attach) joinFrontendOperationSuspended(
	op *frontendOperation,
) (*frontendOperationParticipant, error) {
	if op == nil || op.attach != a {
		return nil, fmt.Errorf("portablefsd: invalid logical frontend operation")
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if op.completed {
		a.frontendGateMu.Unlock()
		return nil, net.ErrClosed
	}
	op.participants++
	op.suspended++
	a.retractIdleOperationLocked(op)
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
	return &frontendOperationParticipant{
		op:            op,
		suspendDepth:  1,
		nonpublishing: true,
	}, nil
}

func (a *attach) finishFrontendOperation(op *frontendOperation) {
	if op == nil {
		return
	}
	a.frontendGateMu.Lock()
	if !op.completed {
		op.completed = true
		if op.gateActive {
			a.retractFromPublicationSetLocked(op)
			op.gateActive = false
		}
		if a.frontendGateCond != nil {
			a.frontendGateCond.Broadcast()
		}
	}
	a.frontendGateMu.Unlock()
}

func (a *attach) finishFrontendParticipant(participant *frontendOperationParticipant) {
	if participant == nil || participant.op == nil || participant.op.attach != a {
		return
	}
	a.frontendGateMu.Lock()
	if participant.finished {
		a.frontendGateMu.Unlock()
		return
	}
	participant.finished = true
	op := participant.op
	if participant.suspendDepth > 0 {
		participant.suspendDepth = 0
		if op.suspended > 0 {
			op.suspended--
		}
	}
	if op.participants > 0 {
		op.participants--
	}
	a.retractIdleOperationLocked(op)
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
}

// suspendFrontendOperation moves a request that is about to wait for a
// delegation release out of the pre-handoff publication set. The operation
// itself runs only after that release, so its eventual reply belongs to the
// post-handoff view. Re-entry blocks until the release hook has reopened the
// overlapping scopes, preventing both self-deadlock and joined-waiter cycles.
func (a *attach) suspendFrontendOperation(ctx context.Context) func() {
	participant, ok := ctx.Value(frontendOperationContextKey{}).(*frontendOperationParticipant)
	if !ok || participant.op == nil || participant.op.attach != a {
		return nil
	}
	op := participant.op
	a.frontendGateMu.Lock()
	if !op.completed && !participant.finished {
		if participant.suspendDepth == 0 {
			op.suspended++
		}
		participant.suspendDepth++
	}
	if a.retractIdleOperationLocked(op) {
		a.frontendGateCond.Broadcast()
	}
	a.frontendGateMu.Unlock()
	resumed := false
	return func() {
		a.frontendGateMu.Lock()
		defer a.frontendGateMu.Unlock()
		if resumed {
			return
		}
		resumed = true
		stopWake := context.AfterFunc(ctx, func() {
			a.frontendGateMu.Lock()
			a.frontendGateCond.Broadcast()
			a.frontendGateMu.Unlock()
		})
		defer stopWake()
		if participant.finished || participant.suspendDepth == 0 {
			return
		}
		participant.suspendDepth--
		if participant.suspendDepth > 0 {
			return
		}
		if participant.nonpublishing {
			// A nonpublishing participant is suspended for its whole
			// lifetime and never re-enters the active publication set, so it
			// must never wait for an overlapping handoff to end.
			participant.suspendDepth = 1
			return
		}
		for !op.completed {
			if ctx.Err() != nil {
				if op.suspended > 0 {
					op.suspended--
				}
				a.frontendGateCond.Broadcast()
				return
			}
			blocked := false
			for scope := range a.frontendHandoffs {
				if op.pathEpoch != a.frontendPathEpoch.Load() ||
					operationOverlapsScope(op.paths, scope) {
					blocked = true
					break
				}
			}
			if !blocked {
				if op.suspended > 0 {
					op.suspended--
				}
				if !op.gateActive {
					a.frontendActive[op] = struct{}{}
					op.gateActive = true
				}
				a.frontendGateCond.Broadcast()
				return
			}
			a.frontendGateCond.Wait()
		}
	}
}

func (a *attach) startFrontendHandoff(ctx context.Context, scope string) error {
	var own *frontendOperationParticipant
	if participant, ok := ctx.Value(frontendOperationContextKey{}).(*frontendOperationParticipant); ok &&
		participant.op != nil && participant.op.attach == a {
		own = participant
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if a.frontendGateErr != nil {
		err := a.frontendGateErr
		a.frontendGateMu.Unlock()
		return err
	}
	stopWake := context.AfterFunc(ctx, func() {
		a.frontendGateMu.Lock()
		a.frontendGateCond.Broadcast()
		a.frontendGateMu.Unlock()
	})
	defer stopWake()
	for {
		if a.frontendGateErr != nil {
			err := a.frontendGateErr
			a.frontendGateMu.Unlock()
			return err
		}
		if err := ctx.Err(); err != nil {
			a.frontendGateMu.Unlock()
			if errors.Is(err, context.DeadlineExceeded) {
				// The release's own budget, not a cancellation. An overlapping
				// handoff still owns this scope: transient and scope-local,
				// exactly like an unsettled barrier, and it must NOT surface as
				// a cancellation the release would treat as terminal.
				return &errPublicationUnsettled{scope: scope, overBudget: true}
			}
			return err
		}
		overlap := false
		for activeScope := range a.frontendHandoffs {
			if scopesOverlap(activeScope, scope) {
				overlap = true
				break
			}
		}
		if !overlap {
			break
		}
		a.frontendGateCond.Wait()
	}
	a.frontendHandoffs[scope]++
	removeHandoff := func() {
		if a.frontendHandoffs[scope] <= 1 {
			delete(a.frontendHandoffs, scope)
		} else {
			a.frontendHandoffs[scope]--
		}
		a.frontendGateCond.Broadcast()
	}
	// THE BOUNDED PUBLICATION WAIT.
	//
	// The drain immediately above this in writeback.(*Engine).finishRelease has
	// been StallVerdict-bounded since round 3; this wait had no verdict at all.
	// It runs under the ENGINE's context by design (a cancelled request must not
	// interrupt Checkin), so the bound cannot come from the caller — it has to
	// be the gate's own. publicationSettleWindow, measured from the gate's
	// PROGRESS clock, is that bound.
	//
	// ── PROGRESS IS THIS SCOPE'S BLOCKER SET, NOT THE MOUNT'S CLOCK ──────────
	//
	// The rearm used to read a mount-wide retraction counter. Any operation
	// leaving the active set anywhere rearmed every waiting handoff, so
	// unrelated traffic in a disjoint subtree — an x/* publication retiring
	// every few hundred milliseconds — held this wait open forever while THIS
	// scope's blockers never changed. The settle window is supposed to bound a
	// wait on an event the daemon does not produce; measured against somebody
	// else's events it bounds nothing.
	//
	// So progress is defined on the identity of the blockers for THIS scope: a
	// blocker this wait has already seen leaving the set (acknowledged,
	// finished, or lost with its connection) is progress; a NEW blocker
	// arriving is not, and neither is anything happening off-scope. The set is
	// compared by operation identity, not by count, so one blocker retiring
	// while another joins still rearms — the gate really did advance — while a
	// steady-state blocker that never moves cannot be kept alive by traffic it
	// has nothing to do with.
	//
	// ── AND THE OUTER BUDGET IS ENFORCED ON THIS WAIT ────────────────────────
	//
	// startHandoffBounded's 20s release budget used to be checked only BETWEEN
	// calls, so a single invocation that never returned could not be bounded by
	// it at all. It now passes its absolute deadline on ctx, and this loop
	// treats reaching it exactly like the settle window expiring: a definite,
	// scoped, TRANSIENT refusal — never a cancellation error, which the release
	// would classify as terminal.
	var settleWake *time.Timer
	defer func() {
		if settleWake != nil {
			settleWake.Stop()
		}
	}()
	budget, hasBudget := ctx.Deadline()
	tracked := map[*frontendOperation]struct{}{}
	firstPass := true
	lastProgress := time.Now()
	for {
		if a.frontendGateErr != nil {
			err := a.frontendGateErr
			removeHandoff()
			a.frontendGateMu.Unlock()
			return err
		}
		blockers, live, current, fenceable := a.publicationBlockersLocked(scope, own)
		if blockers == 0 {
			for _, op := range fenceable {
				// The crossing is recorded HERE, under the same lock hold that
				// decided to take the handoff, and nowhere else. Recording it
				// inside the blocker probe would attach a debt to an operation
				// on every loop iteration, including iterations that then went
				// back to waiting and iterations that ended in a refusal — and
				// a debt for a handoff that never happened would invalidate
				// live, correct kernel state for no reason.
				//
				// RETRACTION IS THE PRIMARY ANSWER; THE FENCE IS THE BACKSTOP.
				//
				// retracted is what actually keeps the stale view out of the
				// kernel: every remaining reply this operation receives carries
				// the flag, the frontend discards what it collected instead of
				// handing it to the framework, and the syscall retries against
				// post-handoff state. Because that is a REFUSAL TO INSTALL
				// rather than a repair, there is no window in which an
				// application can read the crossed value at all.
				//
				// fenced stays because retraction depends on a frontend that
				// honours it. A frontend below the minor that introduced the
				// flag cannot connect at all, so this is not a compatibility
				// fallback — it is the answer for the residue no publication
				// contract covers: state the crossed operation had already
				// caused to be cached before this reply, and any future
				// frontend whose retraction is partial. Discharge makes it an
				// ORDERED repair through the daemon's own kernel refresh, not
				// an event nothing subscribes to; see
				// dischargeFrontendPublicationFence.
				op.retracted = true
				op.fenced = append(op.fenced, scope)
			}
			break
		}
		if !firstPass {
			for op := range tracked {
				if _, still := current[op]; !still {
					// A blocker this wait was holding for is gone: the barrier
					// for THIS scope advanced.
					lastProgress = time.Now()
					break
				}
			}
		}
		tracked = current
		firstPass = false
		unsettled := time.Since(lastProgress)
		overBudget := hasBudget && !time.Now().Before(budget)
		if unsettled >= publicationSettleWindow || overBudget {
			removeHandoff()
			a.frontendGateMu.Unlock()
			return &errPublicationUnsettled{
				scope:      scope,
				blockers:   blockers,
				live:       live,
				unsettled:  unsettled,
				overBudget: overBudget && unsettled < publicationSettleWindow,
			}
		}
		if err := ctx.Err(); err != nil {
			removeHandoff()
			a.frontendGateMu.Unlock()
			return err
		}
		remaining := publicationSettleWindow - unsettled
		if hasBudget {
			if toBudget := time.Until(budget); toBudget < remaining {
				remaining = toBudget
			}
		}
		if remaining < publicationRecheckFloor {
			remaining = publicationRecheckFloor
		}
		// sync.Cond has no timed wait: arm a wake-up so the verdict above is
		// reached even when nothing at all happens on the gate. The timer is the
		// wake-up, the loop is the decision — the same split drainThrough uses
		// between stallRecheckDelay and StallVerdict.
		if settleWake == nil {
			settleWake = time.AfterFunc(remaining, func() {
				a.frontendGateMu.Lock()
				a.frontendGateCond.Broadcast()
				a.frontendGateMu.Unlock()
			})
		} else {
			settleWake.Reset(remaining)
		}
		a.frontendGateCond.Wait()
	}
	a.frontendGateMu.Unlock()
	return nil
}

// publicationBlockersLocked counts the members of the active publication set
// that hold back a handoff of scope, how many of them still have a handler
// running, and returns their IDENTITIES so the settle wait can measure progress
// against this scope's own barrier (see startFrontendHandoff). A blocker with
// no running handler is one the daemon has finished exposing: only the
// frontend's PublicationAck can retire it, which is exactly the wait
// publicationSettleWindow bounds. Caller holds frontendGateMu.
//
// ── SELF-EXCLUSION IS PER PARTICIPANT, NOT PER OPERATION ────────────────────
//
// own used to be the whole frontendOperation, and the loop skipped it outright.
// One FSKit framework callback can have SEVERAL requests in flight at once
// (frontendConn.reserveLogicalOperation admits each as another participant of
// the same operation ID, and each runs in its own handler goroutine), so
// excluding the operation excluded the initiator's SIBLINGS too: participant A
// triggered a delegation release while sibling B was still executing, and the
// handoff crossed B — B then published a pre-handoff view of state the new
// delegation holder believes is exclusively theirs.
//
// The exclusion that is actually needed is the initiator itself: it is inside
// the release, so waiting for it is a self-deadlock. Everything else about its
// operation must still block. So the operation is skipped only when own is the
// ONLY thing keeping it live.
//
// ── AN EXPOSED REPLY IS NEVER "NOTHING CAN CROSS IT NOW" ────────────────────
//
// This function used to skip the initiator's own operation outright whenever
// the initiator was the only thing keeping it live, and justified that with the
// claim that a reply a sibling had already exposed "happened BEFORE the handoff
// — nothing can cross it now". That claim is false, and it is the whole of
// finding 5. Exposure means the daemon WROTE the reply; it does not mean the
// kernel has it. The extension holds the sibling's values until its framework
// callback returns, which is after the initiator is answered, which is after
// this release completes. So the ordering the claim asserts is exactly
// inverted: Checkin lands, a new delegation holder mutates, and only THEN does
// the kernel install the sibling's pre-handoff view — permanently, because the
// peer's own invalidation was delivered and applied before that install and
// nothing contradicts it afterwards.
//
// The second half of the old justification is true and stays true: that
// acknowledgement is unreachable while the initiator runs. One PublicationAck
// per operation, emitted after the whole framework callback returns; the
// callback cannot return while one of its requests is parked in a release; the
// release cannot return without a verdict. Waiting is therefore a DETERMINISTIC
// cycle, not a race — and the shape is completely ordinary, since FSKit's
// removeItem callback issues a publishing getattr and then the remove that
// needs the delegation transition. Blocking would fail every `rm` that has to
// release a delegation.
//
// So the rule is neither "skip it" nor "wait for it". It turns on the one
// question that decides whether waiting is a wait at all: CAN THIS OPERATION'S
// ACKNOWLEDGEMENT STILL ARRIVE while this handoff owns the scope?
//
//   - a RUNNABLE participant means yes. The callback still has work the daemon
//     is not holding up, so it can finish and the acknowledgement can follow.
//     The operation blocks — this is round 8's live sibling, unchanged.
//   - NO runnable participant and NO exposed reply means the operation owes
//     nothing at all. It is skipped, exactly as before.
//   - NO runnable participant, an exposed reply, and PARTICIPANTS THAT ARE ALL
//     SUSPENDED means no. Every remaining request is parked — on a delegation
//     handoff or on a frontend mirror — so the callback cannot end and the
//     acknowledgement cannot be produced until this handoff releases the scope.
//     That is a cycle. The handoff crosses, against a recorded debt that
//     dischargeFrontendPublicationFence repairs the instant the acknowledgement
//     lands.
//   - NO participants at all and an exposed reply means yes again: the daemon
//     has no work left, the acknowledgement is in flight on a live socket, and
//     the bounded settle wait is a real wait with a real resolution. It blocks.
//
// The initiator counts as parked for this test even though its handler is
// running, because it is running INSIDE this release: waiting for it is the
// self-deadlock the per-participant self-exclusion exists to avoid.
//
// The crossing is never REFUSED, and that is deliberate. A refusal here is not
// a bound, it is the round-4 wedge reached by a new route: startHandoffBounded
// would retry a verdict that cannot change until its own budget expired,
// failRelease would record a definite failure, and the triggering syscall would
// answer EIO. So the fence is total — the daemon repairs what it crossed using
// the best statement it has rather than declining to cross. Where the operation
// published a nameable path the repair names that path; the conservative
// mount-wide publication scope IS the root path, so it repairs at the root.
// Either way the crossing is recorded and answered, which is strictly more than
// the exception this replaces ever did.
//
// fenceable is returned rather than recorded here so the debt is written by the
// caller at the moment it actually takes the handoff — never by a probe that
// then loops again, and never for a handoff that ends in a refusal, where a
// debt would invalidate live and correct kernel state for nothing.
func (a *attach) publicationBlockersLocked(
	scope string,
	own *frontendOperationParticipant,
) (blockers, live int, set map[*frontendOperation]struct{}, fenceable []*frontendOperation) {
	// A MOUNT THAT IS BEING TORN DOWN HAS NO KERNEL LEFT TO PROTECT.
	//
	// Every blocker here is an operation whose acknowledgement would tell the
	// daemon that the kernel has finished installing or discarding what the
	// operation published. The barrier exists to keep a delegation handoff from
	// crossing state the kernel is about to cache. Once the attach is detaching,
	// there is no "about to cache": the vnodes and their pages go away with the
	// mount, and the publication set is a set of statements about a cache that
	// is being destroyed.
	//
	// Waiting on it was therefore not conservative, it was unsatisfiable. The
	// final drain barrier a clean unmount runs takes a delegation release; the
	// release waited here for acknowledgements from a frontend that had nothing
	// left to acknowledge them for; the settle window expired; and the unmount
	// was refused with ZERO records unshipped — a healthy, idle, fully drained
	// mount that could only be detached with --force. Forcing a clean unmount is
	// how a durable recovery job gets parked for a volume that never needed one.
	//
	// The verdict is unchanged for every attach that is still serving. This is
	// the one state in which the acknowledgement is not merely late but MOOT.
	a.mu.RLock()
	detaching := a.detached || a.detachPrepared || a.detachForce || a.detachBarrier
	a.mu.RUnlock()
	if detaching {
		return 0, 0, map[*frontendOperation]struct{}{}, nil
	}
	epoch := a.frontendPathEpoch.Load()
	set = make(map[*frontendOperation]struct{}, len(a.frontendActive))
	for op := range a.frontendActive {
		if op.pathEpoch != epoch || operationOverlapsScope(op.paths, scope) {
			isOwn := own != nil && op == own.op
			liveHandlers := op.participants - op.suspended
			if isOwn && !own.finished && own.suspendDepth == 0 {
				// The initiator is still counted as a running handler by the
				// operation; it is the one thing that must not block.
				liveHandlers--
			}
			if liveHandlers <= 0 {
				switch {
				case op.published && op.carriers > 0:
					// A reply of this operation has already captured its
					// retraction verdict and its frame has not yet been written.
					// Crossing now would produce exactly the frame the crossing
					// needs to stamp — built before it, delivered after it — so
					// the handoff waits for the write instead. That wait is one
					// socket write to a peer that is blocked waiting for this very
					// frame, not the unreachable acknowledgement the fence exists
					// for, so it terminates. See frontendOperation.carriers.
					//
					// Only a PUBLISHED operation is held: a retraction that
					// reached an operation with no exposed reply is dropped by
					// frontendConn.captureRetraction anyway (the frontend would
					// have no connection to acknowledge it on), so blocking a
					// crossing for its carrier would buy nothing and would widen
					// the wait beyond the case the finding names.
				case op.published && op.participants > 0:
					// Parked participants only: the acknowledgement cannot be
					// produced until this handoff lets go of the scope.
					//
					// EVERY such operation is collected, not just the newest one
					// the map iteration happened to see. This was a single slot,
					// so two overlapping all-parked publications left one of them
					// crossed with NO record at all: not retracted, not repaired,
					// and permanently stale with nothing to contradict it. Map
					// iteration order made which one that was unpredictable.
					fenceable = append(fenceable, op)
					continue
				case op.published:
					// Nothing left on the daemon's side; the acknowledgement is
					// in flight. Block, bounded by the settle window.
				case isOwn:
					// Owes nothing and the initiator is all that is left. The
					// original self-exclusion, unchanged.
					continue
				}
			}
			blockers++
			if liveHandlers > 0 {
				live++
			}
			set[op] = struct{}{}
		}
	}
	return blockers, live, set, fenceable
}

func (a *attach) endFrontendHandoff(scope string) {
	a.frontendGateMu.Lock()
	if a.frontendHandoffs[scope] <= 1 {
		delete(a.frontendHandoffs, scope)
	} else {
		a.frontendHandoffs[scope]--
	}
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
}

// frontendRequestPublishes is the Go-side copy of the frozen pfslocal
// publication classification. These requests may install namespace,
// metadata, xattr, or content state in a frontend cache and therefore require
// a logical operation ID and one post-callback acknowledgement.
func frontendRequestPublishes(body any) bool {
	switch body.(type) {
	case *pfslocal.LookupRequest,
		*pfslocal.EnumerateRequest,
		*pfslocal.GetAttrRequest,
		*pfslocal.SetAttrRequest,
		*pfslocal.ReadRequest,
		*pfslocal.WriteRequest,
		*pfslocal.CreateRequest,
		*pfslocal.MkdirRequest,
		*pfslocal.RemoveRequest,
		*pfslocal.RenameRequest,
		*pfslocal.SymlinkRequest,
		*pfslocal.ReadlinkRequest,
		*pfslocal.HardLinkRequest,
		*pfslocal.XattrGetRequest,
		*pfslocal.XattrSetRequest,
		*pfslocal.XattrListRequest,
		*pfslocal.XattrRemoveRequest:
		return true
	default:
		return false
	}
}

func (a *attach) frontendOperationPaths(body any) ([]string, uint64, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	pathEpoch := a.frontendPathEpoch.Load()
	itemPath := func(item pfslocal.Item) (string, bool) {
		rec := a.items[item.ItemID]
		if rec == nil || rec.item.ItemGeneration != item.ItemGeneration {
			return "", false
		}
		return rec.path, true
	}
	itemPaths := func(item pfslocal.Item) ([]string, bool) {
		rec := a.items[item.ItemID]
		if rec == nil || rec.item.ItemGeneration != item.ItemGeneration {
			return nil, false
		}
		aliases := a.itemAliases[item.ItemID]
		paths := make([]string, 0, len(aliases))
		for path := range aliases {
			paths = append(paths, path)
		}
		return paths, len(paths) != 0
	}
	handlePaths := func(handle uint64) ([]string, bool) {
		rec := a.handles[handle]
		if rec == nil {
			return nil, false
		}
		if rec.itemID == 0 {
			return []string{rec.path}, true
		}
		aliases := a.itemAliases[rec.itemID]
		paths := make([]string, 0, len(aliases))
		for path := range aliases {
			paths = append(paths, path)
		}
		if len(paths) == 0 {
			// The retained path on an unlinked or overwritten open handle is
			// only an authority addressing hint. It may now name another
			// inode, so treating it as publication scope would let a detached
			// write cross a handoff for a real replacement. Unknown is the
			// exact conservative scope until a genuine alias is discovered.
			paths = append(paths, "")
		}
		return paths, true
	}
	child := func(dir pfslocal.Item, name []byte) (string, string, bool) {
		parent, ok := itemPath(dir)
		if !ok {
			return "", "", false
		}
		path, eno := cleanChild(parent, name)
		return parent, path, eno == 0
	}
	known := func(paths ...string) ([]string, uint64, bool) {
		return paths, pathEpoch, true
	}
	knownSlice := func(paths []string) ([]string, uint64, bool) {
		return paths, pathEpoch, true
	}
	// unknown is the conservative mount-wide scope: a request whose
	// publication target cannot be resolved from the current bindings (a
	// stale Item generation, an unresolvable child name, a handle with no
	// live alias) and the per-inode read publishers (Lookup, Enumerate)
	// whose path-narrowed scopes would race already-passed handoffs of
	// hard-link aliases.
	unknown := func() ([]string, uint64, bool) { return []string{""}, pathEpoch, true }
	withKnownAliases := func(paths []string, candidates ...string) []string {
		seen := make(map[string]struct{}, len(paths))
		for _, path := range paths {
			seen[path] = struct{}{}
		}
		for _, candidate := range candidates {
			rec := a.paths[candidate]
			if rec == nil {
				continue
			}
			for alias := range a.itemAliases[rec.item.ItemID] {
				if _, ok := seen[alias]; ok {
					continue
				}
				seen[alias] = struct{}{}
				paths = append(paths, alias)
			}
		}
		return paths
	}

	switch req := body.(type) {
	case *pfslocal.LookupRequest:
		// Deliberately mount-wide, NOT the looked-up name. A lookup (and a
		// readdir-plus page) publishes per-INODE attributes obtained through a
		// per-PATH delegation, and a hard link can alias that inode under a
		// scope whose handoff has ALREADY passed this gate — a passed handoff
		// cannot be re-blocked, so a path-narrowed scope here can publish a
		// pre-handoff view of an inode the new delegation holder believes is
		// exclusively theirs. The path epoch only widens operations that
		// install NEW bindings; it cannot protect aliases that were already
		// known. Until an inode-identity gate exists that both handoffs and
		// reply publication join, these two read publishers stay mount-wide.
		return unknown()
	case *pfslocal.EnumerateRequest:
		// Mount-wide for the same inode-aliasing reason as Lookup: a
		// readdir-plus page publishes child attributes, and any child can be
		// hard-linked under an already-handed-off scope.
		return unknown()
	case *pfslocal.GetAttrRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.SetAttrRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.ReadRequest:
		paths, ok := handlePaths(req.Handle)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.WriteRequest:
		paths, ok := handlePaths(req.Handle)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.CreateRequest:
		parent, path, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		return known(parent, path)
	case *pfslocal.MkdirRequest:
		parent, path, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		return known(parent, path)
	case *pfslocal.RemoveRequest:
		parent, path, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		return knownSlice(withKnownAliases([]string{parent, path}, path))
	case *pfslocal.RenameRequest:
		fromParent, from, fromOK := child(req.FromDir, req.FromName)
		toParent, to, toOK := child(req.ToDir, req.ToName)
		if !fromOK || !toOK {
			return unknown()
		}
		return knownSlice(withKnownAliases(
			[]string{fromParent, from, toParent, to},
			from,
			to,
		))
	case *pfslocal.SymlinkRequest:
		parent, path, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		return known(parent, path)
	case *pfslocal.ReadlinkRequest:
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.HardLinkRequest:
		sources, sourceOK := itemPaths(req.Item)
		parent, path, targetOK := child(req.Dir, req.Name)
		if !sourceOK || !targetOK {
			return unknown()
		}
		return known(append(sources, parent, path)...)
	case *pfslocal.XattrGetRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrSetRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrListRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrRemoveRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	default:
		// Open/close/fsync/sync/statfs/reclaim/event operations do not
		// publish namespace, metadata, xattr, or content cache state.
		if frontendRequestPublishes(body) {
			return unknown()
		}
		return nil, pathEpoch, false
	}
}

func pathWithinScope(p, scope string) bool {
	return scope == "" || p == scope || strings.HasPrefix(p, scope+"/")
}

func (a *attach) refreshKernelItemExact(ctx context.Context, itemID uint64) error {
	return a.refreshKernelItemExactMode(ctx, itemID, true)
}

func (a *attach) refreshKernelItemExactMode(
	ctx context.Context,
	itemID uint64,
	requireAuthorityIdentity bool,
) error {
	return a.refreshKernelItemExactPass(ctx, itemID, requireAuthorityIdentity, false)
}

// refreshKernelItemExactPass is the exact transaction, in one of two modes.
//
// yieldToMutations takes the item's intent DEFERENTIALLY (refreshintent.go): an
// application size mutation queueing behind this pass preempts it, the pass's
// own context is cancelled, and it returns errRefreshIntentPreempted having
// touched nothing. Only the crossed-scope repair asks for that; every barrier
// caller runs the exclusive mode, unchanged.
//
// The preemption is delivered by CANCELLING THE PASS CONTEXT rather than by a
// check the pass consults at the top of each attempt. That is deliberate: every
// wait inside the pass — the authority sample's own retries, the sample RPC, the
// inter-attempt coalesce — is already context-aware, so one cancellation unwinds
// all of them at once and the application's wait is a wakeup rather than a
// polling interval. The one region that is not cancellable is the pinned
// ftruncate, and preemption is refused while a pin is installed for exactly that
// reason.
func (a *attach) refreshKernelItemExactPass(
	ctx context.Context,
	itemID uint64,
	requireAuthorityIdentity bool,
	yieldToMutations bool,
) (err error) {
	// THE INTENT COMES FIRST, AND IT IS NOT ONE OF THE ATTEMPTS.
	//
	// Reservation contention is not a failure to converge, and spending
	// stale-sample retries on it made the two indistinguishable: one ordinary
	// mutation held past this loop's ≈1.025s budget, or a stream of overlapping
	// writers with no slow mutation at all, exhausted the transaction — and the
	// caller turns that into failCoherence, which is terminal. So the pass
	// declares its intent and WAITS for the item to drain, under a bound that
	// is a property of the reservation holders rather than of this loop, before
	// spending a single attempt. From here on no reservation can appear on the
	// item, so the attempts below are free to be about what they were always
	// about: racing the authority sample, not racing local writers.
	releaseIntent, preempt, err := a.acquireRefreshIntentMode(ctx, itemID, yieldToMutations)
	if err != nil {
		if errors.Is(err, errRefreshIntentPreempted) {
			return err
		}
		return fmt.Errorf("portablefsd: exact kernel refresh item %d: %w", itemID, err)
	}
	defer releaseIntent()
	if yieldToMutations {
		passCtx, cancelPass := context.WithCancel(ctx)
		defer cancelPass()
		go func() {
			select {
			case <-preempt:
				cancelPass()
			case <-passCtx.Done():
			}
		}()
		ctx = passCtx
		defer func() {
			// The pass's own error is whatever the cancellation produced; the
			// CAUSE is what the caller has to act on, and preemption is not a
			// failure. Rewriting it here keeps every return path honest without
			// threading the distinction through each of them.
			if err != nil && preemptedNow(preempt) {
				err = errRefreshIntentPreempted
			}
		}()
	}
	// A concurrent application write can advance the composed view between
	// sample, marked truncate, and verification. Re-run that optimistic
	// transaction a bounded number of times; this is ordering against a live
	// writer, not recovery or a fallback. Failure to establish one stable
	// point fail-freezes the attach at the caller.
	for attempt := 0; attempt <= staleSampleRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("portablefsd: exact kernel refresh item %d: %w", itemID, err)
		}
		if a.refreshKernelItemStateComposedModeContext(
			ctx, a.mountPath, itemID, requireAuthorityIdentity,
		) {
			return nil
		}
		if attempt != staleSampleRetries {
			select {
			case <-ctx.Done():
				return fmt.Errorf("portablefsd: exact kernel refresh item %d: %w", itemID, ctx.Err())
			case <-time.After(refreshCoalesce):
			}
		}
	}
	return fmt.Errorf(
		"portablefsd: exact kernel refresh item %d did not converge after %d ordered attempts",
		itemID, staleSampleRetries+1,
	)
}

func (a *attach) exactKernelRefresh(ctx context.Context, itemID uint64) error {
	return a.exactKernelRefreshMode(ctx, itemID, true)
}

func (a *attach) exactKernelRefreshMode(
	ctx context.Context,
	itemID uint64,
	requireAuthorityIdentity bool,
) error {
	release, err := a.acquireKernelRefreshGate(ctx, itemID)
	if err != nil {
		return err
	}
	defer release()
	if a.testExactKernelRefresh != nil {
		return a.testExactKernelRefresh(ctx, itemID)
	}
	return a.refreshKernelItemExactMode(ctx, itemID, requireAuthorityIdentity)
}

// exactKernelRefreshYielding is exactKernelRefreshMode for the crossed-scope
// repair: a DEFERENTIAL pass that stands aside for application size mutations.
//
// The per-stripe gate is still taken, and taking it is safe here for the reason
// it always was — a pass waiting on the gate holds no claim on any item, so it
// starves nobody — and the wait is bounded by ctx like every other.
func (a *attach) exactKernelRefreshYielding(ctx context.Context, itemID uint64) error {
	release, err := a.acquireKernelRefreshGate(ctx, itemID)
	if err != nil {
		return err
	}
	defer release()
	if a.testExactKernelRefresh != nil {
		return a.testExactKernelRefresh(ctx, itemID)
	}
	// requireAuthorityIdentity is false: a crossed scope's item may have been
	// renamed or replaced by the peer that took the delegation, and a namespace
	// transition is owned by namespace handling rather than by this repair. The
	// exact-identity claim belongs to a RelatedInos refresh, which is making a
	// stronger statement than this one.
	return a.refreshKernelItemExactPass(ctx, itemID, false, true)
}

// preemptedNow reports whether a deferential pass's preemption has already been
// announced. It never blocks.
func preemptedNow(preempt <-chan struct{}) bool {
	if preempt == nil {
		return false
	}
	select {
	case <-preempt:
		return true
	default:
		return false
	}
}

func (a *attach) acquireKernelRefreshGate(
	ctx context.Context,
	itemID uint64,
) (func(), error) {
	stripe := itemID & 63
	a.kernelRefreshGateMu.Lock()
	gate := a.kernelRefreshGates[stripe]
	if gate == nil {
		gate = make(chan struct{}, 1)
		gate <- struct{}{}
		a.kernelRefreshGates[stripe] = gate
	}
	a.kernelRefreshGateMu.Unlock()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"portablefsd: exact kernel refresh item %d gate: %w", itemID, ctx.Err(),
		)
	case <-gate:
		return func() { gate <- struct{}{} }, nil
	}
}

// refreshLocalSample reads the exact composed size for p. It keeps the
// version-floor guard on the shared lane and returns immediately for
// a delegated overlay sample (version zero), whose read permit already fenced
// the release handoff.
func refreshLocalSample(vol *clientcore.Volume, p string) (size int64, version uint64, generation uint64, outcome refreshSampleOutcome) {
	return refreshLocalSampleAuthority(vol, p, 0)
}

func refreshLocalSampleAuthority(
	vol *clientcore.Volume,
	p string,
	expectedAuthorityIno uint64,
) (size int64, version uint64, generation uint64, outcome refreshSampleOutcome) {
	return refreshLocalSampleAuthorityContext(
		context.Background(), vol, p, expectedAuthorityIno,
	)
}

func refreshLocalSampleAuthorityContext(
	ctx context.Context,
	vol *clientcore.Volume,
	p string,
	expectedAuthorityIno uint64,
) (size int64, version uint64, generation uint64, outcome refreshSampleOutcome) {
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return 0, 0, 0, refreshSampleRetry
		}
		attr, ver, gen, st := vol.CoherenceSample(ctx, p)
		if st != fsproto.OK {
			if st == fsproto.ENOENT || st == fsproto.ENOTDIR {
				return 0, 0, 0, refreshSampleTerminal
			}
			return 0, 0, 0, refreshSampleRetry
		}
		// Only regular files have kernel content pages and a size that may
		// safely be refreshed. In particular, never drive truncate through a
		// symlink: its target may name a host path.
		if expectedAuthorityIno != 0 && attr.Ino != expectedAuthorityIno {
			return 0, 0, 0, refreshSampleObsolete
		}
		if attr.Kind != "file" {
			return 0, 0, 0, refreshSampleNonRegular
		}
		knownGen, knownVer := vol.VersionCache.GenAndVersion(p)
		if ver == 0 && gen == 0 {
			return attr.Size, 0, 0, refreshSampleReady
		}
		if gen != 0 && gen == knownGen && ver >= knownVer {
			return attr.Size, ver, gen, refreshSampleReady
		}
		if attempt >= staleSampleRetries {
			return 0, 0, 0, refreshSampleRetry
		}
		select {
		case <-ctx.Done():
			return 0, 0, 0, refreshSampleRetry
		case <-time.After(refreshCoalesce):
		}
	}
}

// retireExpectedTruncate removes the marker installed under seq, if it is still
// the marker bound to p. Identity is the sequence number: a successor installed
// for the same path by a concurrent refresh pass belongs to that pass.
func (a *attach) retireExpectedTruncate(p string, seq uint64) {
	a.mu.Lock()
	if current, exists := a.expectedTruncates[p]; exists && current.seq == seq {
		delete(a.expectedTruncates, p)
	}
	a.mu.Unlock()
}

// expectedTruncateLive reports whether note is still a valid claim of
// daemon provenance at now.
//
// A PINNED note is valid unconditionally: the refresh that installed it has not
// returned, so the request being classified against it can only be that
// refresh's own upcall. Elapsed time says nothing about provenance and must
// never be allowed to overrule it — that reinterpretation is exactly how an
// internal refresh became a real truncate of a file another writer had extended.
func expectedTruncateLive(note expectedTruncate, now time.Time) bool {
	return note.pinned || now.Before(note.deadline)
}

// matchesExpectedTruncate reports whether req is a size set that a refresh
// window could conceivably be about at all.
//
// Anything touching mode, ownership or flags is a real application setattr and
// leaves here immediately: the daemon's refresh never carries one, and a
// request carrying one is BOTH provably not the daemon's and safe to forward,
// because forwarding it is what the application asked for.
//
// Timestamps are the case that is provably not the daemon's and NOT safe to
// forward, so they are deliberately still admitted here and separated by
// explicitTimeSet below — see refreshWindowClassLocked.
func matchesExpectedTruncate(req *pfslocal.SetAttrRequest) bool {
	// SetFlags disqualifies the request like any other real attribute group:
	// the daemon's own refresh never carries one, so a request that does is a
	// genuine chflags whose intent must not be swallowed by the no-op arm.
	return req.Size != nil && req.Mode == nil && req.UID == nil &&
		req.GID == nil && !req.SetFlags
}

// explicitTimeSet reports whether req asks for a timestamp of its own.
//
// ftruncate(2) asks the kernel for a SIZE and nothing else, so the daemon's own
// refresh upcall never carries MtimeMs or AtimeMs. A size-set that does is
// therefore provably NOT this daemon's refresh — but that is only half a
// verdict, and the missing half is what made this a data-losing hole rather
// than a cosmetic one (see refreshWindowClassLocked).
func explicitTimeSet(req *pfslocal.SetAttrRequest) bool {
	return req.MtimeMs != nil || req.AtimeMs != nil
}

// refreshClass is the verdict on one pure size-set: whose request is it?
type refreshClass uint8

const (
	// refreshClassApplication: no pinned window claims this (item, size). The
	// request is an application mutation and reaches the authority.
	refreshClassApplication refreshClass = iota
	// refreshClassInternal: a pinned window claims this (item, size) AND the
	// item's current composed size still equals it, so the request is either
	// the daemon's own refresh upcall or an application size-set that is a
	// semantic no-op. Both are answered locally, identically and safely.
	refreshClassInternal
	// refreshClassAmbiguous: a pinned window claims this (item, size) but a
	// local write has since moved the item's composed size, so the two
	// candidates now demand OPPOSITE answers and the daemon cannot tell them
	// apart. It refuses instead of guessing (see refreshWindowClassLocked).
	refreshClassAmbiguous
)

// refreshWindowClassLocked is THE provenance predicate, and it is deliberately
// the only one. Both call sites — admission (internalRefreshPending) and the
// setattr handler (classifyExpectedTruncate) — ask it the same question and
// must get the same answer for the same request, because a request one of them
// calls daemon bookkeeping and the other calls an application mutation is
// precisely how a refresh becomes a data-destroying truncate.
//
// It CONSUMES NOTHING. Provenance is a property of the open window, never a
// token some other request can spend: a marker was a single-use token once,
// and an application ftruncate to the same item and the same size — byte
// identical on the wire, reaching the dispatcher first, possibly through a
// hard-link alias — could spend it. The daemon's own upcall then arrived
// markerless, was classified as an application mutation, and truncated
// whatever a concurrent write had appended past the sampled size.
//
// ── WHY (item, size, window) IS NOT ENOUGH ON ITS OWN ───────────────────────
//
// A pinned window used to answer "internal" for every matching request, full
// stop. That is safe for the daemon and UNSAFE for the application, and the
// interleaving is short: the refresh samples S and enters its ftruncate; a
// local write extends the inode to N > S; the application then issues a REAL
// ftruncate(item, S) (or open(O_TRUNC) with S == 0). Byte-identical on the
// wire, suppressed as bookkeeping — the app got success, the bytes S..N
// survived, and getattr still reported N.
//
// The size is what separates the two cases, because it decides whether the
// request MEANS anything:
//
//   - current composed size == S. A size-set to S changes no bytes whoever
//     issued it. Answering locally is correct for the daemon's refresh and
//     costs the application only an mtime bump the remote edit has already
//     superseded — the cost documented on truncateNoteTTL, unchanged.
//   - current composed size == N != S. Now the two candidates demand OPPOSITE
//     answers: the daemon's refresh must NOT reach the authority (it would
//     destroy bytes S..N that no application asked to drop), and the
//     application's truncate MUST reach it (suppressing it silently discards
//     the app's intent). Nothing on the wire distinguishes them — FSKit's
//     setAttributes carries no provenance, and its handle is the frontend's
//     per-ITEM open handle, not the issuing descriptor's.
//
// So the second case is refused rather than guessed, and refusal is safe for
// BOTH candidates: the daemon's own ftruncate(2) sees EINTR, which
// refreshKernelFile already classifies as kernelRefreshRetry and the exact
// transaction re-samples and re-runs; an application ftruncate(2) sees EINTR,
// the documented interrupted-syscall outcome, and its retry lands on a window
// that has closed or a size that once again agrees. Neither ever loses data.
//
// The ambiguous window is also as small as it can be made: it opens only when
// the refresh actually issues an ftruncate, and only for that syscall's
// duration (see applyKernelRefresh).
//
// A size-set carrying a real attribute group (mode, ownership, flags) never
// reaches here at all — matchesExpectedTruncate rejects it — and a size-set to
// any OTHER size matches no window and reaches the authority as it must.
//
// ── AND WHY EXPLICIT TIMESTAMPS ARE THE THIRD CASE ──────────────────────────
//
// The predicate used to ignore MtimeMs/AtimeMs entirely, so an application
// issuing a size-set S together with explicit times inside an open window was
// answered Internal: the size was a no-op, and the timestamps were dropped
// without an error. They never reached the authority, and the ctime ordering
// every other observer derives from that mutation never happened.
//
// The honest reading of such a request is that it is provably NOT the daemon's
// — ftruncate(2) asks for a size and nothing else — but it is not therefore
// safe to forward. While this daemon is inside its own syscall for the same
// (item, size), the request in front of the handler is one of two things, and
// forwarding is catastrophic for one of them: if some path the daemon has not
// foreseen ever attaches a timestamp to its own refresh upcall, forwarding
// sends the daemon's refresh to the authority and destroys whatever a
// concurrent writer appended past the sampled size. Suppressing is merely wrong
// for the other. So an explicit-time set inside a window is AMBIGUOUS: refused,
// never suppressed as bookkeeping and never forwarded on an unproven claim. Its
// EINTR retry lands on a closed window and reaches the authority with its
// timestamps intact.
func (a *attach) refreshWindowClassLocked(
	itemID uint64,
	size int64,
	explicitTimes bool,
) refreshClass {
	open := false
	for _, note := range a.expectedTruncates {
		if note.pinned && note.itemID == itemID && note.size == size {
			open = true
			break
		}
	}
	if !open {
		return refreshClassApplication
	}
	if explicitTimes {
		return refreshClassAmbiguous
	}
	// A MUTATION THAT STARTED AFTER THE WINDOW OPENED IS THE SAME AMBIGUITY.
	//
	// The size comparison below asks whether the item's composed size still
	// equals the one the window names, and it is exactly the question a mutation
	// between its commit and its publication cannot answer: the registry has NOT
	// moved, which is the whole defect. A control write (or any other frontend's
	// write) that opened its sequence after this window armed commits N, and
	// until it publishes the comparison reads S and says "still the sampled
	// size, answer locally" — so the daemon answers its own upcall as
	// bookkeeping and the stale ftruncate(S) completes AFTER the newer commit.
	//
	// The arm side already refuses to open a window over an in-flight mutation
	// (refreshSampleSupersededLocked); this is the other half of the same
	// ordering, for a mutation that starts while the window is already open. The
	// two are ordered against each other because both the window and the
	// sequence are mutated under a.mu.
	//
	// Ambiguous, not Application: the refusal is safe for both candidates (the
	// daemon's own ftruncate retries through kernelRefreshRetry, an
	// application's retries the interrupted syscall), while calling it an
	// application mutation would forward the daemon's own refresh to the
	// authority — the one direction that destroys data.
	if a.itemMutationInFlightLocked(itemID) {
		return refreshClassAmbiguous
	}
	// An item the daemon no longer tracks cannot prove the window is dead, and
	// the daemon's own refresh must never be forwarded on an unproven claim.
	if current := a.items[itemID]; current != nil && current.attr.Size != size {
		return refreshClassAmbiguous
	}
	return refreshClassInternal
}

// internalRefreshPending answers, WITHOUT consuming anything, whether body is
// the upcall of a kernel-state refresh this daemon is issuing right now.
//
// It is the dispatcher's provenance test. A daemon-originated refresh is
// coherence bookkeeping, not an application mutation: it publishes state the
// authority has ALREADY applied, it is consumed by the setattr handler and never
// reaches the authority, and it appends nothing to the write-back stream. Pacing
// it against the metadata lane therefore throttles an operation that is not
// responsible for the backlog and cannot help drain it — the same argument that
// keeps the authority lane off the credit ledger — and, worse, the pacing delay
// is precisely what used to let the marker's meaning change underneath it.
//
// The predicate is unforgeable in the only sense that matters: the markers it
// reads are installed exclusively by applyKernelRefresh, only for the duration
// of its own syscall, and a request that matches one is by construction a
// request this daemon is about to answer locally.
// A request the handler will REFUSE as ambiguous also answers true: it is
// answered locally and never reaches the authority, so pacing it against the
// metadata lane would be as pointless as pacing the refresh itself, and the
// two call sites keep the identical verdict for the identical request.
func (a *attach) internalRefreshPending(body any) bool {
	verdict, ok := a.classifyRefreshRequest(body)
	return ok && verdict.class != refreshClassApplication
}

// ── THE FROZEN PHASE-1 VERDICT ──────────────────────────────────────────────
//
// Provenance is decided ONCE, in phase 1, holding nothing — and then it is
// CARRIED. It is not re-derived under the locks, because between phase 1 and
// the handler the request is deliberately parked: it suspends waiting to
// activate into the publication set, and a pinned refresh window lives for
// exactly the extent of one ftruncate(2). The window can therefore close while
// the request it describes is still in flight.
//
// When the handler re-derived the verdict from scratch it found no window,
// called the request an application mutation, and executed a real Setattr
// against the authority — under the frontend mirrors, with NO admission behind
// it, because phase 1 had waved it past admission precisely on the grounds that
// it would never reach the authority. The request that arrived at the authority
// was the daemon's own refresh, and the bytes a concurrent writer had appended
// past the sampled size were destroyed.
//
// The rule the freeze establishes is one-directional and absolute: a request
// phase 1 did not classify as an application mutation can never become one
// under the locks. If the handler finds the frozen verdict's PREREQUISITES no
// longer hold, it unwinds (EINTR) so phase 1 can run again holding nothing — it
// never promotes.
type refreshVerdictKey struct{}

// refreshVerdict is one setattr's provenance, as phase 1 saw it.
//
// item and size are recorded so the handler can tell "the verdict is about this
// request" from "the verdict is about an item that has since been replaced":
// the frozen answer is only binding while the object it was computed for is
// still the object in front of the handler.
type refreshVerdict struct {
	class refreshClass
	item  pfslocal.Item
	size  int64
}

// classifyRefreshRequest is phase 1's provenance test, and the ONLY place a
// verdict is minted.
//
// ok is false for anything that is not a size-bearing setattr the window
// protocol can be about at all; such a request has no provenance question and
// needs no frozen answer.
func (a *attach) classifyRefreshRequest(body any) (refreshVerdict, bool) {
	req, ok := body.(*pfslocal.SetAttrRequest)
	if !ok || !matchesExpectedTruncate(req) {
		return refreshVerdict{}, false
	}
	size := int64(*req.Size)
	a.mu.RLock()
	defer a.mu.RUnlock()
	return refreshVerdict{
		class: a.refreshWindowClassLocked(req.Item.ItemID, size, explicitTimeSet(req)),
		item:  req.Item,
		size:  size,
	}, true
}

// withRefreshVerdict freezes a phase-1 verdict into the operation context the
// handler will run under.
func withRefreshVerdict(ctx context.Context, verdict refreshVerdict) context.Context {
	return context.WithValue(ctx, refreshVerdictKey{}, verdict)
}

// frozenRefreshVerdict returns the verdict phase 1 recorded for req.
//
// A request that did not travel the dispatcher carries no frozen verdict — the
// control plane's own local operations and the in-package tests are the only
// such callers — and there is no admission gap for it to fall through, because
// there was no admission phase. Those classify on the spot, against the same
// predicate. The distinction matters: the freeze exists to close a gap that
// only exists when a request is parked between two phases, not to make the
// predicate itself unreachable.
func (a *attach) frozenRefreshVerdict(
	ctx context.Context,
	req *pfslocal.SetAttrRequest,
) (refreshVerdict, bool) {
	if verdict, ok := ctx.Value(refreshVerdictKey{}).(refreshVerdict); ok {
		if verdict.item == req.Item && req.Size != nil && verdict.size == int64(*req.Size) {
			return verdict, true
		}
		// A verdict minted for a different object cannot speak for this one.
		// Fall through to a fresh classification rather than silently applying
		// somebody else's answer.
	}
	return a.classifyRefreshRequest(req)
}

// classifyExpectedTruncate decides whether req is the daemon's own pending
// kernel-size refresh for path. Only a pure size set (optionally with the
// times the kernel attaches to truncates) can match; anything touching mode or
// ownership is a real application setattr.
//
// A PINNED window answers first and is NOT consumed — see
// refreshWindowClassLocked. This is the same decision admission already made
// for the same request, and keeping it non-consuming is what stops one
// request from spending another's provenance.
//
// Below the window sits the UNPINNED sweeper arm, which is single-use and
// deadline-bounded. No marker should ever be found unpinned —
// applyKernelRefresh retires its own on every exit path — so this is a
// backstop for a marker that outlived its refresh through a path that does not
// exist today, never the primary decision. A size mismatch retires an unpinned
// note: the kernel is performing a REAL truncate that must reach the
// authority, and the stale note must not linger. A pinned note is never
// retired here even on mismatch; it belongs to the refresh that installed it.
func (a *attach) classifyExpectedTruncate(p string, req *pfslocal.SetAttrRequest) refreshClass {
	if !matchesExpectedTruncate(req) {
		return refreshClassApplication
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if class := a.refreshWindowClassLocked(
		req.Item.ItemID, int64(*req.Size), explicitTimeSet(req),
	); class != refreshClassApplication {
		return class
	}
	now := time.Now()
	if note, ok := a.expectedTruncates[p]; ok {
		if note.pinned {
			// A pinned marker that did not match the window is a DIFFERENT
			// refresh's. Leave it alone and let this real setattr through.
			return refreshClassApplication
		}
		delete(a.expectedTruncates, p)
		if expectedTruncateLive(note, now) &&
			note.itemID == req.Item.ItemID &&
			int64(*req.Size) == note.size {
			if explicitTimeSet(req) {
				// Same rule as the pinned window: a request carrying its own
				// timestamps is provably not the daemon's refresh and must not
				// be answered as bookkeeping, but it is not proved to be the
				// application's either while a marker for this exact (item,
				// size) is still live. Refuse.
				return refreshClassAmbiguous
			}
			return refreshClassInternal
		}
		return refreshClassApplication
	}
	// ftruncate addresses an already-open FSItem, not a pathname. A rename
	// can therefore move that item after the secure open/fstat but before its
	// setattr upcall reaches us. Find the exact item marker so the daemon's
	// refresh remains a no-op at the authority rather than becoming a real
	// truncate of the item's new name. Multiple hard-link aliases retain
	// separate path markers and are consumed one at a time.
	//
	// Only UNPINNED markers are reachable here: the pinned window was tested
	// first, over every marker, on exactly this (itemID, size), so a pinned
	// marker matching the condition below would already have returned true.
	// The guard states that rather than relying on it.
	for notedPath, note := range a.expectedTruncates {
		if note.pinned {
			continue
		}
		if !expectedTruncateLive(note, now) {
			delete(a.expectedTruncates, notedPath)
			continue
		}
		if note.itemID == req.Item.ItemID && int64(*req.Size) == note.size {
			delete(a.expectedTruncates, notedPath)
			if explicitTimeSet(req) {
				return refreshClassAmbiguous
			}
			return refreshClassInternal
		}
	}
	return refreshClassApplication
}
