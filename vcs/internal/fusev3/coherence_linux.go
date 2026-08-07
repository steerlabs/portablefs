//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
	"golang.org/x/sys/unix"
)

// CoherenceProfile is the kernel-cache contract a mount declares to the
// authority. It describes what this frontend does with its kernel's caches,
// never which operating system it runs on.
//
// CoherenceUncached is a supported deployment profile, not a degraded mode: it
// caches nothing, so it owes the authority no repair and joins no barrier.
// CoherenceStrict caches names and attributes and pays for that by executing
// the authority's two-phase visibility barrier synchronously.
type CoherenceProfile uint8

const (
	CoherenceUncached CoherenceProfile = iota
	CoherenceStrict
)

func (p CoherenceProfile) String() string {
	if p == CoherenceStrict {
		return "strict"
	}
	return "uncached"
}

const (
	// strictEntryTimeout and strictAttrTimeout are the lifetimes a strict mount
	// publishes with. They are no longer a correctness parameter, which is the
	// whole point of joining the barrier: every authority-visible change to a
	// name or an inode is repaired by NAMESPACE/DATA/ATTRIBUTES notification
	// before the mutating call returns on the machine that made it, so no
	// caller anywhere can observe the old value after the new one exists. A
	// timeout expiry therefore never *fixes* anything; it only re-fetches state
	// this mount already knows is current.
	//
	// One minute is chosen as the largest value that still bounds the blast
	// radius of a future repair defect to a single human-noticeable interval.
	// It is far longer than any metadata-heavy workload's own reuse distance:
	// a `git status` over 5,000 files re-walks the same names within
	// milliseconds, so one minute collapses that walk from one LOOKUP per name
	// per traversal to one LOOKUP per name for the whole run. Raising it
	// further would buy nothing measurable and would widen that blast radius;
	// lowering it would reintroduce the RPC multiplier this design removes.
	strictEntryTimeout = 60 * time.Second
	strictAttrTimeout  = 60 * time.Second

	// defaultCachedNameCapacity is the number of (parent, name) bindings a
	// strict mount is willing to leave resident in its kernel. It is declared
	// to the authority because it is exactly the amount of state this mount
	// promises it can repair, and therefore also the amount it must be able to
	// walk during self-revocation.
	defaultCachedNameCapacity = 1 << 16

	// defaultRepairBudget is the per-phase deadline a strict mount commits to.
	// A phase is a handful of write(2) calls on /dev/fuse; the only thing that
	// can make one slow is a kernel lock held by an unrelated local process, so
	// the budget is sized for lock hand-off, not for I/O.
	defaultRepairBudget = 15 * time.Second

	// visibilityReserve is the authority in-flight slot that only the
	// visibility loop may occupy. Acknowledging is what releases the mutating
	// machine, so this loop must never queue behind bulk kernel I/O.
	visibilityReserve = 1
)

// MountAbsenceProof is evidence that this mount's kernel mount is gone. The
// authority stops holding the whole volume hostage for a departed strict
// participant only against evidence; a closed connection or a tidy shutdown is
// not evidence, so a frontend that cannot observe its own absence must let the
// session die instead of detaching cleanly.
type MountAbsenceProof struct {
	ObservedUnixNanos int64
	Observation       []byte
	Component         string
}

func (p MountAbsenceProof) valid() bool {
	return p.ObservedUnixNanos != 0 && len(p.Observation) != 0 && p.Component != ""
}

// nameKey is one kernel-cached directory binding. The parent is the inode
// number the authority publishes in attributes, which is what a
// VisibilityTarget carries as parent_kernel_ino; the kernel NodeID is resolved
// separately at repair time.
type nameKey struct {
	parent uint64
	name   string
}

type mutationTicket struct {
	slot     uint32
	sequence uint64
}

type mutationPublicationSlot struct {
	// through is the greatest sequence whose response publication has settled.
	// seen holds only later, out-of-order responses until every gap before them
	// settles; transport concurrency bounds it independently of mount lifetime.
	through uint64
	seen    map[uint64]bool
}

// mutationPublicationLedger joins the transport's replay identity to the raw
// FUSE callback which is publishing that mutation's reply. It retains one
// watermark per replay slot plus only the concurrently out-of-order tail, so
// its size is bounded by replay-slot and transport concurrency rather than by
// mount lifetime. Every mutation response advances the slot: failed mutations
// settle immediately, while every successful one settles only when its raw
// callback returns. Tracking all successes avoids duplicating the authority's
// visibility classification here; a new mutation kind cannot accidentally be
// acknowledged before its reply merely because the frontend did not know it
// could emit an event. An event which arrives first creates no entry at all,
// preventing a malformed remote ticket from growing local state.
type mutationPublicationLedger struct {
	mu      sync.Mutex
	bySlot  map[uint32]*mutationPublicationSlot
	changed chan struct{}
}

func (l *mutationPublicationLedger) signalLocked() {
	if l.changed != nil {
		close(l.changed)
	}
	l.changed = make(chan struct{})
}

func advanceMutationSlot(slot *mutationPublicationSlot) {
	for slot.seen[slot.through+1] {
		delete(slot.seen, slot.through+1)
		slot.through++
	}
}

func (l *mutationPublicationLedger) accept(ticket mutationTicket, settled bool) error {
	if ticket.sequence == 0 {
		return errors.New("fusev3: authority returned a zero mutation sequence")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bySlot == nil {
		l.bySlot = make(map[uint32]*mutationPublicationSlot)
	}
	slot := l.bySlot[ticket.slot]
	if slot == nil {
		slot = &mutationPublicationSlot{seen: make(map[uint64]bool)}
		l.bySlot[ticket.slot] = slot
	}
	if ticket.sequence <= slot.through {
		return fmt.Errorf("fusev3: duplicate mutation publication ticket for slot %d sequence %d", ticket.slot, ticket.sequence)
	}
	if _, exists := slot.seen[ticket.sequence]; exists {
		return fmt.Errorf("fusev3: duplicate mutation publication ticket for slot %d sequence %d", ticket.slot, ticket.sequence)
	}
	slot.seen[ticket.sequence] = settled
	advanceMutationSlot(slot)
	l.signalLocked()
	return nil
}

func (l *mutationPublicationLedger) complete(ticket mutationTicket) {
	l.mu.Lock()
	defer l.mu.Unlock()
	slot := l.bySlot[ticket.slot]
	if slot == nil || ticket.sequence <= slot.through {
		return
	}
	if _, exists := slot.seen[ticket.sequence]; !exists {
		return
	}
	slot.seen[ticket.sequence] = true
	advanceMutationSlot(slot)
	l.signalLocked()
}

func (l *mutationPublicationLedger) wait(ctx context.Context, ticket mutationTicket) error {
	if ticket.sequence == 0 {
		return errors.New("fusev3: self COMPLETE omitted its mutation sequence")
	}
	for {
		l.mu.Lock()
		if slot := l.bySlot[ticket.slot]; slot != nil && slot.through >= ticket.sequence {
			l.mu.Unlock()
			return nil
		}
		if l.changed == nil {
			l.changed = make(chan struct{})
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("fusev3: wait for raw reply publication of mutation slot %d sequence %d: %w", ticket.slot, ticket.sequence, ctx.Err())
		}
	}
}

type mutationCallbackKey struct{}

type mutationCallback struct {
	ledger  *mutationPublicationLedger
	mu      sync.Mutex
	tickets []mutationTicket
	done    bool
}

func (c *mutationCallback) accept(ticket mutationTicket) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return fmt.Errorf("fusev3: mutation slot %d sequence %d arrived after its raw callback returned", ticket.slot, ticket.sequence)
	}
	if err := c.ledger.accept(ticket, false); err != nil {
		return err
	}
	c.tickets = append(c.tickets, ticket)
	return nil
}

func (c *mutationCallback) finish() {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	c.done = true
	tickets := append([]mutationTicket(nil), c.tickets...)
	c.mu.Unlock()
	for _, ticket := range tickets {
		c.ledger.complete(ticket)
	}
}

func mutationResponseNeedsCallback(request *authoritypb.Request, response *authoritypb.Response) bool {
	if request.GetReclaim() != nil {
		// A reclaim retires a capability the kernel has already forgotten, so
		// its reply publishes nothing and its replay sequence settles the
		// moment it is accepted. It still must settle: a reclaim consumes a
		// sequence on its slot like any other mutation, and leaving that
		// sequence unrecorded would leave a permanent hole in the slot's
		// publication watermark, deadlocking the deferred self-COMPLETE of the
		// next visible mutation the client assigns to the same slot.
		return false
	}
	if responseErrno(response) == 0 {
		return true
	}
	// write(2) is the one Linux mutation which may commit a prefix and also
	// report an error. The raw frontend returns that positive progress and the
	// authority emits a DATA event for it, so its callback has the same source
	// publication obligation as a wholly successful write.
	return request.GetWrite() != nil && response.GetWrite().GetCount() != 0
}

// recordMutationResponse is called while the raw callback is still active,
// immediately after the transport has returned the authority's accepted replay
// identity. Failed mutations have no COMPLETE to wait for, so they settle
// immediately and advance the per-slot watermark. Every successful mutation
// remains pending until the callback has finished its raw reply; that makes the
// handshake future-proof against the authority adding a new visible operation.
func (m *Mount) recordMutationResponse(ctx context.Context, request *authoritypb.Request, response *authoritypb.Response, callErr error) error {
	if m.profile != CoherenceStrict || callErr != nil || response == nil || response.GetUncertain() {
		return nil
	}
	state := response.GetMutation()
	if state == nil {
		if mutationResponseNeedsCallback(request, response) {
			return errors.New("fusev3: successful mutation response omitted its replay identity")
		}
		return nil
	}
	ticket := mutationTicket{slot: state.GetSlot(), sequence: state.GetAcceptedSequence()}
	if !mutationResponseNeedsCallback(request, response) {
		return m.publications.accept(ticket, true)
	}
	callback, ok := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
	if !ok || callback == nil {
		return errors.New("fusev3: successful mutation response escaped its raw FUSE callback lifecycle")
	}
	return callback.accept(ticket)
}

func (r *rawFileSystem) mutationContext() (context.Context, func()) {
	ctx := r.opContext()
	if r.profile != CoherenceStrict {
		return ctx, func() {}
	}
	callback := &mutationCallback{ledger: &r.mount.publications}
	return context.WithValue(ctx, mutationCallbackKey{}, callback), callback.finish
}

// kernelMount is the identity of the installed FUSE mount, read once from
// /proc/self/mountinfo. The mount ID is the only field the kernel guarantees is
// unique for the lifetime of the mount, which is what makes its later absence
// an exact observation rather than a guess about a path.
type kernelMount struct {
	id     string
	device string
	point  string
}

const mountInfoPath = "/proc/self/mountinfo"

// observeKernelMount records the installed mount so its later disappearance can
// be proven. It is called once, after the kernel has answered INIT.
func observeKernelMount(mountpoint string) (kernelMount, error) {
	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return kernelMount{}, fmt.Errorf("fusev3: read %s: %w", mountInfoPath, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || unescapeMountField(fields[4]) != mountpoint {
			continue
		}
		return kernelMount{id: fields[0], device: fields[2], point: mountpoint}, nil
	}
	return kernelMount{}, fmt.Errorf("fusev3: %s does not list a mount at %s", mountInfoPath, mountpoint)
}

// absent reports whether this exact mount is no longer installed, and returns
// the observation that says so. The recorded mount ID is compared, not the
// path: a different filesystem mounted at the same path afterwards must not be
// mistaken for this one still being there.
//
// A lazily detached mount also leaves mountinfo while processes that were
// already inside it keep their references, so absence alone would be a weaker
// claim than it looks. Revocation is what closes that: it aborts the connection
// before any detach can be attempted, and after an abort there is no request
// this frontend could answer at all.
func (k kernelMount) absent() (MountAbsenceProof, error) {
	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return MountAbsenceProof{}, fmt.Errorf("fusev3: read %s: %w", mountInfoPath, err)
	}
	lines := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		lines++
		if fields[0] == k.id {
			return MountAbsenceProof{}, fmt.Errorf("fusev3: mount %s (%s) is still installed at %s", k.id, k.device, unescapeMountField(fields[4]))
		}
	}
	if lines == 0 {
		return MountAbsenceProof{}, fmt.Errorf("fusev3: %s produced no mount records; absence cannot be observed", mountInfoPath)
	}
	observation := fmt.Sprintf("mount-id=%s device=%s mountpoint=%s present=false records=%d", k.id, k.device, k.point, lines)
	return MountAbsenceProof{ObservedUnixNanos: time.Now().UnixNano(), Observation: []byte(observation), Component: mountInfoPath}, nil
}

// unescapeMountField reverses the octal escaping the kernel applies to paths in
// mountinfo. Comparing escaped bytes against a real path would silently fail to
// find a mount whose directory contains a space.
func unescapeMountField(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var out strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+3 < len(field) {
			if value, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(value))
				i += 3
				continue
			}
		}
		out.WriteByte(field[i])
	}
	return out.String()
}

// abortKernelConnection makes every outstanding and future kernel request on
// this connection fail with ENOTCONN. It is the only primitive that unblocks a
// reverse notification already parked on a VFS lock, so it is what bounds
// self-revocation instead of leaving it at the mercy of unrelated local
// processes. fusectl gives the abort file to the mount owner, so this needs no
// privilege beyond having made the mount.
func (k kernelMount) abortKernelConnection() error {
	_, minor, ok := strings.Cut(k.device, ":")
	if !ok {
		return fmt.Errorf("fusev3: mount device %q is not major:minor", k.device)
	}
	return os.WriteFile("/sys/fs/fuse/connections/"+minor+"/abort", []byte("1"), 0)
}

// coherence is the strict frontend's half of the two-phase visibility barrier.
// It owns nothing the kernel-facing tables own: the cached-name registry and
// the publication gate live in rawFileSystem under one lock, because they are
// decided on the same code path that answers the kernel.
type coherence struct {
	mount   *Mount
	session []byte
	budget  time.Duration
}

// run is the visibility loop. It is a dedicated goroutine holding a dedicated
// transport lane: acknowledging is what releases the mutating machine on every
// other participant, so this loop is never allowed to queue behind bulk I/O.
func (c *coherence) run(ctx context.Context) {
	defer c.mount.wg.Done()
	cursor := c.mount.rpc.InitialVisibilityCursor()
	for {
		event, err := c.mount.rpc.NextVisibility(ctx, cursor)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.mount.revoke(fmt.Errorf("fusev3: visibility stream ended: %w", err))
			return
		}
		if err := c.applyWithinBudget(ctx, event); err != nil {
			c.mount.revoke(err)
			return
		}
		if err := c.mount.rpc.AckVisibility(ctx, event.GetCursor()); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.mount.revoke(fmt.Errorf("fusev3: visibility acknowledgment refused: %w", err))
			return
		}
		cursor = event.GetCursor()
	}
}

// applyWithinBudget performs exactly one phase under the deadline this mount
// declared at attach. A kernel notification cannot be cancelled once it is
// inside write(2), so the budget is enforced by revoking the mount, which
// aborts the connection and releases the stuck write; it is a commitment the
// frontend keeps, not a hope that the kernel is quick.
func (c *coherence) applyWithinBudget(ctx context.Context, event *authoritypb.VisibilityEvent) error {
	overdue := time.AfterFunc(c.budget, func() {
		c.mount.revoke(fmt.Errorf("fusev3: visibility phase exceeded the %s repair budget this mount declared", c.budget))
	})
	defer overdue.Stop()
	return c.apply(ctx, event)
}

func (c *coherence) apply(ctx context.Context, event *authoritypb.VisibilityEvent) error {
	// A change to the volume's route declaration is not a cache repair, and
	// there is no repair that would answer it: the set of paths this mount
	// serves locally was fixed at attach and is what the authority admitted it
	// with. Continuing under the old topology while the volume has moved to a
	// new one is precisely the divergence the revision check exists to prevent,
	// so the mount stops — but it says so first. Dying silently would leave the
	// authority holding this participant's phase until the declared repair
	// budget expired, turning one routing change into a budget-long stall per
	// strict mount; the blocked report discharges the phase immediately and is
	// fenced to the same terminal outcome.
	if err := routesEventChange(c.mount.routesRevision, event); err != nil {
		return c.reportUnservable(ctx, event, err)
	}
	// initiator_session_id is the exemption ticket. A mount that repaired its
	// own mutation would deadlock against itself: the repair needs the parent
	// directory's i_rwsem, which the very syscall that caused the mutation
	// holds across the whole authority round trip. It also has nothing to
	// repair -- the VFS updates its own dcache from the reply to that syscall,
	// under that same lock, which is strictly more precise than a notification.
	self := len(c.session) != 0 && bytes.Equal(event.GetInitiatorSessionId(), c.session)
	switch event.GetCursor().GetPhase() {
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE:
		// PREPARE is never reportable. It closes cache admission by publishing
		// uncacheable, which takes no lock any syscall of this mount can be
		// holding, so there is no phase here that this mount cannot service.
		return c.mount.raw.prepareVisibility(ctx, event.GetTargets(), self)
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE:
		if self {
			ticket := mutationTicket{slot: event.GetMutationSlot(), sequence: event.GetMutationSequence()}
			if err := c.mount.publications.wait(ctx, ticket); err != nil {
				return err
			}
		}
		completion, blocked, err := c.mount.raw.beginVisibilityComplete(event.GetTargets(), self)
		if err != nil {
			return err
		}
		if blocked {
			// The gate is already closed, so this report is not speculative: an
			// admitted callback holds a parent for which this frontend has exact
			// cached-name repair work. The authority refuses those overlapping
			// requests before apply; this mount then drains them and continues.
			if err := c.mount.rpc.ReportVisibilityBlocked(ctx, event.GetCursor(), completion.parentKernelInos); err != nil {
				return fmt.Errorf("fusev3: authority could not interrupt an overlapping namespace mutation for visibility repair: %w", err)
			}
		}
		return c.mount.raw.finishVisibilityComplete(ctx, completion)
	default:
		return fmt.Errorf("fusev3: visibility event %d carried no phase", event.GetCursor().GetSequence())
	}
}

// reportUnservable delivers the blocked report for any terminal condition —
// currently a routing revision this mount cannot adopt — and returns the cause
// the mount revokes with. The report replaces
// the acknowledgment (it IS the acknowledgment, carrying `blocked`), so the
// authority discharges this participant's phase immediately instead of
// waiting out the declared repair budget.
func (c *coherence) reportUnservable(ctx context.Context, event *authoritypb.VisibilityEvent, cause error) error {
	if err := c.mount.rpc.ReportVisibilityBlocked(ctx, event.GetCursor(), nil); err != nil && ctx.Err() == nil {
		return errors.Join(cause, fmt.Errorf("fusev3: the authority did not accept this mount's report that it cannot repair: %w", err))
	}
	return cause
}

// visibilityKeys is one event's target set translated into this frontend's own
// cache keys.
type visibilityKeys struct {
	names  []nameKey
	inodes []uint64
}

// translate converts VisibilityTargets into cache keys. This frontend keys its
// kernel caches by the attr inode number the authority publishes, so a target
// carries that number explicitly (kernel_ino / parent_kernel_ino) alongside the
// stable identity — the stable identity is the exact XFS export handle, whose
// layout deliberately contains no device and no bare inode number, and is not
// parsed here. A target missing its kernel inode or device is malformed and
// fails closed: repairing a guessed coordinate would leave the real one stale.
// The one backing device is pinned on first sight and any later disagreement is
// a violation of the one-volume contract, not something to paper over.
func (r *rawFileSystem) translate(targets []*authoritypb.VisibilityTarget) (visibilityKeys, error) {
	var keys visibilityKeys
	for _, target := range targets {
		// The full shared wire contract is enforced, not just the fields this
		// frontend repairs by. A frontend that silently tolerates a shape the
		// other decoder refuses is how an encoder defect ships through every
		// gate on one platform and revokes every mount on the other.
		if err := visibilitywire.ValidateTarget(target); err != nil {
			return visibilityKeys{}, fmt.Errorf("fusev3: %w", err)
		}
		if err := r.pinIdentityDevice(target.GetDevice()); err != nil {
			return visibilityKeys{}, err
		}
		switch target.GetScope() {
		case authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE:
			keys.names = append(keys.names, nameKey{parent: target.GetParentKernelIno(), name: string(target.GetName())})
		default:
			keys.inodes = append(keys.inodes, target.GetKernelIno())
		}
	}
	return keys, nil
}

func (r *rawFileSystem) pinIdentityDevice(device uint64) error {
	if device == 0 {
		return errors.New("fusev3: visibility target carried no backing device")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.identityDeviceKnown {
		r.identityDevice, r.identityDeviceKnown = device, true
		return nil
	}
	if r.identityDevice != device {
		return fmt.Errorf("fusev3: authority reported coordination identities from two devices (%x and %x); a volume is exactly one filesystem", r.identityDevice, device)
	}
	return nil
}

// prepareVisibility closes cache admission for the affected keys.
//
// Closing admission means publishing them uncacheable, not withholding the
// reply. Withholding a LOOKUP reply is wrong on Linux and would deadlock: the
// process doing the lookup holds the parent's i_rwsem shared for the entire
// round trip, and the COMPLETE repair for the same directory needs that
// i_rwsem exclusively. Answering with a zero lifetime gives the caller the
// pre-mutation truth -- which is still the truth, because the authority has not
// applied yet -- while leaving nothing behind for COMPLETE to have to repair.
func (r *rawFileSystem) prepareVisibility(ctx context.Context, targets []*authoritypb.VisibilityTarget, self bool) error {
	keys, err := r.translate(targets)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if self {
		// The initiating mount does not gate its own names. The VFS resolves
		// the affected binding under the parent's i_rwsem and rebinds it from
		// this operation's own reply under the same lock, so a concurrent local
		// lookup of that name is already ordered against the mutation. Inode
		// state has no such lock, so attributes and data stay gated.
		keys.names = nil
	}
	for _, key := range keys.names {
		r.heldNames[key] = struct{}{}
	}
	for _, inode := range keys.inodes {
		r.heldInodes[inode] = struct{}{}
	}
	r.heldPhase = keys
	r.mu.Unlock()
	// Admission is closed; now wait out the publications that were already
	// decided cacheable before it closed. They are pure local work with no
	// authority round trip inside them, and no mutation waits on them, so this
	// drain cannot participate in the barrier's own dependency cycle.
	//
	// The drain ends when the reply has been handed back to go-fuse, not when
	// the kernel has installed it, and closing that last gap is the kernel's
	// job rather than this frontend's. For a name it is the parent's i_rwsem:
	// lookup_slow holds it across the entire round trip including
	// d_splice_alias, and fuse_reverse_inval_entry takes it exclusively, so an
	// invalidation can never interleave with an installation. For an inode it
	// is fuse_change_attributes, which discards a reply whose attr_version
	// predates the last invalidation. Both are load-bearing; the drain alone
	// would leave a window.
	return r.drainPublications(ctx, keys)
}

func (r *rawFileSystem) drainPublications(ctx context.Context, keys visibilityKeys) error {
	for {
		r.mu.Lock()
		busy := false
		for _, key := range keys.names {
			if r.publishingNames[key] != 0 {
				busy = true
				break
			}
		}
		if !busy {
			for _, inode := range keys.inodes {
				if r.publishingInodes[inode] != 0 {
					busy = true
					break
				}
			}
		}
		if !busy {
			r.mu.Unlock()
			return nil
		}
		settled := r.published
		r.mu.Unlock()
		select {
		case <-settled:
		case <-ctx.Done():
			return fmt.Errorf("fusev3: visibility prepare could not drain in-flight publications: %w", ctx.Err())
		}
	}
}

// repair is one kernel cache repair this frontend owes.
type repair struct {
	parent uint64
	child  uint64
	name   string
	inode  uint64
	data   bool
}

// visibilityCompletion owns one COMPLETE's exact repair work and the parent
// admission gates installed for its namespace notifications.
type visibilityCompletion struct {
	work             []repair
	parents          map[uint64]struct{}
	parentKernelInos []uint64
}

// beginVisibilityComplete resolves the event against the exact cache registry,
// removes those entries from the registry, and closes parent admission in one
// r.mu critical section. The returned boolean says that a callback was already
// admitted in one of those exact parents and therefore needs the authority to
// refuse its queued mutation before this frontend waits for it to drain.
func (r *rawFileSystem) beginVisibilityComplete(targets []*authoritypb.VisibilityTarget, self bool) (visibilityCompletion, bool, error) {
	keys, err := r.translate(targets)
	if err != nil {
		return visibilityCompletion{}, false, err
	}
	completion := visibilityCompletion{parents: make(map[uint64]struct{})}
	r.mu.Lock()
	if !self {
		completion.work = make([]repair, 0, len(keys.names)+len(keys.inodes))
		for _, key := range keys.names {
			record := r.cachedNames[key]
			if record == nil {
				continue
			}
			parent := r.directoryLocked(key.parent)
			r.dropCachedNameLocked(key)
			if parent == nil {
				continue
			}
			completion.work = append(completion.work, repair{parent: parent.id, child: record.id, name: key.name})
			if _, already := completion.parents[key.parent]; !already {
				completion.parents[key.parent] = struct{}{}
				completion.parentKernelInos = append(completion.parentKernelInos, key.parent)
			}
		}
		for _, inode := range keys.inodes {
			record := r.byInodeLocked(inode)
			if record != nil {
				completion.work = append(completion.work, repair{inode: record.id, data: true})
			}
		}
	}
	for parent := range completion.parents {
		r.repairingParents[parent]++
	}
	blocked := r.parkedOverlapLocked(completion.parents)
	r.mu.Unlock()
	return completion, blocked, nil
}

func (r *rawFileSystem) parkedOverlapLocked(parents map[uint64]struct{}) bool {
	for record := range r.parked {
		if _, overlap := parents[record.key.inode]; overlap {
			return true
		}
	}
	return false
}

// waitParkedParents waits on state transitions, not a timer. Progress comes from
// the authority's definite pre-apply refusal of callbacks that won admission
// before the gate. A callback arriving after the gate never parks at all.
func (r *rawFileSystem) waitParkedParents(ctx context.Context, parents map[uint64]struct{}) error {
	for {
		r.mu.Lock()
		if !r.parkedOverlapLocked(parents) {
			r.mu.Unlock()
			return nil
		}
		changed := r.parkedChanged
		if changed == nil {
			changed = make(chan struct{})
			r.parkedChanged = changed
		}
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("fusev3: visibility COMPLETE could not drain parent-exclusive callbacks: %w", ctx.Err())
		}
	}
}

// finishVisibilityComplete drains callbacks admitted before the gate, performs
// the reverse notifications, then atomically reopens namespace and publication
// admission. On failure both remain closed and the caller revokes the mount.
func (r *rawFileSystem) finishVisibilityComplete(ctx context.Context, completion visibilityCompletion) error {
	if err := r.waitParkedParents(ctx, completion.parents); err != nil {
		return err
	}
	for _, item := range completion.work {
		if err := r.applyRepair(item); err != nil {
			// Admission stays closed on failure. The caller revokes this mount and,
			// most importantly, must not acknowledge COMPLETE: a failed reverse
			// notification means this kernel may still serve the pre-mutation state.
			return err
		}
	}
	r.releaseComplete(completion.parents)
	return nil
}

// completeVisibility is retained as the direct, no-transport test seam. The
// production path begins first so it can ask the authority to interrupt an
// already-admitted overlap before finishing.
func (r *rawFileSystem) completeVisibility(targets []*authoritypb.VisibilityTarget, self bool) error {
	completion, _, err := r.beginVisibilityComplete(targets, self)
	if err != nil {
		return err
	}
	return r.finishVisibilityComplete(context.Background(), completion)
}

func (r *rawFileSystem) releaseComplete(parents map[uint64]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for parent := range parents {
		if r.repairingParents[parent]--; r.repairingParents[parent] <= 0 {
			delete(r.repairingParents, parent)
		}
	}
	for _, key := range r.heldPhase.names {
		delete(r.heldNames, key)
	}
	for _, inode := range r.heldPhase.inodes {
		delete(r.heldInodes, inode)
	}
	r.heldPhase = visibilityKeys{}
	r.signalParkedLocked()
}

// applyRepair issues one reverse notification.
//
// NotifyDelete is preferred for a namespace binding because it is the only
// notification that reaches inotify at all: without it a remote unlink is
// invisible to every watcher on this machine. It is also a superset of
// NotifyEntry -- the kernel invalidates the entry first and only then attempts
// the delete against the child it was told about -- so when the delete half is
// refused (the binding now names a different object, the entry is a mount
// point, an old kernel does not implement it) the invalidation still has to be
// made unconditionally, which is what the second call does.
func (r *rawFileSystem) applyRepair(item repair) error {
	server := r.mount.notifier()
	if server == nil {
		return errors.New("fusev3: kernel cache repair has no notification channel")
	}
	if item.data {
		// Offset -1 is attribute-only invalidation; offset 0 with no length
		// additionally drops every cached page. Data and attribute targets are
		// both repaired the strong way because the authoritative post-mutation
		// size cannot be *installed* through any Linux notification -- the
		// kernel only forgets, it never accepts a new value here -- so the
		// following GETATTR is what carries the new size, and it must not be
		// answered from a cache.
		if status := server.InodeNotify(item.inode, 0, 0); !status.Ok() && status != fuse.ENOENT {
			return fmt.Errorf("fusev3: invalidate inode %d: %v", item.inode, status)
		}
		// ENOENT is the strongest successful outcome for invalidation: the
		// kernel has no node state left that could answer from the old cache.
		// It occurs normally when a namespace repair immediately before this
		// one removed the inode's final dentry, and can also race ordinary
		// kernel eviction. Treating absence as a repair failure revokes a
		// healthy observer after a remote unlink.
		return nil
	}
	deleteStatus := server.DeleteNotify(item.parent, item.child, item.name)
	if deleteStatus.Ok() {
		return nil
	}
	entryStatus := server.EntryNotify(item.parent, item.name)
	if entryStatus.Ok() || entryStatus == fuse.ENOENT {
		// ENOENT parallels the inode case above: the kernel reports that no
		// parent alias or dentry for this name survives to answer from the old
		// binding. Dentries are evicted independently of FORGET (which tracks
		// the inode, not the name), so this occurs normally under dcache
		// pressure, for the second alias of a hard link, and for a name whose
		// inode an open descriptor still pins. Absence is the invalidated
		// state; treating it as a repair failure would revoke a healthy mount.
		// DeleteNotify alone is not trusted for this: it also reports ENOENT
		// when the cached dentry names a different inode than the event's
		// child, and that binding still had to fall to EntryNotify above.
		return nil
	}
	return fmt.Errorf("fusev3: invalidate name %q under node %d: delete notification failed with %v and entry notification failed with %v",
		item.name, item.parent, deleteStatus, entryStatus)
}

func (r *rawFileSystem) releaseHeld() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, key := range r.heldPhase.names {
		delete(r.heldNames, key)
	}
	for _, inode := range r.heldPhase.inodes {
		delete(r.heldInodes, inode)
	}
	r.heldPhase = visibilityKeys{}
}

// revokeCachedNames walks the exact set of bindings this mount published and
// takes every one of them back. It is bounded by the cached-name capacity this
// mount declared at attach, which is precisely why that number is part of the
// contract: it is the amount of stale state a dying participant has to be able
// to withdraw.
func (r *rawFileSystem) revokeCachedNames(deadline time.Time) {
	r.mu.Lock()
	work := make([]repair, 0, len(r.cachedNames))
	for key, record := range r.cachedNames {
		parent := r.directoryLocked(key.parent)
		if parent == nil {
			continue
		}
		work = append(work, repair{parent: parent.id, child: record.id, name: key.name})
	}
	r.cachedNames = make(map[nameKey]*inodeRecord)
	r.mu.Unlock()
	server := r.mount.notifier()
	if server == nil {
		return
	}
	for _, item := range work {
		if time.Now().After(deadline) {
			return
		}
		if status := server.DeleteNotify(item.parent, item.child, item.name); !status.Ok() {
			server.EntryNotify(item.parent, item.name)
		}
	}
}

// revoke makes this mount unusable immediately and permanently. It is the local
// obligation that lets the authority stop freezing a whole volume because one
// participant died: a strict mount that can no longer repair must stop serving
// what it already cached rather than continue.
//
// The bound on stale service is stated in three parts, strongest first. Every
// new request is refused synchronously, before this call returns. From the
// mount namespace root the tree becomes unreachable in one syscall. For a
// process whose working directory was already inside the mount, every binding
// this frontend published is withdrawn within the declared repair budget, after
// which the connection is aborted and there is no request this mount could
// answer wrongly at all.
func (m *Mount) revoke(cause error) {
	if cause == nil {
		cause = errors.New("fusev3: strict mount revoked")
	}
	// Synchronous, so that a caller which has just discovered it cannot repair
	// does not serve one more request while teardown is being scheduled.
	m.revoked.Store(true)
	m.failAsync(cause)
}

// withdrawKernelState is the strict half of teardown. It runs on the teardown
// goroutine because two of its three steps can block, and none of them may
// block whoever discovered the failure.
func (m *Mount) withdrawKernelState() {
	m.revoked.Store(true)
	installed := m.kernelMount
	if installed.point != "" {
		_ = unix.Unmount(installed.point, unix.MNT_DETACH)
	}
	if m.raw != nil {
		m.raw.revokeCachedNames(time.Now().Add(m.repairBudget))
	}
	if installed.device != "" {
		_ = installed.abortKernelConnection()
	}
}

func (m *Mount) isRevoked() bool { return m.revoked.Load() }

// kernelNotifier is the reverse channel this frontend uses to take back what it
// published. It is exactly the three go-fuse calls the repair needs, named as
// an interface so the mapping from a visibility target to a notification can be
// tested without a kernel; *fuse.Server is the only production implementation.
type kernelNotifier interface {
	InodeNotify(node uint64, off int64, length int64) fuse.Status
	EntryNotify(parent uint64, name string) fuse.Status
	DeleteNotify(parent uint64, child uint64, name string) fuse.Status
}

var _ kernelNotifier = (*fuse.Server)(nil)

// notifier returns the kernel notification channel, or nil when this mount has
// no installed kernel mount (the unit tests drive rawFileSystem directly).
func (m *Mount) notifier() kernelNotifier {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	return m.notify
}

func (m *Mount) setNotifier(notify kernelNotifier) {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	m.notify = notify
}

// detach releases the authority session. A strict mount may only detach
// cleanly against evidence that its kernel mount is gone; without that
// evidence the correct behaviour is to say nothing and let the session die,
// because the authority must keep treating this participant as a possible
// holder of stale names.
func (m *Mount) detach() {
	ctx, cancel := context.WithTimeout(context.Background(), detachTimeout)
	defer cancel()
	if m.profile != CoherenceStrict {
		_, _ = m.rpc.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{}}})
		return
	}
	if m.kernelMount.point == "" {
		return
	}
	proof, err := m.kernelMount.absent()
	if err != nil || !proof.valid() {
		return
	}
	_ = m.rpc.DetachAfterUnmount(ctx, proof)
}

const detachTimeout = 5 * time.Second

// revokedErrno is what every kernel request gets once this mount has revoked
// itself. ENOTCONN is the exact truth: this frontend is no longer connected to
// an authority it can be coherent with.
const revokedErrno = syscall.ENOTCONN
