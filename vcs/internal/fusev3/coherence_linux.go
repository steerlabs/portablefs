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
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
	"golang.org/x/sys/unix"
)

// CoherenceProfile is the kernel-cache contract a mount declares to the
// authority. Protocol 5 has one coherent mount semantics: every frontend joins
// the visibility barrier and owns its kernel publications through the physical
// reply write. Zero is deliberately invalid so a legacy uncached attachment is
// rejected rather than silently acquiring different semantics.
type CoherenceProfile uint8

const CoherenceStrict CoherenceProfile = 1

func (p CoherenceProfile) String() string {
	if p == CoherenceStrict {
		return "strict"
	}
	return "invalid"
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

// MountAbsenceProof is the official supervisor's local observation that this
// mount's exact kernel identity is gone. It is sent only after the same Mount
// has also observed its go-fuse serving connection terminate. A frontend that
// cannot establish both conditions lets the session die fenced.
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

type mutationCallbackKey struct{}

type mutationCallback struct {
	publication replyPublication
	mount       *Mount
	operationID uint64
}

func (c *mutationCallback) finish() {
	lease := c.publication.source
	if lease != nil && lease.terminalAtCallbackReturn() {
		lease.revoke()
		lease.r.mount.revoke(errors.New("fusev3: visible mutation returned without completing its source publication result"))
		c.publication.consumeAuthorityResponse()
		return
	}
	// A malformed authority result has no kernel state worth publishing. Once
	// its callback revokes the local serving boundary, returning the terminal
	// delivery receipt is safe and lets the fenced authority finish teardown
	// without waiting for a /dev/fuse reply which the revoked mount may drop.
	if c.mount != nil && c.mount.isRevoked() {
		c.publication.consumeAuthorityResponse()
	}
}

func (c *mutationCallback) acquireSource(ctx context.Context, raw *rawFileSystem, gate *authoritypb.SourcePublicationGate) (*sourcePublicationLease, error) {
	if c.publication.source != nil {
		return nil, errors.New("fusev3: raw callback attempted more than one visible source mutation")
	}
	lease, err := raw.acquireSourcePublication(ctx, gate)
	if err != nil {
		return nil, err
	}
	c.publication.source = lease
	return lease, nil
}

// releaseVisibilityRetry closes one definite-preapply attempt without exposing
// it to the kernel. The authority retained no filesystem result (and retains
// staged write bytes separately), so the exact response-consumption boundary
// is this local decision. Clearing source permits the same FUSE callback to
// acquire a fresh cut after the older peer repair. The strict kernel's
// lockless namespace expiration makes the same transition safe for namespace
// callbacks which still hold a parent VFS lock.
func (c *mutationCallback) releaseVisibilityRetry(lease *sourcePublicationLease) error {
	if c == nil || lease == nil || c.publication.source != lease {
		return errors.New("fusev3: visibility retry lost its source publication lease")
	}
	lease.resolveAllNoBinding()
	if err := lease.markDefiniteNoChange(); err != nil {
		return err
	}
	lease.release()
	c.publication.source = nil
	return nil
}

func sourceLeaseFromContext(ctx context.Context) *sourcePublicationLease {
	callback, _ := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
	if callback == nil {
		return nil
	}
	return callback.publication.source
}

func replyPublicationFromContext(ctx context.Context) *replyPublication {
	callback, _ := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
	if callback == nil {
		return nil
	}
	return &callback.publication
}

func retainAuthorityResponse(ctx context.Context, consumption authorityrpc.ResponseConsumption) error {
	if consumption == nil {
		return nil
	}
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		return errors.New("fusev3: authority response escaped its physical kernel reply lifecycle")
	}
	publication.responseConsumptions = append(publication.responseConsumptions, consumption)
	return nil
}

func completeSourcePublication(ctx context.Context) error {
	lease := sourceLeaseFromContext(ctx)
	if lease == nil {
		return nil
	}
	if err := lease.markCallbackPublicationReady(); err != nil {
		return err
	}
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		return errors.New("fusev3: source publication escaped its reply ownership")
	}
	publication.needsPostVFS = true
	return nil
}

// completeDefiniteNoChangePublication closes an assigned source mutation whose
// structured result proves no filesystem state was changed. Its response must
// be physically ordered, but must not request a post-VFS receipt because the
// kernel has no new state to install.
func completeDefiniteNoChangePublication(ctx context.Context) error {
	lease := sourceLeaseFromContext(ctx)
	if lease == nil {
		return errors.New("fusev3: definite no-change mutation escaped its source publication ownership")
	}
	lease.resolveAllNoBinding()
	return lease.markDefiniteNoChange()
}

func (r *rawFileSystem) mutationContext(unique uint64) (context.Context, func(), fuse.Status) {
	ctx := r.opContext()
	callback := &mutationCallback{mount: r.mount, operationID: unique}
	if err := r.registerReplyPublication(unique, &callback.publication); err != nil {
		// Registration is the ownership reservation for every fact this callback
		// could make cacheable. It happens before any lookup/mutation RPC, so an
		// impossible zero/reused FUSE identity cannot race an untracked success
		// reply onto /dev/fuse.
		r.mount.revoke(err)
		return ctx, func() {}, fuse.Status(syscall.ENOTCONN)
	}
	return context.WithValue(ctx, mutationCallbackKey{}, callback), func() {
		callback.finish()
		r.finishReplyPublicationRegistration(unique, &callback.publication)
	}, fuse.OK
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

// observePlannedKernelMountAbsent proves that a FUSE mount with this mount
// attempt's unique source identity was never installed, or has already been
// removed before its kernel mount ID could be recorded. MountVolume uses this
// only on failed startup: FSName contains the random mount-instance ID, and no
// server remains that could install it after this observation.
//
// This is deliberately not a path-only check. Another filesystem may race onto
// the validated mountpoint after our attempt fails; that says nothing about
// whether this exact PortableFS mount still exists. Conversely, finding the
// unique source anywhere in the namespace is enough to refuse clean detach.
// ObservePlannedKernelMountAbsent proves that the exact, attempt-unique FUSE
// source has not been published into this mount namespace. Mount supervisors
// use it both immediately before handing an ACTIVE authority session to
// MountVolume and inside MountVolume's failed-startup cleanup. Exporting this
// one primitive keeps those two ownership boundaries backed by the identical
// /proc/self/mountinfo observation rather than two subtly different parsers.
func ObservePlannedKernelMountAbsent(fsName, mountpoint string) (MountAbsenceProof, error) {
	if fsName == "" || mountpoint == "" {
		return MountAbsenceProof{}, errors.New("fusev3: planned mount identity is incomplete")
	}
	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return MountAbsenceProof{}, fmt.Errorf("fusev3: read %s: %w", mountInfoPath, err)
	}
	records := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+2 >= len(fields) {
			continue
		}
		records++
		if unescapeMountField(fields[separator+2]) == fsName {
			return MountAbsenceProof{}, fmt.Errorf(
				"fusev3: planned mount source %s is still installed as mount %s at %s",
				fsName, fields[0], unescapeMountField(fields[4]),
			)
		}
	}
	if records == 0 {
		return MountAbsenceProof{}, fmt.Errorf("fusev3: %s produced no mount records; absence cannot be observed", mountInfoPath)
	}
	observation := fmt.Sprintf(
		"mount-source=%s mountpoint=%s present=false records=%d stage=startup",
		fsName, mountpoint, records,
	)
	return MountAbsenceProof{
		ObservedUnixNanos: time.Now().UnixNano(),
		Observation:       []byte(observation),
		Component:         mountInfoPath,
	}, nil
}

func observePlannedKernelMountAbsent(fsName, mountpoint string) (MountAbsenceProof, error) {
	return ObservePlannedKernelMountAbsent(fsName, mountpoint)
}

// absent reports whether this exact mount is no longer installed, and returns
// the observation that says so. The recorded mount ID is compared, not the
// path: a different filesystem mounted at the same path afterwards must not be
// mistaken for this one still being there.
//
// A lazily detached mount leaves mountinfo while processes that were already
// inside it may retain references, so this function alone is not authorization
// to report clean detach. Mount.detach additionally waits for the exact go-fuse
// serving connection to terminate, then calls absent again for the final
// timestamped observation.
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
	event, err := c.mount.rpc.NextVisibility(ctx, cursor)
	for {
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
		cursor = event.GetCursor()
		event, err = c.mount.rpc.NextVisibilityAfterAck(ctx, cursor, false)
	}
}

// errRepairBudgetExceeded classifies the one revocation cause a supervisor can
// act on differently: this mount was healthy but too slow to repair. It is a
// sentinel rather than a formatted string so classifyRevocationReason never has
// to read prose.
var errRepairBudgetExceeded = errors.New("fusev3: visibility phase exceeded the repair budget this mount declared")

// applyWithinBudget performs exactly one phase under the deadline this mount
// declared at attach. A kernel notification cannot be cancelled once it is
// inside write(2), so the budget is enforced by revoking the mount, which
// aborts the connection and releases the stuck write; it is a commitment the
// frontend keeps, not a hope that the kernel is quick.
func (c *coherence) applyWithinBudget(ctx context.Context, event *authoritypb.VisibilityEvent) error {
	overdue := time.AfterFunc(c.budget, func() {
		c.mount.revoke(fmt.Errorf("%w (%s)", errRepairBudgetExceeded, c.budget))
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
	// own mutation would race its own VFS postprocessing and is unnecessary: the
	// source-publication gate already owns the exact cut, and the VFS updates its
	// dcache from the operation reply before the generic PUBLISH boundary.
	self := len(c.session) != 0 && bytes.Equal(event.GetInitiatorSessionId(), c.session)
	if self && event.GetRoutes() == nil {
		return errors.New("fusev3: authority delivered this source a filesystem visibility phase; protocol 5 excludes the source because its exact publication gate already owns that cut")
	}
	switch event.GetCursor().GetPhase() {
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE:
		// PREPARE is never reportable. It closes cache admission by publishing
		// uncacheable, which takes no lock any syscall of this mount can be
		// holding, so there is no phase here that this mount cannot service.
		return c.mount.raw.prepareVisibility(ctx, event.GetTargets(), self)
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE:
		completion, _, err := c.mount.raw.beginVisibilityCompleteAt(event.GetTargets(), self, event.GetCursor().GetSequence())
		if err != nil {
			return err
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
	inodes []visibilityInodeKey
}

// visibilityInodeKey is one normalized inode repair. A data target dominates
// any attribute target for the same kernel inode because dropping cached pages
// also requires dropping the cached attributes that describe them.
type visibilityInodeKey struct {
	inode    uint64
	identity publicationIdentity
	data     bool
	size     uint64
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
	// Validate the complete raw event before normalizing or pinning any state.
	// In particular, a malformed ATTRIBUTES target must not disappear merely
	// because an earlier DATA target for the same inode dominates its repair.
	for _, target := range targets {
		// The full shared wire contract is enforced, not just the fields this
		// frontend repairs by. A frontend that silently tolerates a shape the
		// other decoder refuses is how an encoder defect ships through every
		// gate on one platform and revokes every mount on the other.
		if err := visibilitywire.ValidateTarget(target); err != nil {
			return visibilityKeys{}, fmt.Errorf("fusev3: %w", err)
		}
	}
	var device uint64
	for _, target := range targets {
		if device == 0 {
			device = target.GetDevice()
		} else if device != target.GetDevice() {
			return visibilityKeys{}, fmt.Errorf("fusev3: authority reported coordination identities from two devices (%x and %x); a volume is exactly one filesystem", device, target.GetDevice())
		}
	}
	if device != 0 {
		if err := r.pinIdentityDevice(device); err != nil {
			return visibilityKeys{}, err
		}
	}

	var keys visibilityKeys
	var inodeIndexes map[uint64]int
	for _, target := range targets {
		switch target.GetScope() {
		case authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE:
			keys.names = append(keys.names, nameKey{parent: target.GetParentKernelIno(), name: string(target.GetName())})
		case authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES:
			inode := target.GetKernelIno()
			data := target.GetScope() == authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA
			identity, ok := publicationIdentityFromBytes(target.GetIdentity())
			if !ok {
				return visibilityKeys{}, errors.New("fusev3: visibility inode target carried an invalid stable identity")
			}
			if inodeIndexes == nil {
				inodeIndexes = make(map[uint64]int)
			}
			if index, exists := inodeIndexes[inode]; exists {
				key := &keys.inodes[index]
				if key.identity != identity {
					return visibilityKeys{}, fmt.Errorf("fusev3: kernel inode %d carried two stable identities in one visibility event", inode)
				}
				if data {
					size := uint64(target.GetSize())
					if key.data && key.size != size {
						return visibilityKeys{}, fmt.Errorf("fusev3: kernel inode %d carried two authoritative DATA sizes (%d and %d)", inode, key.size, size)
					}
					key.data, key.size = true, size
				}
				continue
			}
			inodeIndexes[inode] = len(keys.inodes)
			key := visibilityInodeKey{inode: inode, identity: identity, data: data}
			if data {
				key.size = uint64(target.GetSize())
			}
			keys.inodes = append(keys.inodes, key)
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
// reply. Answering with a zero lifetime gives the caller the pre-mutation truth
// -- which is still the truth, because the authority has not applied yet --
// while leaving nothing behind for COMPLETE to repair. Withholding the lookup
// would also waste the callback lane needed to service independent work.
func (r *rawFileSystem) prepareVisibility(ctx context.Context, targets []*authoritypb.VisibilityTarget, self bool) error {
	if self {
		return errors.New("fusev3: source filesystem PREPARE is forbidden by the source-owned publication protocol")
	}
	keys, err := r.translate(targets)
	if err != nil {
		return err
	}
	if err := r.acquirePeerPublication(ctx, targets, keys); err != nil {
		return err
	}
	// Admission is closed; now wait out the publications that were already
	// decided cacheable before it closed. They are pure local work with no
	// authority round trip inside them, and no mutation waits on them, so this
	// drain cannot participate in the barrier's own dependency cycle.
	//
	// Publication remains counted through the real /dev/fuse response write.
	// Publication-bearing replies and reverse notifications share go-fuse's
	// writer ordering boundary, so an acknowledged PREPARE cannot be followed
	// by installation of a stale reply that was merely returned by RawFS first.
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
				if r.publishingInodes[inode.inode] != 0 {
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
	parent   uint64
	child    uint64
	name     string
	inode    uint64
	data     bool
	size     uint64
	sequence uint64
}

// visibilityCompletion owns one COMPLETE's exact lockless repair work.
type visibilityCompletion struct {
	work     []repair
	sequence uint64
}

// beginVisibilityComplete resolves the event against the exact cache registry,
// removes those entries from the registry, and closes admission in one r.mu
// critical section. Strict namespace expiration never acquires parent i_rwsem,
// so an already-admitted namespace callback is not a repair dependency.
func (r *rawFileSystem) beginVisibilityCompleteAt(targets []*authoritypb.VisibilityTarget, self bool, sequence uint64) (visibilityCompletion, bool, error) {
	if self {
		return visibilityCompletion{}, false, errors.New("fusev3: source filesystem COMPLETE is forbidden by the source-owned publication protocol")
	}
	if sequence == 0 {
		return visibilityCompletion{}, false, errors.New("fusev3: visibility COMPLETE carried no sequence")
	}
	keys, err := r.translate(targets)
	if err != nil {
		return visibilityCompletion{}, false, err
	}
	completion := visibilityCompletion{sequence: sequence}
	r.mu.Lock()
	for _, inode := range keys.inodes {
		if record := r.byInodeLocked(inode.inode); record != nil && record.identity != inode.identity {
			r.mu.Unlock()
			return visibilityCompletion{}, false, fmt.Errorf("fusev3: visibility target for inode %d does not match the cached stable identity", inode.inode)
		}
	}
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
	}
	for _, inode := range keys.inodes {
		record := r.byInodeLocked(inode.inode)
		if record != nil {
			completion.work = append(completion.work, repair{inode: record.id, data: inode.data, size: inode.size, sequence: sequence})
		}
	}
	r.mu.Unlock()
	return completion, false, nil
}

// beginVisibilityComplete is the direct test seam. Production always supplies
// the authority cursor sequence through beginVisibilityCompleteAt.
func (r *rawFileSystem) beginVisibilityComplete(targets []*authoritypb.VisibilityTarget, self bool) (visibilityCompletion, bool, error) {
	return r.beginVisibilityCompleteAt(targets, self, 1)
}

// finishVisibilityComplete performs lockless reverse notifications, then
// atomically reopens namespace and publication admission. On failure both
// remain closed and the caller revokes the mount.
func (r *rawFileSystem) finishVisibilityComplete(ctx context.Context, completion visibilityCompletion) error {
	_ = ctx
	for _, item := range completion.work {
		if err := r.applyRepair(item); err != nil {
			// Admission stays closed on failure. The caller revokes this mount and,
			// most importantly, must not acknowledge COMPLETE: a failed reverse
			// notification means this kernel may still serve the pre-mutation state.
			return err
		}
	}
	r.releaseComplete(completion)
	return nil
}

// completeVisibility is retained as the direct, no-transport test seam. The
// production path uses the same begin/finish split to bind repair work to the
// authority cursor before it emits any reverse notification.
func (r *rawFileSystem) completeVisibility(targets []*authoritypb.VisibilityTarget, self bool) error {
	completion, _, err := r.beginVisibilityComplete(targets, self)
	if err != nil {
		return err
	}
	return r.finishVisibilityComplete(context.Background(), completion)
}

func (r *rawFileSystem) releaseComplete(completion visibilityCompletion) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, key := range r.heldPhase.names {
		delete(r.heldNames, key)
	}
	for _, inode := range r.heldPhase.inodes {
		delete(r.heldInodes, inode.inode)
	}
	r.heldPhase = visibilityKeys{}
	if completion.sequence > r.completedVisibilitySequence {
		r.completedVisibilitySequence = completion.sequence
	}
	r.releasePeerPublicationLocked()
}

// applyRepair issues one reverse notification.
//
// Strict NotifyDelete is the one exact namespace primitive: the patched kernel
// validates the cached child identity, expires the binding without taking the
// parent inode lock, and emits the watcher event. A weaker name-only fallback
// would be able to expire a newer binding and is therefore forbidden.
func (r *rawFileSystem) applyRepair(item repair) error {
	server := r.mount.notifier()
	if server == nil {
		return errors.New("fusev3: kernel cache repair has no notification channel")
	}
	if item.inode != 0 {
		if item.data {
			// The private notify installs the exact post-mutation EOF at this
			// visibility sequence and invalidates every cached page, including
			// same-size overwrites where an EOF delta alone would do nothing.
			if status := server.PFSSizeNotify(item.inode, item.size, item.sequence); !status.Ok() && status != fuse.ENOENT {
				return fmt.Errorf("fusev3: publish exact size %d at sequence %d for inode %d: %v", item.size, item.sequence, item.inode, status)
			}
			return nil
		}
		if status := server.InodeNotify(item.inode, -1, 0); !status.Ok() && status != fuse.ENOENT {
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
	if deleteStatus.Ok() || deleteStatus == fuse.ENOENT {
		return nil
	}
	// The strict kernel validates the exact child identity before expiring the
	// binding. A mismatch is protocol corruption, not permission to issue a
	// weaker name-only fallback which could invalidate a newer binding.
	return fmt.Errorf("fusev3: expire exact name %q under node %d for child %d: %v",
		item.name, item.parent, item.child, deleteStatus)
}

func (r *rawFileSystem) releaseHeld() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, key := range r.heldPhase.names {
		delete(r.heldNames, key)
	}
	for _, inode := range r.heldPhase.inodes {
		delete(r.heldInodes, inode.inode)
	}
	r.heldPhase = visibilityKeys{}
	r.releasePeerPublicationLocked()
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
	r.cachedStableNames = make(map[publicationNamespace]*inodeRecord)
	r.cachedNameStable = make(map[nameKey]publicationNamespace)
	r.mu.Unlock()
	server := r.mount.notifier()
	if server == nil {
		return
	}
	for _, item := range work {
		if time.Now().After(deadline) {
			return
		}
		_ = server.DeleteNotify(item.parent, item.child, item.name)
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

// The revocation reason vocabulary. It is the machine-readable half of a
// revocation report: one bounded token a supervisor can branch on and persist,
// beside the frontend's own sentence which it can only print. The identical
// tokens are the ones the macOS supervisor's watchdog produces (see the CLI's
// fskit_revocation.go), so one operator-facing vocabulary covers both
// platforms even though the mechanisms behind them cannot be shared.
const (
	// RevocationSessionTerminal: the authority session ended permanently, so
	// nothing can repair this kernel's caches again.
	RevocationSessionTerminal = "session-terminal"
	// RevocationRepairBudgetExceeded: this mount was still connected but did
	// not complete a visibility phase inside the budget it declared at attach.
	RevocationRepairBudgetExceeded = "repair-budget-exceeded"
	// RevocationRoutesChanged: the volume's machine-local route declaration
	// moved under a mount whose topology is fixed for its lifetime.
	RevocationRoutesChanged = "routes-changed"
	// RevocationCoherenceViolation: the residual class. This frontend found a
	// state it cannot serve coherently and stopped being a filesystem.
	RevocationCoherenceViolation = "coherence-violation"
)

// classifyRevocationReason reduces the recorded cause to one vocabulary token.
// Only causes with a sentinel behind them are classified; everything else is a
// coherence violation, which is the honest default because that is what every
// unclassified revoke callsite in this package actually is.
func classifyRevocationReason(cause error) string {
	switch {
	case cause == nil:
		return RevocationCoherenceViolation
	case errors.Is(cause, errRepairBudgetExceeded):
		return RevocationRepairBudgetExceeded
	case errors.Is(cause, errRoutesChanged):
		return RevocationRoutesChanged
	case errors.Is(cause, authorityrpc.ErrSessionEnded):
		return RevocationSessionTerminal
	default:
		return RevocationCoherenceViolation
	}
}

// RevocationReport is one self-revocation made observable: why this mount
// stopped serving, and what its escalating withdrawal actually proved about the
// kernel state it left behind.
//
// KernelStateWithdrawn is the load-bearing field. A revoked mount whose kernel
// mount is still installed is not a tidy failure: the dead FUSE mount remains
// in the namespace, no mount-absence proof can be produced, and the authority's
// durable strict membership therefore stays active until an operator discharges
// it by hand. Reporting false is what lets a supervisor say so instead of
// showing the mount as live.
type RevocationReport struct {
	Reason               string
	Cause                string
	KernelStateWithdrawn bool
	// Withdrawal names every escalation step that failed, in order, as
	// "<round>/<step>: <error>". It is empty on a first-attempt withdrawal.
	Withdrawal []string
}

// withdrawalRounds bounds the escalation ladder. Three rounds is the smallest
// number that expresses the whole escalation — detach, abort, re-detach — and
// still leaves one round of margin; the ladder is additionally bounded by the
// repair budget this mount declared, because a withdrawal that outlived the
// budget has already lost the race it exists to win.
const withdrawalRounds = 3

// withdrawalRetryDelay is the first inter-round pause, doubled each round. It
// is short: the kernel references a busy detach could not take back are
// released by the abort in the same round, not by waiting.
const withdrawalRetryDelay = 25 * time.Millisecond

// withdrawalOutcome accumulates what the ladder did. installed records whether
// there was a recorded kernel identity to withdraw at all, which is different
// from having withdrawn one: a startup that failed before mountinfo yielded an
// ID has nothing here whose absence could be proven.
type withdrawalOutcome struct {
	installed bool
	withdrawn bool
	failures  []string
}

func (o *withdrawalOutcome) record(round int, step string, err error) {
	if err == nil {
		return
	}
	o.failures = append(o.failures, fmt.Sprintf("%d/%s: %v", round, step, err))
}

// kernelWithdrawal is the set of kernel primitives the escalation ladder
// drives. Production binds them to the real syscalls; a test substitutes them
// to exercise the escalation without a kernel, which is the only way to cover
// the failure ladder at all — a unit test cannot make MNT_DETACH return EPERM.
type kernelWithdrawal struct {
	detach func(point string) error
	abort  func(kernelMount) error
	absent func(kernelMount) (MountAbsenceProof, error)
	sleep  func(time.Duration)
}

func productionKernelWithdrawal() kernelWithdrawal {
	return kernelWithdrawal{
		detach: func(point string) error { return unix.Unmount(point, unix.MNT_DETACH) },
		abort:  func(k kernelMount) error { return k.abortKernelConnection() },
		absent: func(k kernelMount) (MountAbsenceProof, error) { return k.absent() },
		sleep:  time.Sleep,
	}
}

func (m *Mount) withdrawalOps() kernelWithdrawal {
	if m.withdrawal.detach != nil {
		return m.withdrawal
	}
	return productionKernelWithdrawal()
}

// withdrawKernelState is the strict half of teardown. It runs on the teardown
// goroutine because most of its steps can block, and none of them may block
// whoever discovered the failure.
//
// Every step's error is now checked. It used to discard all three, which read
// as harmless because the happy path is one successful MNT_DETACH — but under
// load MNT_DETACH can fail, and a discarded failure left a dead FUSE mount
// installed in the namespace with the CLI still reporting it live and the
// authority still holding this participant's strict membership. So the steps
// are an escalation ladder instead: detach, then abort the FUSE connection —
// which is what makes the kernel drop the references the detach could not take
// back — then prove absence, then re-detach and repeat, bounded by
// withdrawalRounds and by the declared repair budget. Whatever it proves is
// returned, so the caller can persist a truthful verdict either way.
func (m *Mount) withdrawKernelState() withdrawalOutcome {
	m.revoked.Store(true)
	ops := m.withdrawalOps()
	installed := m.kernelMount
	out := withdrawalOutcome{installed: installed.point != ""}

	// Round one's namespace detach runs before the cached-name withdrawal, so
	// the tree is already unreachable from the namespace root while the
	// bindings are being taken back one at a time.
	if out.installed {
		out.record(1, "detach", ops.detach(installed.point))
	}
	if m.raw != nil {
		m.raw.revokeCachedNames(time.Now().Add(m.repairBudget))
	}
	deadline := time.Now().Add(m.repairBudget)
	delay := withdrawalRetryDelay
	for round := 1; ; round++ {
		// Aborting is unconditional and is never skipped just because the
		// detach reported success: it is the only primitive that unblocks a
		// reverse notification already parked on a VFS lock, so it is what
		// bounds self-revocation, and it is also what forces the kernel to
		// release a mount a busy detach could not remove.
		if installed.device != "" {
			out.record(round, "abort", ops.abort(installed))
		}
		if !out.installed {
			// No recorded kernel identity: startup failed before mountinfo
			// yielded one. There is nothing here whose absence this ladder
			// could prove, and the caller falls back to the ordinary unmount.
			return out
		}
		if _, err := ops.absent(installed); err == nil {
			out.withdrawn = true
			return out
		} else {
			out.record(round, "absence", err)
		}
		if round >= withdrawalRounds || !time.Now().Before(deadline) {
			return out
		}
		ops.sleep(delay)
		delay *= 2
		out.record(round+1, "detach", ops.detach(installed.point))
	}
}

// reportRevocation hands the supervisor the terminal verdict exactly once, from
// the teardown goroutine, as soon as the ladder has finished. It deliberately
// does not wait for Close: when withdrawal fails there may be no later moment
// at which the supervisor learns anything at all, and an unobserved revocation
// is the defect this whole path exists to remove.
//
// A recorded fatal cause is required. Not every path through the teardown
// goroutine is a revocation: the benign /dev/fuse reply race that follows an
// already-observed external unmount schedules the same teardown without
// recording any cause, and reporting that as a revocation would stamp a
// terminal verdict onto an ordinary clean unmount.
func (m *Mount) reportRevocation(out withdrawalOutcome) {
	observe := m.onRevoked
	cause := m.fatalError()
	if observe == nil || cause == nil {
		return
	}
	report := RevocationReport{
		Reason:               classifyRevocationReason(cause),
		Cause:                cause.Error(),
		KernelStateWithdrawn: out.withdrawn,
		Withdrawal:           out.failures,
	}
	m.revokeOnce.Do(func() { observe(report) })
}

func (m *Mount) isRevoked() bool { return m.revoked.Load() }

// kernelNotifier is the reverse channel this frontend uses to take back what it
// published. It is exactly the strict go-fuse calls the repair needs, named as
// an interface so the mapping from a visibility target to a notification can be
// tested without a kernel; *fuse.Server is the only production implementation.
type kernelNotifier interface {
	InodeNotify(node uint64, off int64, length int64) fuse.Status
	PFSSizeNotify(node uint64, size uint64, sequence uint64) fuse.Status
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

// detach releases the authority session. A strict mount may send a clean-detach
// statement only after both its exact mount identity is absent and its exact
// FUSE serving connection is terminal. Linux lazy unmount makes either fact on
// its own insufficient. A failed check is returned to the supervisor and the
// RPC close leaves durable membership active.
func (m *Mount) detach() error {
	ctx, cancel := context.WithTimeout(context.Background(), detachTimeout)
	defer cancel()
	if m.kernelMount.point == "" {
		// Startup may have installed a FUSE connection and then failed before
		// mountinfo yielded its kernel ID. Once that connection is terminal, the
		// unique planned source is the exact remaining identity to check. If
		// MountVolume never supplied that identity (as in raw unit fixtures), the
		// session remains fenced.
		if m.plannedFSName == "" || m.plannedMountpoint == "" {
			return errors.New("fusev3: strict detach has no recorded or planned kernel mount identity")
		}
		if m.kernelConnectionStarted {
			select {
			case <-m.kernelConnectionDone:
			case <-ctx.Done():
				return fmt.Errorf("fusev3: strict detach waited for the failed-startup FUSE serving connection: %w", ctx.Err())
			}
		}
		proof, err := observePlannedKernelMountAbsent(m.plannedFSName, m.plannedMountpoint)
		if err != nil {
			return fmt.Errorf("fusev3: strict detach cannot establish failed-startup mount absence: %w", err)
		}
		if err := m.rpc.DetachAfterUnmount(ctx, proof); err != nil {
			return fmt.Errorf("fusev3: deliver authenticated failed-startup clean detach: %w", err)
		}
		return nil
	}
	// Refuse a live mount immediately. If it is absent because MNT_DETACH was
	// used, wait below for retained references to release the old connection.
	if _, err := m.kernelMount.absent(); err != nil {
		return fmt.Errorf("fusev3: strict detach cannot establish exact mount absence: %w", err)
	}
	if m.kernelConnectionDone == nil {
		return errors.New("fusev3: strict detach cannot observe the FUSE serving connection")
	}
	select {
	case <-m.kernelConnectionDone:
	case <-ctx.Done():
		return fmt.Errorf("fusev3: strict detach waited for the exact FUSE serving connection: %w", ctx.Err())
	}
	// Produce the statement after connection termination so its timestamp names
	// the complete condition, not merely the earlier namespace detach.
	proof, err := m.kernelMount.absent()
	if err != nil {
		return fmt.Errorf("fusev3: strict detach cannot re-establish exact mount absence: %w", err)
	}
	if !proof.valid() {
		return errors.New("fusev3: strict detach produced an incomplete mount-absence observation")
	}
	if err := m.rpc.DetachAfterUnmount(ctx, proof); err != nil {
		return fmt.Errorf("fusev3: deliver authenticated clean detach: %w", err)
	}
	return nil
}

const detachTimeout = 5 * time.Second

// revokedErrno is what every kernel request gets once this mount has revoked
// itself. ENOTCONN is the exact truth: this frontend is no longer connected to
// an authority it can be coherent with.
const revokedErrno = syscall.ENOTCONN
