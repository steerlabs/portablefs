//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// CoherenceProfile is the retained local spelling of protocol 6's one exact
// lease-backed kernel-cache contract. Zero remains invalid so a caller cannot
// accidentally mount with unspecified local semantics.
type CoherenceProfile uint8

const CoherenceStrict CoherenceProfile = 1

func (p CoherenceProfile) String() string {
	if p == CoherenceStrict {
		return "strict"
	}
	return "invalid"
}

const (
	// strictEntryTimeout is retained as a policy ceiling, but protocol 6 always
	// publishes kernel entry validity as zero. strictAttrTimeout is likewise
	// only a ceiling; an exact reply-local A-R grant supplies the real lifetime.
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

	// defaultCachedNameCapacity is the number of (parent, name) resolutions a
	// strict mount is willing to leave resident in its kernel. It is declared
	// to the authority because it is exactly the amount of state this mount
	// promises it can repair, and therefore also the amount it must be able to
	// walk during self-revocation. Absences count against it exactly like
	// bindings: a name the kernel answers from cache is a repair obligation
	// whether the cached answer is "here it is" or "it is not there".
	defaultCachedNameCapacity = 1 << 16

	// negativeNameShare bounds the part of that capacity spent on absences.
	// The sub-bound exists because nothing reclaims a negative entry the way
	// FORGET reclaims a binding: the kernel holds no inode for a name that does
	// not exist, so it never tells this frontend that it dropped the dentry,
	// and an absence therefore leaves the registry only through a repair or
	// through self-revocation. Without a share, a workload that probes for
	// absent names -- an interpreter walking a search path, a linker trying
	// every -L directory -- could fill the whole declared budget with absences
	// and stop the mount caching the names that do exist. A quarter is far more
	// than any real probe set needs (SQLite probes two names per database) and
	// leaves the majority of the declared state for real bindings.
	negativeNameShare = 4

	// defaultRepairBudget is the per-phase deadline a strict mount commits to.
	// A phase is a handful of write(2) calls on /dev/fuse; the only thing that
	// can make one slow is a kernel lock held by an unrelated local process, so
	// the budget is sized for lock hand-off, not for I/O.
	defaultRepairBudget = 15 * time.Second

	// leaseControlReserve is the authority in-flight slot that only the lease
	// CONTROL loop may occupy. Acknowledging is what releases the mutating
	// machine, so this loop must never queue behind bulk kernel I/O.
	leaseControlReserve = 1
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

// nameKey is one daemon-cached directory binding. The parent is the inode
// number the authority publishes in attributes; the stable parent identity is
// tracked separately in the exact N-lease coordinate.
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

func (c *mutationCallback) acquireSource(ctx context.Context, raw *rawFileSystem, gate *sourcePublicationGate) (*sourcePublicationLease, error) {
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
	if publication == nil || publication.owner == nil {
		return errors.New("fusev3: authority response escaped its physical kernel reply lifecycle")
	}
	publication.owner.mu.Lock()
	if publication.responseConsumptionOwner != responseConsumptionPublication {
		publication.owner.mu.Unlock()
		return errors.New("fusev3: authority response arrived after reply ownership transferred to settlement")
	}
	publication.responseConsumptions = append(publication.responseConsumptions, consumption)
	publication.owner.mu.Unlock()
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

// errRepairBudgetExceeded classifies the one revocation cause a supervisor can
// act on differently: this mount was healthy but too slow to repair. It is a
// sentinel rather than a formatted string so classifyRevocationReason never has
// to read prose.
var errRepairBudgetExceeded = errors.New("fusev3: lease cache withdrawal exceeded its safety budget")

// revokeCachedNames drops daemon-resident N payloads. The portable profile
// gives kernel dentries zero validity, so there is no kernel namespace cache to
// notify or drain at recall or teardown.
func (r *rawFileSystem) revokeCachedNames(_ time.Time) {
	r.mu.Lock()
	for key := range r.cachedNames {
		r.dropCachedNameLocked(key)
	}
	for key := range r.cachedNegatives {
		r.dropCachedNegativeLocked(key)
	}
	r.mu.Unlock()
}

func (r *rawFileSystem) revokeCachedAttrs(deadline time.Time) []string {
	r.mu.Lock()
	work := make([]uint64, 0, len(r.cachedAttrs))
	dataRecords := make(map[*inodeRecord]struct{}, len(r.cachedData))
	for _, record := range r.cachedData {
		dataRecords[record] = struct{}{}
	}
	for _, record := range r.cachedAttrs {
		// The retained-data pass uses the same whole-inode primitive and
		// therefore withdraws this record's attributes too. Leave it to that
		// pass so one terminal obligation produces exactly one notification.
		_, data := dataRecords[record]
		if record != nil && !record.reclaimed && !data {
			work = append(work, record.id)
		}
	}
	r.cachedAttrs = make(map[publicationIdentity]*inodeRecord)
	r.mu.Unlock()
	server := r.mount.notifier()
	if server == nil {
		return nil
	}
	var failures []string
	for index, inode := range work {
		if time.Now().After(deadline) {
			failures = append(failures, fmt.Sprintf("attribute withdrawal exceeded the repair budget with %d inodes unwithdrawn", len(work)-index))
			break
		}
		// Strict FUSE has no attribute-only invalidation. The exact terminal
		// primitive is whole-inode withdrawal: it drops retained pages and
		// This record has no retained-data obligation, so the stock attribute-only
		// shape is sufficient and avoids evicting unrelated clean pages.
		if status := server.InodeNotify(inode, -1, 0); !status.Ok() && status != fuse.ENOENT {
			failures = append(failures, fmt.Sprintf("withdraw cached attributes for inode %d: %v", inode, status))
		}
	}
	return failures
}

// revokeCachedData drops every page this mount told its kernel it could keep.
//
// This is the one withdrawal that has no softer form. A cached name or a cached
// attribute is only ever an answer the kernel will ask about again once it
// expires, and until then the serving path can refuse. A retained page is not:
// with FOPEN_KEEP_CACHE a read of a resident folio is completed inside the
// kernel with no request reaching this process at all, so revoked.Store(true)
// and the ENOTCONN choke point in acquireBulk -- which are what bound every
// other kind of stale service -- cannot see it, let alone refuse it. Neither
// can the FUSE connection abort at the end of the withdrawal ladder: aborting
// fails every future request, and a page that needs no request is unaffected.
// Without this pass a preexisting fd can keep reading resident pre-fence pages.
// The walk runs after namespace detach but before connection abort, while the
// stock notification channel is still alive. Stock FUSE does not report the
// kernel's final invalidate_inode_pages2 result, so a transiently busy page is
// an explicit residual; connection abort prevents new fills but does not prove
// that such a resident page was removed.
func (r *rawFileSystem) revokeCachedData(deadline time.Time) []string {
	r.mu.Lock()
	work := make([]uint64, 0, len(r.cachedData))
	for _, record := range r.cachedData {
		work = append(work, record.id)
	}
	r.cachedData = make(map[uint64]*inodeRecord)
	r.mu.Unlock()
	server := r.mount.notifier()
	if server == nil {
		return nil
	}
	var failures []string
	for _, inode := range work {
		if time.Now().After(deadline) {
			failures = append(failures, fmt.Sprintf("data withdrawal exceeded the repair budget with %d inodes unwithdrawn", len(work)-len(failures)))
			return failures
		}
		// ENOENT is the strongest possible outcome: the kernel holds no inode
		// state at all, so there is nothing left that could answer from the old
		// pages. Every other failure is recorded, because a page this mount
		// could not take back is stale data a fenced participant can still
		// serve, and the operator has to be told that in the revocation report.
		if status := server.InodeNotify(inode, 0, 0); !status.Ok() && status != fuse.ENOENT {
			failures = append(failures, fmt.Sprintf("withdraw cached data for inode %d: %v", inode, status))
		}
	}
	return failures
}

// discardCachedOwnershipAfterConnectionGone clears only daemon bookkeeping.
// It is legal after exact mount and connection absence make further reverse
// notification impossible. It does not claim that a preexisting fd or mapping
// has lost every resident page; that stock-kernel residual remains explicit.
func (r *rawFileSystem) discardCachedOwnershipAfterConnectionGone() {
	r.mu.Lock()
	r.cachedNames = make(map[nameKey]*inodeRecord)
	r.cachedStableNames = make(map[publicationNamespace]*inodeRecord)
	r.cachedNameStable = make(map[nameKey]publicationNamespace)
	r.cachedNameLeases = make(map[nameKey]leaseStamp)
	r.cachedNegatives = make(map[nameKey]struct{})
	r.cachedNegativeLeases = make(map[nameKey]leaseStamp)
	r.cachedAttrs = make(map[publicationIdentity]*inodeRecord)
	r.cachedAttrPayloads = make(map[publicationIdentity]cachedAttrPayload)
	r.cachedData = make(map[uint64]*inodeRecord)
	r.mu.Unlock()
}

// revoke makes this mount unusable immediately and permanently. It is the local
// obligation that lets the authority stop freezing a whole volume because one
// participant died: a strict mount that can no longer repair must stop serving
// what it already cached rather than continue.
//
// New requests are refused synchronously. The asynchronous ladder detaches the
// namespace, attempts stock cache invalidations, and aborts the FUSE connection.
// A failed notification is recorded rather than presented as clean withdrawal.
// Stock FUSE does not expose the kernel's final data-purge result, so resident
// pages reachable through a preexisting fd or mapping are not claimed removed.
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
	// not complete lease cache withdrawal inside the reserved safety interval.
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
	// A "data-withdrawal" step is the one entry that reports residual stale
	// service rather than residual mount state: it means retained pages this
	// mount published could not be dropped, so a process still inside the
	// mount may read pre-fence bytes.
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
// drives. Production binds detach to the mount-owner fusermount helper and the
// remaining steps to kernel interfaces; a test substitutes them
// to exercise the escalation without a kernel, which is the only way to cover
// the failure ladder at all.
type kernelWithdrawal struct {
	detach func(point string) error
	abort  func(kernelMount) error
	absent func(kernelMount) (MountAbsenceProof, error)
	sleep  func(time.Duration)
}

func (m *Mount) productionKernelWithdrawal() kernelWithdrawal {
	return kernelWithdrawal{
		detach: func(string) error {
			if m.server == nil {
				return errors.New("fusev3: lazy detach has no FUSE server")
			}
			return m.server.UnmountLazy()
		},
		abort:  func(k kernelMount) error { return k.abortKernelConnection() },
		absent: func(k kernelMount) (MountAbsenceProof, error) { return k.absent() },
		sleep:  time.Sleep,
	}
}

func (m *Mount) withdrawalOps() kernelWithdrawal {
	if m.withdrawal.detach != nil {
		return m.withdrawal
	}
	return m.productionKernelWithdrawal()
}

// withdrawKernelState is the strict half of teardown. It runs on the teardown
// goroutine because most of its steps can block, and none of them may block
// whoever discovered the failure.
//
// Every step's error is checked. A discarded detach failure leaves a dead FUSE
// mount installed in the namespace with the CLI still reporting it live and
// the authority still holding this participant's strict membership. So the
// steps are an escalation ladder instead: withdraw retained kernel state while
// /dev/fuse is still a valid notification channel, abort the connection,
// lazy-detach through the mount owner's fusermount helper, then prove absence
// and repeat if necessary, bounded by withdrawalRounds and by the declared
// repair budget. Whatever it proves is returned, so the caller can persist a
// truthful verdict either way.
func (m *Mount) withdrawKernelState() withdrawalOutcome {
	m.revoked.Store(true)
	ops := m.withdrawalOps()
	installed := m.kernelMount
	out := withdrawalOutcome{installed: installed.point != ""}
	// One repair budget covers the whole ladder rather than each step: it exists
	// to fit inside the authority's fencing grace, and a per-step budget would
	// let the rounds multiply it.
	deadline := time.Now().Add(m.repairBudget)
	writersJoined := true
	if m.raw != nil {
		writersJoined = m.raw.terminalizeReplyCacheOwnership(deadline)
		if !writersJoined {
			out.record(0, "reply-writer-join", errRepairBudgetExceeded)
		}
	}

	// The retained name, attribute, and data withdrawals run before the first
	// abort because an aborted go-fuse loop can close the notification
	// descriptor before userspace reaches it.
	if m.raw != nil && writersJoined {
		m.raw.revokeCachedNames(deadline)
		for _, failure := range m.raw.revokeCachedAttrs(deadline) {
			out.record(1, "attribute-withdrawal", errors.New(failure))
		}
		for _, failure := range m.raw.revokeCachedData(deadline) {
			out.record(1, "data-withdrawal", errors.New(failure))
		}
	}
	delay := withdrawalRetryDelay
	for round := 1; ; round++ {
		// Aborting is unconditional and comes first in every round. It unblocks
		// any request still parked on an authority operation and terminates the
		// serving connection, and only then is the namespace detach below safe:
		// that step runs the mount owner's fusermount helper as a separate
		// process, whose exec and path resolution can enter this very mount. A
		// detach that ran first would deadlock a mount which can no longer
		// answer - the helper waits for a reply this ladder can only produce
		// after the helper returns - and buys nothing the abort does not.
		if installed.device != "" {
			out.record(round, "abort", ops.abort(installed))
		}
		if out.installed {
			out.record(round, "detach", ops.detach(installed.point))
		}
		if !out.installed {
			// No recorded kernel identity: startup failed before mountinfo
			// yielded one. There is nothing here whose absence this ladder
			// could prove, and the caller falls back to the ordinary unmount.
			if !writersJoined && m.kernelConnectionAbsentBy(deadline) {
				m.raw.terminalizeReplyCacheOwnershipAfterConnectionGone()
				m.raw.discardCachedOwnershipAfterConnectionGone()
			}
			return out
		}
		if _, err := ops.absent(installed); err == nil {
			if !writersJoined {
				if !m.kernelConnectionAbsentBy(deadline) {
					out.record(round, "connection-absence",
						errors.New("FUSE serving connection did not terminate inside the withdrawal budget"))
					return out
				}
				m.raw.terminalizeReplyCacheOwnershipAfterConnectionGone()
				m.raw.discardCachedOwnershipAfterConnectionGone()
			}
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
	}
}

func (m *Mount) kernelConnectionAbsentBy(deadline time.Time) bool {
	if !m.kernelConnectionStarted {
		return true
	}
	if m.kernelConnectionDone == nil {
		return false
	}
	return waitReplyTerminal(m.kernelConnectionDone, deadline)
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
// published. It is the stock go-fuse notification surface, named as an
// interface so lease invalidation can be tested without a kernel; *fuse.Server
// is the only production implementation.
type kernelNotifier interface {
	// InodeNotify(node, -1, 0) withdraws cached attributes only, which is what
	// an A recall owes. InodeNotify(node, 0, 0) asks stock FUSE to invalidate
	// the entire inode data range and its attributes for a D recall.
	InodeNotify(node uint64, off int64, length int64) fuse.Status
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
