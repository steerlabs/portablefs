//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// The withdrawal escalation ladder. These tests exist because the failure they
// cover cannot be produced any other way: a unit test cannot make the
// mount-owner detach helper fail on demand, and the defect being fixed here —
// every error discarded, a dead
// FUSE mount left installed, the CLI still calling it live — was invisible
// precisely because nothing ever observed those errors.

// fakeWithdrawal is a scripted kernel. Each primitive returns the next error in
// its queue (nil once the queue is exhausted), and absence is answered from a
// flag the detach steps flip, which is what a successful lazy unmount does.
type fakeWithdrawal struct {
	mu sync.Mutex
	// detachErrs and abortErrs are consumed one per call.
	detachErrs []error
	abortErrs  []error
	// installed is what mountinfo would still show. A lazy detach clears it
	// when it succeeds. Aborting a FUSE connection does not remove its mount.
	installed bool
	detaches  int
	aborts    int
	absences  int
	slept     []time.Duration
}

// terminalEnforcementRPC models authorityrpc's two terminal edges: pending is
// private to the frontend teardown owner, while done is the public certificate
// released by FinishLocalSessionEnforcement.
type terminalEnforcementRPC struct {
	*fakeRPC
	pending  chan struct{}
	done     chan struct{}
	cause    error
	finish   func()
	finished sync.Once
}

func (r *terminalEnforcementRPC) SessionDone() <-chan struct{}       { return r.done }
func (r *terminalEnforcementRPC) SessionEndPending() <-chan struct{} { return r.pending }
func (r *terminalEnforcementRPC) SessionEndCause() error             { return r.cause }
func (r *terminalEnforcementRPC) SessionError() error {
	select {
	case <-r.done:
		return r.cause
	default:
		return nil
	}
}
func (r *terminalEnforcementRPC) FinishLocalSessionEnforcement() {
	r.finished.Do(func() {
		if r.finish != nil {
			r.finish()
		}
		close(r.done)
	})
}

func (f *fakeWithdrawal) ops() kernelWithdrawal {
	return kernelWithdrawal{
		detach: func(string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.detaches++
			err := next(&f.detachErrs)
			if err == nil {
				f.installed = false
			}
			return err
		},
		abort: func(kernelMount) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.aborts++
			err := next(&f.abortErrs)
			return err
		},
		absent: func(k kernelMount) (MountAbsenceProof, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.absences++
			if f.installed {
				return MountAbsenceProof{}, fmt.Errorf("fusev3: mount %s is still installed", k.id)
			}
			return MountAbsenceProof{ObservedUnixNanos: 1, Observation: []byte("absent"), Component: mountInfoPath}, nil
		},
		sleep: func(d time.Duration) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.slept = append(f.slept, d)
		},
	}
}

func next(queue *[]error) error {
	if len(*queue) == 0 {
		return nil
	}
	err := (*queue)[0]
	*queue = (*queue)[1:]
	return err
}

func revokingMount(t *testing.T, fake *fakeWithdrawal) *Mount {
	t.Helper()
	mount, _ := testMount(t, 8)
	mount.kernelMount = kernelMount{id: "271", device: "0:57", point: t.TempDir()}
	mount.withdrawal = fake.ops()
	// The raw table's cached-name withdrawal walks a real notifier; the tests
	// here are about the kernel-mount ladder, so leave it unhooked.
	mount.repairBudget = 5 * time.Second
	return mount
}

func TestWithdrawalAbortsEvenWhenTheFirstDetachSucceeds(t *testing.T) {
	fake := &fakeWithdrawal{installed: true}
	out := revokingMount(t, fake).withdrawKernelState()
	if !out.withdrawn {
		t.Fatalf("a successful detach did not prove withdrawal: %+v", out)
	}
	// Aborting is what unblocks a reverse notification already parked on a VFS
	// lock. Skipping it on a clean detach would unbound self-revocation.
	if fake.aborts != 1 {
		t.Fatalf("aborts = %d, want exactly 1 even on the happy path", fake.aborts)
	}
	if len(out.failures) != 0 {
		t.Fatalf("clean withdrawal recorded failures: %v", out.failures)
	}
}

func TestConnectionFailureWithInstalledMountEntersWithdrawalBeforeServeEnds(t *testing.T) {
	fake := &fakeWithdrawal{installed: true}
	mount := revokingMount(t, fake)
	mount.kernelConnectionStarted = true

	// OnUnmount runs inside Serve, immediately before kernelConnectionDone is
	// closed.  It must record the failure and schedule withdrawal synchronously
	// instead of racing a clean Close against that terminal edge.
	mount.raw.OnUnmount()
	err := mount.fatalError()
	if err == nil || !strings.Contains(err.Error(), "serving connection terminated") ||
		!strings.Contains(err.Error(), "still installed") {
		t.Fatalf("installed-mount connection failure was not retained: %v", err)
	}
	close(mount.kernelConnectionDone)

	waitFor(t, "connection-failure mount withdrawal", func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return !fake.installed && fake.detaches > 0 && fake.aborts > 0
	})
}

func TestWithdrawalEscalatesFromAFailedDetachThroughAbortToSuccess(t *testing.T) {
	// A first lazy-detach failure must not strand the mount. Aborting the FUSE
	// connection does not remove it, so the ladder must retry the mount-owner
	// detach and prove that attempt in mountinfo.
	fake := &fakeWithdrawal{
		installed:  true,
		detachErrs: []error{syscall.EPERM},
	}
	out := revokingMount(t, fake).withdrawKernelState()
	if !out.withdrawn {
		t.Fatalf("escalation did not recover a failed detach: %+v", out)
	}
	if fake.aborts == 0 {
		t.Fatal("escalation never reached the FUSE connection abort")
	}
	if len(out.failures) == 0 {
		t.Fatal("the refused detach was not recorded; a silently recovered failure is still a failure that happened")
	}
	if !strings.Contains(out.failures[0], "1/detach") ||
		!strings.Contains(out.failures[0], syscall.EPERM.Error()) {
		t.Fatalf("recorded failure does not name the step and its reason: %v", out.failures)
	}
}

func TestWithdrawalRetriesTheDetachAfterTheAbort(t *testing.T) {
	// The abort does not release the mount, so the ladder must actually re-issue
	// the mount-owner lazy detach rather than merely aborting and hoping.
	fake := &fakeWithdrawal{
		installed:  true,
		detachErrs: []error{syscall.EBUSY},
	}
	out := revokingMount(t, fake).withdrawKernelState()
	if !out.withdrawn {
		t.Fatalf("the re-attempted detach did not complete the withdrawal: %+v", out)
	}
	if fake.detaches < 2 {
		t.Fatalf("detaches = %d, want a re-attempt after the abort", fake.detaches)
	}
}

func TestWithdrawalReportsFailureAfterExhaustingItsBoundedLadder(t *testing.T) {
	// Nothing works. The ladder must stop — it runs on the teardown goroutine
	// and an unbounded retry there is a zombie — and must report that the
	// kernel state was NOT withdrawn, which is what stops the CLI calling this
	// mount live and tells the operator the authority membership is stranded.
	fake := &fakeWithdrawal{
		installed:  true,
		detachErrs: []error{syscall.EPERM, syscall.EPERM, syscall.EPERM, syscall.EPERM},
		abortErrs:  []error{syscall.EACCES, syscall.EACCES, syscall.EACCES, syscall.EACCES},
	}
	out := revokingMount(t, fake).withdrawKernelState()
	if out.withdrawn {
		t.Fatal("a mount that is still installed was reported withdrawn")
	}
	if !out.installed {
		t.Fatal("a recorded kernel mount was not reported as installed")
	}
	if fake.detaches > withdrawalRounds || fake.aborts > withdrawalRounds {
		t.Fatalf("ladder exceeded its bound: detaches=%d aborts=%d rounds=%d",
			fake.detaches, fake.aborts, withdrawalRounds)
	}
	// Every failed step is named, not just the last one: the postmortem needs
	// to distinguish "the abort was refused" from "the abort worked and the
	// mount still would not go".
	if len(out.failures) < 2 {
		t.Fatalf("exhausted ladder recorded too little: %v", out.failures)
	}
	var sawAbort bool
	for _, failure := range out.failures {
		if strings.Contains(failure, "/abort") {
			sawAbort = true
		}
	}
	if !sawAbort {
		t.Fatalf("a refused abort was not recorded: %v", out.failures)
	}
}

func TestWithdrawalWithNoRecordedKernelMountProvesNothing(t *testing.T) {
	// Startup can fail before mountinfo yields an ID. There is nothing here
	// whose absence could be proven, and claiming otherwise would let the
	// caller skip the ordinary unmount that is the only remaining cleanup.
	fake := &fakeWithdrawal{}
	mount, _ := testMount(t, 8)
	mount.kernelMount = kernelMount{}
	mount.withdrawal = fake.ops()
	out := mount.withdrawKernelState()
	if out.installed || out.withdrawn {
		t.Fatalf("a mount with no recorded kernel identity claimed a withdrawal: %+v", out)
	}
	if fake.detaches != 0 {
		t.Fatalf("detached a path this mount never recorded (%d calls)", fake.detaches)
	}
}

func TestWithdrawalStopsAtTheDeclaredRepairBudget(t *testing.T) {
	fake := &fakeWithdrawal{
		installed:  true,
		detachErrs: []error{syscall.EPERM, syscall.EPERM, syscall.EPERM, syscall.EPERM},
	}
	mount := revokingMount(t, fake)
	// A budget already spent: the withdrawal exists to fit inside the
	// authority's fencing grace, so it must not outlive it retrying.
	mount.repairBudget = 0
	out := mount.withdrawKernelState()
	if out.withdrawn {
		t.Fatal("withdrawal claimed success with every primitive refusing")
	}
	if fake.detaches != 1 {
		t.Fatalf("detaches = %d; an exhausted budget must not buy another round", fake.detaches)
	}
}

func TestRevocationReportClassifiesItsCause(t *testing.T) {
	cases := []struct {
		name  string
		cause error
		want  string
	}{
		{"repair budget", fmt.Errorf("%w (15s)", errRepairBudgetExceeded), RevocationRepairBudgetExceeded},
		{"routes changed", routesChangeCause(make([]byte, 32), make([]byte, 32)), RevocationRoutesChanged},
		{"session ended", fmt.Errorf("fusev3: %w", authorityrpc.ErrSessionEnded), RevocationSessionTerminal},
		{"anything else", errors.New("fusev3: publication lost its ownership"), RevocationCoherenceViolation},
		{"no cause at all", nil, RevocationCoherenceViolation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRevocationReason(tc.cause); got != tc.want {
				t.Fatalf("classifyRevocationReason(%v) = %q, want %q", tc.cause, got, tc.want)
			}
		})
	}
}

func TestRevocationIsReportedOnceWithTheWithdrawalVerdict(t *testing.T) {
	fake := &fakeWithdrawal{
		installed:  true,
		detachErrs: []error{syscall.EPERM, syscall.EPERM, syscall.EPERM, syscall.EPERM},
		abortErrs:  []error{syscall.EACCES, syscall.EACCES, syscall.EACCES, syscall.EACCES},
	}
	mount := revokingMount(t, fake)
	var reports []RevocationReport
	mount.onRevoked = func(r RevocationReport) { reports = append(reports, r) }
	mount.recordFatalCause(fmt.Errorf("%w (15s)", errRepairBudgetExceeded))

	out := mount.withdrawKernelState()
	mount.reportRevocation(out)
	// A second teardown edge must not produce a second verdict.
	mount.reportRevocation(out)

	if len(reports) != 1 {
		t.Fatalf("reports = %d, want exactly 1", len(reports))
	}
	report := reports[0]
	if report.Reason != RevocationRepairBudgetExceeded {
		t.Fatalf("reason = %q, want %q", report.Reason, RevocationRepairBudgetExceeded)
	}
	if report.KernelStateWithdrawn {
		t.Fatal("a stranded kernel mount was reported as withdrawn; this is the exact lie being removed")
	}
	if report.Cause == "" || len(report.Withdrawal) == 0 {
		t.Fatalf("report carried no diagnostic content: %+v", report)
	}
}

func TestTeardownWithNoFatalCauseIsNotARevocation(t *testing.T) {
	// The benign /dev/fuse reply race that follows an already-observed external
	// unmount runs the same teardown goroutine without recording any cause.
	// Stamping a terminal revoked verdict onto an ordinary clean unmount would
	// be a worse lie than the one being fixed.
	fake := &fakeWithdrawal{installed: true}
	mount := revokingMount(t, fake)
	reported := false
	mount.onRevoked = func(RevocationReport) { reported = true }
	mount.reportRevocation(mount.withdrawKernelState())
	if reported {
		t.Fatal("a causeless teardown was reported as a revocation")
	}
}

func TestSuccessfulWithdrawalReportsCleanKernelState(t *testing.T) {
	fake := &fakeWithdrawal{installed: true}
	mount := revokingMount(t, fake)
	var report RevocationReport
	mount.onRevoked = func(r RevocationReport) { report = r }
	mount.recordFatalCause(errors.New("fusev3: coherence violation"))
	mount.reportRevocation(mount.withdrawKernelState())
	if !report.KernelStateWithdrawn {
		t.Fatal("a proven-absent mount was not reported withdrawn; the clean-detach proof depends on this")
	}
}

// TestWithdrawalDropsRetainedPagesBeforeTheAbort is the ladder half of the
// stale-page story. The other kinds of stale service this mount can commit are
// bounded by refusing requests; a retained page is not, because a read of a
// resident folio never becomes a request at all. So the ladder has to drop the
// pages explicitly while the reverse-notification descriptor is still alive.
// Stock FUSE does not expose the final page-purge result, so this test proves
// notification ordering only; the retained-reference residual stays explicit.
func TestWithdrawalDropsRetainedPagesBeforeTheAbort(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"file": testItem(72, authoritypb.Attr_REGULAR, 72)}
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "file")
	f.openForData(t, entry.NodeId)

	fake := &fakeWithdrawal{installed: true}
	// The abort has to be observable relative to the withdrawal, so record the
	// notifier's call log position at the moment it happens.
	abortedAfter := -1
	ops := fake.ops()
	realAbort := ops.abort
	ops.abort = func(k kernelMount) error {
		abortedAfter = len(f.notify.snapshot())
		return realAbort(k)
	}
	f.mount.kernelMount = kernelMount{id: "271", device: "0:57", point: t.TempDir()}
	f.mount.withdrawal = ops
	f.mount.repairBudget = 5 * time.Second

	out := f.mount.withdrawKernelState()
	if !out.withdrawn {
		t.Fatalf("withdrawal did not complete: %+v", out)
	}
	withdrawn := 0
	for index, call := range f.notify.snapshot() {
		if call.kind != "inode" || call.off != 0 || call.length != 0 {
			continue
		}
		withdrawn++
		if index >= abortedAfter {
			t.Fatalf("dropped pages for inode %d after the connection abort closed the notification window", call.inode)
		}
	}
	if withdrawn != 1 {
		t.Fatalf("whole-inode data withdrawals = %d, want exactly one", withdrawn)
	}
	if f.raw.cachedDataHolds(72) {
		t.Fatal("the ladder left a page-cache withdrawal obligation outstanding")
	}
}

// TestSessionDoneWaitsForRetainedPageWithdrawalAttempt pins the externally
// observable half of the stale-page contract. The authority transport edge may
// start teardown, but SessionDone cannot close while round one's whole-inode
// data notification is still blocked. It is released only after that pass and
// the connection abort have both been attempted, even when the notification
// itself reports failure.
func TestSessionDoneWaitsForRetainedPageWithdrawalAttempt(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"file": testItem(72, authoritypb.Attr_REGULAR, 72)}
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "file")
	f.openForData(t, entry.NodeId)

	dataStarted := make(chan struct{})
	releaseData := make(chan struct{})
	var dataOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseData) }) })
	f.notify.inodeST = fuse.EIO
	f.notify.onInode = func(_ uint64, off, length int64) {
		if off != 0 || length != 0 {
			return
		}
		dataOnce.Do(func() { close(dataStarted) })
		<-releaseData
	}

	fake := &fakeWithdrawal{installed: true}
	finished := make(chan struct {
		aborts int
		data   int
	}, 1)
	rpc := &terminalEnforcementRPC{
		fakeRPC: f.rpc,
		pending: make(chan struct{}),
		done:    make(chan struct{}),
		cause:   errors.New("authority session fenced"),
	}
	rpc.finish = func() {
		fake.mu.Lock()
		aborts := fake.aborts
		fake.mu.Unlock()
		data := 0
		for _, call := range f.notify.snapshot() {
			if call.kind == "inode" && call.off == 0 && call.length == 0 {
				data++
			}
		}
		finished <- struct {
			aborts int
			data   int
		}{aborts: aborts, data: data}
	}
	f.mount.rpc = rpc
	f.mount.kernelMount = kernelMount{id: "271", device: "0:57", point: t.TempDir()}
	f.mount.withdrawal = fake.ops()
	f.mount.repairBudget = time.Second
	close(f.mount.kernelConnectionDone)

	f.mount.wg.Add(1)
	go f.mount.watchSession(f.mount.ctx, rpc.SessionEndPending())
	close(rpc.pending)
	select {
	case <-dataStarted:
	case <-time.After(time.Second):
		t.Fatal("round-one retained-data withdrawal was not attempted")
	}
	select {
	case <-rpc.SessionDone():
		t.Fatal("SessionDone became observable inside the retained-data withdrawal")
	default:
	}
	releaseOnce.Do(func() { close(releaseData) })
	select {
	case <-rpc.SessionDone():
	case <-time.After(2 * time.Second):
		t.Fatal("SessionDone did not close after the bounded withdrawal ladder")
	}
	result := <-finished
	if result.data != 1 {
		t.Fatalf("whole-inode data withdrawal attempts at publication = %d, want 1", result.data)
	}
	if result.aborts != 1 {
		t.Fatalf("connection aborts at publication = %d, want 1", result.aborts)
	}
}

// TestWithdrawalReportsPagesTheLadderCouldNotDrop makes the residual stale-read
// window observable. A supervisor that is told the mount was torn down cleanly
// while a process inside it can still read pre-fence bytes has been told the
// wrong thing.
func TestWithdrawalReportsPagesTheLadderCouldNotDrop(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"file": testItem(72, authoritypb.Attr_REGULAR, 72)}
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "file")
	f.openForData(t, entry.NodeId)
	f.notify.inodeST = fuse.EIO

	fake := &fakeWithdrawal{installed: true}
	f.mount.kernelMount = kernelMount{id: "271", device: "0:57", point: t.TempDir()}
	f.mount.withdrawal = fake.ops()
	f.mount.repairBudget = 5 * time.Second

	out := f.mount.withdrawKernelState()
	found := false
	for _, failure := range out.failures {
		found = found || strings.Contains(failure, "data-withdrawal")
	}
	if !found {
		t.Fatalf("a refused page withdrawal was not reported: %v", out.failures)
	}
}
