//go:build linux

package fusev3

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/coherencebench"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

const (
	baselineInstallFiles = 40000
	baselineInstallDirs  = 2000
	baselineGitFiles     = 20000
	baselinePeerFiles    = 2000
	baselineItemLimit    = 65536
	baselineNameCapacity = 1 << 16
)

type baselineMeasurement struct {
	coherencebench.WorkloadResult
	Target                   string         `json:"target"`
	AuthorityRequests        int            `json:"authority_requests"`
	AuthorityRequestsPerOp   float64        `json:"authority_requests_per_operation"`
	AuthorityFilesystem      int            `json:"authority_filesystem_requests"`
	AuthorityFilesystemPerOp float64        `json:"authority_filesystem_requests_per_operation"`
	AuthorityFilesystemKinds map[string]int `json:"authority_filesystem_breakdown,omitempty"`
	AuthorityControlKinds    map[string]int `json:"authority_control_breakdown,omitempty"`
	AuthorityDrainSeconds    float64        `json:"authority_drain_seconds,omitempty"`
}

// TestCoherenceBaseline is a measurement harness rather than a timing gate. It
// runs the design's representative install, git, and cross-mount workloads
// against a real PortableFS mount and against the loop-backed XFS that backs
// the same Authority. Every PORTABLEFS_BASELINE line is one self-contained JSON
// observation suitable for docs/coherence-v2/baseline.md.
func TestCoherenceBaseline(t *testing.T) {
	if os.Getenv(envPerformance) != "1" {
		t.Skipf("set %s=1 to run the coherence-v2 baseline", envPerformance)
	}
	env := requireWorkloadEnvironment(t)
	kernel, err := exec.Command("uname", "-r").Output()
	if err != nil {
		t.Fatalf("read container kernel version: %v", err)
	}
	t.Logf("PORTABLEFS_BASELINE_KERNEL %s", strings.TrimSpace(string(kernel)))

	t.Run("install-direct-xfs", func(t *testing.T) {
		for _, workers := range []int{1, 8} {
			t.Run(fmt.Sprintf("workers-%d", workers), func(t *testing.T) {
				root := newDirectBaselineRoot(t, env, fmt.Sprintf("install-%d", workers))
				result, err := coherencebench.Install(root, baselineInstallFiles, baselineInstallDirs, workers)
				if err != nil {
					t.Fatalf("direct-XFS install with %d workers: %v", workers, err)
				}
				recordBaseline(t, baselineMeasurement{WorkloadResult: result, Target: "direct-xfs"})
			})
		}
	})

	for _, workers := range []int{1, 8} {
		t.Run(fmt.Sprintf("install-portablefs-workers-%d", workers), func(t *testing.T) {
			fixture := newIntegrationFixture(t, baselineIntegrationConfig(1))
			enableBaselineOpenTracking(fixture.counter)
			root := fixture.join(0, "install")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatalf("create mounted install root: %v", err)
			}
			measureBaseline(t, "portablefs", fixture.counter, func() (coherencebench.WorkloadResult, error) {
				return coherencebench.Install(root, baselineInstallFiles, baselineInstallDirs, workers)
			})
		})
	}

	t.Run("git-direct-xfs", func(t *testing.T) {
		root := newDirectBaselineRoot(t, env, "git")
		if err := coherencebench.PrepareGit(root, baselineGitFiles); err != nil {
			t.Fatalf("prepare direct-XFS git repository: %v", err)
		}
		if err := coherencebench.EvictFilePages(root); err != nil {
			t.Fatalf("evict direct-XFS git file pages: %v", err)
		}
		for _, temperature := range []string{"cold", "warm"} {
			result, err := coherencebench.GitStatus(root, temperature, baselineGitFiles)
			if err != nil {
				t.Fatalf("direct-XFS %s git status: %v", temperature, err)
			}
			recordBaseline(t, baselineMeasurement{WorkloadResult: result, Target: "direct-xfs"})
		}
	})

	t.Run("git-portablefs", func(t *testing.T) {
		preparationConfig := baselineIntegrationConfig(1)
		// The 20k setup disconnected during git add with the shipping cache.
		// Prepare with the working integration cache, then recreate the Authority
		// and mount with the shipping capacity before either measured status.
		preparationConfig.CachedNameCapacity = integrationCachedNames
		fixture := newIntegrationFixture(t, preparationConfig)
		root := fixture.join(0, "repo")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatalf("create mounted git repository: %v", err)
		}
		if err := coherencebench.PrepareGit(root, baselineGitFiles); err != nil {
			t.Fatalf("prepare mounted git repository: %v; mount health: %s", err, fixture.sessionDiagnostics())
		}
		fixture.cfg.CachedNameCapacity = baselineNameCapacity
		fixture.remount()
		enableBaselineOpenTracking(fixture.counter)
		for _, temperature := range []string{"cold", "warm"} {
			measureBaseline(t, "portablefs", fixture.counter, func() (coherencebench.WorkloadResult, error) {
				return coherencebench.GitStatus(root, temperature, baselineGitFiles)
			})
		}
	})

	t.Run("peer-direct-xfs", func(t *testing.T) {
		root := newDirectBaselineRoot(t, env, "peer")
		result, err := coherencebench.PeerWriteRead(root, root, baselinePeerFiles)
		if err != nil {
			t.Fatalf("direct-XFS peer workload: %v", err)
		}
		recordBaseline(t, baselineMeasurement{WorkloadResult: result, Target: "direct-xfs"})
	})

	t.Run("peer-portablefs", func(t *testing.T) {
		fixture := newIntegrationFixture(t, baselineIntegrationConfig(2))
		enableBaselineOpenTracking(fixture.counter)
		rootA := fixture.join(0, "peer")
		rootB := fixture.join(1, "peer")
		if err := os.Mkdir(rootA, 0o700); err != nil {
			t.Fatalf("create source peer root: %v", err)
		}
		if err := waitForEnumeratedName(fixture.mountPath(1), "peer", 30*time.Second); err != nil {
			t.Fatalf("discover peer root through mount B: %v", err)
		}
		measureBaseline(t, "portablefs", fixture.counter, func() (coherencebench.WorkloadResult, error) {
			return coherencebench.PeerWriteRead(rootA, rootB, baselinePeerFiles)
		})
	})
}

func baselineIntegrationConfig(mounts int) integrationConfig {
	return integrationConfig{
		Mounts: mounts, MaxItemsPerSession: baselineItemLimit, MaxItems: baselineItemLimit,
		CachedNameCapacity: baselineNameCapacity,
	}
}

func newDirectBaselineRoot(t *testing.T, env integrationEnv, label string) string {
	t.Helper()
	root := filepath.Join(env.xfsRoot, integrationVolumeDirectory(t)+"."+label+".direct")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("create direct-XFS %s root: %v", label, err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove direct-XFS %s root: %v", label, err)
		}
	})
	return root
}

func waitForEnumeratedName(root, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() == name && entry.IsDir() {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not appear within %s", name, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func measureBaseline(t *testing.T, target string, counter *countingHandler, run func() (coherencebench.WorkloadResult, error)) {
	t.Helper()
	drainBaselineOpens(t, counter)
	meter := &baselineRequestMeter{byKind: make(map[string]int)}
	counter.setBeforeHandle(meter.observe)
	result, err := run()
	if err != nil {
		counter.setBeforeHandle(nil)
		t.Fatalf("%s %s: %v", target, result.Scenario, err)
	}
	// close(2) can return before FUSE RELEASE reaches the daemon. Keep counting
	// through the corresponding Authority CLOSE replies, without adding that
	// drain to the POSIX workload's wall time or charging it to the next phase.
	drainStart := time.Now()
	drainBaselineOpens(t, counter)
	drainSeconds := time.Since(drainStart).Seconds()
	all, filesystem, control := meter.result()
	counter.setBeforeHandle(nil)
	total := sumBaselineRequests(all)
	filesystemTotal := sumBaselineRequests(filesystem)
	totalRate := 0.0
	filesystemRate := 0.0
	if result.Operations > 0 {
		totalRate = float64(total) / float64(result.Operations)
		filesystemRate = float64(filesystemTotal) / float64(result.Operations)
	}
	recordBaseline(t, baselineMeasurement{
		WorkloadResult: result, Target: target, AuthorityRequests: total,
		AuthorityRequestsPerOp: totalRate, AuthorityFilesystem: filesystemTotal,
		AuthorityFilesystemPerOp: filesystemRate, AuthorityFilesystemKinds: filesystem,
		AuthorityControlKinds: control,
		AuthorityDrainSeconds: drainSeconds,
	})
}

func enableBaselineOpenTracking(counter *countingHandler) {
	counter.mu.Lock()
	defer counter.mu.Unlock()
	counter.openHandles = make(map[integrationOpenKey]struct{})
	counter.trackOpens = true
}

func drainBaselineOpens(t *testing.T, counter *countingHandler) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		counter.mu.Lock()
		enabled, handles, pending := counter.trackOpens, len(counter.openHandles), counter.openOperations
		counter.mu.Unlock()
		if !enabled {
			t.Fatal("baseline handle tracking was not enabled before workload opens")
		}
		if handles == 0 && pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("baseline CLOSE drain timed out: %d open handles, %d open/close requests in flight", handles, pending)
		}
		time.Sleep(time.Millisecond)
	}
}

type baselineRequestMeter struct {
	mu     sync.Mutex
	byKind map[string]int
	closed bool
}

func (m *baselineRequestMeter) observe(request *authoritypb.Request) {
	kind := baselineRequestKind(request)
	m.mu.Lock()
	if !m.closed {
		m.byKind[kind]++
	}
	m.mu.Unlock()
}

func (m *baselineRequestMeter) result() (map[string]int, map[string]int, map[string]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	all := make(map[string]int, len(m.byKind))
	filesystem := make(map[string]int)
	control := make(map[string]int)
	for kind, count := range m.byKind {
		all[kind] = count
		if baselineControlRequest(kind) {
			control[kind] = count
		} else {
			filesystem[kind] = count
		}
	}
	return all, filesystem, control
}

func baselineRequestKind(request *authoritypb.Request) string {
	message := request.ProtoReflect()
	body := message.Descriptor().Oneofs().ByName("body")
	if body == nil {
		return "missing-body-oneof"
	}
	field := message.WhichOneof(body)
	if field == nil {
		return "empty-body"
	}
	return string(field.Name())
}

func baselineControlRequest(kind string) bool {
	switch kind {
	case "hello", "attach", "resume", "keep_alive", "detach", "cancel", "reauthorize",
		"reclaim", "activate", "abort_attach", "terminal_delivery_receipt", "apply_routes",
		"subscribe", "renew_subscription", "next_control_event", "change_ack",
		"delegation_recall_ack", "delegation_break_ack", "delegation_mode_change_ack", "delegation_release", "barrier",
		"next_fskit_repair", "ack_fskit_repair":
		return true
	default:
		return false
	}
}

func sumBaselineRequests(requests map[string]int) int {
	total := 0
	for _, count := range requests {
		total += count
	}
	return total
}

func recordBaseline(t *testing.T, measurement baselineMeasurement) {
	t.Helper()
	if len(measurement.AuthorityFilesystemKinds) == 0 {
		measurement.AuthorityFilesystemKinds = nil
	}
	if len(measurement.AuthorityControlKinds) == 0 {
		measurement.AuthorityControlKinds = nil
	}
	encoded, err := json.Marshal(measurement)
	if err != nil {
		t.Fatalf("encode baseline result: %v", err)
	}
	t.Logf("PORTABLEFS_BASELINE %s", encoded)
}

type baselineAccountingHandler struct {
	authorityrpc.Handler
	response *authoritypb.Response
}

func (h *baselineAccountingHandler) Handle(context.Context, *authoritypb.Request) *authoritypb.Response {
	return h.response
}

func TestBaselineOpenAccounting(t *testing.T) {
	handle := []byte("same-token-across-sessions")
	for _, shape := range []struct {
		name     string
		request  *authoritypb.Request
		response *authoritypb.Response
	}{
		{"open", &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{}}}, &authoritypb.Response{Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: handle}}}},
		{"create", &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{}}}, &authoritypb.Response{Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Handle: handle}}}},
		{"tmpfile", &authoritypb.Request{Body: &authoritypb.Request_Tmpfile{Tmpfile: &authoritypb.TmpfileRequest{}}}, &authoritypb.Response{Body: &authoritypb.Response_Tmpfile{Tmpfile: &authoritypb.TmpfileReply{Handle: handle}}}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			inner := &baselineAccountingHandler{response: shape.response}
			counter := &countingHandler{inner: inner}
			enableBaselineOpenTracking(counter)
			for _, session := range []string{"A", "B"} {
				shape.request.Session = &authoritypb.SessionProof{Id: []byte(session)}
				counter.Handle(context.Background(), shape.request)
			}
			if len(counter.openHandles) != 2 || counter.openOperations != 0 {
				t.Fatalf("open accounting: handles=%d pending=%d", len(counter.openHandles), counter.openOperations)
			}
			closeRequest := &authoritypb.Request{Session: &authoritypb.SessionProof{Id: []byte("A")}, Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: handle}}}
			inner.response = &authoritypb.Response{Errno: 5}
			counter.Handle(context.Background(), closeRequest)
			if len(counter.openHandles) != 2 {
				t.Fatal("failed CLOSE removed a live handle")
			}
			inner.response = &authoritypb.Response{}
			for _, session := range []string{"A", "B"} {
				closeRequest.Session.Id = []byte(session)
				counter.Handle(context.Background(), closeRequest)
			}
			drainBaselineOpens(t, counter)
		})
	}
}

func TestBaselineMeterFreezesAtDrainBoundary(t *testing.T) {
	meter := &baselineRequestMeter{byKind: make(map[string]int)}
	request := &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{}}}
	meter.observe(request)
	all, _, _ := meter.result()
	meter.observe(request)
	after, _, _ := meter.result()
	if all["close"] != 1 || after["close"] != 1 {
		t.Fatalf("late callback changed completed measurement: before=%v after=%v", all, after)
	}
}
