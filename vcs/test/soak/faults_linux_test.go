//go:build linux

package soak

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

const soakGate = "PORTABLEFS_SOAK_TEST"

// faultListener records accepted DATA/CONTROL pairs and can cut exactly one
// transport while refusing its reconnects. Mounts attach sequentially, and the
// protocol opens DATA before CONTROL, so connection 2*m+1 is mount m's CONTROL
// lane. Rejecting later accepts is essential: closing one socket without doing
// that measures reconnect latency, not the ten-second subscription horizon.
type faultListener struct {
	net.Listener

	mu          sync.Mutex
	connections []net.Conn
	blocked     bool
}

func (l *faultListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		blocked := l.blocked
		if !blocked {
			l.connections = append(l.connections, conn)
		}
		l.mu.Unlock()
		if blocked {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

func (l *faultListener) cutControl(t *testing.T, mount int) {
	t.Helper()
	l.mu.Lock()
	if len(l.connections) != 4 {
		l.mu.Unlock()
		t.Fatalf("CONTROL fault requires two established transport pairs; got %d connections", len(l.connections))
	}
	l.blocked = true
	conn := l.connections[2*mount+1]
	l.mu.Unlock()
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cut mount %d CONTROL: %v", mount, err)
	}
}

func (l *faultListener) heal() {
	l.mu.Lock()
	l.blocked = false
	l.mu.Unlock()
}

func TestSoakFaults(t *testing.T) {
	if os.Getenv(soakGate) != "1" {
		t.Skipf("set %s=1 to run the destructive real-mount fault soak", soakGate)
	}
	t.Run("authority-new-epoch", testSoakAuthorityNewEpoch)
	t.Run("control-horizon", testSoakControlHorizon)
	t.Run("writeback-cap", testSoakWritebackCap)
	t.Run("dirty-unmount", testSoakDirtyUnmount)
}

func testSoakAuthorityNewEpoch(t *testing.T) {
	if isolateSoak(t, 90*time.Second) {
		return
	}
	started := time.Now()
	f := newFixtureConfig(t, integrationConfig{Mounts: 2})
	mustMkdir(t, f.join(1, "epoch-peer-work"))
	stopTraffic, trafficDone := startFaultTraffic(f.join(1, "epoch-peer-work"), true)
	defer func() {
		stopTraffic()
		if err := f.bounded(t, "join peer workload", 10*time.Second, func() error { return <-trafficDone }); err != nil {
			t.Errorf("peer traffic during Authority epoch fault: %v", err)
		}
	}()

	durable := bytes.Repeat([]byte("durable-before-epoch\n"), 512)
	mustWrite(t, f.join(0, "epoch-durable"), durable, 0o600)
	durableFile := mustOpenFile(t, f.join(0, "epoch-durable"), os.O_RDWR, 0)
	if err := durableFile.Sync(); err != nil {
		t.Fatalf("durable file fsync before epoch replacement: %v", err)
	}
	oldRoot := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
	if err := oldRoot.Sync(); err != nil {
		t.Fatalf("initial run barrier: %v", err)
	}

	// Hold delegated WRITE before transport assignment so an accepted local
	// write is definitely non-durable when the Authority epoch changes.
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	releaseFault := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseFault()
	f.transports[0].hookMu.Lock()
	f.transports[0].beforeDelegatedMutation = func(ctx context.Context, request *authoritypb.Request) error {
		if request.GetWrite() == nil || request.GetWrite().GetDelegation() == nil {
			return nil
		}
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.transports[0].hookMu.Unlock()
	dirty := mustOpenFile(t, f.join(0, "epoch-dirty"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if _, err := dirty.Write([]byte("accepted but deliberately not durable")); err != nil {
		t.Fatalf("buffer dirty epoch write: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			f.dump(t, "epoch-pre-handle-cleanup")
		}
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("background flush did not reach the injected slow Authority")
	}

	oldEpoch := append([]byte(nil), f.clients[0].Epoch()...)
	f.replaceAuthorityEpoch()
	releaseFault()

	waitForFreshBarrier(t, f.mountPath(0), 30*time.Second)
	waitForFreshBarrier(t, f.mountPath(1), 30*time.Second)
	newEpoch := f.authority.Epoch()
	if bytes.Equal(oldEpoch, newEpoch[:]) {
		t.Fatal("Authority restart retained its epoch")
	}

	buf := make([]byte, 1)
	if _, err := durableFile.ReadAt(buf, 0); !errors.Is(err, syscall.EIO) {
		t.Fatalf("old-epoch read = %v, want EIO", err)
	}
	if _, err := durableFile.WriteAt([]byte("x"), 0); !errors.Is(err, syscall.EIO) {
		t.Fatalf("old-epoch write = %v, want EIO", err)
	}
	if _, err := durableFile.Stat(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("old-epoch fstat = %v, want EIO", err)
	}
	if err := durableFile.Sync(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("old-epoch file fsync = %v, want EIO", err)
	}
	if err := dirty.Sync(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("dirty old-epoch file fsync = %v, want EIO", err)
	}
	if err := oldRoot.Sync(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("run barrier spanning lost epoch = %v, want EIO", err)
	}

	requireContent(t, f.join(0, "epoch-durable"), durable, "fresh open after epoch replacement")
	fresh := []byte("fresh-epoch-data")
	mustWrite(t, f.join(0, "epoch-fresh"), fresh, 0o600)
	requireContent(t, f.join(1, "epoch-fresh"), fresh, "peer read after epoch replacement")
	requireContent(t, filepath.Join(f.volumeRoot, "epoch-durable"), durable, "direct XFS durability after epoch replacement")
	assertBarrier(t, f.mountPath(0), nil, "fresh mount A barrier")
	assertBarrier(t, f.mountPath(1), nil, "fresh mount B barrier")
	logFaultPass(t, f, "authority-new-epoch", started)
}

func testSoakControlHorizon(t *testing.T) {
	if isolateSoak(t, 90*time.Second) {
		return
	}
	var listener *faultListener
	started := time.Now()
	f := newFixtureConfig(t, integrationConfig{Mounts: 2, wrapListener: func(inner net.Listener) net.Listener {
		listener = &faultListener{Listener: inner}
		return listener
	}})
	defer listener.heal()
	mustMkdir(t, f.join(1, "control-peer-work"))
	stopTraffic, trafficDone := startFaultTraffic(f.join(1, "control-peer-work"), true)
	defer func() {
		stopTraffic()
		if err := f.bounded(t, "join peer workload", 10*time.Second, func() error { return <-trafficDone }); err != nil {
			t.Errorf("peer traffic during CONTROL fault: %v", err)
		}
	}()

	old := []byte("cached before CONTROL loss")
	fresh := []byte("committed after CONTROL horizon")
	mustWrite(t, f.join(0, "control-payload"), old, 0o600)
	assertBarrier(t, f.mountPath(0), nil, "pre-partition barrier")
	retained := mustOpenFile(t, f.join(1, "control-payload"), os.O_RDONLY, 0)
	if got := readAt(t, retained, len(old)); !bytes.Equal(got, old) {
		t.Fatalf("initial retained read = %q, want %q", got, old)
	}
	oldRoot := mustOpenFile(t, f.mountPath(1), os.O_RDONLY, 0)

	cutStart := time.Now()
	listener.cutControl(t, 1)
	writeDone := make(chan error, 1)
	go func() { writeDone <- os.WriteFile(f.join(0, "control-payload"), fresh, 0o600) }()
	select {
	case err := <-writeDone:
		t.Fatalf("peer write crossed live cache permission before the horizon: %v", err)
	case <-time.After(8 * time.Second):
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("peer write after CONTROL horizon: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("peer write did not pass the CONTROL horizon within 15 seconds")
	}

	buf := make([]byte, len(old))
	if _, err := retained.ReadAt(buf, 0); !errors.Is(err, syscall.EIO) {
		t.Errorf("partitioned retained read = %v, want EIO", err)
	}
	if bytes.Equal(buf, old) {
		t.Error("partitioned retained read returned stale cached bytes")
	}
	if _, err := os.Stat(f.join(1, "cold-during-control-cut")); !errors.Is(err, syscall.EIO) {
		t.Errorf("cold lookup after horizon = %v, want EIO", err)
	}

	// Keep the cut in place for the full requested 15 seconds even when the
	// horizon passes early, then prove cold resubscription restores service.
	if remaining := 15*time.Second - time.Since(cutStart); remaining > 0 {
		timer := time.NewTimer(remaining)
		<-timer.C
	}
	listener.heal()
	waitForContent(t, f.join(1, "control-payload"), fresh, 20*time.Second)
	if err := oldRoot.Sync(); err != nil {
		t.Fatalf("run barrier after lossless CONTROL recovery: %v", err)
	}
	assertBarrier(t, f.mountPath(1), nil, "fresh barrier after CONTROL recovery")
	logFaultPass(t, f, "control-horizon", started)
}

func testSoakWritebackCap(t *testing.T) {
	if isolateSoak(t, 90*time.Second) {
		return
	}
	started := time.Now()
	f := newFixtureConfig(t, integrationConfig{Mounts: 2})
	mustMkdir(t, f.join(0, "capacity"))
	mustMkdir(t, f.join(1, "peer-work"))

	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	f.transports[0].hookMu.Lock()
	f.transports[0].beforeDelegatedMutation = func(ctx context.Context, request *authoritypb.Request) error {
		if request.GetWrite() == nil || request.GetWrite().GetDelegation() == nil {
			return nil
		}
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.transports[0].hookMu.Unlock()

	stopTraffic, trafficDone := startFaultTraffic(f.join(1, "peer-work"), false)
	defer func() {
		stopTraffic()
		if err := f.bounded(t, "join peer workload", 10*time.Second, func() error { return <-trafficDone }); err != nil {
			t.Errorf("peer traffic during capacity fault: %v", err)
		}
	}()

	target := mustOpenFile(t, f.join(0, "capacity", "buffer"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	payload := bytes.Repeat([]byte{0x6d}, writeback.MaxPayload)
	type writeResult struct {
		completed int64
		err       error
	}
	result := make(chan writeResult, 1)
	var accepted atomic.Int64
	go func() {
		var completed int64
		for completed <= int64(writeback.DefaultMaxBytes) {
			n, err := target.WriteAt(payload, completed)
			if err != nil {
				result <- writeResult{completed: completed, err: err}
				return
			}
			if n != len(payload) {
				result <- writeResult{completed: completed, err: fmt.Errorf("short write %d/%d", n, len(payload))}
				return
			}
			completed += int64(n)
			accepted.Store(completed)
		}
		result <- writeResult{completed: completed}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("slow Authority hook saw no delegated WRITE")
	}
	waitUntil(t, 10*time.Second, "writer to fill the 64 MiB cap", func() bool { return accepted.Load() == int64(writeback.DefaultMaxBytes) })
	select {
	case got := <-result:
		t.Fatalf("writer did not block at the %d-byte cap: completed=%d err=%v", writeback.DefaultMaxBytes, got.completed, got.err)
	case <-time.After(2 * time.Second):
	}
	close(release)
	var got writeResult
	select {
	case got = <-result:
	case <-time.After(30 * time.Second):
		t.Fatal("capacity-blocked writer did not continue after the Authority recovered")
	}
	if got.err != nil {
		t.Fatalf("capacity-blocked writer after recovery: completed=%d err=%v", got.completed, got.err)
	}
	if got.completed <= int64(writeback.DefaultMaxBytes) {
		t.Fatalf("completed bytes = %d, want more than cap %d", got.completed, writeback.DefaultMaxBytes)
	}
	if err := target.Sync(); err != nil {
		t.Fatalf("capacity file fsync: %v", err)
	}
	assertBarrier(t, f.mountPath(0), nil, "capacity durability barrier")
	info, err := os.Stat(filepath.Join(f.volumeRoot, "capacity", "buffer"))
	if err != nil {
		t.Fatalf("stat capacity file through direct XFS: %v", err)
	}
	if info.Size() != got.completed {
		t.Fatalf("direct XFS capacity file size = %d, want %d", info.Size(), got.completed)
	}
	wantHash := sha256.New()
	for n := int64(0); n < got.completed; n += int64(len(payload)) {
		_, _ = wantHash.Write(payload)
	}
	for _, base := range []string{f.mountPath(1), f.volumeRoot} {
		actual, err := workloadFileHash(filepath.Join(base, "capacity", "buffer"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual[:], wantHash.Sum(nil)) {
			t.Fatalf("capacity data hash differs through %s", base)
		}
	}
	stopTraffic()
	if err := f.bounded(t, "join capacity peer before barrier", 10*time.Second, func() error { return <-trafficDone }); err != nil {
		t.Fatal(err)
	}
	f.barrier(t)
	logFaultPass(t, f, "writeback-cap", started)
}

func testSoakDirtyUnmount(t *testing.T) {
	if isolateSoak(t, 90*time.Second) {
		return
	}
	var reportsMu sync.Mutex
	var reports []fusev3.WritebackDropReport
	started := time.Now()
	f := newFixtureConfig(t, integrationConfig{Mounts: 1, OnWritebackDrop: func(report fusev3.WritebackDropReport) {
		reportsMu.Lock()
		reports = append(reports, report)
		reportsMu.Unlock()
	}})

	entered := make(chan struct{})
	var enteredOnce sync.Once
	f.transports[0].hookMu.Lock()
	f.transports[0].beforeDelegatedMutation = func(ctx context.Context, request *authoritypb.Request) error {
		if request.GetWrite() == nil || request.GetWrite().GetDelegation() == nil {
			return nil
		}
		enteredOnce.Do(func() { close(entered) })
		<-ctx.Done()
		return ctx.Err()
	}
	f.transports[0].hookMu.Unlock()

	root := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
	payload := []byte("dirty data that cannot reach the Authority")
	dirty := mustOpenFile(t, f.join(0, "dirty-unmount"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if _, err := dirty.Write(payload); err != nil {
		t.Fatalf("dirty write before unmount: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			f.dump(t, "dirty-unmount-pre-handle-cleanup")
		}
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("dirty write never attempted background flush")
	}
	// Open descriptors deliberately keep a lazy FUSE mount alive. Close them
	// first so Unmount tests dirty-buffer draining rather than an EBUSY mount.
	if err := dirty.Close(); err != nil {
		t.Fatalf("close dirty writer before unmount: %v", err)
	}
	_ = root.Close()
	for _, h := range f.barriers {
		_ = h.Close()
	}
	f.stopAuthority()

	start := time.Now()
	err := f.mounts[0].Unmount()
	if err == nil {
		t.Fatal("dirty unmount with an unreachable Authority reported success")
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("dirty unmount exceeded the subscription horizon: %s", time.Since(start))
	}
	f.mounts[0] = nil
	if isMounted(t, f.mountPath(0)) {
		t.Fatal("dirty unmount returned with the mount still installed")
	}

	reportsMu.Lock()
	got := append([]fusev3.WritebackDropReport(nil), reports...)
	reportsMu.Unlock()
	if len(got) != 1 {
		t.Fatalf("dirty unmount drop reports = %+v, want exactly one", got)
	}
	if got[0].Bytes != int64(len(payload)) || got[0].Entries != 1 || got[0].LossSequence == 0 {
		t.Fatalf("dirty unmount drop report = %+v", got[0])
	}
	if !strings.Contains(got[0].Reason, "barrier failed") && !strings.Contains(got[0].Reason, "cold subscription replacement") {
		t.Fatalf("dirty unmount loss reason = %q, want bounded shutdown or horizon fence", got[0].Reason)
	}
	logFaultPass(t, f, "dirty-unmount", started)
}

// replaceAuthorityEpoch starts a new server/runtime against the same open XFS
// tree and on the same TCP address. Kernel mounts and frontend processes remain
// untouched, so recovery must happen through the real epoch-change path.
func (f *integrationFixture) replaceAuthorityEpoch() {
	f.t.Helper()
	address := f.listener.Addr().String()
	f.stopAuthority()

	authority, err := volumeserver.New(integrationVolumeID, volumeserver.Config{
		SessionLease: f.cfg.SessionLease, MaxReplaySlots: integrationMaxReplaySlots,
		MaxSessions: 8, MaxLockRecords: 4096, Now: f.now,
	})
	if err != nil {
		f.t.Fatalf("create replacement authority epoch: %v", err)
	}
	f.authority = authority
	f.membership = newRecordingMembership()
	f.fencer = &recordingFencer{inner: authority}
	coordination, err := authorityrpc.NewCoordination(authorityrpc.CoordinationConfig{
		Store: f.store, Fencer: f.fencer, Locks: authority.Locks(), Membership: f.membership,
		Prior: volumeserver.PriorEpochStrictMountsFenced, ClockSkew: time.Minute,
		MaxCachedNameCapacity: uint64(f.cfg.CachedNameCapacity), MaxRepairBudget: time.Minute, Now: f.now,
	})
	if err != nil {
		f.t.Fatalf("assemble replacement authority coordination: %v", err)
	}
	f.coherence = coordination.Coherence
	f.routes = coordination.Routes
	handler := &authorityrpc.VolumeHandler{
		Store: f.store, Runtime: authority, Authorizer: integrationAuthorizer{now: f.now},
		MaxFrame: integrationMaxFrame, MaxRead: 1 << 20, MaxWrite: 1 << 20,
		MaxInFlight: integrationServerInFlight, MaxItemsPerSession: f.cfg.MaxItemsPerSession,
		MaxOpensPerSession: 4096, MaxItems: f.cfg.MaxItems, MaxOpens: 16384,
		MaxRetainedReplyBytes: integrationAllocationBudget, WriteAdmission: f.writeAdmission,
		MaxWriteBytesPerSession: integrationWriteBytesPerSession, MaxWriteBytesInFlight: integrationWriteBytes,
		MaxWritesPerSession: integrationWritesPerSession, MaxWrites: integrationWrites,
		WriteAdmissionProgressTimeout: integrationWriteProgressTimeout, WriteAbsoluteTimeout: integrationWriteAbsoluteTimeout,
		TerminalDeliveryTimeout: integrationTerminalDeliveryTimeout, FskitWriteStaging: f.fskitStaging,
		MaxFskitWriteBytes:                  authorityrpc.RequiredFskitWriteBytes,
		MaxFskitWriteStagingBytesPerSession: integrationWriteBytesPerSession,
		MaxFskitWriteStagingBytes:           integrationWriteBytes, MaxFskitWritesPerSession: integrationWritesPerSession,
		MaxFskitWrites: integrationWrites, FskitWriteProgressTimeout: integrationWriteProgressTimeout,
		FskitWriteAbsoluteTimeout: integrationWriteAbsoluteTimeout,
	}
	coordination.Bind(handler)
	priorCounts := map[string]int{}
	f.counter.mu.Lock()
	for k, v := range f.counter.byKind {
		priorCounts[k] = v
	}
	f.counter.mu.Unlock()
	f.counter = &countingHandler{inner: handler, byKind: priorCounts}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		f.t.Fatalf("listen for replacement authority on %s: %v", address, err)
	}
	f.listener = listener
	ctx, cancel := context.WithCancel(context.Background())
	f.stopServe, f.served, f.stopped = cancel, make(chan error, 1), false
	f.server = &authorityrpc.Server{
		Handler: f.counter, MaxFrame: integrationMaxFrame, MaxInFlight: integrationServerInFlight,
		MaxConnections: 16, MaxFrameBytesInFlight: integrationAllocationBudget,
		HandshakeTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute, WriteTimeout: 30 * time.Second,
	}
	served := f.served
	go func() {
		pprof.Do(ctx, pprof.Labels("component", "authority-replacement"), func(ctx context.Context) {
			served <- f.server.Serve(ctx, listener, f.serverTLS)
		})
	}()
}

func waitForFreshBarrier(t *testing.T, root string, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	var last error
	for time.Now().Before(deadline) {
		file, err := os.Open(root)
		if err == nil {
			last = file.Sync()
			_ = file.Close()
			if last == nil {
				return
			}
		} else {
			last = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fresh root barrier did not recover within %s: %v", bound, last)
}

func assertBarrier(t *testing.T, root string, want error, what string) {
	t.Helper()
	file, err := os.Open(root)
	if err != nil {
		t.Fatalf("%s: open root: %v", what, err)
	}
	err = file.Sync()
	_ = file.Close()
	if want == nil && err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

func readAt(t *testing.T, file *os.File, length int) []byte {
	t.Helper()
	buf := make([]byte, length)
	n, err := file.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("read retained descriptor: %v", err)
	}
	return buf[:n]
}

func waitForContent(t *testing.T, path string, want []byte, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	var last error
	for time.Now().Before(deadline) {
		got, err := os.ReadFile(path)
		if err == nil && bytes.Equal(got, want) {
			return
		}
		if err == nil {
			err = fmt.Errorf("got %q, want %q", got, want)
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s did not converge within %s: %v", path, bound, last)
}

// startFaultTraffic keeps a disjoint mount subtree under real listing, stat,
// read, create, rename and unlink traffic while a fault is active. Callers may
// allow EIO for a horizon/epoch interval; ESTALE and ENOTCONN always fail.
func startFaultTraffic(root string, allowEIO bool) (func(), <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		defer close(done)
		for iteration := 0; ; iteration++ {
			select {
			case <-ctx.Done():
				done <- nil
				return
			default:
			}
			path := filepath.Join(root, fmt.Sprintf("traffic-%016d.tmp", iteration))
			published := strings.TrimSuffix(path, ".tmp")
			for _, operation := range []func() error{
				func() error { return os.WriteFile(path, []byte(fmt.Sprintf("%d", iteration)), 0o600) },
				func() error { return os.Rename(path, published) },
				func() error { _, err := os.Stat(published); return err },
				func() error { _, err := os.ReadFile(published); return err },
				func() error { _, err := os.ReadDir(root); return err },
				func() error { return os.Remove(published) },
			} {
				if err := operation(); err != nil {
					if errors.Is(err, syscall.ESTALE) || errors.Is(err, syscall.ENOTCONN) {
						done <- err
						return
					}
					if allowEIO && errors.Is(err, syscall.EIO) {
						break
					}
					done <- err
					return
				}
			}
		}
	}()
	return cancel, done
}

func logFaultPass(t *testing.T, f *fixture, name string, started time.Time) {
	t.Helper()
	t.Logf("SOAK_FAULT_PASS name=%s seconds=%.3f authority_requests=%v", name, time.Since(started).Seconds(), f.counts())
}
