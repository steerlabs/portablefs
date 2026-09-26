//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFuseMountControlSnapshotRunsDuringRenewal(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	control, err := startFuseReauthorizationControl(func(ctx context.Context, _ string, _ uint64, _ []byte) (time.Time, error) {
		close(entered)
		select {
		case <-release:
			return time.Now().Add(time.Hour), nil
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		}
	}, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "7"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance, ReauthorizationControlSocket: control.SocketPath()}
	renewed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := reauthorizeFuseMount(ctx, state, "capability", 1, []byte("certificate"))
		renewed <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("renewal did not reach the control handler")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	snapshot, err := readFuseMountLoss(ctx, state, lossTestInstance)
	if err != nil || snapshot.LossSequence != "7" {
		t.Fatalf("snapshot while renewal is blocked = %+v, %v", snapshot, err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-renewed; err != nil {
		t.Fatal(err)
	}
}

func waitForFuseMountControlConnections(t *testing.T, control fuseReauthorizationControl, want int) {
	t.Helper()
	c := control.(*unixReauthorizationControl)
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.Lock()
		got := len(c.connections)
		c.mu.Unlock()
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("accepted control connections = %d, want at least %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForQueuedRenewal(t *testing.T, control fuseReauthorizationControl, entered <-chan uint64) {
	t.Helper()
	c := control.(*unixReauthorizationControl)
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case sequence := <-entered:
			t.Fatalf("renewal %d overtook an earlier accepted renewal", sequence)
		default:
		}
		c.mu.Lock()
		accepted := len(c.connections)
		c.mu.Unlock()
		if accepted >= 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("second renewal was not retained behind the first (active connections=%d)", accepted)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFuseMountControlOrdersConcurrentRenewalsWithoutBlockingLoss(t *testing.T) {
	entered := make(chan uint64, 2)
	releaseFirst := make(chan struct{})
	control, err := startFuseReauthorizationControl(func(ctx context.Context, _ string, sequence uint64, _ []byte) (time.Time, error) {
		entered <- sequence
		if sequence == 1 {
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return time.Time{}, ctx.Err()
			}
		}
		return time.Now().Add(time.Hour), nil
	}, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "9"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseFirst) })
	state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance, ReauthorizationControlSocket: control.SocketPath()}
	renewed := make(chan error, 2)
	startRenewal := func(sequence uint64) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			_, err := reauthorizeFuseMount(ctx, state, "capability", sequence, []byte("certificate"))
			renewed <- err
		}()
	}
	startRenewal(1)
	select {
	case sequence := <-entered:
		if sequence != 1 {
			t.Fatalf("first callback sequence = %d", sequence)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first renewal did not enter")
	}
	startRenewal(2)
	waitForQueuedRenewal(t, control, entered)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	snapshot, err := readFuseMountLoss(ctx, state, lossTestInstance)
	if err != nil || snapshot.LossSequence != "9" {
		t.Fatalf("snapshot during queued renewal = %+v, %v", snapshot, err)
	}
	select {
	case sequence := <-entered:
		t.Fatalf("renewal %d overtook unfinished renewal 1", sequence)
	case <-time.After(150 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseFirst) })
	for i := 0; i < 2; i++ {
		select {
		case err := <-renewed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("ordered renewal did not complete")
		}
	}
	select {
	case sequence := <-entered:
		if sequence != 2 {
			t.Fatalf("second callback sequence = %d", sequence)
		}
	default:
		t.Fatal("second renewal completed without entering its callback")
	}
}

func TestFuseMountControlPreservesAcceptedRenewalOrderAcrossPartialRequest(t *testing.T) {
	entered := make(chan uint64, 2)
	control, err := startFuseReauthorizationControl(func(_ context.Context, _ string, sequence uint64, _ []byte) (time.Time, error) {
		entered <- sequence
		return time.Now().Add(time.Hour), nil
	}, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "10"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance, ReauthorizationControlSocket: control.SocketPath()}
	first, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: control.SocketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte(`{"capability":"capability","clientCertificatePem":"certificate","sequence":`)); err != nil {
		t.Fatal(err)
	}
	waitForFuseMountControlConnections(t, control, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if snapshot, err := readFuseMountLoss(ctx, state, lossTestInstance); err != nil || snapshot.LossSequence != "10" {
		t.Fatalf("snapshot behind partial renewal = %+v, %v", snapshot, err)
	}
	secondDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_, err := reauthorizeFuseMount(ctx, state, "capability", 2, []byte("certificate"))
		secondDone <- err
	}()
	waitForQueuedRenewal(t, control, entered)
	select {
	case sequence := <-entered:
		t.Fatalf("renewal %d overtook an earlier accepted partial renewal", sequence)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := first.Write([]byte("1}")); err != nil {
		t.Fatal(err)
	}
	if err := first.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case sequence := <-entered:
		if sequence != 1 {
			t.Fatalf("first accepted callback sequence = %d, want 1", sequence)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first accepted renewal did not enter")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	select {
	case sequence := <-entered:
		if sequence != 2 {
			t.Fatalf("second callback sequence = %d, want 2", sequence)
		}
	default:
		t.Fatal("second renewal completed without entering")
	}
}

func TestFuseMountControlCloseInterruptsIncompleteClient(t *testing.T) {
	control, err := startFuseReauthorizationControl(nil, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "0"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("unix", control.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(`{"operation":`)); err != nil {
		t.Fatal(err)
	}
	state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance, ReauthorizationControlSocket: control.SocketPath()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := readFuseMountLoss(ctx, state, lossTestInstance); err != nil {
		connection.Close()
		control.Close()
		t.Fatalf("incomplete peer blocked a later loss snapshot: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- control.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		connection.Close()
		<-closed
		t.Fatal("control close waited for an incomplete client request")
	}
}

func TestFuseMountControlCloseCancelsActiveRenewal(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	control, err := startFuseReauthorizationControl(func(ctx context.Context, _ string, _ uint64, _ []byte) (time.Time, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return time.Time{}, ctx.Err()
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := &mountState{ReauthorizationControlSocket: control.SocketPath()}
	renewed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := reauthorizeFuseMount(ctx, state, "capability", 1, []byte("certificate"))
		renewed <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("renewal did not reach the control handler")
	}
	closed := make(chan error, 1)
	go func() { closed <- control.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control close did not cancel the active renewal")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("renewal handler did not receive cancellation")
	}
	if err := <-renewed; err == nil {
		t.Fatal("renewal succeeded after control shutdown")
	}
	if connection, err := net.Dial("unix", control.SocketPath()); err == nil {
		connection.Close()
		t.Fatal("closed control socket still accepts connections")
	}
}

func TestFuseMountControlBoundsConcurrentHandlers(t *testing.T) {
	const slots = 8
	entered, release := make(chan struct{}, slots+1), make(chan struct{})
	var active, peak atomic.Int32
	control, err := startFuseReauthorizationControl(nil, func() (mountLossSnapshot, error) {
		current := active.Add(1)
		for previous := peak.Load(); current > previous && !peak.CompareAndSwap(previous, current); previous = peak.Load() {
		}
		defer active.Add(-1)
		entered <- struct{}{}
		<-release
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "0"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance, ReauthorizationControlSocket: control.SocketPath()}
	finished := make(chan error, slots)
	for i := 0; i < slots; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := readFuseMountLoss(ctx, state, lossTestInstance)
			finished <- err
		}()
	}
	for i := 0; i < slots; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d bounded handlers entered", i, slots)
		}
	}
	overflow := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err := readFuseMountLoss(ctx, state, lossTestInstance)
		overflow <- err
	}()
	select {
	case err := <-overflow:
		if err == nil {
			t.Fatal("control admitted a ninth renewal beyond its handler capacity")
		}
	case <-entered:
		t.Fatal("server admitted more than its bounded handler capacity")
	case <-time.After(2 * time.Second):
		t.Fatal("over-capacity connection was neither refused nor served")
	}
	if got := peak.Load(); got != slots {
		t.Fatalf("peak concurrent handlers = %d, want %d", got, slots)
	}
	releaseOnce.Do(func() { close(release) })
	for i := 0; i < slots; i++ {
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Fatal("client did not finish after bounded handlers released")
		}
	}
}

func TestFuseReauthorizationControlUsesLifetimeScopedBoundedAddress(t *testing.T) {
	first, err := newFuseReauthorizationSocketName()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newFuseReauthorizationSocketName()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "@portablefs-reauthorization-") || len(first) >= 100 {
		t.Fatalf("abstract control address = %q (length %d)", first, len(first))
	}
	if first == second {
		t.Fatal("independent controls received the same unpredictable address")
	}
	if !validReauthorizationControlAddress(first) {
		t.Fatalf("generated control address was not accepted: %q", first)
	}
	for _, invalid := range []string{
		"/tmp/portablefs.sock",
		"@portablefs-reauthorization-1-deadbeef",
		strings.Replace(first, "@portablefs", "@another-product", 1),
		first + "00",
	} {
		if validReauthorizationControlAddress(invalid) {
			t.Fatalf("invalid control address was accepted: %q", invalid)
		}
	}
}

func TestReauthorizeCommandDeliversCredentialToExactLiveFuseSupervisor(t *testing.T) {
	e, stdout, stderr := testEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	type observedRequest struct {
		token       string
		sequence    uint64
		certificate string
	}
	observed := make(chan observedRequest, 1)
	deadline := time.Now().Add(10 * time.Minute).Truncate(time.Millisecond)
	control, err := startFuseReauthorizationControl(
		func(_ context.Context, token string, sequence uint64, certificate []byte) (time.Time, error) {
			observed <- observedRequest{token: token, sequence: sequence, certificate: string(certificate)}
			return deadline, nil
		}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()

	state := validFuseMountState(t, mountPath)
	state.Branch = ""
	state.Engine = mountEngineFuseV3
	state.DataPlaneTransport = dataPlaneTransportTLSSystemPKI
	state.DataPlaneServerName = "authority.example"
	state.AuthorizationSessionID = "AAAAAAAAAAAAAAAAAAAAAA"
	state.ReauthorizationControlSocket = control.SocketPath()
	writeRawMountState(t, stateDir, state)
	e.mountHealthFn = func(*mountState) string { return "live" }
	e.getenv = func(key string) string {
		if key == mountTokenEnv {
			return "v1.hosted-capability.signature"
		}
		return ""
	}
	certificatePath := filepath.Join(t.TempDir(), "renewed.pem")
	const certificate = "-----BEGIN CERTIFICATE-----\nrenewed\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(9 * time.Minute).UnixMilli()
	if code := e.run([]string{
		"reauthorize", mountPath,
		"--client-cert", certificatePath,
		"--auth-expires-at-ms", formatInt64(expiresAt),
		"--auth-sequence", "3",
		"--json",
	}); code != 0 {
		t.Fatalf("reauthorize code=%d stderr=%s", code, stderr.String())
	}
	request := <-observed
	if request.token != "v1.hosted-capability.signature" || request.sequence != 3 || request.certificate != certificate {
		t.Fatalf("supervisor request = %+v", request)
	}
	var result reauthorizationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.MountPath != mountPath || result.Sequence != 3 || result.AuthorizationDeadlineUnixMs != deadline.UnixMilli() {
		t.Fatalf("reauthorization result = %+v", result)
	}
}

func TestReauthorizeCommandRefusesAnAutomaticallyOwnedMountBeforeDelivery(t *testing.T) {
	e, _, stderr := testEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := validFuseMountState(t, mountPath)
	state.Branch = ""
	state.Engine = mountEngineFuseV3
	state.DataPlaneTransport = dataPlaneTransportTLSSystemPKI
	state.DataPlaneServerName = "authority.example"
	state.AuthorizationSessionID = "AAAAAAAAAAAAAAAAAAAAAA"
	state.MountEnrollmentID = "22222222-2222-4222-8222-222222222222"
	state.AuthorizationDeadlineAtMs = time.Now().Add(10 * time.Minute).UnixMilli()
	writeRawMountState(t, stateDir, state)
	e.mountHealthFn = func(*mountState) string { return "live" }
	e.getenv = func(key string) string {
		if key == mountTokenEnv {
			return "v1.hosted-capability.signature"
		}
		return ""
	}
	code := e.run([]string{
		"reauthorize", mountPath,
		"--client-cert", "/this/path/must/not/be/read",
		"--auth-expires-at-ms", formatInt64(time.Now().Add(9 * time.Minute).UnixMilli()),
		"--auth-sequence", "2",
	})
	if code == 0 || !strings.Contains(stderr.String(), "owned by its automatic Manager enrollment") {
		t.Fatalf("automatic owner refusal code=%d stderr=%s", code, stderr.String())
	}
}

func formatInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}
