//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const lossTestInstance = "mnt_0000000000000000000001"

func TestMountLossReadsExactLiveCounterOnAutomaticallyRenewedMount(t *testing.T) {
	e, stdout, stderr := testEnv(t)
	path, err := canonicalMountPath(t.TempDir())
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
	var counter atomic.Uint64
	control, err := startFuseReauthorizationControl(nil, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: strconv.FormatUint(counter.Load(), 10)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	state := validFuseMountState(t, path)
	state.MountInstanceID = lossTestInstance
	state.AuthorizationSessionID = "AAAAAAAAAAAAAAAAAAAAAA"
	state.ReauthorizationControlSocket = control.SocketPath()
	state.MountEnrollmentID = "22222222-2222-4222-8222-222222222222"
	state.AuthorizationDeadlineAtMs = time.Now().Add(time.Hour).UnixMilli()
	writeRawMountState(t, stateDir, state)
	e.mountHealthFn = func(*mountState) string { return "live" }
	for _, n := range []uint64{0, 1, ^uint64(0)} {
		counter.Store(n)
		stdout.Reset()
		if code := e.run([]string{"mount-loss", path, "--mount-instance", lossTestInstance, "--json"}); code != 0 {
			t.Fatalf("snapshot code=%d stderr=%s", code, stderr.String())
		}
		var result mountLossResult
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.MountPath != path || result.MountInstanceID != lossTestInstance || result.LossSequence != strconv.FormatUint(n, 10) {
			t.Fatalf("snapshot = %+v", result)
		}
	}
	// A client bypassing the public CLI still cannot rotate automatically owned
	// authorization through the newly always-present read-only endpoint.
	if _, err := reauthorizeFuseMount(context.Background(), &state, "capability", 1, []byte("certificate")); err == nil {
		t.Fatal("automatic mount accepted external reauthorization")
	}
}

func TestMountLossRefusesMissingWrongUnavailableAndInvalidCounters(t *testing.T) {
	for _, tc := range []struct {
		name, instance, counter string
		err                     error
	}{
		{"different-instance", "mnt_0000000000000000000002", "0", nil},
		{"missing-counter", lossTestInstance, "", nil},
		{"unavailable", lossTestInstance, "0", errors.New("unavailable")},
		{"overflow", lossTestInstance, "18446744073709551616", nil},
		{"signed", lossTestInstance, "+1", nil},
		{"leading-zero", lossTestInstance, "01", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control, err := startFuseReauthorizationControl(nil, func() (mountLossSnapshot, error) {
				return mountLossSnapshot{MountInstanceID: tc.instance, LossSequence: tc.counter}, tc.err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance, ReauthorizationControlSocket: control.SocketPath()}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := readFuseMountLoss(ctx, state, lossTestInstance); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance}
	if _, err := readFuseMountLoss(context.Background(), state, lossTestInstance); err == nil {
		t.Fatal("missing endpoint became zero loss")
	}
	control, err := startFuseReauthorizationControl(nil, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "0"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	state.ReauthorizationControlSocket = control.SocketPath()
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readFuseMountLoss(context.Background(), state, lossTestInstance); err == nil {
		t.Fatal("dead endpoint became zero loss")
	}
}

func TestMountLossValidatesRequestAndKernelPeerCredentials(t *testing.T) {
	var calls atomic.Int32
	control, err := startFuseReauthorizationControl(nil, func() (mountLossSnapshot, error) {
		calls.Add(1)
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "0"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	for _, body := range []string{
		`{"operation":"loss-snapshot","mountInstanceId":"bad"}`,
		`{"operation":"loss-snapshot","mountInstanceId":"` + lossTestInstance + `","capability":"secret"}`,
		`{"operation":"loss-snapshot","mountInstanceId":"` + lossTestInstance + `","sequence":1}`,
		`{"operation":"loss-snapshot","mountInstanceId":"` + lossTestInstance + `","unexpected":1}`,
		`{"operation":"loss-snapshot","mountInstanceId":"` + lossTestInstance + `"} {}`,
	} {
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: control.SocketPath(), Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if err := requireSameUserPeer(connection); err != nil {
			t.Fatalf("kernel same-user peer: %v", err)
		}
		if err := requireUserPeer(connection, uint32(os.Geteuid())+1); err == nil {
			t.Fatal("different required uid accepted the kernel peer credential")
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(connection, body)
		_ = connection.CloseWrite()
		response, err := io.ReadAll(connection)
		_ = connection.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(response), `"ok":false`) {
			t.Fatalf("invalid request response %s", response)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("malformed requests reached the live counter %d times", calls.Load())
	}
}
