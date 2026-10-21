//go:build linux

package fusev3

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// Preserve the reproduction's independent parked-process control. No response
// loss is injected. Explicitly age the authority clocks while the owned client
// is SIGSTOPped; the 45-second wall wait is the client suspension, not the proof
// that the authority subscription expired.
func TestKernelStoppedClient45SecondsWithoutSocketLoss(t *testing.T) {
	testStoppedClientRecovery(t, 45*time.Second, false)
}
func TestKernelStoppedClientLostOpenReplay(t *testing.T) {
	testStoppedClientRecovery(t, 15*time.Second, true)
}
func testStoppedClientRecovery(t *testing.T, stoppedFor time.Duration, inject bool) {
	t.Helper()
	var listener *replayCutListener
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1, skipMounts: true, SessionLease: 2 * time.Minute, wrapListener: func(l net.Listener) net.Listener { listener = &replayCutListener{Listener: l}; return listener }})
	f.server.IdleTimeout = 5 * time.Minute
	inner := f.counter.inner.(*authorityrpc.VolumeHandler)
	inner.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: replayAuthorityClock{f}})
	f.coherence = inner.Coherence
	observer := &replayRecoveryHandler{Handler: f.server.Handler, kind: "open", entered: make(chan struct{}), release: make(chan struct{}), cold: make(chan struct{}), replayed: make(chan *authoritypb.Response, 4), settled: make(chan struct{})}
	var releaseOnce, settleOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(observer.release) }) }
	settle := func() { settleOnce.Do(func() { close(observer.settled) }) }
	t.Cleanup(func() { release(); settle() })
	f.server.Handler = observer
	dir := t.TempDir()
	binary := filepath.Join(dir, "portablefs-mount-v3")
	if out, err := exec.Command("go", "build", "-o", binary, "../../cmd/portablefs-mount-v3").CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := volumecap.Sign(key, volumecap.Claims{VolumeID: integrationVolumeID, Access: []string{"write"}, Expires: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-authority", f.listener.Addr().String(), "-volume-id", integrationVolumeID, "-mountpoint", f.mountPath(0), "-access-token-file", write("token", capability), "-tls-cert", write("client.pem", f.credentials.ClientCertificatePEM), "-tls-key", write("key.pem", f.credentials.ClientPrivateKeyPEM), "-tls-server-ca", write("ca.pem", f.credentials.AuthorityCAPEM), "-tls-server-name", "localhost")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	var readyOnce sync.Once
	logsDone := make(chan struct{})
	var mu sync.Mutex
	var logs strings.Builder
	go func() {
		defer close(logsDone)
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			logs.WriteString(line + "\n")
			mu.Unlock()
			if strings.Contains(line, "mounted at") {
				readyOnce.Do(func() { close(ready) })
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGCONT)
		_ = exec.Command("fusermount3", "-u", "-z", f.mountPath(0)).Run()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		<-logsDone
	})
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		mu.Lock()
		output := logs.String()
		mu.Unlock()
		t.Fatalf("helper startup timed out\n%s", output)
	}
	p := f.join(0, "data")
	mustWrite(t, p, []byte("initial"), 0600)
	held := mustOpenFile(t, p, os.O_RDWR, 0)
	defer held.Close()
	root := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
	defer root.Close()
	if err := root.Sync(); err != nil {
		t.Fatal(err)
	}
	kernel, err := observeKernelMount(f.mountPath(0))
	if err != nil {
		t.Fatal(err)
	}
	var pendingOpen chan *os.File
	var pendingError chan error
	if inject {
		pendingOpen = make(chan *os.File, 1)
		pendingError = make(chan error, 1)
		observer.armed.Store(true)
		go func() { file, err := os.OpenFile(p, os.O_RDWR, 0); pendingOpen <- file; pendingError <- err }()
		select {
		case <-observer.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("standalone OPEN did not reach recorded boundary")
		}
	}
	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	oldInc := observer.latestInc.Load()
	session, ok := f.membership.last()
	if !ok || oldInc == 0 {
		t.Fatal("no live subscription observed")
	}
	f.advanceClock(stoppedFor)
	if err := f.coherence.CheckSession(volumeserver.SubscriptionToken{Session: session, Incarnation: oldInc}); err == nil {
		t.Fatal("authority horizon did not expire")
	}
	time.Sleep(stoppedFor)
	if inject {
		listener.cut(t, "data")
		release()
	}
	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if inject {
		select {
		case file := <-pendingOpen:
			if err := <-pendingError; err != nil {
				t.Fatalf("standalone exact OPEN replay=%v", err)
			}
			defer file.Close()
		case <-time.After(20 * time.Second):
			t.Fatal("standalone assigned OPEN did not resolve")
		}
		settle()
		select {
		case replay := <-observer.replayed:
			observer.mu.Lock()
			want := proto.Clone(observer.outcome).(*authoritypb.Response)
			observer.mu.Unlock()
			want.RequestId = replay.RequestId
			if !proto.Equal(want, replay) || replay.GetMutation() == nil {
				t.Fatalf("standalone replay lost its outcome or sequence: %v", replay)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("standalone OPEN did not replay")
		}
	}
	// Cold admission may initially return scoped EIO; wait for an independent
	// successful operation, then require continued descriptor and barrier service.
	waitUntil(t, 20*time.Second, "stopped client cold recovery", func() bool {
		file, err := os.Open(p)
		if err != nil {
			return false
		}
		file.Close()
		return true
	})
	if got := readExactlyAt(t, held, 0, 7, "held descriptor after 45-second stop"); string(got) != "initial" {
		t.Fatal(string(got))
	}
	if err := root.Sync(); err != nil && !errors.Is(err, syscall.EIO) {
		t.Fatalf("old root barrier=%v", err)
	}
	fresh := mustOpenFile(t, f.join(0, "fresh"), os.O_CREATE|os.O_RDWR, 0600)
	if _, err := fresh.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Sync(); err != nil {
		t.Fatal(err)
	}
	fresh.Close()
	newRoot := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
	if err := newRoot.Sync(); err != nil {
		t.Fatal(err)
	}
	newRoot.Close()
	installed, err := observeKernelMount(f.mountPath(0))
	if err != nil {
		t.Fatal(err)
	}
	if installed.id != kernel.id || installed.device != kernel.device || installed.source != kernel.source {
		t.Fatal("stopped client replaced its kernel connection")
	}
	if !inject {
		listener.mu.Lock()
		count := len(listener.connections)
		listener.mu.Unlock()
		if count != 2 {
			t.Fatalf("no-loss control replaced a role socket: connections=%d", count)
		}
	}
	mu.Lock()
	output := logs.String()
	mu.Unlock()
	if strings.Contains(output, "unresolved") || strings.Contains(output, "reply publication registered after terminal") || strings.Contains(output, "connection ended before the operation outcome") {
		t.Fatalf("stopped client terminalized\n%s", output)
	}
}
