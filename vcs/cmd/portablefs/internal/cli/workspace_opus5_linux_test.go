//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"golang.org/x/sys/unix"
)

func o5FDs(t *testing.T) int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

func o5Wait(t *testing.T, c *unixReauthorizationControl) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.connections)
		c.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("listener did not join connections")
}

// send performs one malformed/edge frame; it returns whether the case is a
// proven grammar failure that must invalidate admission.
var o5Answered atomic.Int32

func o5Send(t *testing.T, c *unixReauthorizationControl, kind string, writer int) bool {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.SocketPath(), Net: "unix"})
	if err != nil {
		t.Error(err)
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	prepare, _ := json.Marshal(workspaceRequest("1", "workspace-prepare"))
	install := workspaceRequest("1", "workspace-install-kernel")
	install.Workspace.Phase = &mountcontrol.Phase{ActionID: "1", Options: []string{"nodev"}, Witness: mountcontrol.Witness{Process: "p", Source: "s", Target: "/t", Kernel: "k"}}
	installBody, _ := json.Marshal(install)
	grammar := true
	halfClose := true
	switch kind {
	case "split-rights-2+2":
		half := len(prepare) / 2
		conn.WriteMsgUnix(prepare[:half], unix.UnixRights(writer, writer), nil)
		time.Sleep(time.Millisecond)
		conn.WriteMsgUnix(prepare[half:], unix.UnixRights(writer, writer), nil)
	case "install-three-rights":
		conn.WriteMsgUnix(installBody, unix.UnixRights(writer, writer, writer), nil)
	case "prepare-two-rights": // framed: AdmitFrame rejects rights for a non-install op
		conn.WriteMsgUnix(prepare, unix.UnixRights(writer, writer), nil)
	case "oversize-chunks":
		chunk := []byte(strings.Repeat(" ", 16<<10))
		for sent := 0; sent <= mountcontrol.MaxWorkspaceRequest; sent += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				break
			}
		}
	case "partial-then-close":
		grammar = false
		halfClose = false
		conn.WriteMsgUnix([]byte(`{"workspace":{"version":8`), unix.UnixRights(writer), nil)
	case "complete-then-close":
		grammar = false
		halfClose = false
		conn.Write(prepare)
		time.Sleep(time.Millisecond)
	case "valid-observe":
		grammar = false
		b, _ := json.Marshal(workspaceRequest("9", "workspace-observe"))
		conn.Write(b)
	}
	if halfClose {
		conn.CloseWrite()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n == 0 {
			return false // closed unread at the two-connection workspace reserve
		}
		o5Answered.Add(1)
	}
	return grammar
}

func TestO5ReceiveLevelInvalidationCases(t *testing.T) {
	for _, kind := range []string{"split-rights-2+2", "install-three-rights", "prepare-two-rights", "oversize-chunks", "partial-then-close", "complete-then-close", "valid-observe"} {
		t.Run(kind, func(t *testing.T) {
			var closed atomic.Int32
			c, _ := rootWorkspace(t, nil, func(cfg *workspaceControlConfig) { cfg.Owner.CloseAdmission = func() { closed.Add(1) } })
			var pipe [2]int
			if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pipe[0])
			base := o5FDs(t)
			want := o5Send(t, c, kind, pipe[1])
			unix.Close(pipe[1])
			o5Wait(t, c)
			var n int
			var err error
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				if n, err = unix.Read(pipe[0], make([]byte, 1)); n == 0 && err == nil {
					break
				}
			}
			t.Logf("%s: admission closes=%d (want invalidation=%v) pipe read n=%d err=%v fdDelta=%d", kind, closed.Load(), want, n, err, o5FDs(t)-(base-1))
			if (closed.Load() > 0) != want {
				t.Errorf("%s: invalidation=%d want %v", kind, closed.Load(), want)
			}
			if n != 0 || err != nil {
				t.Errorf("%s: listener retained received writer rights (n=%d err=%v)", kind, n, err)
			}
		})
	}
}

func TestO5ReceiveLevelConcurrentStress(t *testing.T) {
	var closed atomic.Int32
	c, _ := rootWorkspace(t, nil, func(cfg *workspaceControlConfig) { cfg.Owner.CloseAdmission = func() { closed.Add(1) } })
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[0])
	base := o5FDs(t)
	kinds := []string{"split-rights-2+2", "install-three-rights", "prepare-two-rights", "partial-then-close", "complete-then-close", "valid-observe", "oversize-chunks"}
	var wantGrammar atomic.Int32
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if o5Send(t, c, kinds[(g+i)%len(kinds)], pipe[1]) {
					wantGrammar.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	unix.Close(pipe[1])
	o5Wait(t, c)
	var n int
	var err error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if n, err = unix.Read(pipe[0], make([]byte, 1)); n == 0 && err == nil {
			break
		}
	}
	o5Wait(t, c)
	delta := o5FDs(t) - (base - 1)
	t.Logf("receive stress: answered=%d answered grammar frames=%d admission closes=%d pipe EOF=%v fdDelta=%d", o5Answered.Load(), wantGrammar.Load(), closed.Load(), n == 0 && err == nil, delta)
	if closed.Load() != wantGrammar.Load() {
		t.Errorf("missing invalidations: %d < %d", closed.Load(), wantGrammar.Load())
	}
	if n != 0 || err != nil || delta != 0 {
		t.Errorf("descriptor leak: pipe n=%d err=%v fdDelta=%d", n, err, delta)
	}
	_ = fmt.Sprint
}
