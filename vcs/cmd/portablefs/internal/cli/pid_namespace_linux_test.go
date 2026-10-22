//go:build linux

package cli

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestOrdinaryPIDNamespaceServer(t *testing.T) {
	if os.Getenv("PFS_TEST_PIDNS_ROLE") != "server" {
		return
	}
	c, err := startFuseReauthorizationControl(nil, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "5"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	os.Stdout.WriteString(c.SocketPath() + "\n")
	io.Copy(io.Discard, os.Stdin)
}

// Imported Opus zz_pidns_probe_linux_test.go: ordinary UID access must not
// depend on resolving the client's PID through the server's /proc namespace.
func TestOrdinaryLossReadAcrossPIDNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("PID namespace regression requires the owned Linux container with CAP_SYS_ADMIN")
	}
	if os.Getenv("PFS_TEST_PIDNS_ROLE") != "" {
		return
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare")
	}
	for _, mode := range []string{"same-namespace", "server-in-child-pid-namespace"} {
		args := []string{os.Args[0], "-test.run=TestOrdinaryPIDNamespaceServer"}
		var cmd *exec.Cmd
		if mode == "same-namespace" {
			cmd = exec.Command(args[0], args[1:]...)
		} else {
			cmd = exec.Command("unshare", append([]string{"--pid", "--fork"}, args...)...)
		}
		cmd.Env = append(os.Environ(), "PFS_TEST_PIDNS_ROLE=server")
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			t.Fatal(mode, err)
		}
		path := strings.TrimSpace(line)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance, ReauthorizationControlSocket: path}
		loss, err := readFuseMountLoss(ctx, state, lossTestInstance)
		cancel()
		if err != nil || loss.LossSequence != "5" {
			t.Errorf("%s: loss=%+v err=%v", mode, loss, err)
		}
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Fatal(mode, err)
		}
	}
}
