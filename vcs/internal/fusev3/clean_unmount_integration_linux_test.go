//go:build linux

package fusev3

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
)

// Exercise the foreground signal owner against the real helper and kernel.
// Synthetic-clock supervisor tests separately prove the absence of retries
// across arbitrarily long intervals; every transition here uses process events.
func TestNormalUnmountRequiresAnotherSignalAfterBusyDescriptor(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1, skipMounts: true})
	dir := t.TempDir()
	binary := filepath.Join(dir, "portablefs-mount-v3")
	if out, err := exec.Command("go", "build", "-o", binary, "../../cmd/portablefs-mount-v3").CombinedOutput(); err != nil {
		t.Fatalf("build foreground mount: %v\n%s", err, out)
	}
	realHelper, err := exec.LookPath("fusermount3")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// The fixture authorizer admits test grants; their shape still exercises
	// the production renewal source without a credential-startup refusal.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := volumecap.Sign(key, volumecap.Claims{VolumeID: integrationVolumeID, Access: []string{"write"}, Expires: time.Now().Add(24 * time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	token := write("capability", capability, 0600)
	cert := write("client.pem", f.credentials.ClientCertificatePEM, 0600)
	clientKey := write("client-key.pem", f.credentials.ClientPrivateKeyPEM, 0600)
	ca := write("ca.pem", f.credentials.AuthorityCAPEM, 0600)
	attempts := write("attempts", nil, 0600)
	// The mount helper receives only go-fuse's explicit fd environment.
	quoteShell := func(path string) string { return "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'" }
	shim := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = -u ]; then printf 'attempt\\n' >> %s; fi\nexec %s \"$@\"\n", quoteShell(attempts), quoteShell(realHelper))
	write("fusermount3", []byte(shim), 0700)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	cmd := exec.Command(binary, "-authority", f.listener.Addr().String(), "-volume-id", integrationVolumeID,
		"-mountpoint", f.mountPath(0), "-access-token-file", token, "-tls-cert", cert,
		"-tls-key", clientKey, "-tls-server-ca", ca, "-tls-server-name", "localhost")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	cmd.Stdout, cmd.Stderr = writer, writer
	if err := cmd.Start(); err != nil {
		_ = writer.Close()
		t.Fatal(err)
	}
	_ = writer.Close()
	lines := make(chan string, 128)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	done := make(chan struct{})
	var runErr error
	go func() { runErr = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = cmd.Process.Kill()
			<-done
			t.Error("foreground mount owner did not finish cleanly")
		}
		if isMounted(t, f.mountPath(0)) {
			t.Error("foreground owner left its mount installed")
			_ = exec.Command(realHelper, "-u", "-z", f.mountPath(0)).Run()
		}
	})
	var transcript []string
	awaitLog := func(fragment string) {
		t.Helper()
		deadline := time.NewTimer(30 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("foreground logs ended before %q:\n%s", fragment, strings.Join(transcript, "\n"))
				}
				transcript = append(transcript, line)
				if strings.Contains(line, fragment) {
					return
				}
			case <-deadline.C:
				t.Fatalf("foreground owner did not report %q:\n%s", fragment, strings.Join(transcript, "\n"))
			}
		}
	}
	assertAttempts := func(want int) {
		t.Helper()
		data, err := os.ReadFile(attempts)
		if err != nil || string(data) != strings.Repeat("attempt\n", want) {
			t.Fatalf("normal helper attempts = %q, %v; want %d", data, err, want)
		}
	}
	awaitLog("mounted at")
	path := filepath.Join(f.mountPath(0), "busy")
	mustWrite(t, path, []byte("still served"), 0600)
	retained, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = retained.Close() })
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	awaitLog("normal unmount refused")
	assertAttempts(1)
	if !isMounted(t, f.mountPath(0)) || f.membership.activeCount() != 1 {
		t.Fatal("refusal released the installed mount or authenticated membership")
	}
	requireContent(t, path, []byte("still served"), "after refused normal request")
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	// RELEASE and unrelated pathname activity are not new unmount requests.
	requireContent(t, path, []byte("still served"), "after dropping the busy reference")
	assertAttempts(1)
	select {
	case <-done:
		t.Fatalf("foreground owner exited after refusal: %v", runErr)
	default:
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if runErr != nil {
			t.Fatalf("second explicit request: %v", runErr)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("second explicit request did not finish")
	}
	assertAttempts(2)
	if isMounted(t, f.mountPath(0)) || f.membership.activeCount() != 0 {
		t.Fatalf("successful normal request left mount or membership: %d", f.membership.activeCount())
	}
}
