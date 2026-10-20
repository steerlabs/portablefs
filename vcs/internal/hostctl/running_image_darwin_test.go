//go:build darwin && cgo

package hostctl

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildNativePeer(t *testing.T, root, image, arch, signing string) (string, string) {
	t.Helper()
	path := filepath.Join(root, image)
	out, err := exec.Command("/usr/bin/clang", "-arch", arch, "-DIMAGE=\""+image+"\"", "testdata/peer.c", "-o", path).CombinedOutput()
	if err != nil {
		t.Fatalf("compile native image: %v: %s", err, out)
	}
	if signing != "unsigned" {
		args := []string{"--force", "--sign", "-"}
		if signing == "runtime" {
			args = append(args, "--options", "runtime")
		}
		args = append(args, path)
		if out, err := exec.Command("/usr/bin/codesign", args...).CombinedOutput(); err != nil {
			t.Fatalf("sign native image: %v: %s", err, out)
		}
	} else {
		if out, err := exec.Command("/usr/bin/codesign", "--remove-signature", path).CombinedOutput(); err != nil {
			t.Fatalf("remove fixture signature: %v: %s", err, out)
		}
	}
	out, err = exec.Command("/usr/bin/codesign", "-d", "--verbose=4", "--arch", arch, path).CombinedOutput()
	if signing == "unsigned" {
		return path, strings.Repeat("0", 40)
	}
	if err != nil {
		t.Fatalf("inspect fixture CDHash: %v: %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(line, "CDHash="); ok {
			return path, value
		}
	}
	t.Fatal("fixture has no CDHash")
	return "", ""
}

func startNativePeer(t *testing.T, path, socket string) (*exec.Cmd, *bufio.Scanner) {
	t.Helper()
	identity := filepath.Join(filepath.Dir(socket), "identity")
	if err := os.WriteFile(identity, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, socket, identity)
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "ready ") {
		t.Fatalf("native image did not start: %v", scanner.Err())
	}
	return cmd, scanner
}

func connectNativePeer(t *testing.T, socket string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestAuthenticateSocketPeerBindsNativeRunningImage(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-image-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	a, aHash := buildNativePeer(t, root, "A", arch, "runtime")
	b, bHash := buildNativePeer(t, root, "B", arch, "runtime")
	if aHash == bHash {
		t.Fatal("distinct fixture images share CDHash")
	}
	cmd, _ := startNativePeer(t, a, filepath.Join(root, "peer.sock"))
	conn := connectNativePeer(t, filepath.Join(root, "peer.sock"))
	if err := AuthenticateSocketPeer(conn, a, aHash); err != nil {
		t.Fatalf("real signed runtime peer refused: %v", err)
	}
	copyPath := filepath.Join(root, "same-image-at-another-path")
	copyBytes, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, copyBytes, 0755); err != nil {
		t.Fatal(err)
	}
	startNativePeer(t, copyPath, filepath.Join(root, "other.sock"))
	otherConn := connectNativePeer(t, filepath.Join(root, "other.sock"))
	if err := AuthenticateSocketPeer(otherConn, a, aHash); err == nil {
		t.Fatal("correct image at an unauthenticated path accepted")
	}
	for _, test := range []struct{ path, hash string }{{b, aHash}, {a, bHash}, {a, ""}, {"", aHash}} {
		if err := AuthenticateSocketPeer(conn, test.path, test.hash); err == nil {
			t.Fatalf("substitution accepted: %+v", test)
		}
	}
	witness, err := exactPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	stale := witness
	stale.PIDVersion++
	if err := stale.requireRunningImage(a, aHash); err == nil {
		t.Fatal("stale pidversion accepted")
	}
	stale = witness
	stale.auditToken[7]++
	if err := stale.requireRunningImage(a, aHash); err == nil {
		t.Fatal("substituted token incarnation accepted")
	}
	if err := os.Rename(b, a); err != nil {
		t.Fatal(err)
	}
	if hash, err := witness.runningImageHash(); err != nil || hash != aHash {
		t.Fatalf("kernel running hash changed to the pathname replacement: %s: %v", hash, err)
	}
	if err := AuthenticateSocketPeer(conn, a, bHash); err == nil {
		t.Fatal("rename-over-running-image accepted the replacement hash")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected killed fixture")
	}
	if err := witness.requireRunningImage(a, aHash); err == nil {
		t.Fatal("departed execution accepted")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := AuthenticateSocketPeer(conn, a, aHash); err == nil {
		t.Fatal("failed socket syscall admitted")
	}
}

func TestAuthenticateSocketPeerRejectsMissingHardenedRuntime(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-status-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	path, hash := buildNativePeer(t, root, "plain", arch, "signed")
	startNativePeer(t, path, filepath.Join(root, "peer.sock"))
	conn := connectNativePeer(t, filepath.Join(root, "peer.sock"))
	if err := AuthenticateSocketPeer(conn, path, hash); err == nil || !strings.Contains(err.Error(), "running image") {
		t.Fatalf("missing runtime: %v", err)
	}
	// Native token validation also refuses a malformed witness before a syscall.
	if err := (ProcessWitness{}).requireRunningImage(path, hash); err == nil {
		t.Fatal("malformed witness accepted")
	}
}

func TestNativeRunningImageRejectsTokenBoundSyscallFailure(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-token-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	path, _ := buildNativePeer(t, root, "A", arch, "runtime")
	startNativePeer(t, path, filepath.Join(root, "peer.sock"))
	conn := connectNativePeer(t, filepath.Join(root, "peer.sock"))
	witness, err := exactPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	witness.PIDVersion++
	witness.auditToken[7]++
	if _, err := witness.runningImageHash(); err == nil {
		t.Fatal("csops admitted a stale audit-token incarnation")
	}
}

func TestNativeSocketRejectsDifferentUIDBeforeSendingAnyRequest(t *testing.T) {
	// usbmuxd's public Unix socket supplies a real different-uid peer without
	// privileged fixture setup. No service-protocol bytes are sent.
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "/var/run/usbmuxd", Net: "unix"})
	if err != nil {
		t.Skipf("native different-uid system socket unavailable: %v", err)
	}
	defer conn.Close()
	if os.Geteuid() == 0 {
		t.Skip("different-uid fixture requires an unprivileged test process")
	}
	if err := AuthenticateSocketPeer(conn, "/usr/libexec/usbmuxd", strings.Repeat("0", 40)); err == nil || !strings.Contains(err.Error(), "uid") {
		t.Fatalf("different-uid socket was not refused by kernel credentials: %v", err)
	}
}

func TestNativeUniversalImageUsesExactRunningSliceCDHash(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-universal-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	arm, _ := buildNativePeer(t, root, "arm", "arm64", "runtime")
	x86, _ := buildNativePeer(t, root, "intel", "x86_64", "runtime")
	universal := filepath.Join(root, "universal")
	if out, err := exec.Command("/usr/bin/lipo", "-create", arm, x86, "-output", universal).CombinedOutput(); err != nil {
		t.Fatalf("lipo: %v: %s", err, out)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", universal).CombinedOutput(); err != nil {
		t.Fatalf("sign universal: %v: %s", err, out)
	}
	hashes := map[string]string{}
	for _, arch := range []string{"arm64", "x86_64"} {
		out, err := exec.Command("/usr/bin/codesign", "-d", "--verbose=4", "--arch", arch, universal).CombinedOutput()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if hash, ok := strings.CutPrefix(line, "CDHash="); ok {
				hashes[arch] = hash
			}
		}
	}
	if hashes["arm64"] == hashes["x86_64"] {
		t.Fatal("universal fixture has no distinct slice hashes")
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		t.Run(arch, func(t *testing.T) {
			if arch == "x86_64" && runtime.GOARCH == "arm64" {
				out, err := exec.Command("/usr/bin/arch", "-x86_64", "/usr/bin/true").CombinedOutput()
				if err != nil && strings.Contains(string(out), "Bad CPU type in executable") {
					t.Skip("x86_64 execution is unavailable on this arm64 Mac; native Intel qualification is still required")
				}
				if err != nil {
					t.Fatalf("probe x86_64 execution: %v: %s", err, out)
				}
			}
			if runtime.GOARCH == "amd64" && arch == "arm64" {
				t.Skip("native Intel host cannot execute arm64")
			}
			socket := filepath.Join(root, arch+".sock")
			identity := filepath.Join(root, arch+".identity")
			if err := os.WriteFile(identity, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/usr/bin/arch", "-"+arch, universal, socket, identity)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			if scanner := bufio.NewScanner(stdout); !scanner.Scan() {
				t.Fatal("required universal fixture slice could not execute")
			}
			conn := connectNativePeer(t, socket)
			if err := AuthenticateSocketPeer(conn, universal, hashes[arch]); err != nil {
				t.Fatalf("exact running %s slice: %v", arch, err)
			}
			other := "arm64"
			if arch == other {
				other = "x86_64"
			}
			if err := AuthenticateSocketPeer(conn, universal, hashes[other]); err == nil {
				t.Fatal("non-running universal slice hash accepted")
			}
		})
	}
}

func TestNativeUnsignedImageCannotAuthenticate(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "pfs-unsigned-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	path, _ := buildNativePeer(t, root, "unsigned", arch, "unsigned")
	socket := filepath.Join(root, "peer.sock")
	identity := filepath.Join(root, "identity")
	if err := os.WriteFile(identity, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, socket, identity)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Logf("kernel refused unsigned executable before a socket existed: %v", err)
		return
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		if err := cmd.Wait(); err == nil {
			t.Fatal("unsigned fixture exited without native refusal")
		}
		t.Log("kernel terminated unsigned executable before a socket existed")
		return
	}
	conn := connectNativePeer(t, socket)
	if err := AuthenticateSocketPeer(conn, path, strings.Repeat("0", 40)); err == nil {
		t.Fatal("unsigned running image admitted")
	}
}
