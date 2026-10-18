//go:build darwin && cgo

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func nativeCLIImage(t *testing.T, root, image string) daemonRelease {
	t.Helper()
	path := filepath.Join(root, image)
	source := "../../../../internal/hostctl/testdata/peer.c"
	architecture, err := nativeCodeArchitecture()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/clang", "-arch", architecture, "-DIMAGE=\""+image+"\"", source, "-o", path).CombinedOutput(); err != nil {
		t.Fatalf("compile peer: %v: %s", err, out)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", path).CombinedOutput(); err != nil {
		t.Fatalf("sign peer: %v: %s", err, out)
	}
	out, err := exec.Command("/usr/bin/codesign", "-d", "--verbose=4", path).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := exactCodesignField(string(out), "CDHash")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := daemonctl.FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := testDaemonRelease(path, "native-peer-"+image, digest)
	expected.identity.CodeDirectoryHash = hash
	return expected
}

func startCLIImage(t *testing.T, expected daemonRelease, socket string, identity daemonctl.Identity) (*exec.Cmd, <-chan string) {
	t.Helper()
	body, err := daemonctl.EncodeIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	return startCLIImageBody(t, expected, socket, body)
}

func startCLIImageBody(t *testing.T, expected daemonRelease, socket string, body []byte) (*exec.Cmd, <-chan string) {
	t.Helper()
	file := filepath.Join(filepath.Dir(socket), "identity.json")
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(expected.path, socket, file)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "ready ") {
		t.Fatalf("native peer startup failed: %v", scanner.Err())
	}
	requests := make(chan string, 32)
	go func() {
		defer close(requests)
		for scanner.Scan() {
			requests <- scanner.Text()
		}
	}()
	return cmd, requests
}

func TestFSDControlAuthenticatesEveryDialAndReusesAuthenticatedConnection(t *testing.T) {
	root := shortSocketDir(t)
	a := nativeCLIImage(t, root, "A")
	b := nativeCLIImage(t, root, "B")
	socket := filepath.Join(root, "control.sock")
	identity := daemonctl.Identity{SchemaVersion: 1, ControlProtocol: daemonctl.ControlProtocolVersion, DaemonVersion: a.identity.DaemonVersion, ExecutableSHA256: a.identity.ExecutableSHA256, PFSLocalMajor: pfslocal.ProtocolMajor, PFSLocalMinor: pfslocal.ProtocolMinor}
	cmd, requests := startCLIImage(t, a, socket, identity)
	var authCalls atomic.Int32
	ctl, err := newFsdControlAuthenticated(socket, a, func(conn net.Conn, path, hash string) error {
		authCalls.Add(1)
		if path != a.path || hash != a.identity.CodeDirectoryHash {
			t.Error("constructor identity changed")
		}
		return authenticateFSDPeer(conn, path, hash)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.close()
	if !ctl.healthy() {
		t.Fatal("authenticated health refused")
	}
	if err := ctl.requireCompatibleIdentity(a.identity.DaemonVersion, a.identity.ExecutableSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.lifecycleInventory(); err != nil {
		t.Fatal(err)
	}
	if authCalls.Load() != 1 {
		t.Fatalf("health/identity/inventory authenticated %d dials", authCalls.Load())
	}
	for range 3 {
		select {
		case <-requests:
		case <-time.After(time.Second):
			t.Fatal("missing native HTTP request")
		}
	}
	ctl.close()
	if _, err := ctl.lifecycleInventory(); err != nil {
		t.Fatal(err)
	}
	if authCalls.Load() != 2 {
		t.Fatal("reconnect was not authenticated")
	}
	<-requests
	ctl.close()
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	_ = os.Remove(socket)
	// B has the right reported JSON but a different running image at the same
	// admitted daemon pathname. Authentication must fail before HTTP reaches it.
	if err := os.Rename(b.path, a.path); err != nil {
		t.Fatal(err)
	}
	_, substituted := startCLIImage(t, a, socket, identity)
	if _, err := ctl.lifecycleInventory(); err == nil {
		t.Fatal("substituted reconnect accepted")
	}
	select {
	case got := <-substituted:
		t.Fatalf("unauthenticated request reached substitute: %s", got)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestFSDControlRejectsAuthenticationBeforeHealthOrLifecycle(t *testing.T) {
	for _, action := range []string{"health", "identity", "inventory", "stop"} {
		t.Run(action, func(t *testing.T) {
			root := shortSocketDir(t)
			a := nativeCLIImage(t, root, "A")
			socket := filepath.Join(root, "control.sock")
			identity := daemonctl.Identity{SchemaVersion: 1, ControlProtocol: 2, DaemonVersion: a.identity.DaemonVersion, ExecutableSHA256: a.identity.ExecutableSHA256, PFSLocalMajor: 2}
			_, requests := startCLIImage(t, a, socket, identity)
			a.identity.CodeDirectoryHash = strings.Repeat("0", 40)
			ctl, err := newFsdControl(socket, a)
			if err != nil {
				t.Fatal(err)
			}
			defer ctl.close()
			var callErr error
			switch action {
			case "health":
				if ctl.healthy() {
					t.Fatal("unauthenticated health succeeded")
				}
				callErr = errors.New("refused")
			case "identity":
				callErr = ctl.requireOutgoingIdentityWithin(a.identity, time.Second)
			case "inventory":
				_, callErr = ctl.lifecycleInventory()
			case "stop":
				callErr = ctl.stopIfIdle()
			}
			if callErr == nil {
				t.Fatal("wrong running image accepted")
			}
			select {
			case got := <-requests:
				t.Fatalf("request reached rejected peer: %s", got)
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
}

func TestNativeOutgoingLifecycleAcceptsActualProtocolsButOperationsRequirePairing(t *testing.T) {
	root := shortSocketDir(t)
	for _, control := range []int{19, 71} {
		t.Run(fmt.Sprint(control), func(t *testing.T) {
			expected := nativeCLIImage(t, root, fmt.Sprintf("outgoing-%d", control))
			dir := shortSocketDir(t)
			socket := filepath.Join(dir, "control.sock")
			identity := daemonctl.Identity{SchemaVersion: 1, ControlProtocol: control, DaemonVersion: expected.identity.DaemonVersion, ExecutableSHA256: expected.identity.ExecutableSHA256, PFSLocalMajor: uint32(control + 1), PFSLocalMinor: 0}
			_, requests := startCLIImage(t, expected, socket, identity)
			ctl, err := newFsdControl(socket, expected)
			if err != nil {
				t.Fatal(err)
			}
			defer ctl.close()
			if err := ctl.requireOutgoingIdentityWithin(expected.identity, time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := ctl.lifecycleInventory(); err != nil {
				t.Fatal(err)
			}
			if err := ctl.stopIfIdle(); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				<-requests
			}
			if _, err := ctl.listAttaches(); err == nil {
				t.Fatal("operational request accepted outgoing protocol numbers")
			}
			if request := <-requests; request != "request "+daemonctl.LifecycleIdentityPath {
				t.Fatalf("unpaired operational HTTP reached native peer: %s", request)
			}
			select {
			case got := <-requests:
				t.Fatalf("unpaired operation reached peer: %s", got)
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
	expected := nativeCLIImage(t, root, "outgoing")
	for _, mutation := range []string{"version", "hash", "schema", "negative zero"} {
		t.Run(mutation, func(t *testing.T) {
			identity := daemonctl.Identity{SchemaVersion: 1, ControlProtocol: 19, DaemonVersion: expected.identity.DaemonVersion, ExecutableSHA256: expected.identity.ExecutableSHA256, PFSLocalMajor: 20}
			body, err := daemonctl.EncodeIdentity(identity)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "version":
				body = []byte(strings.ReplaceAll(string(body), `"daemonVersion":"`+identity.DaemonVersion+`"`, `"daemonVersion":"substituted"`))
			case "hash":
				body = []byte(strings.ReplaceAll(string(body), expected.identity.ExecutableSHA256, strings.Repeat("0", 64)))
			case "schema":
				body = []byte(strings.ReplaceAll(string(body), `"schemaVersion":1`, `"schemaVersion":2`))
			case "negative zero":
				body = []byte(strings.ReplaceAll(string(body), `"pfslocalMinor":0`, `"pfslocalMinor":-0`))
			}
			socket := filepath.Join(shortSocketDir(t), "control.sock")
			startCLIImageBody(t, expected, socket, body)
			ctl, err := newFsdControl(socket, expected)
			if err != nil {
				t.Fatal(err)
			}
			defer ctl.close()
			if err := ctl.requireOutgoingIdentityWithin(expected.identity, time.Second); err == nil {
				t.Fatalf("outgoing %s spoof or malformed identity accepted", mutation)
			}
		})
	}
}

func TestFSDControlRequiresImmutableReleaseAtConstruction(t *testing.T) {
	expected := testDaemonRelease("/expected/portablefsd", "test", strings.Repeat("a", 64))
	for _, value := range []daemonRelease{{}, {path: expected.path}, {identity: expected.identity}} {
		if ctl, err := newFsdControl("/expected/control.sock", value); err == nil {
			ctl.close()
			t.Fatal("incomplete mandatory release admitted")
		}
	}
	if ctl, err := newFsdControlAuthenticated("/expected/control.sock", expected, nil); err == nil {
		ctl.close()
		t.Fatal("missing native authenticator admitted")
	}
}
