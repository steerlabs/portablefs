//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStrictDetachRequiresObservedMountAbsence(t *testing.T) {
	fixture := newStrictFixture(t)
	if err := fixture.mount.detach(); err == nil {
		t.Fatal("strict detach without a kernel mount identity succeeded")
	}
	fixture.rpc.mu.Lock()
	proofs := len(fixture.rpc.detachProofs)
	fixture.rpc.mu.Unlock()
	if proofs != 0 {
		t.Fatalf("strict mount detached with %d proofs and no exact observation", proofs)
	}
	fixture.mount.kernelMount = kernelMount{id: "999999999", device: "0:999", point: "/nonexistent-portablefs-mount"}
	done := make(chan struct{})
	close(done)
	fixture.mount.kernelConnectionDone = done
	if err := fixture.mount.detach(); err != nil {
		t.Fatalf("detach after exact mount and connection termination: %v", err)
	}
	fixture.rpc.mu.Lock()
	defer fixture.rpc.mu.Unlock()
	if len(fixture.rpc.detachProofs) != 1 {
		t.Fatalf("detach proofs = %d, want 1", len(fixture.rpc.detachProofs))
	}
	proof := fixture.rpc.detachProofs[0]
	if !proof.valid() || proof.Component != mountInfoPath || !strings.Contains(string(proof.Observation), "present=false") {
		t.Fatalf("invalid exact absence proof: %+v", proof)
	}
}

func TestStrictDetachWaitsForTheExactFUSEConnection(t *testing.T) {
	fixture := newStrictFixture(t)
	fixture.mount.kernelMount = kernelMount{id: "999999998", device: "0:998", point: "/nonexistent-portablefs-lazy-mount"}
	fixture.mount.kernelConnectionDone = make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- fixture.mount.detach() }()
	time.Sleep(50 * time.Millisecond)
	fixture.rpc.mu.Lock()
	proofs := len(fixture.rpc.detachProofs)
	fixture.rpc.mu.Unlock()
	if proofs != 0 {
		t.Fatal("lazy-unmounted mount detached while its FUSE connection could still serve retained references")
	}
	close(fixture.mount.kernelConnectionDone)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("detach after FUSE connection exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("detach did not proceed after the exact FUSE connection terminated")
	}
}

func TestStrictClosePreservesDetachDeliveryFailure(t *testing.T) {
	fixture := newStrictFixture(t)
	fixture.mount.kernelMount = kernelMount{id: "999999997", device: "0:997", point: "/nonexistent-portablefs-detach-failure"}
	done := make(chan struct{})
	close(done)
	fixture.mount.kernelConnectionDone = done
	delivery := errors.New("authority refused clean detach")
	fixture.rpc.detachErr = delivery
	if first := fixture.mount.Close(); !errors.Is(first, delivery) {
		t.Fatalf("first Close = %v, want detach delivery failure", first)
	}
	if second := fixture.mount.Close(); !errors.Is(second, delivery) {
		t.Fatalf("second Close = %v, want preserved detach delivery failure", second)
	}
	fixture.rpc.mu.Lock()
	defer fixture.rpc.mu.Unlock()
	if len(fixture.rpc.detachProofs) != 1 || fixture.rpc.closes != 1 {
		t.Fatalf("detach deliveries = %d, RPC closes = %d; Close must execute once", len(fixture.rpc.detachProofs), fixture.rpc.closes)
	}
}

func TestMountAbsenceRefusesAMountThatIsStillInstalled(t *testing.T) {
	installed, err := observeKernelMount("/")
	if err != nil {
		t.Skipf("this environment does not report a mount at /: %v", err)
	}
	if _, err := installed.absent(); err == nil {
		t.Fatal("installed mount was reported absent")
	}
}

func TestPlannedMountSourceAbsenceProducesExactStartupProof(t *testing.T) {
	fsName := fmt.Sprintf("portablefs-unit-never-installed-%d", time.Now().UnixNano())
	proof, err := observePlannedKernelMountAbsent(fsName, "/nonexistent-portablefs-startup-target")
	if err != nil {
		t.Fatalf("observe planned source absence: %v", err)
	}
	if !proof.valid() || proof.Component != mountInfoPath ||
		!strings.Contains(string(proof.Observation), "mount-source="+fsName) ||
		!strings.Contains(string(proof.Observation), "stage=startup") {
		t.Fatalf("startup absence proof = %+v", proof)
	}
}

func TestPlannedMountSourceAbsenceRefusesAnInstalledSource(t *testing.T) {
	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		for separator := 6; separator+2 < len(fields); separator++ {
			if fields[separator] != "-" {
				continue
			}
			source := unescapeMountField(fields[separator+2])
			if _, err := observePlannedKernelMountAbsent(source, "/irrelevant-to-source-identity"); err == nil {
				t.Fatalf("installed mount source %q was reported absent", source)
			}
			return
		}
	}
	t.Fatal("mountinfo contained no installed source to test")
}

func TestFailedHelperMountIsExactlyUnmountedBeforeSessionRelease(t *testing.T) {
	fixture := newStrictFixture(t)
	directory := t.TempDir()
	mountInfo := directory + "/mountinfo"
	fsName := "portablefs:11111111-1111-4111-8111-111111111111"
	mountpoint := "/workspaces/example"
	if err := os.WriteFile(mountInfo, []byte("42 1 0:99 / /workspaces/example rw - fuse.portablefs "+fsName+" rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	priorReadMountInfo, priorUnmount := readMountInfo, unmountFailedHelperMount
	readMountInfo = func() ([]byte, error) { return os.ReadFile(mountInfo) }
	unmountFailedHelperMount = func(path string) error {
		if path != mountpoint {
			t.Fatalf("unmount path = %q, want %q", path, mountpoint)
		}
		if err := os.WriteFile(mountInfo, []byte("1 0 0:1 / / rw - ext4 /dev/root rw\n"), 0o600); err != nil {
			return err
		}
		return errors.New("fusermount removed the mount but failed to update mtab")
	}
	t.Cleanup(func() {
		readMountInfo, unmountFailedHelperMount = priorReadMountInfo, priorUnmount
	})

	if err := releaseMountInstalledByFailedHelper(fixture.rpc, fsName, mountpoint); err != nil {
		t.Fatalf("release failed helper mount: %v", err)
	}
	fixture.rpc.mu.Lock()
	defer fixture.rpc.mu.Unlock()
	if len(fixture.rpc.detachProofs) != 1 || !fixture.rpc.detachProofs[0].valid() {
		t.Fatalf("detach proofs = %+v, want one exact absence proof", fixture.rpc.detachProofs)
	}
}

func TestFailedHelperMountCleanupRetainsSessionWhenUnmountDoesNotRemoveMount(t *testing.T) {
	fixture := newStrictFixture(t)
	mountInfo := t.TempDir() + "/mountinfo"
	fsName := "portablefs:22222222-2222-4222-8222-222222222222"
	mountpoint := "/workspaces/example"
	installed := "42 1 0:99 / /workspaces/example rw - fuse.portablefs " + fsName + " rw\n"
	if err := os.WriteFile(mountInfo, []byte(installed), 0o600); err != nil {
		t.Fatal(err)
	}
	priorReadMountInfo, priorUnmount := readMountInfo, unmountFailedHelperMount
	readMountInfo = func() ([]byte, error) { return os.ReadFile(mountInfo) }
	unmountFailedHelperMount = func(string) error { return errors.New("fusermount failed") }
	t.Cleanup(func() {
		readMountInfo, unmountFailedHelperMount = priorReadMountInfo, priorUnmount
	})

	if err := releaseMountInstalledByFailedHelper(fixture.rpc, fsName, mountpoint); err == nil {
		t.Fatal("failed unmount was treated as clean")
	}
	fixture.rpc.mu.Lock()
	defer fixture.rpc.mu.Unlock()
	if len(fixture.rpc.detachProofs) != 0 {
		t.Fatalf("detach proofs = %d, want none while the mount remains", len(fixture.rpc.detachProofs))
	}
}

func TestFailedHelperMountCleanupRefusesUnexpectedKernelIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		records string
	}{
		{name: "different path", records: "42 1 0:99 / /other rw - fuse.portablefs portablefs:test rw\n"},
		{name: "foreign overmount", records: "42 1 0:99 / /workspaces/example rw - ext4 /dev/foreign rw\n43 1 0:100 / /workspaces/example rw - fuse.portablefs portablefs:test rw\n"},
		{name: "different filesystem", records: "42 1 0:99 / /workspaces/example rw - fuse.other portablefs:test rw\n"},
		{name: "stacked", records: "42 1 0:99 / /workspaces/example rw - fuse.portablefs portablefs:test rw\n43 1 0:100 / /workspaces/example rw - fuse.portablefs portablefs:test rw\n"},
		{name: "malformed record", records: "malformed\n42 1 0:99 / /workspaces/example rw - fuse.portablefs portablefs:test rw\n"},
		{name: "malformed record without planned source", records: "1 0 0:1 / / rw - ext4 /dev/root rw\nmalformed\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStrictFixture(t)
			mountInfo := t.TempDir() + "/mountinfo"
			if err := os.WriteFile(mountInfo, []byte(test.records), 0o600); err != nil {
				t.Fatal(err)
			}
			priorReadMountInfo, priorUnmount := readMountInfo, unmountFailedHelperMount
			readMountInfo = func() ([]byte, error) { return os.ReadFile(mountInfo) }
			unmounted := false
			unmountFailedHelperMount = func(string) error { unmounted = true; return nil }
			t.Cleanup(func() {
				readMountInfo, unmountFailedHelperMount = priorReadMountInfo, priorUnmount
			})

			if err := releaseMountInstalledByFailedHelper(fixture.rpc, "portablefs:test", "/workspaces/example"); err == nil {
				t.Fatal("unexpected kernel identity was cleaned")
			}
			fixture.rpc.mu.Lock()
			proofs := len(fixture.rpc.detachProofs)
			fixture.rpc.mu.Unlock()
			if unmounted || proofs != 0 {
				t.Fatalf("unmounted = %t, detach proofs = %d; want fail-closed", unmounted, proofs)
			}
		})
	}
}

func TestMountInfoPathsAreUnescaped(t *testing.T) {
	if got := unescapeMountField(`/tmp/with\040space`); got != "/tmp/with space" {
		t.Fatalf("unescaped %q, want %q", got, "/tmp/with space")
	}
	if got := unescapeMountField("/plain/path"); got != "/plain/path" {
		t.Fatalf("unescaped %q, want %q", got, "/plain/path")
	}
}
