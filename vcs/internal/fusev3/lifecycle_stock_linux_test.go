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

func TestMountInfoPathsAreUnescaped(t *testing.T) {
	if got := unescapeMountField(`/tmp/with\040space`); got != "/tmp/with space" {
		t.Fatalf("unescaped %q, want %q", got, "/tmp/with space")
	}
	if got := unescapeMountField("/plain/path"); got != "/plain/path" {
		t.Fatalf("unescaped %q, want %q", got, "/plain/path")
	}
}
