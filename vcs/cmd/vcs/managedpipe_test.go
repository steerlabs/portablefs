package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/managerlease"
)

// These tests drive the cmd/vcs side of the manager pipe contract over REAL
// pipes, exactly the way runRemotePrimary wires it: the guard consumes
// TS-layout lease frames from the inherited heartbeat descriptor, readiness
// gates on the first GROUNDED frame (a capability-bound lease-facts probe,
// faked here the way the journal seam provides it), and the one-shot
// bootstrap frame is consumed the way the TS manager's consumeBootstrap
// does — one bounded line, nothing trailing.

func testGuardIdentity() managerlease.Identity {
	return managerlease.Identity{
		ManagerEpoch:        "1",
		ManagerRuntimeID:    "pfmgr_a",
		AuthorityInstanceID: "pfvcs_a",
		AuthorityRuntimeSeq: "1",
		AuthorityRuntimeID:  "pfrt_a",
	}
}

// tsLeaseFrame renders the exact bytes the TS manager's flushHeartbeatFrame
// writes for this child (JSON.stringify member order, newline-terminated).
func tsLeaseFrame(seq int64, dbTimeMs, leaseRemainingMs int64) string {
	return fmt.Sprintf(`{"v":1,"seq":%d,"managerEpoch":"1","managerRuntimeId":"pfmgr_a","authorityInstanceId":"pfvcs_a","authorityRuntimeSeq":"1","authorityRuntimeId":"pfrt_a","dbTimeMs":%d,"leaseRemainingMs":%d}`+"\n",
		seq, dbTimeMs, leaseRemainingMs)
}

// groundedProber is the fake journal lease-facts seam: the database's
// capability-bound answer for the LIVE claim, always current with a
// comfortable remaining window.
type groundedProber struct{}

func (groundedProber) ProbeLeaseFacts(context.Context) (managerlease.LeaseFacts, error) {
	return managerlease.LeaseFacts{
		Current:             true,
		DBTimeMs:            1_000_000,
		ExpiresAtDbMs:       1_000_000 + 60_000,
		ManagerEpoch:        "1",
		AuthorityRuntimeSeq: "1",
		AuthorityRuntimeID:  "pfrt_a",
	}, nil
}

// TestManagerPipeFirstFrameGatesReadiness: a TS-layout frame arriving on the
// heartbeat pipe, grounded through the journal seam, releases
// waitForInitialManagerLease — the pre-readiness gate runRemotePrimary
// enforces before binding listeners.
func TestManagerPipeFirstFrameGatesReadiness(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	guard := managerlease.NewGuard(testGuardIdentity(), 0)
	guard.SetProber(groundedProber{})
	go guard.Run(reader)

	if _, err := writer.WriteString(tsLeaseFrame(1, 1_000_000, 30_000)); err != nil {
		t.Fatalf("write lease frame: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- waitForInitialManagerLease(context.Background(), guard, make(chan struct{})) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("grounded first frame must release the readiness gate: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readiness gate never released on a grounded TS frame")
	}
	// Manager death (pipe EOF) fences the child even after readiness.
	_ = writer.Close()
	select {
	case <-guard.Fenced():
	case <-time.After(5 * time.Second):
		t.Fatal("pipe EOF did not fence the child")
	}
	if guard.Cause() == nil {
		t.Fatal("fence must carry a cause")
	}
}

// TestManagerPipeEOFBeforeFirstFrameRefusesServing: a manager that dies (or
// never writes) before the first valid frame must refuse serving — the child
// exits instead of holding the writer claim on a dead control plane.
func TestManagerPipeEOFBeforeFirstFrameRefusesServing(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	guard := managerlease.NewGuard(testGuardIdentity(), 0)
	guard.SetProber(groundedProber{})
	go guard.Run(reader)
	_ = writer.Close() // manager died before speaking

	err = waitForInitialManagerLease(context.Background(), guard, make(chan struct{}))
	if err == nil || !strings.Contains(err.Error(), "fenced before the first valid frame") {
		t.Fatalf("EOF before the first frame must refuse serving, got %v", err)
	}
}

// TestManagerPipeForeignFrameFences: a frame naming a foreign runtime binding
// fences immediately — the guard never refreshes its lease view from an
// identity it was not launched under.
func TestManagerPipeForeignFrameFences(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	guard := managerlease.NewGuard(testGuardIdentity(), 0)
	guard.SetProber(groundedProber{})
	go guard.Run(reader)

	foreign := strings.Replace(tsLeaseFrame(1, 1_000_000, 30_000), `"authorityRuntimeId":"pfrt_a"`, `"authorityRuntimeId":"pfrt_FOREIGN"`, 1)
	if _, err := writer.WriteString(foreign); err != nil {
		t.Fatalf("write foreign frame: %v", err)
	}
	select {
	case <-guard.Fenced():
	case <-time.After(5 * time.Second):
		t.Fatal("a foreign frame did not fence the child")
	}
	err = waitForInitialManagerLease(context.Background(), guard, make(chan struct{}))
	if err == nil || !strings.Contains(err.Error(), "fenced before the first valid frame") {
		t.Fatalf("a fenced guard must refuse serving, got %v", err)
	}
}

// TestBootstrapPipeOneShotConsumption emits the bootstrap frame over a real
// pipe and consumes it the way the TS manager's consumeBootstrap does: one
// bounded newline-terminated line, then EOF — no trailing bytes (the TS side
// refuses to adopt a child whose pipe keeps speaking).
func TestBootstrapPipeOneShotConsumption(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	frame := managerlease.Bootstrap{
		AuthorityInstanceID: "pfvcs_a",
		VolumeID:            "vol_1",
		Branch:              "main",
		ManagerEpoch:        "1",
		AuthorityRuntimeSeq: "1",
		AuthorityRuntimeID:  "pfrt_a",
		FSAddr:              "127.0.0.1:42001",
		MetricsAddr:         "127.0.0.1:43001",
		JournalGenerationID: "pfgen_sim_1",
		ProtocolVersion:     managedProtocolVersion,
		HAPolicyHash:        tsPinnedHAPolicyHash,
	}
	// The serving path emits exactly one frame and closes the descriptor.
	if err := managerlease.EmitBootstrap(writer, frame); err != nil {
		t.Fatalf("emit bootstrap: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close bootstrap pipe: %v", err)
	}

	buffered := bufio.NewReader(reader)
	line, err := buffered.ReadString('\n')
	if err != nil {
		t.Fatalf("read bootstrap line: %v", err)
	}
	if len(line) > 4096 {
		t.Fatalf("bootstrap frame exceeds the 4 KiB bound: %d bytes", len(line))
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("bootstrap frame is not one JSON object: %v", err)
	}
	// The exact fields validateBootstrapFrame cross-checks before adoption.
	for field, want := range map[string]any{
		"v":                   float64(1),
		"authorityInstanceId": "pfvcs_a",
		"volumeId":            "vol_1",
		"branch":              "main",
		"managerEpoch":        "1",
		"authorityRuntimeSeq": "1",
		"authorityRuntimeId":  "pfrt_a",
		"fsAddr":              "127.0.0.1:42001",
		"metricsAddr":         "127.0.0.1:43001",
		"journalGenerationId": "pfgen_sim_1",
		"protocolVersion":     float64(managedProtocolVersion),
		"haPolicyHash":        tsPinnedHAPolicyHash,
	} {
		if decoded[field] != want {
			t.Fatalf("bootstrap %s = %v, want %v (the TS manager would refuse adoption)", field, decoded[field], want)
		}
	}
	// One-shot: nothing may follow the newline.
	if _, err := buffered.ReadByte(); err == nil {
		t.Fatal("bootstrap pipe carries trailing bytes after the one-shot frame")
	}
}
