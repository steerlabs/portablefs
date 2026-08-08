package stableboundary

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	helperMarker = "PORTABLEFS_DIRECTSTORE_BOUNDARY_HELPER"
	unsafeCut    = Event("unsafe-after-append-response")
)

func TestCrashAtEveryOrderingPoint(t *testing.T) {
	bundle := testBundle()
	for _, cut := range OrderingPoints {
		cut := cut
		t.Run(string(cut), func(t *testing.T) {
			root := t.TempDir()
			if err := PrepareLayout(root); err != nil {
				t.Fatal(err)
			}
			events := runKilledHelper(t, root, cut, "safe")
			got, err := Inspect(root, bundle)
			if err != nil {
				t.Fatalf("recovery after %s: %v", cut, err)
			}

			wantObject := atOrAfter(cut, AfterObjectSync)
			wantState := atOrAfter(cut, AfterStateCommitSync)
			wantPrepared := atOrAfter(cut, AfterRaftSync)
			wantInstalled := atOrAfter(cut, AfterInstallSync)
			if got.ObjectStable != wantObject {
				t.Fatalf("object stable after %s = %t, want %t", cut, got.ObjectStable, wantObject)
			}
			if got.StateCommitStable != wantState {
				t.Fatalf("state commit stable after %s = %t, want %t", cut, got.StateCommitStable, wantState)
			}
			if got.Prepared != wantPrepared {
				t.Fatalf("prepared after %s = %t, want %t", cut, got.Prepared, wantPrepared)
			}
			if got.Installed != wantInstalled {
				t.Fatalf("installed after %s = %t, want %t", cut, got.Installed, wantInstalled)
			}

			appendResponseSeen := containsEvent(events, AppendResponse)
			clientReplySeen := containsEvent(events, ClientReply)
			if appendResponseSeen && !got.Prepared {
				t.Fatalf("append response preceded complete prepared storage after %s", cut)
			}
			if clientReplySeen && !got.Installed {
				t.Fatalf("client reply preceded installed storage after %s", cut)
			}
			if appendResponseSeen != atOrAfter(cut, AfterAppendResponse) {
				t.Fatalf("append response observation after %s = %t", cut, appendResponseSeen)
			}
			if clientReplySeen != atOrAfter(cut, AfterClientReply) {
				t.Fatalf("client reply observation after %s = %t", cut, clientReplySeen)
			}
		})
	}
}

func TestUnsafeResponseBeforeObjectSyncIsDetected(t *testing.T) {
	root := t.TempDir()
	if err := PrepareLayout(root); err != nil {
		t.Fatal(err)
	}
	events := runKilledHelper(t, root, unsafeCut, "unsafe")
	if !containsEvent(events, AppendResponse) {
		t.Fatal("negative control did not emit its unsafe append response")
	}
	_, err := Inspect(root, testBundle())
	if err == nil || !strings.Contains(err.Error(), "missing materialized object") {
		t.Fatalf("unsafe recovery error = %v, want missing materialized object", err)
	}
}

func TestBoundaryCrashHelper(t *testing.T) {
	if os.Getenv(helperMarker) != "1" {
		t.Skip("subprocess helper")
	}
	root := os.Getenv(helperMarker + "_ROOT")
	cut := Event(os.Getenv(helperMarker + "_CUT"))
	mode := os.Getenv(helperMarker + "_MODE")
	observe := func(event Event) {
		fmt.Fprintln(os.Stdout, event)
		if event == cut {
			select {}
		}
	}
	var err error
	switch mode {
	case "safe":
		err = Persist(root, testBundle(), observe)
	case "unsafe":
		err = persistUnsafe(root, testBundle(), observe)
	default:
		err = fmt.Errorf("unknown helper mode %q", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func persistUnsafe(root string, bundle Bundle, observe func(Event)) error {
	r, err := buildRecords(bundle)
	if err != nil {
		return err
	}
	if err := writeDurableAtomic(
		filepath.Join(root, "state"), r.stateName, r.state,
		BeforeStateCommitSync, AfterStateCommitSync, nil,
	); err != nil {
		return err
	}
	if err := writeDurableAtomic(
		filepath.Join(root, "raft"), r.raftName, r.raft,
		BeforeRaftSync, AfterRaftSync, nil,
	); err != nil {
		return err
	}
	emit(observe, AppendResponse)
	emit(observe, unsafeCut)
	return writeDurableAtomic(
		filepath.Join(root, "objects"), r.objectName, bundle.Object,
		BeforeObjectSync, AfterObjectSync, nil,
	)
}

func runKilledHelper(t *testing.T, root string, cut Event, mode string) []Event {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBoundaryCrashHelper$")
	cmd.Env = append(os.Environ(),
		helperMarker+"=1",
		helperMarker+"_ROOT="+root,
		helperMarker+"_CUT="+string(cut),
		helperMarker+"_MODE="+mode,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	var events []Event
	found := false
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		event := Event(scanner.Text())
		events = append(events, event)
		if event == cut {
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("read helper events: %v", err)
	}
	if !found {
		err := cmd.Wait()
		t.Fatalf("helper exited before cut %s: %v: %s", cut, err, stderr.String())
	}
	if err := cmd.Process.Kill(); err != nil {
		_ = cmd.Wait()
		t.Fatalf("kill helper at %s: %v", cut, err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatalf("helper at %s exited cleanly after kill", cut)
	}
	return events
}

func testBundle() Bundle {
	// Index one is derived from the empty-log case exercised by this spike.
	return Bundle{
		Index:   1,
		Object:  []byte("portablefs direct-store stable-boundary object"),
		Outcome: []byte("exact outcome"),
	}
}

func atOrAfter(got Event, threshold Event) bool {
	gotIndex, thresholdIndex := orderingIndex(got), orderingIndex(threshold)
	return gotIndex >= thresholdIndex
}

func orderingIndex(want Event) int {
	for i, event := range OrderingPoints {
		if event == want {
			return i
		}
	}
	panic("event absent from ordering points: " + string(want))
}

func containsEvent(events []Event, want Event) bool {
	for _, event := range events {
		if event == want {
			return true
		}
	}
	return false
}
