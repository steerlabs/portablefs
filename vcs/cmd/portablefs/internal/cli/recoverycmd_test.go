package cli

// ROUND 21b, DEFECT 2, CLI half: the shipped resolution surface, and the
// message graph that must never send an operator in a circle.
//
// Live, a terminally-conflict recovery job produced this and nothing else:
//
//	portablefs umount                  -> "run portablefs umount --force"
//	portablefs umount --force          -> "... requires explicit recovery resolution (409)"
//	portablefs umount --discard-record -> "run portablefs umount --force ... first"
//
// The phrase "explicit recovery resolution" existed in exactly one place in the
// product: the error that refused. There was no command. The operator escaped by
// moving our state directory by hand.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

const testAttachRef = "att_AAAAAAAAAAAAAAAAAAAAAA"

// writeAttachInventory writes the durable portablefsd attach inventory naming
// mountPath — the record `--discard-record` refuses on, and the one
// `recovery` uses to find the store without a live daemon.
func writeAttachInventory(t *testing.T, daemonStateDir, mountPath string) {
	t.Helper()
	if err := os.MkdirAll(daemonStateDir, 0o700); err != nil {
		t.Fatalf("create daemon state dir: %v", err)
	}
	entry := map[string]any{
		"ref":                testAttachRef,
		"volumeId":           "vol",
		"branch":             "main",
		"mountPath":          mountPath,
		"authorityUrl":       "http://127.0.0.1:1",
		"dataPlaneTransport": "plaintext",
		"options":            map[string]any{},
		"identityEpoch":      1,
	}
	body, err := json.Marshal(map[string]any{
		"version":  2,
		"attaches": []any{entry},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(daemonStateDir, "attaches.json")
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write attach inventory: %v", err)
	}
}

// wedgedFSKitStore leaves a write-back store on disk whose recovery registry
// holds one terminally-conflict job: the exact shape that refused force-park.
//
// The store is built from its durable primitives rather than from a live
// engine, because that is precisely the situation this command serves — nothing
// is running, and the operator has only the bytes on disk.
func wedgedFSKitStore(t *testing.T, daemonStateDir string) (storeDir, jobID string) {
	t.Helper()
	storeDir = portablefsd.WritebackStoreDir(daemonStateDir, "vol", "main")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatalf("create store dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "engine.lock"), nil, 0o600); err != nil {
		t.Fatalf("create store lock: %v", err)
	}
	mountID := strings.Repeat("ab", 16)
	if err := os.WriteFile(filepath.Join(storeDir, "mount-id"), []byte(mountID+"\n"), 0o600); err != nil {
		t.Fatalf("write mount id: %v", err)
	}
	streamDir := filepath.Join(storeDir, "stream-0000000000000001")
	if err := os.MkdirAll(streamDir, 0o700); err != nil {
		t.Fatalf("create stream dir: %v", err)
	}
	// A retained WAL segment stands for the acknowledged bytes the resolution
	// must MOVE and never delete.
	if err := os.WriteFile(filepath.Join(streamDir, "wb-0000000000000001.pfw"), []byte("PFW5"), 0o600); err != nil {
		t.Fatalf("write stream segment: %v", err)
	}
	jobID = "job" + strings.Repeat("0", 31) + "1"
	job := writeback.RecoveryJob{
		Version: 1, JobID: jobID, VolumeID: "vol", Branch: "main",
		MountID: mountID, WALEpoch: 1, WritebackID: "wb-test",
		State: writeback.JobConflict, PendingRecords: 3, PendingBytes: 4096,
		LastError: "authority reported a typed recovery conflict",
	}
	body, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(streamDir, "job.json"), append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write recovery registry: %v", err)
	}
	return storeDir, jobID
}

// TestRecoveryListNamesTheBlockingJobAndTheCommandThatClearsIt is the
// diagnostic half. An operator staring at a refused unmount must be able to see
// WHAT is blocking it and WHICH invocation clears it, with no live daemon.
func TestRecoveryListNamesTheBlockingJobAndTheCommandThatClearsIt(t *testing.T) {
	e, stdout, stderr := testEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	daemonStateDir := daemonStateDirFor(stateDir)
	writeAttachInventory(t, daemonStateDir, mountPath)
	_, jobID := wedgedFSKitStore(t, daemonStateDir)

	if code := e.run([]string{"recovery", "list", mountPath}); code != 0 {
		t.Fatalf("recovery list exited %d: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, jobID) {
		t.Fatalf("recovery list does not name the blocking job %s: %s", jobID, out)
	}
	if !strings.Contains(out, writeback.JobConflict) {
		t.Fatalf("recovery list does not name the job's terminal state: %s", out)
	}
	if !strings.Contains(out, "portablefs recovery resolve "+mountPath) {
		t.Fatalf("recovery list does not print the invocation that clears the block: %s", out)
	}
}

// TestRecoveryResolveClearsTheBlockAndKeepsTheBytes is the resolution half, end
// to end through the shipped command.
func TestRecoveryResolveClearsTheBlockAndKeepsTheBytes(t *testing.T) {
	e, stdout, stderr := testEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	daemonStateDir := daemonStateDirFor(stateDir)
	writeAttachInventory(t, daemonStateDir, mountPath)
	storeDir, jobID := wedgedFSKitStore(t, daemonStateDir)

	// NO IMPLICIT BLAST RADIUS: naming nothing is a usage error, not a sweep.
	if code := e.run([]string{"recovery", "resolve", mountPath}); code != 2 {
		t.Fatalf("resolve with no job named exited %d, want a usage error: %s", code, stderr.String())
	}
	stderr.Reset()

	if code := e.run([]string{"recovery", "resolve", mountPath, "--job", jobID, "--json"}); code != 0 {
		t.Fatalf("recovery resolve exited %d: %s", code, stderr.String())
	}
	var payload struct {
		Resolved int `json:"resolved"`
		Stores   []struct {
			Result struct {
				Resolved []writeback.ResolvedJob `json:"resolved"`
			} `json:"result"`
		} `json:"stores"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode resolve output %q: %v", stdout.String(), err)
	}
	if payload.Resolved != 1 {
		t.Fatalf("resolve reported %d resolved job(s): %s", payload.Resolved, stdout.String())
	}
	resolved := payload.Stores[0].Result.Resolved[0]
	if resolved.JobID != jobID {
		t.Fatalf("resolved %q, want the job that was blocking (%q)", resolved.JobID, jobID)
	}
	if resolved.LostRecords != 3 || resolved.LostBytes != 4096 {
		t.Fatalf("resolve did not state the loss the registry recorded: %+v", resolved)
	}

	// NEVER DELETE WHAT CANNOT BE PROVEN DISPOSABLE.
	if _, err := os.Lstat(resolved.QuarantinePath); err != nil {
		t.Fatalf("resolve named %q for the retained bytes but nothing is there: %v", resolved.QuarantinePath, err)
	}
	if _, err := os.Lstat(filepath.Join(resolved.QuarantinePath, "wb-0000000000000001.pfw")); err != nil {
		t.Fatalf("resolve DELETED the acknowledged bytes instead of retaining them: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(storeDir, "stream-0000000000000001")); !os.IsNotExist(err) {
		t.Fatalf("the resolved stream is still in the recovery scan path: %v", err)
	}
	if !strings.HasPrefix(resolved.QuarantinePath, storeDir) {
		t.Fatalf("retained bytes left the mount's own store: %q", resolved.QuarantinePath)
	}
	if resolved.Remedy == "" || !strings.Contains(resolved.Remedy, resolved.QuarantinePath) {
		t.Fatalf("the remedy does not name where the surviving bytes are: %q", resolved.Remedy)
	}

	// The block is cleared: a second list reports the job as quarantined and no
	// longer resolvable, which is what force-park's validator now walks past.
	stdout.Reset()
	if code := e.run([]string{"recovery", "list", mountPath, "--json"}); code != 0 {
		t.Fatalf("recovery list exited %d: %s", code, stderr.String())
	}
	var listed struct {
		Jobs []struct {
			JobID       string `json:"jobId"`
			Quarantined bool   `json:"quarantined"`
			Resolvable  bool   `json:"resolvable"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil {
		t.Fatalf("decode list output %q: %v", stdout.String(), err)
	}
	for _, row := range listed.Jobs {
		if row.JobID != jobID {
			continue
		}
		if !row.Quarantined || row.Resolvable {
			t.Fatalf("after resolution the job is still reported as a live blocker: %+v", row)
		}
		return
	}
	t.Fatalf("the resolved job vanished from the inventory; a loss must stay reported: %s", stdout.String())
}

// TestUmountMessageGraphNamesTheResolutionInsteadOfLooping is the audit. The
// --discard-record refusal sent the operator to `umount --force`, which sent
// them back. It must now also name the command that breaks the tie.
func TestUmountMessageGraphNamesTheResolutionInsteadOfLooping(t *testing.T) {
	e, _, stderr := testEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeAttachInventory(t, daemonStateDirFor(stateDir), mountPath)

	if code := e.run([]string{"umount", mountPath, "--discard-record"}); code == 0 {
		t.Fatal("--discard-record discarded a record whose daemon attach is still recorded")
	}
	msg := stderr.String()
	if !strings.Contains(msg, "portablefs umount --force") {
		t.Fatalf("the --discard-record refusal no longer names the force path: %s", msg)
	}
	if !strings.Contains(msg, "portablefs recovery resolve") {
		t.Fatalf("REPRO: the --discard-record refusal sends the operator to `umount --force` "+
			"and nothing else. When that force is itself refused by a terminal recovery job, "+
			"the two messages point at each other with no exit — the closed cycle observed "+
			"live. It must also name the resolution:\n%s", msg)
	}
}

// TestRecoveryHelpIsReachable keeps the command discoverable: a command an
// operator cannot find is a command that does not exist to them.
func TestRecoveryHelpIsReachable(t *testing.T) {
	e, stdout, stderr := testEnv(t)
	if code := e.run([]string{"help", "recovery"}); code != 0 {
		t.Fatalf("help recovery exited %d: %s", code, stderr.String())
	}
	help := stdout.String()
	for _, want := range []string{
		"portablefs recovery list",
		"portablefs recovery resolve",
		"--all-terminal",
		"NEVER DELETE",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("`help recovery` does not document %q:\n%s", want, help)
		}
	}
	stdout.Reset()
	if code := e.run([]string{"help", "umount"}); code != 0 {
		t.Fatalf("help umount exited %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "portablefs recovery resolve") {
		t.Fatalf("`help umount` does not name the resolution that unblocks --force:\n%s", stdout.String())
	}
	if !strings.Contains(rootHelp(), "recovery") {
		t.Fatalf("the root help does not list the recovery command:\n%s", rootHelp())
	}
}
