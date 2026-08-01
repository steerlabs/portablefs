package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func TestLegacyConflictBlocksRegistryAttachReadiness(t *testing.T) {
	ctx := context.Background()
	authority := serveAuthority(t)
	seed, err := clientcore.Dial(ctx, clientcore.Options{
		Addr: authority, Pool: 2, WALDir: privateTestDir(t), VolumeID: "legacy-gate-seed", Branch: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	file, st := seed.CreateExcl(ctx, "startup-conflict", 0o644)
	if st != fsproto.OK {
		_ = seed.Close()
		t.Fatalf("seed file: status %d", st)
	}
	if file.Ino == 0 {
		_ = seed.Close()
		t.Fatal("seed file has no stable authority inode")
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed volume: %v", err)
	}

	const volumeID, branch = "legacy-gate", "main"
	stateDir := privateTestDir(t)
	walPath := writeLegacyStartupRecord(t, stateDir, volumeID, branch, wal.Record{
		Op: wal.OpMkdir, Path: "startup-conflict", Mode: 0o755, Inos: []uint64{file.Ino},
	})
	sidecarPath := walPath + ".drain.json"
	sidecar := []byte(`{"nextOffset":{"sentinel":41},"lastAppliedSeq":{"sentinel":7}}`)
	if err := os.WriteFile(sidecarPath, sidecar, 0o600); err != nil {
		t.Fatal(err)
	}

	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	a, created, err := r.ensure(ctx, ensureAttachRequest{
		VolumeID: volumeID, Branch: branch, AuthorityURL: authority, MountPath: "/Volumes/LegacyGate",
		DataPlaneTransport: "plaintext",
	})
	if !errors.Is(err, errLegacyAdoptionConflict) {
		t.Fatalf("ensure error = %v, want legacy adoption conflict", err)
	}
	var conflict *legacyAdoptionConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("ensure error type = %T, want *legacyAdoptionConflictError", err)
	}
	if a != nil || created {
		t.Fatalf("failed ensure returned attach=%v created=%v", a, created)
	}
	if got := r.list(); len(got) != 0 {
		t.Fatalf("blocked attach remains frontend-visible: %d registry entries", len(got))
	}
	assertLegacyStartupDebtPreserved(t, walPath, sidecarPath, sidecar)
}

func TestCorruptLegacyWALLeavesAttachUnstartedAndDebtVisible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authority := serveAuthority(t)

	const volumeID, branch = "legacy-corrupt-gate", "main"
	stateDir := privateTestDir(t)
	store := filepath.Join(stateDir, "wal", stableStorageID(storageKey(volumeID, branch)))
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	writeWALIdentity(store, walIdentity{VolumeID: volumeID, Branch: branch})
	walPath := filepath.Join(store, "sess-corrupt.wal")
	corrupt := []byte("definitely-not-a-portablefs-wal")
	if err := os.WriteFile(walPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	req := ensureAttachRequest{
		VolumeID: volumeID, Branch: branch, AuthorityURL: authority, MountPath: "/Volumes/LegacyCorrupt",
		DataPlaneTransport: "plaintext",
	}
	a := newAttach("legacy-corrupt-ref", attachKey(volumeID, branch, req.MountPath), req, stateDir)
	err := a.activate(ctx, "", 0)
	if err == nil || !strings.Contains(err.Error(), "legacy write-back debt blocks attach readiness") {
		t.Fatalf("activate error = %v, want blocked legacy debt", err)
	}

	a.mu.RLock()
	vol := a.vol
	eventClient := a.eventClient
	parked := append([]parkedWAL(nil), a.legacyParked...)
	a.mu.RUnlock()
	if vol != nil || eventClient != nil {
		t.Fatalf("blocked attach published resources: volume=%v eventClient=%v", vol != nil, eventClient != nil)
	}
	select {
	case <-a.eventReady:
		t.Fatal("blocked attach signaled event/frontend readiness")
	default:
	}
	if len(parked) != 1 || parked[0].WAL != walPath || parked[0].LastError == "" {
		t.Fatalf("parked legacy debt = %+v, want corrupt WAL with surfaced error", parked)
	}
	status := a.status()
	if status.State != stateString(pfslocal.AttachStateDegraded) ||
		status.WriteBack == nil || len(status.WriteBack.ParkedWALs) != 1 ||
		!strings.Contains(status.LastError, "legacy write-back debt blocks attach readiness") {
		t.Fatalf("blocked attach status = %+v", status)
	}
	got, readErr := os.ReadFile(walPath)
	if readErr != nil {
		t.Fatalf("corrupt WAL was removed: %v", readErr)
	}
	if !bytes.Equal(got, corrupt) {
		t.Fatalf("corrupt WAL changed: got %q, want %q", got, corrupt)
	}
}

func writeLegacyStartupRecord(t *testing.T, stateDir, volumeID, branch string, rec wal.Record) string {
	t.Helper()
	store := filepath.Join(stateDir, "wal", stableStorageID(storageKey(volumeID, branch)))
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	writeWALIdentity(store, walIdentity{VolumeID: volumeID, Branch: branch})
	walPath := filepath.Join(store, "sess-startup-gate.wal")
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	seq, err := w.AppendBuffered(rec)
	if err != nil {
		_ = w.Close()
		t.Fatal(err)
	}
	if err := w.CommitThrough(seq); err != nil {
		_ = w.Close()
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return walPath
}

func assertLegacyStartupDebtPreserved(t *testing.T, walPath, sidecarPath string, sidecar []byte) {
	t.Helper()
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatalf("blocked legacy WAL was removed: %v", err)
	}
	records, err := w.Replay()
	if err != nil {
		_ = w.Close()
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("blocked legacy WAL records = %d, want 1", len(records))
	}
	got, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatalf("blocked legacy sidecar was removed: %v", err)
	}
	if !bytes.Equal(got, sidecar) {
		t.Fatalf("blocked legacy sidecar changed: got %q, want %q", got, sidecar)
	}
}
