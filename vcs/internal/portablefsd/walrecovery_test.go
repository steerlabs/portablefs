package portablefsd

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

func readAuthorityFile(t *testing.T, authority, name string) string {
	t.Helper()
	cli, err := fsproto.Dial(authority, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	data, st, err := cli.Read(name, 0, 1<<16)
	if err != nil {
		t.Fatalf("authority read %s: %v", name, err)
	}
	if st != fsproto.OK {
		return ""
	}
	return string(data)
}

// TestWALRecoveryAcrossMountPathChange pins the re-keyed storage identity:
// write-back parked by a SIGKILLed daemon serving /Volumes/A must be found
// and replayed when the volume is next attached at /Volumes/B — the WAL
// store is keyed by (volume, branch), not by where the volume was mounted.
//
// The flusher ships within milliseconds, so the parked state is produced the
// way it happens in production: the delegation is established while the
// authority is up, the authority then becomes unreachable, and a delegated
// write is acknowledged locally with a tail that cannot ship before the
// SIGKILL.
func TestWALRecoveryAcrossMountPathChange(t *testing.T) {
	prevTTL := workfs.SessionLeaseTTL()
	workfs.SetSessionLeaseTTL(time.Second)
	t.Cleanup(func() { workfs.SetSessionLeaseTTL(prevTTL) })

	// One managed FS behind a stoppable listener: durable authority state
	// (journal, grants, stream ledger) survives the listener bounce.
	fs := newManagedTestFS(t, daemonTestBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := ln.Addr().String()
	srvCtx, srvStop := context.WithCancel(context.Background())
	go func() { _ = fsproto.NewServer(fs, fs).Serve(srvCtx, ln) }()

	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("/tmp", "pfsd-movewal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd-move1")
	ref1 := ensureAttachWithPolicyOptions(t, p1.hc, authority, "vol-move", "main", "/Volumes/OldPath", "writeback", nil)
	c1 := dialPFS(t, p1.cfg.FrontendSocket)
	c1.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "move-before"})
	res1 := c1.call(&pfslocal.ResolveRequest{AttachRef: ref1}).(*pfslocal.ResolveReply)
	// A subtree file: its parent directory is a delegable scope (the volume
	// root is not).
	mk := c1.call(&pfslocal.MkdirRequest{Dir: res1.Root, Name: []byte("d"), Mode: 0o755}).(*pfslocal.MkdirReply)
	cr := c1.call(&pfslocal.CreateRequest{Dir: mk.Attr.Item, Name: []byte("moved.txt"), Mode: 0o644}).(*pfslocal.CreateReply)
	c1.call(&pfslocal.WriteRequest{Handle: cr.Handle, Data: []byte("seed")})
	// v5 fsync means authority-durable: its success proves the delegation +
	// stream are established and the seed shipped. (A direct authority read
	// here would be a peer op and would RECALL the delegation.)
	c1.call(&pfslocal.FsyncRequest{Handle: cr.Handle})

	// Authority gone: the next delegated write is acknowledged locally
	// (the open handle keeps the delegation held) but its tail cannot ship.
	srvStop()
	c1.call(&pfslocal.WriteRequest{Handle: cr.Handle, Offset: 0, Data: []byte("survives the move")})
	p1.stop() // SIGKILL: the un-shipped tail parks in the WAL store
	c1.close()

	// Authority back on the SAME address over the SAME durable state.
	ln2, err := net.Listen("tcp", authority)
	if err != nil {
		t.Fatal(err)
	}
	srvCtx2, srvStop2 := context.WithCancel(context.Background())
	t.Cleanup(srvStop2)
	go func() { _ = fsproto.NewServer(fs, fs).Serve(srvCtx2, ln2) }()

	if got := readAuthorityFile(t, authority, "d/moved.txt"); got == "survives the move" {
		t.Fatal("data leaked to authority before recovery")
	}

	// Same volume, DIFFERENT mount path: the parked WAL must still recover.
	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd-move2")
	defer p2.stop()
	ensureAttachOnceWithPolicy(t, p2.hc, authority, "vol-move", "main", "/Volumes/NewPath", "writeback", "", nil)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if got := readAuthorityFile(t, authority, "d/moved.txt"); got == "survives the move" {
			break
		}
		if time.Now().After(deadline) {
			got := readAuthorityFile(t, authority, "d/moved.txt")
			t.Fatalf("recovery across mount-path change failed: authority holds %q", got)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// fnvHex mirrors the session manager's root-hash used in WAL filenames
// (sess-<owner>-<hash>.wal).
func fnvHex(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return strconv.FormatUint(h.Sum64(), 16)
}

// TestLegacyWALDirAdoption pins the upgrade path: a WAL store written under
// the retired (volume, branch, mountPath) directory scheme — including the
// old owner embedded in the session WAL filename — is adopted into the
// (volume, branch) store on the next attach and its records replay.
func TestLegacyWALDirAdoption(t *testing.T) {
	authority := serveAuthority(t)
	dir, err := os.MkdirTemp("/tmp", "pfsd-legacy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	stateDir := filepath.Join(dir, "state")

	// Fabricate the legacy store exactly as the old daemon laid it out for
	// an attach at THIS mount path.
	const volumeID, branch, mountPath = "vol-legacy", "main", "/Volumes/Legacy"
	legacyID := stableStorageID(attachKey(volumeID, branch, mountPath))
	legacyOwner := "portablefsd-" + legacyID
	legacyDir := filepath.Join(stateDir, "wal", legacyID)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	walPath := filepath.Join(legacyDir, fmt.Sprintf("sess-%s-%s.wal", legacyOwner, fnvHex("adopt")))
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []wal.Record{
		{Op: wal.OpMkdir, Path: "adopt", Mode: 0o755},
		{Op: wal.OpCreate, Path: "adopt/f", Mode: 0o644},
		{Op: wal.OpWrite, Path: "adopt/f", Offset: 0, Data: []byte("legacy adopted")},
	} {
		if _, err := w.AppendBuffered(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.CommitThrough(2); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		FrontendSocket: filepath.Join(dir, "run", "frontend.sock"),
		ControlSocket:  filepath.Join(dir, "run", "control.sock"),
		StateDir:       stateDir,
		Version:        "portablefsd-test",
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := NewServer(cfg)
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = s.Run(ctx) }()
	// The state dir cleanup must not race the daemon's shutdown detach
	// (which drains and writes into it): wait for Run to fully exit.
	defer func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(60 * time.Second):
			t.Error("daemon Run did not exit after cancel")
		}
	}()
	waitUnix(t, cfg.ControlSocket)
	hc := httpUDSClient(cfg.ControlSocket)

	// Attaching the volume (any path — here the same one) adopts the legacy
	// dir and replays the parked records to the authority.
	ensureAttachOnceWithPolicy(t, hc, authority, volumeID, branch, mountPath, "writeback", "",
		map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)})

	if got := readAuthorityFile(t, authority, "adopt/f"); got != "legacy adopted" {
		t.Fatalf("legacy WAL did not replay: authority holds %q", got)
	}
	if _, err := os.Stat(legacyDir); !os.IsNotExist(err) {
		t.Fatalf("legacy dir %s should be gone after adoption (err=%v)", legacyDir, err)
	}
	newDir := filepath.Join(stateDir, "wal", stableStorageID(storageKey(volumeID, branch)))
	if id, ok := readWALIdentity(newDir); !ok || id.VolumeID != volumeID || id.Branch != branch {
		t.Fatalf("adopted store identity = %+v ok=%v", id, ok)
	}

	// The attach's status must now show no parked debt.
	var status attachStatus
	var list struct {
		Attaches []attachStatus `json:"attaches"`
	}
	controlJSON(t, hc, http.MethodGet, "/v1/attaches", nil, http.StatusOK, &list)
	if len(list.Attaches) != 1 {
		t.Fatalf("attaches = %d, want 1", len(list.Attaches))
	}
	status = list.Attaches[0]
	if status.WriteBack != nil && len(status.WriteBack.ParkedWALs) > 0 {
		t.Fatalf("parked WALs remain after adoption+recovery: %+v", status.WriteBack)
	}
}

// TestOrphanWALSweep pins the daemon-start sweep: fully-drained logs in an
// unclaimed store are removed (dir included), while a store with pending
// records for an UNKNOWN volume is preserved.
func TestOrphanWALSweep(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pfsd-sweep-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	stateDir := filepath.Join(dir, "state")

	drainedDir := filepath.Join(stateDir, "wal", "deadbeef000000000000000000000000")
	if err := os.MkdirAll(drainedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	drained := filepath.Join(drainedDir, "sess-portablefsd-x-1.wal")
	w, err := wal.Open(drained)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AppendBuffered(wal.Record{Op: wal.OpCreate, Path: "gone", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := w.CommitThrough(0); err != nil {
		t.Fatal(err)
	}
	if err := w.CompactThrough(1); err != nil { // fully acked: nothing pending
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	pendingDir := filepath.Join(stateDir, "wal", "cafef00d000000000000000000000000")
	if err := os.MkdirAll(pendingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(pendingDir, "sess-portablefsd-y-2.wal")
	w2, err := wal.Open(pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.AppendBuffered(wal.Record{Op: wal.OpCreate, Path: "keep", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := w2.CommitThrough(0); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}

	sweepWALRoot(stateDir, nil)

	if _, err := os.Stat(drainedDir); !os.IsNotExist(err) {
		t.Fatalf("drained orphan store should be removed (err=%v)", err)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("pending orphan WAL must be preserved: %v", err)
	}
}
