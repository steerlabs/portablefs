package portablefsd

import (
	"net/http"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestSyncVolumeOpAndDetachDrainWriteBack pins the two production callers of
// the real drain barrier: the frontend SyncVolume op (FSKit synchronize) must
// drain acknowledged write-back to the authority before replying (not a
// statfs shrug), and detach must do the same through SyncVolumeBounded so a
// clean unmount leaves no parked WAL. Writes land in delegable
// subdirectories (the volume root is never delegated); the barrier — not the
// racy 10ms background flusher — is what the assertions rely on.
func TestSyncVolumeOpAndDetachDrainWriteBack(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()

	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-syncop", "main", "/Volumes/SyncOp", "writeback", nil)

	pfs := dialPFS(t, cfg.FrontendSocket)
	defer pfs.close()
	root := resolveRoot(t, pfs, ref)

	writeFile := func(dir pfslocal.Item, name, content string) {
		cr := pfs.call(&pfslocal.CreateRequest{Dir: dir, Name: []byte(name), Mode: 0o644}).(*pfslocal.CreateReply)
		if wr := pfs.call(&pfslocal.WriteRequest{Handle: cr.Handle, Offset: 0, Data: []byte(content)}).(*pfslocal.WriteReply); wr.Written != uint32(len(content)) {
			t.Fatalf("write %s: wrote %d", name, wr.Written)
		}
		pfs.call(&pfslocal.CloseRequest{Handle: cr.Handle})
	}
	readAuthority := func(name string) string {
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

	d1 := pfs.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte("d1"), Mode: 0o755}).(*pfslocal.MkdirReply)
	writeFile(d1.Attr.Item, "synced.txt", "via-sync-op")
	rep := pfs.call(&pfslocal.SyncVolumeRequest{}).(*pfslocal.SyncVolumeReply)
	if rep.Degraded {
		t.Fatal("healthy loopback sync reported degraded")
	}
	if got := readAuthority("d1/synced.txt"); got != "via-sync-op" {
		t.Fatalf("SyncVolume did not drain: authority holds %q", got)
	}

	// Second file rides the DETACH drain (SyncVolumeBounded inside detach).
	// A fresh scope: the authority read above recalled d1 for contention,
	// so d1 would run write-through for the cooldown — d2 delegates again.
	d2 := pfs.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte("d2"), Mode: 0o755}).(*pfslocal.MkdirReply)
	writeFile(d2.Attr.Item, "detached.txt", "via-detach")
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
	if got := readAuthority("d2/detached.txt"); got != "via-detach" {
		t.Fatalf("detach did not drain: authority holds %q", got)
	}
}

// TestControlSyncEndpointReportsVerdict pins the CLI's pre-unmount drain
// surface: POST /v1/attaches/{ref}/sync drains and answers with the verdict
// shape `portablefs umount` prints.
func TestControlSyncEndpointReportsVerdict(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-syncctl", "main", "/Volumes/SyncCtl", "writeback", opts)

	pfs := dialPFS(t, cfg.FrontendSocket)
	defer pfs.close()
	root := resolveRoot(t, pfs, ref)
	cr := pfs.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("ctl.txt"), Mode: 0o644}).(*pfslocal.CreateReply)
	pfs.call(&pfslocal.WriteRequest{Handle: cr.Handle, Data: []byte("ctl")})
	pfs.call(&pfslocal.CloseRequest{Handle: cr.Handle})

	var verdict struct {
		Degraded       bool  `json:"degraded"`
		PendingRecords int   `json:"pendingRecords"`
		PendingBytes   int64 `json:"pendingBytes"`
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/sync", nil, http.StatusOK, &verdict)
	if verdict.Degraded {
		t.Fatalf("healthy drain reported degraded: %+v", verdict)
	}
	if verdict.PendingRecords != 0 || verdict.PendingBytes != 0 {
		t.Fatalf("drain left a backlog: %+v", verdict)
	}
}
