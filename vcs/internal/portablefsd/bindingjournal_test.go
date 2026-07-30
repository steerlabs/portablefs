package portablefsd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBindingJournalReplayAcrossRestart pins the delta-durability contract the
// journal provides between full-state persists: bindings minted, rekeyed, and
// unbound after the last compaction survive a daemon crash (the journal file
// outlives the process), while corrupt lines, stale generations, and escaping
// paths are discarded with the state file remaining authoritative.
func TestBindingJournalReplayAcrossRestart(t *testing.T) {
	stateDir := privateTestDir(t)
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{{
		Ref:                "att_CCCCCCCCCCCCCCCCCCCCCC",
		VolumeID:           "vol-j",
		Branch:             "main",
		MountPath:          "/Volumes/J",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		Options:            AttachOptions{DiskCacheMB: 1},
		IdentityEpoch:      7,
		Items: []persistedItemRecord{
			{Path: "", ItemID: 1, ItemGeneration: 7, AuthorityIno: true},
			{Path: "dir/old.txt", ItemID: 99, ItemGeneration: 7, AuthorityIno: true},
			{Path: "gone.txt", ItemID: 50, ItemGeneration: 7, AuthorityIno: true},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	// The journal a crashed process left behind: a fresh bind, a subtree
	// rekey, an unbind, then garbage that must not poison the replay — a
	// stale-generation bind, an escaping path, an unknown ref, and the torn
	// trailing line of a machine crash.
	journal := `{"ref":"att_CCCCCCCCCCCCCCCCCCCCCC","op":"bind","path":"dir/new.txt","id":123,"gen":7,"auth":true}
{"ref":"att_CCCCCCCCCCCCCCCCCCCCCC","op":"rekey","from":"dir","to":"dir2"}
{"ref":"att_CCCCCCCCCCCCCCCCCCCCCC","op":"unbind","path":"gone.txt"}
{"ref":"att_CCCCCCCCCCCCCCCCCCCCCC","op":"bind","path":"stale.txt","id":7,"gen":6}
{"ref":"att_CCCCCCCCCCCCCCCCCCCCCC","op":"bind","path":"../escape","id":8,"gen":7}
{"ref":"att_other","op":"bind","path":"x","id":9,"gen":7}
{"ref":"att_CCCCCCCCCCCCCCCCCCCCCC","op":"bind","pa`
	if err := os.WriteFile(filepath.Join(stateDir, bindingJournalName), []byte(journal), 0o600); err != nil {
		t.Fatal(err)
	}

	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	a := r.byRef["att_CCCCCCCCCCCCCCCCCCCCCC"]
	if a == nil {
		t.Fatal("attach not revived")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pendingBindings) != 0 {
		t.Fatalf("replay left %d pending deltas buffered; they are already durable", len(a.pendingBindings))
	}
	// The journaled bind survives, under its REKEYED path (replay is ordered).
	if rec := a.paths["dir2/new.txt"]; rec == nil || rec.item.ItemID != 123 || !rec.state.AuthIno() {
		t.Fatalf("journaled bind did not survive rekey: %+v", rec)
	}
	// The state-file item moved with the rekey and keeps its identity.
	if rec := a.paths["dir2/old.txt"]; rec == nil || rec.item.ItemID != 99 {
		t.Fatalf("rekey lost the persisted item: %+v", rec)
	}
	if a.paths["dir/old.txt"] != nil || a.paths["dir/new.txt"] != nil {
		t.Fatal("old paths still bound after rekey replay")
	}
	// The unbind dropped both indexes.
	if a.paths["gone.txt"] != nil || a.items[50] != nil {
		t.Fatal("unbound item survived replay")
	}
	// Garbage rejected: stale generation, escaping path, torn line.
	if a.paths["stale.txt"] != nil || a.items[8] != nil {
		t.Fatal("sanitize failed: stale-gen or escaping bind applied")
	}
	if a.root == nil || a.root.item.ItemID != 1 {
		t.Fatalf("root binding lost: %+v", a.root)
	}
}
