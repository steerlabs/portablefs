package portablefsd

import "testing"

func TestAttachRegistryPersistsItemIdentities(t *testing.T) {
	stateDir := t.TempDir()
	entries := []persistedAttachEntry{{
		Ref:           "att_identity",
		VolumeID:      "vol-identity",
		Branch:        "main",
		MountPath:     "/Volumes/Identity",
		AuthorityURL:  "127.0.0.1:1",
		Options:       AttachOptions{WritePolicy: "writethrough", FsyncPolicy: "local", DiskCacheMB: 1},
		IdentityEpoch: 7,
		Items: []persistedItemRecord{
			{Path: "", ItemID: 1, ItemGeneration: 7, AuthorityIno: true},
			{Path: "dir/file.txt", ItemID: 99, ItemGeneration: 7, AuthorityIno: true},
			{Path: "dir/file2.txt", ItemID: 99, ItemGeneration: 7, AuthorityIno: true},
			{Path: "zero-id", ItemID: 0, ItemGeneration: 7},
			{Path: "stale-generation", ItemID: 100, ItemGeneration: 6},
			{Path: "dir/duplicate-id", ItemID: 99, ItemGeneration: 7},
			{Path: "./dir/../dir/file.txt", ItemID: 101, ItemGeneration: 7},
		},
	}}
	if err := writePersistedAttaches(stateDir, entries); err != nil {
		t.Fatal(err)
	}

	loaded := loadPersistedAttaches(stateDir)
	if len(loaded) != 1 {
		t.Fatalf("loaded %d attaches, want 1", len(loaded))
	}
	got := loaded[0]
	if got.Ref != "att_identity" || got.IdentityEpoch != 7 {
		t.Fatalf("loaded attach = %+v", got)
	}
	if len(got.Items) != 3 {
		t.Fatalf("loaded %d items, want 3: %+v", len(got.Items), got.Items)
	}
	if got.Items[0] != (persistedItemRecord{Path: "", ItemID: 1, ItemGeneration: 7, AuthorityIno: true}) {
		t.Fatalf("root item = %+v", got.Items[0])
	}
	if got.Items[1] != (persistedItemRecord{Path: "dir/file.txt", ItemID: 99, ItemGeneration: 7, AuthorityIno: true}) {
		t.Fatalf("file item = %+v", got.Items[1])
	}
	if got.Items[2] != (persistedItemRecord{Path: "dir/file2.txt", ItemID: 99, ItemGeneration: 7, AuthorityIno: true}) {
		t.Fatalf("hardlink alias item = %+v", got.Items[2])
	}
}
