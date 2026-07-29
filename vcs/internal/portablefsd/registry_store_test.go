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
		Options:       AttachOptions{DiskCacheMB: 1},
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

func TestAttachRegistryPreservesPromotedAuthorityIdentity(t *testing.T) {
	stateDir := t.TempDir()
	entry := persistedAttachEntry{
		Ref:           "att_promoted",
		VolumeID:      "vol-promoted",
		Branch:        "main",
		MountPath:     "/Volumes/Promoted",
		AuthorityURL:  "127.0.0.1:1",
		Options:       AttachOptions{DiskCacheMB: 1},
		IdentityEpoch: 9,
		Items: []persistedItemRecord{{
			Path:            "d/source",
			ItemID:          localItemIDMarker | 123,
			ItemGeneration:  9,
			AuthorityIno:    true,
			AuthorityItemID: 456,
		}},
	}
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{entry}); err != nil {
		t.Fatal(err)
	}
	loaded := loadPersistedAttaches(stateDir)
	if len(loaded) != 1 || len(loaded[0].Items) != 1 {
		t.Fatalf("loaded=%+v", loaded)
	}
	item := loaded[0].Items[0]
	if item.ItemID != localItemIDMarker|123 || item.authorityItemID() != 456 {
		t.Fatalf("promoted item=%+v", item)
	}

	a := newAttach("att_promoted", "key", ensureAttachRequest{
		VolumeID: "vol-promoted", Branch: "main", MountPath: "/Volumes/Promoted",
		AuthorityURL: "127.0.0.1:1",
	}, stateDir)
	a.identityEpoch = 9
	a.restoreItemsLocked(loaded[0].Items)
	rec := a.paths["d/source"]
	if rec == nil || rec.state.StableIno() != localItemIDMarker|123 || rec.state.AuthorityIno() != 456 {
		t.Fatalf("restored promoted binding=%+v", rec)
	}
	persisted := a.persistedItemsLocked()
	if len(persisted) != 1 || persisted[0].AuthorityItemID != 456 {
		t.Fatalf("re-persisted promoted binding=%+v", persisted)
	}
}
