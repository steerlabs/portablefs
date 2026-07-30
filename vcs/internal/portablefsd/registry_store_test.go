package portablefsd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

func TestAttachRegistryPersistsItemIdentities(t *testing.T) {
	stateDir := privateTestDir(t)
	entries := []persistedAttachEntry{{
		Ref:                "att_AAAAAAAAAAAAAAAAAAAAAA",
		VolumeID:           "vol-identity",
		Branch:             "main",
		MountPath:          "/Volumes/Identity",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		Options:            AttachOptions{DiskCacheMB: 1},
		IdentityEpoch:      7,
		Items: []persistedItemRecord{
			{Path: "", ItemID: 1, ItemGeneration: 7, AuthorityIno: true},
			{Path: "dir/file.txt", ItemID: 99, ItemGeneration: 7, AuthorityIno: true},
			{Path: "dir/file2.txt", ItemID: 99, ItemGeneration: 7, AuthorityIno: true},
		},
	}}
	if err := writePersistedAttaches(stateDir, entries); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadPersistedAttaches(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d attaches, want 1", len(loaded))
	}
	got := loaded[0]
	if got.Ref != "att_AAAAAAAAAAAAAAAAAAAAAA" || got.IdentityEpoch != 7 {
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
	stateDir := privateTestDir(t)
	entry := persistedAttachEntry{
		Ref:                "att_BBBBBBBBBBBBBBBBBBBBBB",
		VolumeID:           "vol-promoted",
		Branch:             "main",
		MountPath:          "/Volumes/Promoted",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		Options:            AttachOptions{DiskCacheMB: 1},
		IdentityEpoch:      9,
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
	loaded, err := loadPersistedAttaches(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || len(loaded[0].Items) != 1 {
		t.Fatalf("loaded=%+v", loaded)
	}
	item := loaded[0].Items[0]
	if item.ItemID != localItemIDMarker|123 || item.authorityItemID() != 456 {
		t.Fatalf("promoted item=%+v", item)
	}

	a := newAttach("att_promoted", "key", ensureAttachRequest{
		VolumeID: "vol-promoted", Branch: "main", MountPath: "/Volumes/Promoted",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
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

func TestAttachRegistryCorruptionFailsClosed(t *testing.T) {
	validEntry := `{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol","branch":"main","mountPath":"/Volumes/Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}`
	for name, body := range map[string]string{
		"malformed":         `{`,
		"unsupported":       `{"version":999,"attaches":[]}`,
		"unknown field":     `{"version":2,"attaches":[],"future":true}`,
		"invalid ref":       `{"version":2,"attaches":[{"ref":"att_bad","volumeId":"vol","branch":"main","mountPath":"/Volumes/Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}]}`,
		"invalid local dir": `{"version":2,"attaches":[{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol","branch":"main","mountPath":"/Volumes/Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{"localDirs":["../escape"]},"identityEpoch":1}]}`,
		"noncanonical path": `{"version":2,"attaches":[{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol","branch":"main","mountPath":"/Volumes/../Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}]}`,
		"duplicate branch":  `{"version":2,"attaches":[` + validEntry + `,{"ref":"att_BBBBBBBBBBBBBBBBBBBBBB","volumeId":"vol","branch":"main","mountPath":"/Volumes/Other","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}]}`,
		"trailing json":     `{"version":2,"attaches":[]}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(privateTestDir(t), "state")
			if err := privatepath.WriteFileAtomic(attachRegistryPath(stateDir), []byte(body)); err != nil {
				t.Fatal(err)
			}
			if _, err := loadPersistedAttaches(stateDir); err == nil {
				t.Fatal("corrupt attach registry was treated as empty")
			}
		})
	}
	t.Run("unsafe file", func(t *testing.T) {
		stateDir := filepath.Join(privateTestDir(t), "state")
		if err := privatepath.EnsureDir(stateDir); err != nil {
			t.Fatal(err)
		}
		path := attachRegistryPath(stateDir)
		if err := os.WriteFile(path, []byte(`{"version":2,"attaches":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPersistedAttaches(stateDir); err == nil {
			t.Fatal("unsafe registry file was accepted")
		}
	})
}

func TestDeletePersistFailureRetainsRetryableDetachedRecord(t *testing.T) {
	stateDir := privateTestDir(t)
	const attachRef = "att_PPPPPPPPPPPPPPPPPPPPPP"
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{{
		Ref:                attachRef,
		VolumeID:           "vol-delete-retry",
		Branch:             "main",
		MountPath:          "/Volumes/DeleteRetry",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		IdentityEpoch:      1,
	}}); err != nil {
		t.Fatal(err)
	}
	registry := newRegistry(stateDir)
	t.Cleanup(registry.stopPersister)
	if registry.loadErr != nil {
		t.Fatal(registry.loadErr)
	}
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	found, _, err := registry.delete(context.Background(), attachRef, false)
	if !found || err == nil {
		t.Fatalf("delete = found %v err %v, want visible persist failure", found, err)
	}
	if registry.get(attachRef) == nil {
		t.Fatal("failed durable delete became a false 404")
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	found, _, err = registry.delete(context.Background(), attachRef, false)
	if !found || err != nil {
		t.Fatalf("retry delete = found %v err %v", found, err)
	}
	registry.stopPersister()

	restarted := newRegistry(stateDir)
	t.Cleanup(restarted.stopPersister)
	if restarted.loadErr != nil {
		t.Fatal(restarted.loadErr)
	}
	if got := restarted.list(); len(got) != 0 {
		t.Fatalf("deleted attach revived after restart: %+v", got)
	}
}

func TestRevivedLocalBackingFailureBlocksRegistryStartup(t *testing.T) {
	stateDir := privateTestDir(t)
	entry := persistedAttachEntry{
		Ref:                "att_LLLLLLLLLLLLLLLLLLLLLL",
		VolumeID:           "vol-local-backing",
		Branch:             "main",
		MountPath:          "/Volumes/LocalBacking",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		Options:            AttachOptions{LocalDirs: []string{"node_modules"}},
		IdentityEpoch:      1,
	}
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{entry}); err != nil {
		t.Fatal(err)
	}
	localParent := filepath.Join(stateDir, "local")
	if err := os.MkdirAll(localParent, 0o700); err != nil {
		t.Fatal(err)
	}
	localRoot := filepath.Join(localParent, stableStorageID(storageKey(entry.VolumeID, entry.Branch)))
	if err := os.WriteFile(localRoot, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := newRegistry(stateDir)
	t.Cleanup(registry.stopPersister)
	if registry.loadErr == nil || !strings.Contains(registry.loadErr.Error(), "local-dir backing") {
		t.Fatalf("load error = %v, want strict local backing refusal", registry.loadErr)
	}
}

func TestPersistedDormantAttachRequiresExplicitDetachBeforePathChange(t *testing.T) {
	stateDir := privateTestDir(t)
	const attachRef = "att_DDDDDDDDDDDDDDDDDDDDDD"
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{{
		Ref:                attachRef,
		VolumeID:           "vol-durable",
		Branch:             "main",
		MountPath:          "/Volumes/Original",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		IdentityEpoch:      1,
	}}); err != nil {
		t.Fatal(err)
	}
	registry := newRegistry(stateDir)
	t.Cleanup(registry.stopPersister)
	_, created, err := registry.ensure(context.Background(), ensureAttachRequest{
		AttachRef:          "att_NNNNNNNNNNNNNNNNNNNNNN",
		VolumeID:           "vol-durable",
		Branch:             "main",
		MountPath:          "/Volumes/New",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	})
	if err == nil || !strings.Contains(err.Error(), "detach that exact attach") {
		t.Fatalf("ensure error = %v, want explicit exact-detach refusal", err)
	}
	if created {
		t.Fatal("conflicting path unexpectedly created an attach")
	}
	attaches := registry.list()
	if len(attaches) != 1 || attaches[0].ref != attachRef || attaches[0].mountPath != "/Volumes/Original" {
		t.Fatalf("persisted ownership was changed: %+v", attaches)
	}
}
