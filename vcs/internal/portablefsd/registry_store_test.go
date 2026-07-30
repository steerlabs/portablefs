package portablefsd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
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

func TestPersistedUnrepresentableItemBlocksRegistryStartup(t *testing.T) {
	stateDir := privateTestDir(t)
	invalid := persistedAttachEntry{
		Ref:                "att_XXXXXXXXXXXXXXXXXXXXXX",
		VolumeID:           "vol-invalid-item",
		Branch:             "main",
		MountPath:          "/Volumes/InvalidItem",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		IdentityEpoch:      7,
		Items: []persistedItemRecord{{
			Path: "", ItemID: ^uint64(0), ItemGeneration: 7, AuthorityIno: true,
		}},
	}
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{invalid}); err == nil {
		t.Fatal("persistence accepted an unrepresentable item")
	}
	body := []byte(`{
	  "version": 2,
	  "attaches": [{
	    "ref": "att_XXXXXXXXXXXXXXXXXXXXXX",
	    "volumeId": "vol-invalid-item",
	    "branch": "main",
	    "mountPath": "/Volumes/InvalidItem",
	    "authorityUrl": "127.0.0.1:1",
	    "dataPlaneTransport": "plaintext",
	    "options": {},
	    "identityEpoch": 7,
	    "items": [{
	      "path": "",
	      "itemId": 18446744073709551615,
	      "itemGeneration": 7,
	      "authorityIno": true
	    }]
	  }]
	}`)
	if err := privatepath.WriteFileAtomic(attachRegistryPath(stateDir), body); err != nil {
		t.Fatal(err)
	}
	registry := newRegistry(stateDir)
	t.Cleanup(registry.stopPersister)
	if registry.loadErr == nil || !strings.Contains(registry.loadErr.Error(), "unrepresentable itemId") {
		t.Fatalf("load error = %v, want unrepresentable item refusal", registry.loadErr)
	}
}

func TestRuntimeRegistrationRejectsUnrepresentableAuthorityItem(t *testing.T) {
	a := newAttach("att_runtime_item", "key", ensureAttachRequest{
		VolumeID: "vol-runtime-item", Branch: "main", MountPath: "/Volumes/RuntimeItem",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))
	valid := a.registerLocked("same", fsproto.Attr{Ino: 41, Kind: "file", Size: 3})
	if valid == nil {
		t.Fatal("valid item registration failed")
	}
	if got := a.registerLocked("same", fsproto.Attr{Ino: ^uint64(0), Kind: "file", Size: 9}); got != nil {
		t.Fatalf("unrepresentable item registered: %+v", got)
	}
	if got := a.paths["same"]; got != valid || got.attr.Size != 3 {
		t.Fatalf("rejected registration mutated existing identity: %+v", got)
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
	alias := a.registerLocked("d/alias", fsproto.Attr{Ino: 456, Kind: "file"})
	if alias.item != rec.item || alias.state != rec.state {
		t.Fatalf("restored authority index split alias: source=%+v alias=%+v", rec, alias)
	}
	a.renamePathLocked("d/alias", "d/moved")
	if moved := a.paths["d/moved"]; moved == nil || moved.item != rec.item || moved.state != rec.state {
		t.Fatalf("rename changed canonical authority identity: source=%+v moved=%+v", rec, moved)
	}
	a.removePathLocked("d/source")
	identity, ok := a.authorityItems[456]
	if !ok || identity.item != rec.item || identity.state != rec.state {
		t.Fatalf("removing one alias dropped live authority identity: %+v", identity)
	}
	a.removePathLocked("d/moved")
	if identity, ok := a.authorityItems[456]; !ok ||
		identity.item != rec.item || identity.state != rec.state {
		t.Fatalf("removing final alias dropped published identity before reclaim: %+v ok=%v",
			identity, ok)
	}

	// Restore once more for the persistence round-trip assertion below.
	a.restoreItemsLocked(loaded[0].Items)
	persisted := a.persistedItemsLocked()
	if len(persisted) != 1 || persisted[0].AuthorityItemID != 456 {
		t.Fatalf("re-persisted promoted binding=%+v", persisted)
	}
	rebound := a.registerLocked("d/source", fsproto.Attr{Ino: 789, Kind: "file"})
	if identity, ok := a.authorityItems[456]; !ok ||
		identity.item != rec.item || identity.state != rec.state {
		t.Fatalf("authority rebind dropped detached published identity: %+v ok=%v", identity, ok)
	}
	if identity, ok := a.authorityItems[789]; !ok ||
		identity.item != rebound.item || identity.state != rebound.state {
		t.Fatalf("authority rebind index=%+v ok=%v rebound=%+v", identity, ok, rebound)
	}
}

func TestRegisterReincarnatedHardLinkSplitsIdentityIndexes(t *testing.T) {
	a := newAttach("att_reincarnation", "key", ensureAttachRequest{
		VolumeID: "vol-reincarnation", Branch: "main",
		MountPath: "/Volumes/Reincarnation", AuthorityURL: "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))
	a.identityEpoch = 11

	old := a.registerLocked("a", fsproto.Attr{Ino: 41, Kind: "file", Nlink: 2, Size: 3})
	alias := a.registerLocked("b", fsproto.Attr{Ino: 41, Kind: "file", Nlink: 2, Size: 3})
	if alias.item != old.item || alias.state != old.state {
		t.Fatalf("initial hard links split identity: a=%+v b=%+v", old, alias)
	}
	oldHandle := a.newHandleLocked("a", old.item.ItemID, old.state, false)

	replacement := a.registerLocked("a", fsproto.Attr{Ino: 99, Kind: "file", Nlink: 1, Size: 7})
	if replacement.item == old.item || replacement.state == old.state {
		t.Fatalf("replacement reused old identity: old=%+v replacement=%+v", old, replacement)
	}
	if got := a.paths["a"]; got != replacement || got.state.AuthorityIno() != 99 {
		t.Fatalf("replacement path binding=%+v", got)
	}
	if got := a.paths["b"]; got != alias || got.item != old.item || got.state != old.state {
		t.Fatalf("surviving alias binding=%+v want old=%+v", got, old)
	}
	if got := a.items[old.item.ItemID]; got != alias {
		t.Fatalf("old canonical record=%+v want surviving alias=%+v", got, alias)
	}
	if got := a.items[replacement.item.ItemID]; got != replacement {
		t.Fatalf("replacement canonical record=%+v want=%+v", got, replacement)
	}
	if _, ok := a.itemAliases[old.item.ItemID]["b"]; !ok || len(a.itemAliases[old.item.ItemID]) != 1 {
		t.Fatalf("old aliases=%v want only b", a.itemAliases[old.item.ItemID])
	}
	if _, ok := a.itemAliases[replacement.item.ItemID]["a"]; !ok || len(a.itemAliases[replacement.item.ItemID]) != 1 {
		t.Fatalf("replacement aliases=%v want only a", a.itemAliases[replacement.item.ItemID])
	}
	if got := a.authorityItems[41]; got.item != old.item || got.state != old.state {
		t.Fatalf("old authority index=%+v want old identity", got)
	}
	if got := a.authorityItems[99]; got.item != replacement.item || got.state != replacement.state {
		t.Fatalf("replacement authority index=%+v want replacement identity", got)
	}
	if got := a.handles[oldHandle]; got == nil || got.itemID != old.item.ItemID || got.state != old.state {
		t.Fatalf("old handle changed identity: %+v", got)
	}

	persisted := a.persistedItemsLocked()
	if len(persisted) != 2 ||
		persisted[0].Path != "a" || persisted[0].ItemID != replacement.item.ItemID ||
		persisted[1].Path != "b" || persisted[1].ItemID != old.item.ItemID {
		t.Fatalf("persisted reincarnation bindings=%+v", persisted)
	}

	// With no surviving name, the detached old Item must remain addressable
	// until FSKit explicitly reclaims it, and reclaim must not touch the
	// replacement now bound to the same pathname.
	single := a.registerLocked("single", fsproto.Attr{Ino: 141, Kind: "file"})
	singleReplacement := a.registerLocked("single", fsproto.Attr{Ino: 199, Kind: "file"})
	if a.items[single.item.ItemID] != single {
		t.Fatalf("detached last-name item was retired before reclaim: %+v", a.items[single.item.ItemID])
	}
	if got := a.authorityItems[141]; got.item != single.item || got.state != single.state {
		t.Fatalf("detached item lost authority index before reclaim: %+v", got)
	}
	if _, eno := a.item(single.item); eno != darwinENOENT {
		t.Fatalf("detached item ordinary lookup errno=%d want ENOENT", eno)
	}
	discovered := a.registerLocked("peer-only-alias", fsproto.Attr{Ino: 141, Kind: "file"})
	if discovered.item != single.item || discovered.state != single.state {
		t.Fatalf("late hard-link discovery split detached identity: old=%+v discovered=%+v",
			single, discovered)
	}
	if a.items[single.item.ItemID] != discovered {
		t.Fatalf("late hard-link alias did not become canonical: got=%+v want=%+v",
			a.items[single.item.ItemID], discovered)
	}
	if got, eno := a.item(single.item); eno != 0 || got.path != "peer-only-alias" {
		t.Fatalf("promoted alias item lookup=%+v errno=%d", got, eno)
	}
	if eno := a.reclaim(&pfslocal.ReclaimRequest{Item: single.item}); eno != 0 {
		t.Fatalf("reclaim detached item errno=%d", eno)
	}
	if a.items[single.item.ItemID] != nil {
		t.Fatalf("reclaimed old item still indexed: %+v", a.items[single.item.ItemID])
	}
	if a.authorityItems[141].state != nil {
		t.Fatalf("reclaimed old authority identity still indexed: %+v", a.authorityItems[141])
	}
	if a.paths["single"] != singleReplacement || a.items[singleReplacement.item.ItemID] != singleReplacement {
		t.Fatalf("reclaim disturbed replacement: path=%+v item=%+v",
			a.paths["single"], a.items[singleReplacement.item.ItemID])
	}

	local := a.registerWithItemLocked(
		"local-only", fsproto.Attr{Kind: "file", Size: 4},
		localItemIDMarker|991, false, false, false,
	)
	a.removePathLocked("local-only")
	if a.paths["local-only"] != nil || a.items[local.item.ItemID] != local {
		t.Fatalf("local-only removed Item did not survive until reclaim: path=%+v item=%+v",
			a.paths["local-only"], a.items[local.item.ItemID])
	}
	if eno := a.reclaim(&pfslocal.ReclaimRequest{Item: local.item}); eno != 0 {
		t.Fatalf("reclaim local-only item errno=%d", eno)
	}
	if a.items[local.item.ItemID] != nil {
		t.Fatalf("reclaimed local-only item still indexed: %+v", a.items[local.item.ItemID])
	}
}

func TestDetachedIdentityPersistsAcrossDaemonRestartUntilReclaim(t *testing.T) {
	newTestAttach := func() *attach {
		a := newAttach("att_detached_restart", "key", ensureAttachRequest{
			VolumeID: "vol-detached-restart", Branch: "main",
			MountPath: "/Volumes/DetachedRestart",
		}, privateTestDir(t))
		a.identityEpoch = 17
		return a
	}

	original := newTestAttach()
	old := original.registerLocked(
		"replaced", fsproto.Attr{Ino: 701, Kind: "file", Size: 3},
	)
	original.removePathLocked("replaced")
	persisted := original.persistedItemsLocked()
	if len(persisted) != 1 || !persisted[0].Detached ||
		persisted[0].Kind != "file" || persisted[0].authorityItemID() != 701 {
		t.Fatalf("detached persisted record=%+v", persisted)
	}

	restarted := newTestAttach()
	restarted.restoreItemsLocked(persisted)
	if restarted.paths["replaced"] != nil {
		t.Fatalf("detached stale name restored as live: %+v", restarted.paths["replaced"])
	}
	retained := restarted.items[old.item.ItemID]
	if retained == nil || retained.item != old.item || retained.attr.Kind != "file" {
		t.Fatalf("detached Item not restored: %+v", retained)
	}
	if _, eno := restarted.item(old.item); eno != darwinENOENT {
		t.Fatalf("ordinary detached Item op errno=%d want ENOENT", eno)
	}
	late := restarted.registerLocked(
		"peer-only-link", fsproto.Attr{Ino: 701, Kind: "file", Size: 3},
	)
	if late.item != old.item || late.state != retained.state {
		t.Fatalf("post-restart peer alias split identity: retained=%+v late=%+v", retained, late)
	}
	if !restarted.reclaimItemLocked(old.item) {
		t.Fatal("explicit Reclaim did not retire restored Item")
	}
	if restarted.items[old.item.ItemID] != nil || restarted.authorityItems[701].state != nil {
		t.Fatalf("reclaimed restored identity survived: item=%+v authority=%+v",
			restarted.items[old.item.ItemID], restarted.authorityItems[701])
	}
}

func TestRestoreAndJournalReplayRepopulateAwaitingAuthorityItems(t *testing.T) {
	newTestAttach := func(ref string) *attach {
		a := newAttach(ref, "key", ensureAttachRequest{
			VolumeID: "vol-awaiting-restart", Branch: "main",
			MountPath: "/Volumes/AwaitingRestart",
		}, privateTestDir(t))
		a.identityEpoch = 19
		return a
	}
	const (
		persistedPending = localItemIDMarker | 101
		persistedAuth    = localItemIDMarker | 102
		persistedGraft   = localItemIDMarker | 103
		persistedGone    = localItemIDMarker | 104
		journalPending   = localItemIDMarker | 105
	)
	restored := newTestAttach("att-awaiting-state")
	restored.restoreItemsLocked([]persistedItemRecord{
		{Path: "d/pending", ItemID: persistedPending, ItemGeneration: 19, Kind: "file"},
		{
			Path: "d/assigned", ItemID: persistedAuth, ItemGeneration: 19,
			AuthorityIno: true, AuthorityItemID: 8002, Kind: "file",
		},
		{
			Path: "cache/local", ItemID: persistedGraft, ItemGeneration: 19,
			Kind: "file", Graft: true,
		},
		{
			Path: "d/detached", ItemID: persistedGone, ItemGeneration: 19,
			Kind: "file", Detached: true,
		},
	})
	if _, ok := restored.awaitingAuthorityItems[persistedPending]; !ok {
		t.Fatal("active authority-routed auth-zero state item was not restored awaiting")
	}
	for _, id := range []uint64{persistedAuth, persistedGraft, persistedGone} {
		if _, ok := restored.awaitingAuthorityItems[id]; ok {
			t.Fatalf("ineligible restored item %d entered awaiting set", id)
		}
	}

	replayed := newTestAttach("att-awaiting-journal")
	replayed.applyJournalEntry(bindingJournalEntry{
		Ref: replayed.ref, Op: "bind", Path: "d/replayed",
		ID: journalPending, Gen: 19, Kind: "file",
	})
	if _, ok := replayed.awaitingAuthorityItems[journalPending]; !ok {
		t.Fatal("active authority-routed auth-zero journal bind was not restored awaiting")
	}
}

func TestPreparedHandoffAssignsClosedPublishedIdentityBeforeCheckin(t *testing.T) {
	addr := serveAuthority(t)
	cli, err := fsproto.Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("closed-published-identity")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("exact session: %v", err)
	}
	if _, st, err := cli.Mkdir("w", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir w status=%d err=%v", st, err)
	}
	authorityAttr, st, err := cli.Create("w/closed", 0o644)
	if err != nil || st != fsproto.OK {
		t.Fatalf("create authority target status=%d err=%v", st, err)
	}
	grant, err := cli.DelegationAcquire("w", "wb-closed-published")
	if err != nil {
		t.Fatalf("delegation acquire: %v", err)
	}
	if !grant.Granted {
		t.Fatal("authority denied test delegation")
	}

	stateDir := privateTestDir(t)
	a := newAttach("att-closed-published", "key", ensureAttachRequest{
		VolumeID: "vol-closed-published", Branch: "main",
		MountPath: "/Volumes/ClosedPublished",
	}, stateDir)
	a.identityEpoch = 53
	a.journal = newBindingJournal(stateDir)
	rec := a.registerCreatedLocked("w/closed", fsproto.Attr{Kind: "file", Mode: 0o644})
	if len(a.handles) != 0 {
		t.Fatalf("test Item unexpectedly has an open handle: %+v", a.handles)
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		t.Fatalf("initial auth-zero binding errno=%d", eno)
	}
	end, err := a.persistAssignedAuthorityIdentities(
		context.Background(), "w", grant.Epoch, cli,
	)
	if err != nil {
		t.Fatalf("prepared identity boundary: %v", err)
	}
	if end == nil {
		t.Fatal("prepared identity boundary returned no pin retirement")
	}
	if got := rec.state.AuthorityIno(); got != authorityAttr.Ino {
		t.Fatalf("closed Item authority inode=%d want %d", got, authorityAttr.Ino)
	}
	if identity := a.authorityItems[authorityAttr.Ino]; identity.item != rec.item ||
		identity.state != rec.state {
		t.Fatalf("authority identity=%+v want Item=%+v", identity, rec.item)
	}
	if _, ok := a.awaitingAuthorityItems[rec.item.ItemID]; ok {
		t.Fatal("assigned closed Item remained in awaiting set")
	}
	var durable bool
	for _, entry := range loadBindingJournal(stateDir) {
		if entry.Op == "bind" && entry.ID == rec.item.ItemID &&
			entry.authorityItemID() == authorityAttr.Ino {
			durable = true
		}
	}
	if !durable {
		t.Fatal("assigned closed Item identity was not journaled before Checkin")
	}
	if err := cli.CheckinManaged("w", grant.Epoch); err != nil {
		t.Fatalf("checkin: %v", err)
	}
	end(true)
	if a.lastErr != "" {
		t.Fatalf("prepared pin retirement degraded attach: %s", a.lastErr)
	}
}

func TestDetachedJournalReplayAndReclaimTombstone(t *testing.T) {
	stateDir := privateTestDir(t)
	journal := newBindingJournal(stateDir)
	newTestAttach := func() *attach {
		a := newAttach("att_journal_lifetime", "key", ensureAttachRequest{
			VolumeID: "vol-journal-lifetime", Branch: "main",
			MountPath: "/Volumes/JournalLifetime",
		}, stateDir)
		a.identityEpoch = 23
		a.journal = journal
		return a
	}

	beforeCrash := newTestAttach()
	old := beforeCrash.registerLocked(
		"only-known-name", fsproto.Attr{Ino: 811, Kind: "file"},
	)
	if eno := beforeCrash.flushBindingDelta(); eno != 0 {
		t.Fatalf("bind journal errno=%d", eno)
	}
	beforeCrash.mu.Lock()
	beforeCrash.removePathLocked("only-known-name")
	beforeCrash.mu.Unlock()
	if eno := beforeCrash.flushBindingDelta(); eno != 0 {
		t.Fatalf("detach journal errno=%d", eno)
	}

	afterCrash := newTestAttach()
	for _, entry := range loadBindingJournal(stateDir) {
		afterCrash.applyJournalEntry(entry)
	}
	if afterCrash.paths["only-known-name"] != nil ||
		afterCrash.items[old.item.ItemID] == nil ||
		afterCrash.authorityItems[811].state == nil {
		t.Fatalf("journal replay lost detached identity: paths=%+v items=%+v authority=%+v",
			afterCrash.paths, afterCrash.items, afterCrash.authorityItems)
	}
	if eno := afterCrash.reclaim(&pfslocal.ReclaimRequest{Item: old.item}); eno != 0 {
		t.Fatalf("reclaim errno=%d", eno)
	}

	afterSecondCrash := newTestAttach()
	for _, entry := range loadBindingJournal(stateDir) {
		afterSecondCrash.applyJournalEntry(entry)
	}
	if afterSecondCrash.items[old.item.ItemID] != nil ||
		afterSecondCrash.authorityItems[811].state != nil {
		t.Fatalf("reclaim tombstone resurrected detached identity: item=%+v authority=%+v",
			afterSecondCrash.items[old.item.ItemID], afterSecondCrash.authorityItems[811])
	}
}

func TestBindingJournalFailureFailsCurrentPublicationClosed(t *testing.T) {
	for name, writer := range map[string]func([]byte) (int, error){
		"zero short write": func([]byte) (int, error) { return 0, nil },
		"disk full":        func([]byte) (int, error) { return 0, syscall.ENOSPC },
		"partial then full": func() func([]byte) (int, error) {
			first := true
			return func(p []byte) (int, error) {
				if first {
					first = false
					return len(p) / 2, nil
				}
				return 0, errors.New("injected terminal write failure")
			}
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			a := newAttach("att_journal_failure", "key", ensureAttachRequest{
				VolumeID: "vol-journal-failure", Branch: "main",
				MountPath: "/Volumes/JournalFailure",
			}, privateTestDir(t))
			a.identityEpoch = 29
			a.journal = &bindingJournal{testWrite: writer}
			a.registerLocked("published", fsproto.Attr{Ino: 901, Kind: "file"})
			if eno := a.flushBindingDelta(); eno != darwinEIO {
				t.Fatalf("flush errno=%d want EIO", eno)
			}
			if err := a.frontendAdmissionError(); err == nil {
				t.Fatal("journal failure did not fail-freeze later admissions")
			}
			if !strings.Contains(a.lastErr, "item identity journal failed closed") {
				t.Fatalf("failure detail=%q", a.lastErr)
			}
			if end, err := a.persistAssignedAuthorityIdentities(
				context.Background(), "d", "epoch", nil,
			); err == nil || end != nil {
				t.Fatalf("frozen identity journal allowed later Checkin boundary: hasEnd=%t err=%v", end != nil, err)
			}
		})
	}
}

func TestAttachRegistryCorruptionFailsClosed(t *testing.T) {
	validEntry := `{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol","branch":"main","mountPath":"/Volumes/Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}`
	for name, body := range map[string]string{
		"malformed":                 `{`,
		"unsupported zero":          `{"version":0,"attaches":[]}`,
		"unsupported future":        `{"version":3,"attaches":[]}`,
		"legacy omitted":            `{"version":1}`,
		"legacy null":               `{"version":1,"attaches":null}`,
		"legacy duplicate version":  `{"version":2,"version":1,"attaches":[]}`,
		"legacy duplicate attaches": `{"version":1,"attaches":[{}],"attaches":[]}`,
		"legacy unknown field":      `{"version":1,"attaches":[],"future":true}`,
		"legacy trailing json":      `{"version":1,"attaches":[]}{}`,
		"unknown field":             `{"version":2,"attaches":[],"future":true}`,
		"duplicate attach field":    `{"version":2,"attaches":[{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol","volumeId":"other","branch":"main","mountPath":"/Volumes/Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}]}`,
		"duplicate options field":   `{"version":2,"attaches":[{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol","branch":"main","mountPath":"/Volumes/Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{"diskCacheMb":1,"diskCacheMb":2},"identityEpoch":1}]}`,
		"invalid ref":               `{"version":2,"attaches":[{"ref":"att_bad","volumeId":"vol","branch":"main","mountPath":"/Volumes/Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}]}`,
		"invalid local dir":         `{"version":2,"attaches":[{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol","branch":"main","mountPath":"/Volumes/Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{"localDirs":["../escape"]},"identityEpoch":1}]}`,
		"noncanonical path":         `{"version":2,"attaches":[{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol","branch":"main","mountPath":"/Volumes/../Test","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}]}`,
		"duplicate branch":          `{"version":2,"attaches":[` + validEntry + `,{"ref":"att_BBBBBBBBBBBBBBBBBBBBBB","volumeId":"vol","branch":"main","mountPath":"/Volumes/Other","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}]}`,
		"trailing json":             `{"version":2,"attaches":[]}{}`,
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

func TestNonemptyLegacyAttachRegistryFailsClosed(t *testing.T) {
	stateDir := filepath.Join(privateTestDir(t), "state")
	body := []byte(`{
	  "version": 1,
	  "attaches": [{
	    "ref": "att_legacy",
	    "volumeId": "vol-legacy",
	    "branch": "main",
	    "mountPath": "/Volumes/Legacy",
	    "authorityUrl": "127.0.0.1:1",
	    "options": {}
	  }]
	}`)
	if err := privatepath.WriteFileAtomic(attachRegistryPath(stateDir), body); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPersistedAttaches(stateDir); err == nil ||
		!strings.Contains(err.Error(), "unsupported nonempty legacy version 1 inventory") {
		t.Fatalf("nonempty legacy registry error = %v, want explicit fail-closed refusal", err)
	}
}

func TestEmptyLegacyAttachRegistryIsReadOnlyCompatible(t *testing.T) {
	stateDir := filepath.Join(privateTestDir(t), "state")
	body := []byte("{\n  \"version\": 1,\n  \"attaches\": []\n}\n")
	path := attachRegistryPath(stateDir)
	if err := privatepath.WriteFileAtomic(path, body); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	registry := newRegistry(stateDir)
	if registry.loadErr != nil {
		t.Fatalf("empty legacy registry load error = %v", registry.loadErr)
	}
	if got := registry.list(); len(got) != 0 {
		t.Fatalf("loaded %d legacy attaches, want 0", len(got))
	}
	if err := registry.closeAll(context.Background()); err != nil {
		t.Fatalf("close empty legacy registry: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("empty legacy registry was silently replaced")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("empty legacy registry was rewritten:\n%s", got)
	}
}

func TestCurrentAttachRegistryVersionStillLoadsAndPersists(t *testing.T) {
	stateDir := privateTestDir(t)
	if err := writePersistedAttaches(stateDir, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPersistedAttaches(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Fatalf("loaded %d current attaches, want 0", len(loaded))
	}
	data, err := os.ReadFile(attachRegistryPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version": 2`) {
		t.Fatalf("current writer did not persist version 2:\n%s", data)
	}
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
