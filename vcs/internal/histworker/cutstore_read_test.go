package histworker

import (
	"context"
	"testing"
)

func TestPreferredReadableCopyUsesConfiguredLocalityOrder(t *testing.T) {
	stores, err := NewDomainStores(
		staticStore{domain: "local"},
		staticStore{domain: "remote"},
	)
	if err != nil {
		t.Fatal(err)
	}
	store := newCutStore(context.Background(), newFakeRepo(nil), stores, CutClaim{}, Config{
		UploadConcurrency:     1,
		MaxPendingUploadBytes: 1,
		MaxCacheBytes:         1,
	})
	// The database projection is freshness-ordered and therefore deliberately
	// presents the remote receipt first. Worker locality order must win.
	copyRec, selected, ok := store.preferredReadableCopy([]CopyRecord{
		{FailureDomain: "remote", StorageKey: "remote-key", LastVerified: 200},
		{FailureDomain: "local", StorageKey: "local-key", LastVerified: 100},
	})
	if !ok {
		t.Fatal("preferred copy was not selected")
	}
	if copyRec.FailureDomain != "local" || copyRec.StorageKey != "local-key" {
		t.Fatalf("selected %+v, want local copy", copyRec)
	}
	if selected.Domain() != "local" {
		t.Fatalf("selected store %q, want local", selected.Domain())
	}
}

func TestPreferredReadableCopyDoesNotInventAnUnrecordedDomain(t *testing.T) {
	stores, err := NewDomainStores(staticStore{domain: "local"})
	if err != nil {
		t.Fatal(err)
	}
	store := newCutStore(context.Background(), newFakeRepo(nil), stores, CutClaim{}, Config{
		UploadConcurrency:     1,
		MaxPendingUploadBytes: 1,
		MaxCacheBytes:         1,
	})
	if _, _, ok := store.preferredReadableCopy([]CopyRecord{{
		FailureDomain: "remote",
		StorageKey:    "remote-key",
	}}); ok {
		t.Fatal("selected a copy from an unconfigured domain")
	}
}
