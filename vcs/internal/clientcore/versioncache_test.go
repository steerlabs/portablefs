package clientcore

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestVersionCacheApplyMonotonicAndGen(t *testing.T) {
	vc := NewVersionCache()
	const g = 42
	vc.RefreshAll(g)

	if !vc.FillOK(g, "p", 5) {
		t.Fatal("first fill must succeed")
	}
	if vc.Apply(g, "p", 5) {
		t.Fatal("an invalidation at an already-held version must not evict")
	}
	if !vc.Apply(g, "p", 6) {
		t.Fatal("an invalidation newer than held must evict")
	}
	if vc.FillOK(g, "p", 5) {
		t.Fatal("monotonic fill must reject installing a version older than held")
	}
	if !vc.FillOK(g, "p", 7) {
		t.Fatal("a newer fill must succeed")
	}
	if vc.Apply(99, "p", 1000) {
		t.Fatal("apply under a foreign generation must be a no-op")
	}
	if vc.FillOK(99, "p", 1000) {
		t.Fatal("fill under a foreign generation must be a no-op")
	}
	if !vc.SeenGen(g) || vc.SeenGen(99) {
		t.Fatal("generation tracking wrong before refresh")
	}
	vc.RefreshAll(99)
	if !vc.FillOK(99, "p", 1) {
		t.Fatal("after a generation change a low version installs")
	}
}

func TestVersionCachePrefixFenceRejectsLateReadAndInvalidation(t *testing.T) {
	vc := NewVersionCache()
	const g = 42
	vc.RefreshAll(g)
	if !vc.FillOK(g, "d/f", 5) {
		t.Fatal("seed fill")
	}
	late := vc.CaptureToken()
	vc.FencePrefix("d")
	if gotGen, gotVersion := vc.GenAndVersion("d/f"); gotGen != g || gotVersion != 0 {
		t.Fatalf("fenced version = (%d,%d), want (%d,0)", gotGen, gotVersion, g)
	}
	if vc.Apply(g, "d/f", 5) || vc.Apply(g, "d/f", 4) {
		t.Fatal("equal/older delayed invalidation crossed prefix fence")
	}
	if !vc.Apply(g, "d/f", 6) {
		t.Fatal("newer delayed invalidation did not advance retained floor")
	}
	if _, gotVersion := vc.GenAndVersion("d/f"); gotVersion != 0 {
		t.Fatalf("newer delayed invalidation validated fence at version %d", gotVersion)
	}
	if vc.FillOKToken(late, g, "d/f", 5) {
		t.Fatal("late read response crossed prefix fence")
	}
	current := vc.CaptureToken()
	if !vc.FillOKToken(current, g, "d/f", 7) {
		t.Fatal("post-fence read could not validate fresh version")
	}
	if _, got := vc.GenAndVersion("d/f"); got != 7 {
		t.Fatalf("validated version = %d, want 7", got)
	}
}

func TestVersionCacheGenerationTokenCannotFlipNonceBack(t *testing.T) {
	vc := NewVersionCache()
	vc.RefreshAll(11)
	oldRequest := vc.CaptureToken()
	newRequest := vc.CaptureToken()
	newRequest, ok := vc.AcceptGeneration(newRequest, 22)
	if !ok || !vc.FillOKToken(newRequest, 22, "p", 1) {
		t.Fatal("current response could not adopt new generation")
	}
	if _, ok := vc.AcceptGeneration(oldRequest, 11); ok {
		t.Fatal("late old-generation response flipped nonce back")
	}
	if !vc.SeenGen(22) {
		t.Fatal("new generation anchor was lost")
	}
}

func TestVersionCachePublishIsAtomicWithPrefixFence(t *testing.T) {
	vc := NewVersionCache()
	vc.RefreshAll(7)
	token := vc.CaptureToken()
	publishEntered := make(chan struct{})
	releasePublish := make(chan struct{})
	publishDone := make(chan struct{})
	go func() {
		vc.PublishOKToken(token, 7, "d/f", 1, func() {
			close(publishEntered)
			<-releasePublish
		})
		close(publishDone)
	}()
	<-publishEntered
	fenceDone := make(chan struct{})
	go func() {
		vc.FencePrefix("d")
		close(fenceDone)
	}()
	select {
	case <-fenceDone:
		t.Fatal("prefix fence crossed an in-progress cache publication")
	case <-time.After(20 * time.Millisecond):
	}
	close(releasePublish)
	<-publishDone
	<-fenceDone
	if _, version := vc.GenAndVersion("d/f"); version != 0 {
		t.Fatalf("published version remained reachable after fence: %d", version)
	}
}

func TestVersionCacheDirectoryPublishIsAtomicWithChildFence(t *testing.T) {
	vc := NewVersionCache()
	vc.RefreshAll(7)
	token := vc.CaptureToken()
	publishEntered := make(chan struct{})
	releasePublish := make(chan struct{})
	publishDone := make(chan struct{})
	go func() {
		vc.PublishDirectoryOKToken(token, 7, 1, "d", func() {
			close(publishEntered)
			<-releasePublish
		})
		close(publishDone)
	}()
	<-publishEntered
	fenceDone := make(chan struct{})
	go func() {
		vc.FencePrefix("d/f")
		close(fenceDone)
	}()
	select {
	case <-fenceDone:
		t.Fatal("child fence crossed an in-progress directory publication")
	case <-time.After(20 * time.Millisecond):
	}
	close(releasePublish)
	<-publishDone
	<-fenceDone
	if vc.TokenCurrent(token, 7, "d/f") {
		t.Fatal("pre-fence directory token remained valid for child")
	}
}

func TestVersionCachePrefixHistoryIsBounded(t *testing.T) {
	vc := NewVersionCache()
	for i := 0; i <= maxPrefixFences; i++ {
		vc.FencePrefix(fmt.Sprintf("scope-%d", i))
	}
	vc.mu.RLock()
	count := len(vc.fences)
	rootFence := vc.fences[""]
	vc.mu.RUnlock()
	if count > maxPrefixFences || rootFence == 0 {
		t.Fatalf("fence compaction = count %d root %d", count, rootFence)
	}
}

func TestSharedVolumeReadAdmissionAddsNoAllocations(t *testing.T) {
	v := &Volume{VersionCache: NewVersionCache()}
	ctx := context.Background()
	allocs := testing.AllocsPerRun(1000, func() {
		view, err := v.beginRead(ctx, "shared/file")
		if err != nil {
			panic(err)
		}
		view.Close()
	})
	if allocs != 0 {
		t.Fatalf("shared Volume beginRead allocations = %v, want 0", allocs)
	}
}

func TestMutationGenerationMismatchResetsInsteadOfRollingBack(t *testing.T) {
	v := &Volume{
		VersionCache: NewVersionCache(),
		AttrCache:    NewAttrCache(),
		dirCache:     map[string]dirCacheEntry{},
	}
	v.VersionCache.RefreshAll(22)
	v.noteSelfMutation("p", 11, 9, true)
	if got := v.VersionCache.CurrentGen(); got != 0 {
		t.Fatalf("delayed mutation response re-anchored generation %d, want unknown", got)
	}
}
