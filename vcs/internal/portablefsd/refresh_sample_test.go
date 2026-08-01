package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestRefreshSampleStaleGuard pins the mid-race guard in refreshLocalSample: a
// coherence refresh must never install an authority sample that is OLDER
// than a version the daemon has already seen for the path (the simultaneous
// same-file write race: the raw getattr lands between the remote truncate
// and the local, echo-suppressed write, and clamping the kernel to that
// sample wedges it on a superseded state with no further event to correct
// it). Fresh samples pass, samples at the floor pass, samples below the
// floor make the refresh bail without touching the kernel.
func TestRefreshSampleStaleGuard(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	cli := vol.Client()
	if _, st, err := cli.Create("g.txt", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("create st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("g.txt", 0, []byte("hello"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("write st=%d err=%v", st, err)
	}
	if _, st, err := cli.Symlink("outside-target", "link"); err != nil || st != fsproto.OK {
		t.Fatalf("symlink st=%d err=%v", st, err)
	}
	if size, _, _, outcome := refreshLocalSample(vol, "link"); outcome != refreshSampleNonRegular {
		t.Fatalf("symlink sample = (%d, %v), want nonregular", size, outcome)
	}

	// Empty version-cache floor: any sample is acceptable.
	size, _, _, outcome := refreshLocalSample(vol, "g.txt")
	if outcome != refreshSampleReady || size != 5 {
		t.Fatalf("fresh sample = (%d, %v), want (5, ready)", size, outcome)
	}

	_, ver, gen, _, st, err := cli.GetattrV("g.txt")
	if err != nil || st != fsproto.OK {
		t.Fatalf("getattrv st=%d err=%v", st, err)
	}

	// Floor one version AHEAD of the authority (a self-write the sample has
	// not caught up with), then advance the authority past it: the sample
	// catches up within the retry loop and passes with the new size.
	vol.VersionCache.RefreshAll(gen)
	vol.VersionCache.FillOK(gen, "g.txt", ver+1)
	if _, st, err := cli.Write("g.txt", 5, []byte("+++"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("write st=%d err=%v", st, err)
	}
	size, _, _, outcome = refreshLocalSample(vol, "g.txt")
	if outcome != refreshSampleReady || size != 8 {
		t.Fatalf("caught-up sample = (%d, %v), want (8, ready)", size, outcome)
	}

	// Floor far ahead with the authority never catching up: the refresh must
	// bail after bounded retries rather than clamp the kernel to a size the
	// daemon has already superseded.
	vol.VersionCache.FillOK(gen, "g.txt", ver+100)
	if size, _, _, outcome = refreshLocalSample(vol, "g.txt"); outcome != refreshSampleRetry {
		t.Fatalf("stale sample = (%d, %v), want retry", size, outcome)
	}
}

func TestRefreshSampleTransportFailureIsRetryable(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := vol.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, outcome := refreshLocalSample(vol, "anything"); outcome != refreshSampleRetry {
		t.Fatalf("closed transport outcome = %v, want retry", outcome)
	}
}

func TestCoherenceSampleHonorsCanceledContext(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, _, _, st := vol.CoherenceSample(ctx, "anything"); st != fsproto.EIO {
		t.Fatalf("canceled CoherenceSample status=%d want EIO", st)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("canceled CoherenceSample took %v", elapsed)
	}
}

func TestRefreshSampleRejectsReplacementAuthorityInode(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	cli := vol.Client()
	old, st, err := cli.Create("old", 0o644)
	if err != nil || st != fsproto.OK {
		t.Fatalf("create old st=%d err=%v", st, err)
	}
	replacement, st, err := cli.Create("replacement", 0o644)
	if err != nil || st != fsproto.OK {
		t.Fatalf("create replacement st=%d err=%v", st, err)
	}
	if old.Ino == 0 || replacement.Ino == 0 || old.Ino == replacement.Ino {
		t.Fatalf("test authority identities old=%+v replacement=%+v", old, replacement)
	}

	if _, _, _, outcome := refreshLocalSampleAuthority(vol, "replacement", old.Ino); outcome != refreshSampleObsolete {
		t.Fatalf("replacement sample outcome=%v want obsolete", outcome)
	}

	applied := false
	item := pfslocal.Item{ItemID: 71, ItemGeneration: 1}
	state := clientcore.NewNodeState(old.Ino, true)
	rec := &itemRecord{
		item: item, path: "replacement", state: state,
		attr: fsproto.Attr{Ino: old.Ino, Kind: "file"},
	}
	a := &attach{
		vol:         vol,
		mountPath:   "/unused",
		items:       map[uint64]*itemRecord{item.ItemID: rec},
		paths:       map[string]*itemRecord{"replacement": rec},
		itemAliases: map[uint64]map[string]struct{}{item.ItemID: {"replacement": {}}},
	}
	a.testRefreshKernelFile = func(string, string, uint64, int64, func() (func(), error)) (kernelRefreshOutcome, error) {
		applied = true
		return kernelRefreshApplied, nil
	}
	if a.refreshKernelItemStateComposedMode(a.mountPath, item.ItemID, true) {
		t.Fatal("required old-inode refresh settled on replacement pathname")
	}
	if applied {
		t.Fatal("replacement inode size was applied to the old cached vnode")
	}
	if !a.refreshKernelItemStateComposedMode(a.mountPath, item.ItemID, false) {
		t.Fatal("ordinary namespace replacement did not settle as obsolete")
	}
	if applied {
		t.Fatal("ordinary obsolete refresh applied replacement inode size")
	}

	// A direct InPlace regular-file batch is also an exact inode claim. If a
	// later rename-over reaches this mount before the content batch is
	// sampled, ACK must remain blocked on the old Item rather than treating
	// the replacement name as an ordinary obsolete transition.
	stream := make(chan coherence.Batch, 1)
	acked := make(chan uint64, 1)
	done := make(chan struct{})
	go func() {
		a.forwardEvents(context.Background(), nil, stream, func(pos uint64) { acked <- pos })
		close(done)
	}()
	stream <- coherence.Batch{Pos: 51, Invs: []coherence.Invalidation{{
		Path: "replacement", InPlace: true, Version: 9,
	}}}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("direct stale-identity refresh did not fail closed")
	}
	select {
	case pos := <-acked:
		t.Fatalf("direct stale-identity batch falsely acked position %d", pos)
	default:
	}
	if err := a.frontendAdmissionError(); err == nil {
		t.Fatal("direct stale-identity batch did not fail-freeze attach")
	}
	if applied {
		t.Fatal("direct stale-identity batch applied replacement size")
	}
}
