package portablefsd

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestRefreshSampleStaleGuard pins the mid-race guard in refreshSample: a
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
	if size, _, ok := refreshSample(vol, "link"); ok {
		t.Fatalf("symlink sample passed = (%d, %v), want bail", size, ok)
	}

	// Empty version-cache floor: any sample is acceptable.
	size, _, ok := refreshSample(vol, "g.txt")
	if !ok || size != 5 {
		t.Fatalf("fresh sample = (%d, %v), want (5, true)", size, ok)
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
	size, _, ok = refreshSample(vol, "g.txt")
	if !ok || size != 8 {
		t.Fatalf("caught-up sample = (%d, %v), want (8, true)", size, ok)
	}

	// Floor far ahead with the authority never catching up: the refresh must
	// bail after bounded retries rather than clamp the kernel to a size the
	// daemon has already superseded.
	vol.VersionCache.FillOK(gen, "g.txt", ver+100)
	if size, _, ok = refreshSample(vol, "g.txt"); ok {
		t.Fatalf("stale sample passed = (%d, %v), want bail", size, ok)
	}
}
