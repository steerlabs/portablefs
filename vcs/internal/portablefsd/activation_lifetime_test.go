package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func dirHasEntry(ents []clientcore.DirEntry, name string) bool {
	for _, e := range ents {
		if e.Name == name {
			return true
		}
	}
	return false
}

// TestAttachInvalidationsOutliveTheActivatingRequest pins the lifetime rule for
// everything attach starts in the background.
//
// `POST /v1/attaches/<ref>/credential` activates a restored (credential-pending)
// attach from an HTTP handler and used to hand that handler's r.Context() to
// clientcore.Dial and to the invalidation watcher. The handler returns the
// instant activation succeeds, so the mount lost its subscription to peer
// invalidations milliseconds after coming up — for the whole life of the mount,
// with nothing in the logs. Cross-machine coherence must be scoped to the
// attach, not to the request that happened to start it.
func TestAttachInvalidationsOutliveTheActivatingRequest(t *testing.T) {
	authority := serveAuthority(t)
	a := newAttach("att-activation-lifetime", "key", ensureAttachRequest{
		VolumeID:           "vol-activation-lifetime",
		Branch:             "main",
		MountPath:          "/Volumes/ActivationLifetime",
		AuthorityURL:       authority,
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))

	requestCtx, endRequest := context.WithCancel(context.Background())
	if err := a.start(requestCtx); err != nil {
		t.Fatalf("activate attach: %v", err)
	}
	t.Cleanup(func() { _, _ = a.detach(context.Background(), true) })
	// The control-plane response is written: the activating request is over.
	endRequest()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before, st := a.vol.Readdir(ctx, "")
	if st != fsproto.OK {
		t.Fatalf("pre-create readdir: %d", st)
	}
	if dirHasEntry(before, "sync") {
		t.Fatal("peer directory existed before the peer created it")
	}

	peer, err := fsproto.Dial(authority, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	peer.SetOwner("peer")
	if live, err := peer.EnsureExactSession(); err != nil || !live {
		t.Fatalf("peer exact session: live=%v err=%v", live, err)
	}
	if _, st, err := peer.Mkdir("sync", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("peer mkdir: status=%d err=%v", st, err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		ents, st := a.vol.Readdir(ctx, "")
		if st != fsproto.OK {
			t.Fatalf("post-create readdir: %d", st)
		}
		if dirHasEntry(ents, "sync") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("attach kept serving a stale root listing after the activating "+
				"request ended: %v", ents)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
