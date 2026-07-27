package fsproto

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// serveManagedAuthority starts a managed (journal-native) authority over a real
// TCP listener and returns its address. Mirrors newManagedServer but served on
// a socket so a real *Client (which negotiates ServerManaged) can dial it.
func serveManagedAuthority(t *testing.T) string {
	t.Helper()
	addr, _ := serveManagedAuthorityFS(t)
	return addr
}

// TestWriteBackManagedCoordination proves the --fast fix at its root. Against a
// managed authority the LEGACY envelope-less checkout is refused with EPERM
// (the "checkout: status 1" that made --fast create-EIO and silently drop
// acked appends). The write-back path now routes through the managed
// coordination surface — CheckoutManaged returns a durable grant epoch,
// FlushBatchWriteBack applies the buffered create+write under that grant, the
// acked bytes are durable on the authority, and CheckinManaged releases it.
func TestWriteBackManagedCoordination(t *testing.T) {
	addr := serveManagedAuthority(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("M")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("establish exact session: %v", err)
	}
	if !cli.ServerManaged() {
		t.Fatal("expected a managed authority (ServerManaged=true)")
	}

	// The bug: the legacy envelope-less checkout write-back used before this fix
	// is categorically refused by a managed authority.
	if _, _, lerr := cli.Checkout("f.txt", "M"); lerr == nil {
		t.Fatal("legacy checkout unexpectedly succeeded against a managed authority (bug repro expected EPERM)")
	}

	// The fix: managed checkout grants a durable epoch (file-grain, since managed
	// refuses the volume-root "" checkout).
	granted, _, epoch, err := cli.CheckoutManaged("f.txt")
	if err != nil || !granted || epoch == "" {
		t.Fatalf("managed checkout: granted=%v epoch=%q err=%v", granted, epoch, err)
	}

	// Write-back flush of a create+write batch routes through the managed surface.
	through, st, err := cli.FlushBatchWriteBack("wb-1", 1, "M", "f.txt", epoch, []wal.Record{
		{Seq: 1, Op: wal.OpCreate, Path: "f.txt", Mode: 0o644},
		{Seq: 2, Op: wal.OpWrite, Path: "f.txt", Offset: 0, Data: []byte("hello-writeback")},
	})
	if err != nil || st != OK || through < 2 {
		t.Fatalf("managed write-back flush: through=%d st=%d err=%v", through, st, err)
	}

	// The acked write is durable on the authority (this is what --fast silently lost before).
	data, _, _, rst, err := cli.ReadV("f.txt", 0, 128)
	if err != nil || rst != OK || string(data) != "hello-writeback" {
		t.Fatalf("readback after managed flush: st=%d data=%q err=%v", rst, string(data), err)
	}

	if err := cli.CheckinManaged("f.txt", epoch); err != nil {
		t.Fatalf("managed checkin: %v", err)
	}
}
