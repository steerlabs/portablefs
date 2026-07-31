package portablefsd

// chflags(2) on a GRAFT. A graft's backing is a real host inode, so no
// authority feature bit is involved: the host filesystem is the durable store
// and chflags(2) on the backing file is the operation.

import (
	"context"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func graftAttachWithFile(t *testing.T, name string) (*attach, *itemRecord) {
	t.Helper()
	a := newAttach(name, "key", ensureAttachRequest{
		VolumeID: "vol-" + name, Branch: "main",
		MountPath: "/Volumes/" + name,
		Options:   AttachOptions{LocalDirs: []string{"cache"}},
	}, privateTestDir(t))
	if _, err := a.addLocalDirs([]string{"cache"}); err != nil {
		t.Fatal(err)
	}
	itemID, eno := a.writeLocalFile("cache/f", "cache", []byte("graft"))
	if eno != 0 {
		t.Fatalf("write graft errno=%d", eno)
	}
	a.mu.RLock()
	rec := a.items[itemID]
	a.mu.RUnlock()
	if rec == nil || !rec.graft {
		t.Fatalf("graft record = %+v", rec)
	}
	return a, rec
}

// TestGraftSetattrFlagsReachTheBackingFile: the change lands on the real host
// inode and is visible through the graft's own stat path, with no authority
// involved at all.
func TestGraftSetattrFlagsReachTheBackingFile(t *testing.T) {
	a, rec := graftAttachWithFile(t, "att-graft-flags")
	ctx := context.Background()

	want := uint32(unix.UF_HIDDEN | unix.UF_NODUMP)
	reply, eno := a.setattr(ctx, &pfslocal.SetAttrRequest{
		Item: rec.item, SetFlags: true, Flags: want,
	})
	if eno != 0 {
		t.Fatalf("graft chflags errno=%d", eno)
	}
	if reply.Attr.Flags != want {
		t.Fatalf("graft chflags reply flags = %#x, want %#x", reply.Attr.Flags, want)
	}
	attr, eno := a.statLocal("cache/f")
	if eno != 0 || attr.Flags != want {
		t.Fatalf("backing stat flags = %#x errno=%d, want %#x", attr.Flags, eno, want)
	}

	// mode + flags in one request both land on the backing file.
	mode := uint32(0o600)
	both, eno := a.setattr(ctx, &pfslocal.SetAttrRequest{
		Item: rec.item, Mode: &mode, SetFlags: true, Flags: uint32(unix.UF_NODUMP),
	})
	if eno != 0 {
		t.Fatalf("graft mode+flags errno=%d", eno)
	}
	if both.Attr.Flags != uint32(unix.UF_NODUMP) || both.Attr.Mode&0o777 != 0o600 {
		t.Fatalf("graft mode+flags attr = %+v", both.Attr)
	}

	// Clearing everything is a real state.
	cleared, eno := a.setattr(ctx, &pfslocal.SetAttrRequest{Item: rec.item, SetFlags: true})
	if eno != 0 || cleared.Attr.Flags != 0 {
		t.Fatalf("graft clear: attr=%+v errno=%d", cleared.Attr, eno)
	}
}

// TestGraftSetattrRefusesFlagsOutsideTheRepublishedMask: a bit the graft's stat
// path would never report back must be REFUSED, not written. Writing it would
// change host state the mount then denies having changed — and UF_COMPRESSED in
// particular would make the kernel run decmpfs over bytes PortableFS serves
// uncompressed.
func TestGraftSetattrRefusesFlagsOutsideTheRepublishedMask(t *testing.T) {
	a, rec := graftAttachWithFile(t, "att-graft-flags-mask")
	ctx := context.Background()

	for _, bit := range []uint32{
		uint32(unix.UF_COMPRESSED),
		uint32(unix.UF_TRACKED),
		uint32(unix.SF_RESTRICTED),
	} {
		if bit&graftFlagsMask != 0 {
			t.Fatalf("%#x is inside graftFlagsMask; pick a genuinely excluded bit", bit)
		}
		if _, eno := a.setattr(ctx, &pfslocal.SetAttrRequest{
			Item: rec.item, SetFlags: true, Flags: bit | uint32(unix.UF_HIDDEN),
		}); eno != darwinEINVAL {
			t.Fatalf("out-of-mask flag %#x errno=%d, want EINVAL", bit, eno)
		}
	}
	// And nothing landed — not even the in-mask bit that travelled with it.
	attr, eno := a.statLocal("cache/f")
	if eno != 0 || attr.Flags != 0 {
		t.Fatalf("a refused graft chflags stored %#x errno=%d", attr.Flags, eno)
	}
}

// TestGraftSetattrFlagsPreserveHostManagedBits: the request is authoritative
// over the republished subset only. Bits the backing volume set outside it
// survive, because this volume never owned them.
func TestGraftSetattrFlagsPreserveHostManagedBits(t *testing.T) {
	a, rec := graftAttachWithFile(t, "att-graft-flags-preserve")
	ctx := context.Background()

	backing := filepath.Join(a.localRoot, "cache", "f")
	const hostManaged = uint32(unix.UF_TRACKED)
	if err := unix.Chflags(backing, int(hostManaged)); err != nil {
		t.Skipf("cannot set a host-managed flag on this filesystem: %v", err)
	}

	if _, eno := a.setattr(ctx, &pfslocal.SetAttrRequest{
		Item: rec.item, SetFlags: true, Flags: uint32(unix.UF_HIDDEN),
	}); eno != 0 {
		t.Fatalf("graft chflags errno=%d", eno)
	}
	var st unix.Stat_t
	if err := unix.Lstat(backing, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&hostManaged == 0 {
		t.Fatalf("backing flags %#x lost the host-managed bit %#x", st.Flags, hostManaged)
	}
	if st.Flags&uint32(unix.UF_HIDDEN) == 0 {
		t.Fatalf("backing flags %#x missing the requested bit", st.Flags)
	}
	// The mount republishes only its own subset.
	attr, eno := a.statLocal("cache/f")
	if eno != 0 || attr.Flags != uint32(unix.UF_HIDDEN) {
		t.Fatalf("republished flags = %#x errno=%d, want %#x", attr.Flags, eno, uint32(unix.UF_HIDDEN))
	}
}
