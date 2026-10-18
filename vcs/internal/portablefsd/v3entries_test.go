package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// readDirPages serves each ReadDir call from the next page and records the
// requests it saw.
func readDirPages(pages ...*authoritypb.ReadDirReply) (func(context.Context, authorityrpc.MutationIdentity, *authoritypb.Request) (*authoritypb.Response, error), *[]*authoritypb.ReadDirRequest) {
	var seen []*authoritypb.ReadDirRequest
	return func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetReadDir() == nil {
			return nil, errors.New("enumeration sent a non-ReadDir authority request")
		}
		seen = append(seen, request.GetReadDir())
		if len(pages) == 0 {
			return nil, errors.New("no more test pages")
		}
		response := exactTestMutationReply(identity)
		response.Body = &authoritypb.Response_ReadDir{ReadDir: pages[0]}
		pages = pages[1:]
		return response, nil
	}, &seen
}

func enumerateTestRoot(t *testing.T, d *v3DataPlane) (pfslocal.Item, uint64) {
	t.Helper()
	root := d.resolveReply().Root
	handle, err := d.installHandle(bytes.Repeat([]byte{0x7d}, 16), root, false)
	if err != nil {
		t.Fatal(err)
	}
	return root, handle.id
}

func TestV3EnumerateEntriesRequestsNoItemsAndRetainsNothing(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root, handle := enumerateTestRoot(t, d)
	mutation, seen := readDirPages(&authoritypb.ReadDirReply{
		Verifier: bytes.Repeat([]byte{0x71}, 16), Eof: true,
		Entries: []*authoritypb.Dirent{
			testV3Dirent("file", 10, authoritypb.Attr_REGULAR, 0x91, 1),
			{Name: []byte("fifo"), Attr: &authoritypb.Attr{Inode: 11}, NextCookie: []byte{2}},
			testV3Dirent("dir", 12, authoritypb.Attr_DIRECTORY, 0x92, 3),
			testV3Dirent("link", 13, authoritypb.Attr_SYMLINK, 0x93, 4),
		},
	})
	client.mutation = mutation
	replyAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.EnumerateEntriesRequest{
		Dir: root, Handle: handle, MaxEntries: 16, WantAttrs: true,
	})
	if errno != 0 {
		t.Fatalf("enumerate errno=%d", errno)
	}
	if len(*seen) != 1 || (*seen)[0].GetWantItems() || len((*seen)[0].GetHeldIdentities()) != 0 {
		t.Fatalf("ReadDir requests = %v, want one request for no Items", *seen)
	}
	reply := replyAny.(*pfslocal.EnumerateEntriesReply)
	want := []struct {
		name   string
		kind   pfslocal.ItemKind
		fileID uint64
	}{
		{name: "file", kind: pfslocal.ItemKindFile, fileID: 10},
		{name: "dir", kind: pfslocal.ItemKindDirectory, fileID: 12},
		{name: "link", kind: pfslocal.ItemKindSymlink, fileID: 13},
	}
	if len(reply.Entries) != len(want) {
		t.Fatalf("entries = %+v, want the opaque name skipped", reply.Entries)
	}
	for index, entry := range reply.Entries {
		if string(entry.Name) != want[index].name || entry.Attr.Kind != want[index].kind ||
			entry.Attr.FileID != want[index].fileID || entry.Attr.ParentFileID != v3RootFileID ||
			entry.Attr.Item != (pfslocal.Item{}) || entry.Attr.Parent != nil ||
			entry.Attr.Mode != 0o644 || entry.Attr.Size != 3 || entry.Attr.UID != 501 {
			t.Fatalf("entry[%d] = %+v, want a non-owning snapshot of %+v", index, entry, want[index])
		}
	}
	if reply.Entries[2].Cookie != 0 || reply.NextCookie != 0 {
		t.Fatalf("EOF cookies = %+v", reply)
	}
	d.mu.Lock()
	records := len(d.itemsByID)
	d.mu.Unlock()
	if records != 1 || len(client.reclaimBatches()) != 0 || client.liveTokens() != 1 {
		t.Fatalf("enumeration retained records=%d reclaims=%d live=%d, want nothing", records, len(client.reclaimBatches()), client.liveTokens())
	}
	if bearing, err := resourceBearingV3Reply(reply, &v3ReplyResourceCollector{d: d}); bearing || err != nil {
		t.Fatalf("entries reply resource contract = (%t,%v), want no disposition", bearing, err)
	}
}

func TestV3EnumerateEntriesCarriesFullAttrsOnlyWhenRequested(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root, handle := enumerateTestRoot(t, d)
	client.mutation, _ = readDirPages(&authoritypb.ReadDirReply{
		Verifier: bytes.Repeat([]byte{0x72}, 16), Eof: true,
		Entries: []*authoritypb.Dirent{testV3Dirent("file", 10, authoritypb.Attr_REGULAR, 0x91, 1)},
	})
	replyAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.EnumerateEntriesRequest{
		Dir: root, Handle: handle, MaxEntries: 16,
	})
	if errno != 0 {
		t.Fatalf("enumerate errno=%d", errno)
	}
	want := pfslocal.Attr{Kind: pfslocal.ItemKindFile, FileID: 10, ParentFileID: v3RootFileID}
	if entries := replyAny.(*pfslocal.EnumerateEntriesReply).Entries; len(entries) != 1 || entries[0].Attr != want {
		t.Fatalf("entries without want_attrs = %+v, want only %+v", entries, want)
	}
}

func TestV3EnumerateEntriesListsHardLinksUnderOneFileID(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root, handle := enumerateTestRoot(t, d)
	client.mutation, _ = readDirPages(&authoritypb.ReadDirReply{
		Verifier: bytes.Repeat([]byte{0x73}, 16), Eof: true,
		Entries: []*authoritypb.Dirent{
			testV3Dirent("a", 10, authoritypb.Attr_REGULAR, 0x91, 1),
			testV3Dirent("b", 10, authoritypb.Attr_REGULAR, 0x91, 2),
		},
	})
	replyAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.EnumerateEntriesRequest{
		Dir: root, Handle: handle, MaxEntries: 16,
	})
	entries := replyAny.(*pfslocal.EnumerateEntriesReply).Entries
	if errno != 0 || len(entries) != 2 || entries[0].Attr.FileID != 10 || entries[1].Attr.FileID != 10 {
		t.Fatalf("hard-link entries = (%+v,%d), want two names for file ID 10", entries, errno)
	}
}

// A packer that accepts only a prefix resumes from the last cookie it packed.
// That cookie must address the authority position after that exact entry,
// not the last entry the daemon fetched.
func TestV3EnumerateEntriesResumesFromAPackerPrefix(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root, handle := enumerateTestRoot(t, d)
	verifier := bytes.Repeat([]byte{0x74}, 16)
	mutation, seen := readDirPages(
		&authoritypb.ReadDirReply{Verifier: verifier, Entries: []*authoritypb.Dirent{
			testV3Dirent("a", 10, authoritypb.Attr_REGULAR, 0x91, 1),
			testV3Dirent("b", 11, authoritypb.Attr_REGULAR, 0x92, 2),
			testV3Dirent("c", 12, authoritypb.Attr_REGULAR, 0x93, 3),
		}},
		&authoritypb.ReadDirReply{Verifier: verifier, Eof: true, Entries: []*authoritypb.Dirent{
			testV3Dirent("b", 11, authoritypb.Attr_REGULAR, 0x92, 2),
			testV3Dirent("c", 12, authoritypb.Attr_REGULAR, 0x93, 3),
		}},
	)
	client.mutation = mutation
	firstAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.EnumerateEntriesRequest{Dir: root, Handle: handle, MaxEntries: 3})
	if errno != 0 {
		t.Fatalf("first page errno=%d", errno)
	}
	first := firstAny.(*pfslocal.EnumerateEntriesReply)
	if len(first.Entries) != 3 || first.NextCookie != first.Entries[2].Cookie || first.NextCookie == 0 {
		t.Fatalf("first page = %+v, want a non-terminal page", first)
	}
	secondAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.EnumerateEntriesRequest{
		Dir: root, Handle: handle, MaxEntries: 3, Cookie: first.Entries[0].Cookie,
	})
	if errno != 0 {
		t.Fatalf("prefix resume errno=%d", errno)
	}
	if len(*seen) != 2 || !bytes.Equal((*seen)[1].GetCookie(), []byte{1}) || !bytes.Equal((*seen)[1].GetVerifier(), verifier) {
		t.Fatalf("resume ReadDir = %+v, want the position after the packed entry", (*seen)[1])
	}
	second := secondAny.(*pfslocal.EnumerateEntriesReply)
	if len(second.Entries) != 2 || string(second.Entries[0].Name) != "b" || second.Entries[1].Cookie != 0 || second.NextCookie != 0 {
		t.Fatalf("resumed page = %+v", second)
	}
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.EnumerateEntriesRequest{
		Dir: root, Handle: handle, MaxEntries: 3, Cookie: 1<<63 + 1<<40,
	}); errno != darwinESTALE {
		t.Fatalf("unknown cookie errno=%d, want ESTALE", errno)
	}
}

func TestV3EnumerateEntriesRefusesMalformedEntries(t *testing.T) {
	for _, test := range []struct {
		name  string
		entry *authoritypb.Dirent
	}{
		{name: "unrequested-item", entry: func() *authoritypb.Dirent {
			entry := testV3Dirent("x", 10, authoritypb.Attr_REGULAR, 0x91, 1)
			entry.Item = authorityTestItem(10, authoritypb.Attr_REGULAR, 0x55, 0x91)
			return entry
		}()},
		{name: "short-identity", entry: func() *authoritypb.Dirent {
			entry := testV3Dirent("x", 10, authoritypb.Attr_REGULAR, 0x91, 1)
			entry.StableIdentity = entry.StableIdentity[:15]
			return entry
		}()},
		{name: "zero-identity", entry: func() *authoritypb.Dirent {
			entry := testV3Dirent("x", 10, authoritypb.Attr_REGULAR, 0x91, 1)
			entry.StableIdentity = make([]byte, 16)
			return entry
		}()},
		{name: "inode-out-of-range", entry: testV3Dirent("x", 1, authoritypb.Attr_REGULAR, 0x91, 1)},
		{name: "unknown-kind", entry: testV3Dirent("x", 10, authoritypb.Attr_KIND_UNSPECIFIED, 0x91, 1)},
		{name: "missing-cookie", entry: func() *authoritypb.Dirent {
			entry := testV3Dirent("x", 10, authoritypb.Attr_REGULAR, 0x91, 1)
			entry.NextCookie = nil
			return entry
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			root, handle := enumerateTestRoot(t, d)
			client.mutation, _ = readDirPages(&authoritypb.ReadDirReply{
				Verifier: bytes.Repeat([]byte{0x75}, 16), Eof: true, Entries: []*authoritypb.Dirent{test.entry},
			})
			if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.EnumerateEntriesRequest{
				Dir: root, Handle: handle, MaxEntries: 16,
			}); errno != darwinEIO || d.terminalError() == nil {
				t.Fatalf("malformed entry errno=%d, want terminal EIO", errno)
			}
		})
	}
}

// A snapshot carries no identity the frontend could check, so an entry that
// names a held identity (the root included) must keep that object's inode and
// kind; the daemon neither interns nor retains the entry either way.
func TestV3EnumerateEntriesHoldsHeldIdentitiesImmutable(t *testing.T) {
	for _, test := range []struct {
		name     string
		identity byte
		inode    uint64
		kind     authoritypb.Attr_Kind
		fileID   uint64
	}{
		{name: "held-unchanged", identity: 0x40, inode: 2, kind: authoritypb.Attr_REGULAR, fileID: 2},
		{name: "held-inode-changed", identity: 0x40, inode: 3, kind: authoritypb.Attr_REGULAR},
		{name: "held-kind-changed", identity: 0x40, inode: 2, kind: authoritypb.Attr_DIRECTORY},
		{name: "root-inode-changed", identity: 0x20, inode: 5, kind: authoritypb.Attr_DIRECTORY},
		{name: "root-kind-changed", identity: 0x20, inode: 1, kind: authoritypb.Attr_REGULAR},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			held := lookupTestAttr(t, d, d.resolveReply().Root, "file")
			root, handle := enumerateTestRoot(t, d)
			// The listing is a later coherent sample than the lookup.
			entry := testV3Dirent("entry", test.inode, test.kind, test.identity, 1)
			entry.ObjectVersion, entry.SnapshotSequence = 2, 2
			client.mutation, _ = readDirPages(&authoritypb.ReadDirReply{
				Verifier: bytes.Repeat([]byte{0x76}, 16), Eof: true,
				Entries: []*authoritypb.Dirent{entry},
			})
			replyAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.EnumerateEntriesRequest{
				Dir: root, Handle: handle, MaxEntries: 16,
			})
			if test.fileID == 0 {
				if errno != darwinEIO || d.terminalError() == nil {
					t.Fatalf("contradicting entry = (%#v,%d), want terminal EIO", replyAny, errno)
				}
				return
			}
			entries := replyAny.(*pfslocal.EnumerateEntriesReply).Entries
			if errno != 0 || len(entries) != 1 || entries[0].Attr.FileID != test.fileID || entries[0].Attr.Item != (pfslocal.Item{}) {
				t.Fatalf("consistent entry = (%+v,%d)", entries, errno)
			}
			d.mu.Lock()
			record := d.itemsByID[held.Item.ItemID]
			provisional, records := record.provisional, len(d.itemsByID)
			d.mu.Unlock()
			if provisional != 0 || records != 2 {
				t.Fatalf("listing a held identity changed ownership: provisional=%d records=%d", provisional, records)
			}
		})
	}
}
