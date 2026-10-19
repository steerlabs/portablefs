package portablefsd

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// Check both directions and the mount-wide charges after every lifecycle edge.
func requireV3Bindings(t *testing.T, d *v3DataPlane) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	names, bytes, dirs := 0, 0, 0
	for _, parent := range d.itemsByID {
		if len(parent.children) != 0 {
			dirs++
		}
		_, indexed := d.bindingDirs[parent]
		if indexed != (len(parent.children) != 0) {
			t.Fatal("directory membership disagrees")
		}
		for name, child := range parent.children {
			if d.itemsByID[child.item.ItemID] != child {
				t.Fatal("binding retained a retired child")
			}
			if _, ok := child.bindings[v3Binding{parent: parent, name: name}]; !ok {
				t.Fatal("missing reverse membership")
			}
			names++
			bytes += len(name)
		}
		for binding := range parent.bindings {
			if d.itemsByID[binding.parent.item.ItemID] != binding.parent || binding.parent.children[binding.name] != parent {
				t.Fatal("reverse membership retained a stale coordinate")
			}
		}
	}
	if names != d.bindingNames || bytes != d.bindingBytes || dirs != len(d.bindingDirs) || names > v3MaxCompleteNames || bytes > v3MaxCompleteBytes {
		t.Fatalf("bindings=%d/%d bytes=%d/%d dirs=%d/%d", names, d.bindingNames, bytes, d.bindingBytes, dirs, len(d.bindingDirs))
	}
}

func TestV3AliasLifecycle(t *testing.T) {
	for _, action := range []string{"cross-directory", "unlink-first", "unlink-second", "same-inode-rename", "overwrite", "exchange", "permission-ABA", "parent-retirement", "reclaim-relookup", "duplicate-capability", "delayed-post-state", "terminal", "authorization-loss"} {
		t.Run(action, func(t *testing.T) {
			f := newCachedV3Fixture(t, map[byte]*v3TestObject{
				0x50: {inode: 5, kind: authoritypb.Attr_DIRECTORY, nlink: 2},
				0x70: {inode: 7, kind: authoritypb.Attr_REGULAR, nlink: 2},
				0x71: {inode: 8, kind: authoritypb.Attr_REGULAR, nlink: 1},
			})
			f.ns.bind(0x20, "dir", 0x50)
			f.ns.bind(0x20, "a", 0x70)
			f.ns.bind(0x50, "b", 0x70)
			f.ns.bind(0x20, "victim", 0x71)
			f.getattr(f.root)
			dir := f.lookup(f.root, "dir")
			file := f.lookup(f.root, "a")
			f.requireOperations([]string{"lookup"}, func() {
				if alias := f.lookup(dir.Item, "b"); alias.Item != file.Item || alias.ParentFileID != dir.FileID {
					t.Fatalf("alias=%+v", alias)
				}
			})
			waitV3ReleasesIdle(t, f.d)
			if f.client.liveTokens() != 3 {
				t.Fatalf("aliases own %d tokens, want root, directory and file", f.client.liveTokens())
			}
			rootRecord, dirRecord, fileRecord := f.record(f.root), f.record(dir.Item), f.record(file.Item)
			call := func(body any) {
				t.Helper()
				if _, errno := f.dispatch(body); errno != 0 {
					t.Fatalf("%T errno=%d", body, errno)
				}
			}
			check := func(parent pfslocal.Item, name string, item pfslocal.Item) {
				t.Helper()
				f.requireOperations(nil, func() {
					if got := f.lookup(parent, name); got.Item != item || got.Parent == nil || *got.Parent != parent {
						t.Fatalf("%s=%+v", name, got)
					}
				})
			}
			switch action {
			case "cross-directory":
				check(f.root, "a", file.Item)
				check(dir.Item, "b", file.Item)
			case "unlink-first", "unlink-second":
				parent, name, other, otherName := f.root, "a", dir.Item, "b"
				if action == "unlink-second" {
					parent, name, other, otherName = dir.Item, "b", f.root, "a"
				}
				call(&pfslocal.RemoveRequest{Dir: parent, Name: []byte(name)})
				check(other, otherName, file.Item)
				f.requireOperations(nil, func() {
					if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: parent, Name: []byte(name)}); errno != darwinENOENT {
						t.Fatalf("removed alias errno=%d", errno)
					}
				})
				if attr := f.getattr(file.Item); attr.Parent == nil || *attr.Parent != other || attr.Nlink != 1 {
					t.Fatalf("surviving parent=%+v", attr)
				}
			case "same-inode-rename":
				call(&pfslocal.RenameRequest{FromDir: f.root, FromName: []byte("a"), ToDir: dir.Item, ToName: []byte("b")})
				check(f.root, "a", file.Item)
				check(dir.Item, "b", file.Item)
			case "overwrite":
				victim := f.lookup(f.root, "victim")
				call(&pfslocal.RenameRequest{FromDir: f.root, FromName: []byte("victim"), ToDir: dir.Item, ToName: []byte("b")})
				check(f.root, "a", file.Item)
				check(dir.Item, "b", victim.Item)
			case "exchange":
				victim := f.lookup(f.root, "victim")
				// The frontend has no exchange flag. Exercise simultaneous bindings at
				// the cache boundary without changing the non-exchange wire contract.
				if err := f.d.applyMutation(&v3MutationEffect{snapshot: 2, names: []v3NameEffect{
					{parent: rootRecord, name: "victim", bound: true, identity: file.Item.StableIdentity},
					{parent: dirRecord, name: "b", bound: true, identity: victim.Item.StableIdentity},
				}}); err != nil {
					t.Fatal(err)
				}
				check(f.root, "a", file.Item)
				check(f.root, "victim", file.Item)
				check(dir.Item, "b", victim.Item)
			case "permission-ABA":
				for _, mode := range []uint32{0o700, 0o755} {
					call(&pfslocal.SetAttrRequest{Item: dir.Item, Mode: &mode})
				}
				check(f.root, "a", file.Item)
				f.d.mu.Lock()
				f.d.fillLookupLocked(dirRecord, "b", fileRecord, 1)
				stale := dirRecord.children["b"] != nil
				f.d.mu.Unlock()
				if stale {
					t.Fatal("ABA admitted old lookup")
				}
				f.requireOperations([]string{"lookup"}, func() { f.lookup(dir.Item, "b") })
			case "parent-retirement":
				call(&pfslocal.ReclaimRequest{Item: dir.Item})
				check(f.root, "a", file.Item)
				if attr := f.getattr(file.Item); attr.Parent == nil || *attr.Parent != f.root {
					t.Fatalf("retired parent=%+v", attr)
				}
				f.requireOperations([]string{"lookup"}, func() {
					replacement := f.lookup(f.root, "dir")
					if replacement.Item == dir.Item {
						t.Fatal("reused retired parent incarnation")
					}
					f.d.mu.Lock()
					f.d.fillLookupLocked(dirRecord, "b", fileRecord, 100)
					f.d.mu.Unlock()
				})
			case "reclaim-relookup":
				call(&pfslocal.ReclaimRequest{Item: file.Item})
				if len(fileRecord.bindings) != 0 || rootRecord.children["a"] != nil || dirRecord.children["b"] != nil {
					t.Fatal("reclaim left alias memberships")
				}
				f.requireOperations([]string{"lookup"}, func() {
					replacement := f.lookup(dir.Item, "b")
					if replacement.Item == file.Item || replacement.FileID != file.FileID {
						t.Fatalf("relookup=%+v", replacement)
					}
				})
			case "duplicate-capability":
				f.d.mu.Lock()
				f.d.dropNameLocked(rootRecord, "a")
				f.d.mu.Unlock()
				f.requireOperations([]string{"lookup"}, func() {
					if got := f.lookup(f.root, "a"); got.Item != file.Item {
						t.Fatal("duplicate capability duplicated inode")
					}
				})
				waitV3ReleasesIdle(t, f.d)
				if f.client.liveTokens() != 3 {
					t.Fatal("duplicate capability leaked")
				}
				check(dir.Item, "b", file.Item)
			case "delayed-post-state":
				call(&pfslocal.RemoveRequest{Dir: dir.Item, Name: []byte("b")})
				if err := f.d.applyMutation(&v3MutationEffect{snapshot: 1, names: []v3NameEffect{{parent: dirRecord, name: "b", bound: true, identity: file.Item.StableIdentity}}}); err != nil {
					t.Fatal(err)
				}
				check(f.root, "a", file.Item)
				f.requireOperations([]string{"lookup"}, func() {
					if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: dir.Item, Name: []byte("b")}); errno != darwinENOENT {
						t.Fatalf("stale alias errno=%d", errno)
					}
				})
			case "terminal":
				f.client.poisoned.Store(true)
				if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: dir.Item, Name: []byte("b")}); errno == 0 {
					t.Fatal("terminal alias hit")
				}
			case "authorization-loss":
				f.d.mu.Lock()
				f.d.authorizationDeadline = time.Now().Add(-time.Second)
				f.d.mu.Unlock()
				f.requireOperations([]string{"lookup"}, func() { f.lookup(dir.Item, "b") })
			}
			requireV3Bindings(t, f.d)
		})
	}
}

func TestV3AliasCapacityEvictionOnlyForgetsAnswers(t *testing.T) {
	for _, bound := range []string{"count", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			f := newCachedV3Fixture(t, map[byte]*v3TestObject{
				0x50: {inode: 5, kind: authoritypb.Attr_DIRECTORY, nlink: 2},
				0x70: {inode: 7, kind: authoritypb.Attr_REGULAR, nlink: 1},
				0x71: {inode: 8, kind: authoritypb.Attr_REGULAR, nlink: 1},
			})
			f.ns.bind(0x20, "dir", 0x50)
			f.ns.bind(0x50, "other", 0x71)
			f.ns.bind(0x20, "original", 0x70)
			f.getattr(f.root)
			file := f.lookup(f.root, "original")
			dir := f.lookup(f.root, "dir")
			other := f.lookup(dir.Item, "other")
			root, record := f.record(f.root), f.record(file.Item)
			dirRecord, otherRecord := f.record(dir.Item), f.record(other.Item)
			f.d.mu.Lock()
			for i := 0; i < v3MaxCompleteNames; i++ {
				name := fmt.Sprintf("alias-%05d", i)
				if bound == "bytes" {
					name += strings.Repeat("x", 240)
				}
				// Each inode and directory stays below either bound on its own.
				// Only the combined mount-wide population forces eviction.
				parent, child := root, record
				if i%2 != 0 {
					parent, child = dirRecord, otherRecord
				}
				f.d.bindNameLocked(parent, name, child)
				if root.children["original"] == nil {
					break
				}
			}
			evicted := root.children["original"] == nil
			_, absent := root.negatives["original"]
			owned := f.d.itemsByID[file.Item.ItemID] == record && f.d.itemsByID[other.Item.ItemID] == otherRecord
			f.d.mu.Unlock()
			if !evicted || absent || !owned {
				t.Fatalf("evicted=%t absent=%t owned=%t", evicted, absent, owned)
			}
			requireV3Bindings(t, f.d)
			f.requireOperations([]string{"lookup"}, func() {
				if got := f.lookup(f.root, "original"); got.Item != file.Item {
					t.Fatal("eviction destroyed inode")
				}
			})
			f.requireOperations(nil, func() { f.lookup(f.root, "original"); f.getattr(file.Item) })
			requireV3Bindings(t, f.d)
		})
	}
}
