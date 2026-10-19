package portablefsd

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func (f *cachedV3Fixture) operations() []string {
	f.client.mu.Lock()
	defer f.client.mu.Unlock()
	var result []string
	for _, op := range f.client.operations {
		if op != "close_batch" && op != "reclaim" {
			result = append(result, op)
		}
	}
	return result
}

// These are authority calls made during real frontend dispatch, including any
// newly inserted request. Release waits are tested separately with held replies.
func (f *cachedV3Fixture) requireOperations(want []string, body func()) {
	f.t.Helper()
	before := len(f.operations())
	body()
	got := f.operations()[before:]
	if len(got) != len(want) || len(got) != 0 && !reflect.DeepEqual(got, want) {
		f.t.Fatalf("awaited operations = %v, want %v", got, want)
	}
}

func TestV3CallbackAuthorityTrips(t *testing.T) {
	for _, operation := range []string{"cached-lookup", "cached-getattr", "cold-lookup", "cold-negative", "create", "open", "read", "write", "link", "unlink", "rename", "mkdir", "synchronize"} {
		t.Run(operation, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.bind(0x20, "file", 0x70)
			f.ns.bind(0x20, "cold", 0x50)
			f.getattr(f.root)
			file := f.lookup(f.root, "file")
			opened, errno := f.dispatch(&pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeReadWrite})
			if errno != 0 {
				t.Fatal(errno)
			}
			handle := opened.(*pfslocal.OpenReply).Handle
			var body any
			var want []string
			switch operation {
			case "cached-lookup":
				body = &pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")}
			case "cached-getattr":
				body = &pfslocal.GetAttrRequest{Item: file.Item}
			case "cold-lookup":
				body = &pfslocal.LookupRequest{Dir: f.root, Name: []byte("cold")}
				want = []string{"lookup"}
			case "cold-negative":
				body = &pfslocal.LookupRequest{Dir: f.root, Name: []byte("missing")}
				want = []string{"lookup"}
			case "create":
				body = &pfslocal.CreateRequest{Dir: f.root, Name: []byte("new"), Mode: 0o644, Exclusive: true}
				want = []string{"create"}
			case "open":
				body = &pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeRead}
				want = []string{"open"}
			case "read":
				body = &pfslocal.ReadRequest{Handle: handle, Length: 3}
				want = []string{"read"}
			case "write":
				body = &pfslocal.WriteRequest{Handle: handle, Data: []byte("abc")}
				want = []string{"write"}
			case "link":
				body = &pfslocal.HardLinkRequest{Item: file.Item, Dir: f.root, Name: []byte("alias")}
				want = []string{"link"}
			case "unlink":
				body = &pfslocal.RemoveRequest{Dir: f.root, Name: []byte("file")}
				want = []string{"unlink"}
			case "rename":
				body = &pfslocal.RenameRequest{FromDir: f.root, FromName: []byte("file"), ToDir: f.root, ToName: []byte("renamed")}
				want = []string{"rename"}
			case "mkdir":
				body = &pfslocal.MkdirRequest{Dir: f.root, Name: []byte("dir"), Mode: 0o755}
				want = []string{"mkdir"}
			case "synchronize":
				want = []string{"sync_fs", "stat_fs"}
			}
			f.requireOperations(want, func() {
				if operation == "synchronize" {
					// The Swift callback awaits these two local requests in this order.
					for _, request := range []any{&pfslocal.SyncVolumeRequest{}, &pfslocal.StatfsRequest{}} {
						if _, errno := f.dispatch(request); errno != 0 {
							t.Fatal(errno)
						}
					}
				} else if _, errno := f.dispatch(body); errno != 0 && !(operation == "cold-negative" && errno == darwinENOENT) {
					t.Fatal(errno)
				}
			})
		})
	}
}

func TestV3GitObjectAuthorityChain(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.getattr(f.root)
	var file pfslocal.Item
	var handle uint64
	step := func(want []string, body any) any {
		t.Helper()
		var reply any
		f.requireOperations(want, func() {
			var errno int32
			reply, errno = f.dispatch(body)
			if errno != 0 {
				t.Fatalf("%T errno=%d", body, errno)
			}
		})
		return reply
	}
	created := step([]string{"create"}, &pfslocal.CreateRequest{Dir: f.root, Name: []byte("temporary"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	file, handle = created.Attr.Item, created.Handle
	step([]string{"write"}, &pfslocal.WriteRequest{Handle: handle, Data: []byte("object")})
	step(nil, &pfslocal.CloseRequest{Handle: handle})
	step([]string{"link"}, &pfslocal.HardLinkRequest{Item: file, Dir: f.root, Name: []byte("object")})
	for _, name := range []string{"temporary", "object"} {
		step(nil, &pfslocal.LookupRequest{Dir: f.root, Name: []byte(name)})
	}
	step([]string{"unlink"}, &pfslocal.RemoveRequest{Dir: f.root, Name: []byte("temporary")})
	step(nil, &pfslocal.LookupRequest{Dir: f.root, Name: []byte("object")})
}

func TestV3ReleaseCallbacksDoNotAwaitAuthorityReplies(t *testing.T) {
	for _, operation := range []string{"close", "reclaim"} {
		t.Run(operation, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.bind(0x20, "file", 0x70)
			file := f.lookup(f.root, "file")
			var body any = &pfslocal.ReclaimRequest{Item: file.Item}
			if operation == "close" {
				reply, errno := f.dispatch(&pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeRead})
				if errno != 0 {
					t.Fatal(errno)
				}
				body = &pfslocal.CloseRequest{Handle: reply.(*pfslocal.OpenReply).Handle}
			}
			entered, release := make(chan struct{}, 2), make(chan struct{})
			defer close(release)
			f.client.mu.Lock()
			original := f.client.mutation
			f.client.mutation = func(ctx context.Context, id authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				if request.GetCloseBatch() != nil || request.GetReclaim() != nil {
					entered <- struct{}{}
					<-release
				}
				return original(ctx, id, request)
			}
			f.client.mu.Unlock()
			completed := make(chan int32, 1)
			go func() { _, errno := f.dispatch(body); completed <- errno }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("release never reached authority")
			}
			select {
			case errno := <-completed:
				if errno != 0 {
					t.Fatal(errno)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("callback awaited a held release reply despite available capacity")
			}
		})
	}
}

func TestV3DisjointOneTripCallbacksOverlap(t *testing.T) {
	f := newCachedV3Fixture(t, map[byte]*v3TestObject{0x70: {inode: 7, kind: authoritypb.Attr_REGULAR, nlink: 1}, 0x71: {inode: 8, kind: authoritypb.Attr_REGULAR, nlink: 1}})
	var handles []uint64
	for i, name := range []string{"a", "b"} {
		f.ns.bind(0x20, name, byte(0x70+i))
		file := f.lookup(f.root, name)
		reply, errno := f.dispatch(&pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeRead})
		if errno != 0 {
			t.Fatal(errno)
		}
		handles = append(handles, reply.(*pfslocal.OpenReply).Handle)
	}
	entered, release := make(chan struct{}, 2), make(chan struct{})
	defer close(release)
	f.client.mu.Lock()
	original := f.client.read
	f.client.read = func(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetRead() != nil {
			entered <- struct{}{}
			<-release
		}
		return original(ctx, request)
	}
	f.client.mu.Unlock()
	completed := make(chan int32, 2)
	before := len(f.operations())
	for _, handle := range handles {
		go func() { _, errno := f.dispatch(&pfslocal.ReadRequest{Handle: handle, Length: 3}); completed <- errno }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("disjoint callback serialized behind the first response")
		}
	}
	select {
	case <-completed:
		t.Fatal("callback completed while its authority reply was held")
	default:
	}
	release <- struct{}{}
	release <- struct{}{}
	for range 2 {
		select {
		case errno := <-completed:
			if errno != 0 {
				t.Fatal(errno)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("callback did not complete")
		}
	}
	if got := f.operations()[before:]; !reflect.DeepEqual(got, []string{"read", "read"}) {
		t.Fatalf("operations=%v", got)
	}
}
