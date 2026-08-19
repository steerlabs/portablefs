package readonlyfs

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestClientReadsByOpaqueLookupAndReleasesEveryAuthorityHandle(t *testing.T) {
	rpc := &fakeAuthority{root: testItem(1, authoritypb.Attr_DIRECTORY, []byte("root"), 0)}
	client := newClient(rpc, time.Second)
	t.Cleanup(func() { _ = client.Close() })
	key, err := EncodePath([][]byte{[]byte("README.md")})
	if err != nil {
		t.Fatal(err)
	}

	file, err := client.OpenFile(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	read, err := file.ReadAt(context.Background(), buffer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if read != len(buffer) || string(buffer) != "hello" {
		t.Fatalf("ReadAt = %d, %q", read, buffer)
	}
	if err := file.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(context.Background()); err != nil {
		t.Fatalf("second close was not idempotent: %v", err)
	}

	rpc.mu.Lock()
	operations := append([]string(nil), rpc.operations...)
	rpc.mu.Unlock()
	want := []string{"lookup:README.md", "open", "reclaim", "read:0:2", "read:2:2", "read:4:1", "close"}
	if fmt.Sprint(operations) != fmt.Sprint(want) {
		t.Fatalf("operations = %v, want %v", operations, want)
	}
}

func TestClientPagesDirectoryWithOneOwnedCursor(t *testing.T) {
	rpc := &fakeAuthority{root: testItem(1, authoritypb.Attr_DIRECTORY, []byte("root"), 0)}
	client := newClient(rpc, time.Second)
	t.Cleanup(func() { _ = client.Close() })

	first, err := client.List(context.Background(), "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Entries) != 1 || first.Next == nil || string(first.Entries[0].Name) != "first" {
		t.Fatalf("first page = %+v", first)
	}
	second, err := client.List(context.Background(), "", 1, first.Next)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Entries) != 1 || second.Next != nil || string(second.Entries[0].Name) != "second" {
		t.Fatalf("second page = %+v", second)
	}

	rpc.mu.Lock()
	operations := append([]string(nil), rpc.operations...)
	rpc.mu.Unlock()
	want := []string{"open", "readdir:1", "readdir:1", "close"}
	if fmt.Sprint(operations) != fmt.Sprint(want) {
		t.Fatalf("operations = %v, want %v", operations, want)
	}
}

func TestClientRejectsAuthorityDirectoryPageAboveRequestedBound(t *testing.T) {
	rpc := &fakeAuthority{
		oversizedDirectoryPage: true,
		root:                   testItem(1, authoritypb.Attr_DIRECTORY, []byte("root"), 0),
	}
	client := newClient(rpc, time.Second)
	t.Cleanup(func() { _ = client.Close() })

	if _, err := client.List(context.Background(), "", 1, nil); err == nil {
		t.Fatal("oversized authority directory page was accepted")
	}
	rpc.mu.Lock()
	operations := append([]string(nil), rpc.operations...)
	rpc.mu.Unlock()
	if fmt.Sprint(operations) != fmt.Sprint([]string{"open", "readdir:1", "close"}) {
		t.Fatalf("operations = %v", operations)
	}
}

func TestClientAcknowledgesVisibilityWithoutCachingNamespaceState(t *testing.T) {
	acknowledged := make(chan *authoritypb.VisibilityCursor, 1)
	rpc := &fakeAuthority{
		root: testItem(1, authoritypb.Attr_DIRECTORY, []byte("root"), 0),
		visibilityEvent: &authoritypb.VisibilityEvent{Cursor: &authoritypb.VisibilityCursor{
			Sequence: 2,
			Phase:    authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE,
		}},
		visibilityAcknowledged: acknowledged,
	}
	client := newClient(rpc, time.Second)
	t.Cleanup(func() { _ = client.Close() })

	select {
	case cursor := <-acknowledged:
		if cursor.GetSequence() != 2 || cursor.GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE {
			t.Fatalf("acknowledged cursor = %v", cursor)
		}
	case <-time.After(time.Second):
		t.Fatal("cacheless client did not acknowledge the visibility event")
	}
}

type fakeAuthority struct {
	// releases counts authenticated detaches. Close must send exactly one, and
	// a session that leaves without one costs the next writer two repair
	// budgets, so the count is the assertion.
	releases atomic.Int64

	mu                     sync.Mutex
	operations             []string
	oversizedDirectoryPage bool
	readDirCalls           int
	root                   *authoritypb.Item
	visibilityEvent        *authoritypb.VisibilityEvent
	visibilityAcknowledged chan<- *authoritypb.VisibilityCursor
}

func (f *fakeAuthority) CallMutation(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Lookup:
		f.operations = append(f.operations, "lookup:"+string(body.Lookup.GetName()))
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{
			Item: testItem(2, authoritypb.Attr_REGULAR, []byte("file-token"), 5),
		}}}, nil
	case *authoritypb.Request_Open:
		f.operations = append(f.operations, "open")
		return &authoritypb.Response{Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: []byte("file-handle")}}}, nil
	case *authoritypb.Request_Reclaim:
		f.operations = append(f.operations, "reclaim")
		return &authoritypb.Response{}, nil
	case *authoritypb.Request_Close:
		f.operations = append(f.operations, "close")
		return &authoritypb.Response{}, nil
	case *authoritypb.Request_ReadDir:
		f.operations = append(f.operations, fmt.Sprintf("readdir:%d", body.ReadDir.GetMaxEntries()))
		f.readDirCalls++
		entry := func(name string, cookie byte) *authoritypb.Dirent {
			return &authoritypb.Dirent{
				Attr:       testItem(uint64(cookie), authoritypb.Attr_REGULAR, []byte{name[0]}, 1).GetAttr(),
				Name:       []byte(name),
				NextCookie: []byte{cookie},
			}
		}
		entries := []*authoritypb.Dirent{entry("first", 2)}
		if f.readDirCalls > 1 {
			entries = []*authoritypb.Dirent{entry("second", 3)}
		}
		if f.oversizedDirectoryPage {
			entries = append(entries, entry("extra", 4))
		}
		return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{
			Entries: entries, Eof: f.readDirCalls > 1, Verifier: []byte("directory-verifier"),
		}}}, nil
	default:
		return nil, fmt.Errorf("unexpected mutation %T", body)
	}
}

func (f *fakeAuthority) CallRead(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Read:
		f.operations = append(f.operations, fmt.Sprintf("read:%d:%d", body.Read.GetOffset(), body.Read.GetLength()))
		contents := []byte("hello")
		start := min(int(body.Read.GetOffset()), len(contents))
		end := min(start+int(body.Read.GetLength()), len(contents))
		return &authoritypb.Response{Body: &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: contents[start:end]}}}, nil
	case *authoritypb.Request_KeepAlive:
		return &authoritypb.Response{}, nil
	default:
		return nil, fmt.Errorf("unexpected read %T", body)
	}
}

func (f *fakeAuthority) Close() error { return nil }

func (f *fakeAuthority) ReleaseBeforeMount(context.Context) error {
	f.releases.Add(1)
	return nil
}
func (f *fakeAuthority) IOLimits() (uint32, uint32) { return 2, 256 }
func (f *fakeAuthority) InitialVisibilityCursor() *authoritypb.VisibilityCursor {
	return &authoritypb.VisibilityCursor{Sequence: 1}
}
func (f *fakeAuthority) NextVisibility(ctx context.Context, _ *authoritypb.VisibilityCursor) (*authoritypb.VisibilityEvent, error) {
	f.mu.Lock()
	event := f.visibilityEvent
	f.visibilityEvent = nil
	f.mu.Unlock()
	if event != nil {
		return event, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (f *fakeAuthority) AckVisibility(_ context.Context, cursor *authoritypb.VisibilityCursor) error {
	if f.visibilityAcknowledged != nil {
		f.visibilityAcknowledged <- cursor
	}
	return nil
}
func (f *fakeAuthority) Root() *authoritypb.Item     { return f.root }
func (f *fakeAuthority) SessionLease() time.Duration { return time.Hour }

func testItem(inode uint64, kind authoritypb.Attr_Kind, token []byte, size int64) *authoritypb.Item {
	return &authoritypb.Item{
		Attr:           &authoritypb.Attr{Inode: inode, Kind: kind, Mode: 0o644, Nlink: 1, Size: size},
		StableIdentity: bytes.Repeat([]byte{byte(inode)}, 16),
		Token:          append([]byte(nil), token...),
	}
}

// A session that leaves without an authenticated detach stays in the
// authority's barrier audience. The next peer mutation then waits this
// session's whole repair budget for a phase nobody will acknowledge, and a
// further budget of post-fence grace after that -- so the writer pays two
// budgets for a reader that has already exited. Close must not do that.
func TestClientDetachesBeforeClosingTheTransport(t *testing.T) {
	rpc := &fakeAuthority{root: testItem(1, authoritypb.Attr_DIRECTORY, []byte("root"), 0)}
	client := newClient(rpc, time.Second)
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if released := rpc.releases.Load(); released != 1 {
		t.Fatalf("close sent %d authenticated detaches, want exactly 1", released)
	}
	// Close is idempotent, and a second one must not send a second detach: the
	// session is already gone and Detach on a departed session is an error.
	if err := client.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if released := rpc.releases.Load(); released != 1 {
		t.Fatalf("a repeated close sent %d detaches, want the first one only", released)
	}
}
