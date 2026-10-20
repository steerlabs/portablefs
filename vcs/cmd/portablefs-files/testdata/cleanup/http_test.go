package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/readonlyfs"
)

// The cleanup lane cannot send CLOSE before its bounded session context ends.
// Nothing reaches the authority, so the transport returns the bare context
// error and the authority session remains healthy.
type reviewCleanupRPC struct {
	mu                            sync.Mutex
	items, handles, closeAttempts int
	ended                         bool
}

func (*reviewCleanupRPC) Root() *authoritypb.Item {
	return &authoritypb.Item{Token: []byte("root"), Attr: &authoritypb.Attr{Inode: 1, Kind: authoritypb.Attr_DIRECTORY}}
}
func (*reviewCleanupRPC) IOLimits() (uint32, uint32)               { return 4096, 4096 }
func (*reviewCleanupRPC) SessionLease() time.Duration              { return time.Hour }
func (*reviewCleanupRPC) ReleaseBeforeMount(context.Context) error { return nil }
func (r *reviewCleanupRPC) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended = true
	r.items = 0
	r.handles = 0
	return nil
}
func (*reviewCleanupRPC) CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error) {
	return &authoritypb.Response{}, nil
}
func (r *reviewCleanupRPC) CallMutation(ctx context.Context, req *authoritypb.Request) (*authoritypb.Response, error) {
	if req.GetClose() != nil {
		r.mu.Lock()
		r.closeAttempts++
		r.mu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case req.GetLookup() != nil:
		r.items++
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: &authoritypb.Item{Token: []byte("file-item"), Attr: &authoritypb.Attr{Inode: 2, Kind: authoritypb.Attr_REGULAR}}}}}, nil
	case req.GetOpen() != nil:
		r.handles++
		return &authoritypb.Response{Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: []byte("handle")}}}, nil
	case req.GetReclaim() != nil:
		r.items -= len(req.GetReclaim().GetItems())
		return &authoritypb.Response{}, nil
	case req.GetReadDir() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Verifier: []byte("v"), Entries: []*authoritypb.Dirent{{Name: []byte("file"), NextCookie: []byte("1"), Attr: &authoritypb.Attr{Inode: 2, Kind: authoritypb.Attr_REGULAR}}}}}}, nil
	default:
		return nil, fmt.Errorf("unexpected %T", req.GetBody())
	}
}
func TestReviewHTTPAbandonedCloseRetainsSessionOwner(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "content", true: "drop-cursor"}[directory], func(t *testing.T) {
			rpc := &reviewCleanupRPC{}
			client := readonlyfs.ReviewNewClient(rpc, time.Second)
			t.Cleanup(func() { _ = client.Close() })
			public, private := testKeys(t)
			service := newTestServer(t, public, nil)
			session := &volumeSession{client: client, expiresAt: time.Now().Add(10 * time.Minute)}
			service.sessions["volume-a"] = session
			if directory {
				page, err := client.List(t.Context(), "", 1, nil)
				if err != nil || page.Next == nil {
					t.Fatalf("List: %v next=%v", err, page.Next)
				}
				token, err := service.storeCursor("volume-a", "", session, page.Next)
				if err != nil {
					t.Fatal(err)
				}
				service.dropCursor(token, "volume-a", "", session)
				if len(service.cursors) != 0 {
					t.Fatal("cursor was not dropped")
				}
			} else {
				key, err := readonlyfs.EncodePath([][]byte{[]byte("file")})
				if err != nil {
					t.Fatal(err)
				}
				req := signedRequest(t, private, "GET", "/content?file="+key+"&mode=preview&length=1", tokenClaims{Operation: "preview", VolumeID: "volume-a", PathKey: key, Length: 1}, nil)
				req.SetPathValue("volume", "volume-a")
				writer := httptest.NewRecorder()
				service.handleContent(writer, req)
				if writer.Code != 200 {
					t.Fatalf("HTTP=%d body=%s", writer.Code, writer.Body.String())
				}
			}
			rpc.mu.Lock()
			defer rpc.mu.Unlock()
			t.Logf("handles=%d items=%d attempts=%d ended=%v session=%v cursors=%d", rpc.handles, rpc.items, rpc.closeAttempts, rpc.ended, client.Err(), len(service.cursors))
			if rpc.handles != 0 && client.Err() == nil {
				t.Fatal("HTTP owner discarded; allocated description remains on a live session with no retry owner")
			}
		})
	}
}
