package authorityrpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

func mkdirTestReply(search bool) *authoritypb.Response {
	item := &authoritypb.Item{
		Token: bytes.Repeat([]byte{0x31}, 16), StableIdentity: bytes.Repeat([]byte{0x20}, 16),
		Attr:          &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY, Inode: 2, Mode: 0o700, Nlink: 2},
		ObjectVersion: 9, SnapshotSequence: 11,
	}
	return &authoritypb.Response{
		Body: &authoritypb.Response_Mkdir{Mkdir: &authoritypb.MkdirReply{Item: item, ChildSearchPermitted: search}},
		PostState: &authoritypb.PostState{VisibilitySequence: 11, SnapshotSequence: 11, Objects: []*authoritypb.ObjectPostState{
			{StableIdentity: bytes.Repeat([]byte{0x10}, 16), ObjectVersion: 11,
				Attr: &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY, Inode: 1}, Roles: postStateRoleParent},
			{StableIdentity: append([]byte(nil), item.StableIdentity...), ObjectVersion: item.ObjectVersion,
				Attr: proto.Clone(item.Attr).(*authoritypb.Attr), Roles: postStateRoleCreated},
		}},
	}
}

func TestMkdirReplyCanonicalFrame(t *testing.T) {
	for _, search := range []bool{false, true} {
		t.Run(fmt.Sprint(search), func(t *testing.T) {
			reply := mkdirTestReply(search)
			raw, err := canonicalBytes(reply.ProtoReflect())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("..", "authoritypb", "testdata", fmt.Sprintf("mkdir-reply-%t.hex", search))
			if os.Getenv("UPDATE_GOLDENS") == "1" {
				if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			golden, err := os.ReadFile(path)
			if err != nil || string(golden) != hex.EncodeToString(raw)+"\n" {
				t.Fatalf("mkdir canonical golden: %v", err)
			}
			body, err := canonicalBytes(reply.GetMkdir().ProtoReflect())
			if err != nil {
				t.Fatal(err)
			}
			// The true scalar is the only byte delta; evaluated false is omitted.
			without := mkdirTestReply(false)
			base, err := canonicalBytes(without.GetMkdir().ProtoReflect())
			if err != nil {
				t.Fatal(err)
			}
			if search {
				base = append(base, 0x10, 1)
			}
			if !bytes.Equal(body, base) {
				t.Fatal("child search scalar changed canonical presence")
			}
			assertCanonicalRoundTrip(t, reply)
			assertFrameRoundTrip(t, reply)
		})
	}
}

func TestMkdirClientRequiresExactOwningResult(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*authoritypb.Response)
	}{
		{"lookup body", func(r *authoritypb.Response) {
			r.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: r.GetMkdir().GetItem()}}
		}},
		{"missing body", func(r *authoritypb.Response) { r.Body = nil }},
		{"nil body message", func(r *authoritypb.Response) { r.Body = &authoritypb.Response_Mkdir{} }},
		{"missing item", func(r *authoritypb.Response) { r.GetMkdir().Item = nil }},
		{"short token", func(r *authoritypb.Response) { r.GetMkdir().Item.Token = []byte{1} }},
		{"zero token", func(r *authoritypb.Response) { r.GetMkdir().Item.Token = make([]byte, 16) }},
		{"short identity", func(r *authoritypb.Response) { r.GetMkdir().Item.StableIdentity = []byte{1} }},
		{"zero identity", func(r *authoritypb.Response) { r.GetMkdir().Item.StableIdentity = make([]byte, 16) }},
		{"missing attributes", func(r *authoritypb.Response) { r.GetMkdir().Item.Attr = nil }},
		{"wrong kind", func(r *authoritypb.Response) { r.GetMkdir().Item.Attr.Kind = authoritypb.Attr_REGULAR }},
		{"zero inode", func(r *authoritypb.Response) { r.GetMkdir().Item.Attr.Inode = 0 }},
		{"zero version", func(r *authoritypb.Response) { r.GetMkdir().Item.ObjectVersion = 0 }},
		{"version beyond snapshot", func(r *authoritypb.Response) { r.GetMkdir().Item.ObjectVersion = 12 }},
		{"missing post-state", func(r *authoritypb.Response) { r.PostState = nil }},
		{"zero snapshot", func(r *authoritypb.Response) { r.PostState.SnapshotSequence = 0 }},
		{"unequal snapshot", func(r *authoritypb.Response) { r.PostState.SnapshotSequence = 12; r.PostState.VisibilitySequence = 12 }},
		{"unequal visibility", func(r *authoritypb.Response) { r.PostState.VisibilitySequence = 10 }},
		{"missing parent", func(r *authoritypb.Response) { r.PostState.Objects = r.PostState.Objects[1:] }},
		{"wrong roles", func(r *authoritypb.Response) { r.PostState.Objects[1].Roles = postStateRoleTarget }},
		{"duplicate objects", func(r *authoritypb.Response) { r.PostState.Objects[0] = r.PostState.Objects[1] }},
		{"zero post identity", func(r *authoritypb.Response) { r.PostState.Objects[0].StableIdentity = make([]byte, 16) }},
		{"wrong created identity", func(r *authoritypb.Response) { r.PostState.Objects[1].StableIdentity[0]++ }},
		{"wrong created version", func(r *authoritypb.Response) { r.PostState.Objects[1].ObjectVersion-- }},
		{"wrong created attributes", func(r *authoritypb.Response) { r.PostState.Objects[1].Attr.Mode = 0 }},
		{"contradictory failure", func(r *authoritypb.Response) { r.Failure = authoritypb.FailureClass_FAILURE_CLASS_INTERNAL }},
	} {
		t.Run(test.name, func(t *testing.T) {
			reply := mkdirTestReply(true)
			test.change(reply)
			client, got, err := callMkdirPeer(t, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE, reply)
			if err == nil || got != nil || client.LocalAdmissionOpen() {
				t.Fatalf("accepted malformed mkdir: %v, %v; admission=%t", got, err, client.LocalAdmissionOpen())
			}
		})
	}
}

// Raw peer frames bypass authority egress validation, proving the actual client
// refuses malformed input rather than only the writer refusing to produce it.
func callMkdirPeer(t *testing.T, profile authoritypb.FrontendProfile, reply *authoritypb.Response) (*Client, *authoritypb.Response, error) {
	t.Helper()
	data, peer := net.Pipe()
	control, controlPeer := net.Pipe()
	client := newTerminalDrainTestClient(data, control, time.Second)
	client.cfg.FrontendProfile = profile
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close(); _ = controlPeer.Close() })
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go client.readLoop(client.data, data)
	type result struct {
		response *authoritypb.Response
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		response, err := client.CallMutation(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Name: []byte("child")}}})
		completed <- result{response, err}
	}()
	request := new(authoritypb.Request)
	if err := readFrame(peer, testMaxFrame, nil, 0, request); err != nil {
		t.Fatal(err)
	}
	reply.RequestId, reply.Epoch = request.RequestId, client.sessionEpoch()
	reply.Mutation = &authoritypb.MutationState{Slot: request.GetMutation().GetSlot(), AcceptedSequence: request.GetMutation().GetSequence()}
	raw, err := canonicalBytes(reply.ProtoReflect())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAll(peer, encodedRawFrame(raw, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-completed:
		return client, result.response, result.err
	case <-time.After(3 * time.Second):
		t.Fatal("mkdir call did not settle")
		return nil, nil, nil
	}
}

func TestMkdirClientAcceptsBothSearchVerdicts(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		for _, search := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", profile, search), func(t *testing.T) {
				want := mkdirTestReply(search)
				client, got, err := callMkdirPeer(t, profile, want)
				if err != nil || !proto.Equal(got, want) || !client.LocalAdmissionOpen() {
					t.Fatalf("mkdir result = %v, %v", got, err)
				}
			})
		}
	}
}

func TestMkdirReplyCannotSatisfyAnotherOperation(t *testing.T) {
	request := &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{}}}
	if err := validateMkdirResult(request, mkdirTestReply(false)); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("cross-operation result = %v", err)
	}
	request.Body = &authoritypb.Request_Mkdir{}
	if err := validateMkdirResult(request, &authoritypb.Response{}); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("nil request message bypassed result classification: %v", err)
	}
}

func TestMkdirLostReplyRetainsItemPostStateAndSearchVerdict(t *testing.T) {
	for _, search := range []bool{false, true} {
		t.Run(fmt.Sprint(search), func(t *testing.T) {
			runtime, err := volumeserver.New("mkdir-replay", volumeserver.Config{ContinuousNow: func() (time.Duration, error) { return 0, nil }, SessionLease: time.Minute, MaxReplaySlots: 9, MaxSessions: 4, MaxLockRecords: 16})
			if err != nil {
				t.Fatal(err)
			}
			var currentPermission atomic.Bool
			currentPermission.Store(search)
			handler := &replayHandler{
				runtime: runtime, access: volumeserver.AccessRead | volumeserver.AccessWrite, fskit: true,
				afterExecution: make(chan struct{}), releaseFirst: make(chan struct{}),
				mutationResult: func() *authoritypb.Response { return mkdirTestReply(currentPermission.Load()) },
			}
			address, tls, stop := startTestServer(t, handler, 9, time.Minute)
			defer stop()
			cfg := coherentTestClientConfig(address, tls, "mkdir-replay", 9, 9)
			cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE
			client, err := DialClient(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			type result struct {
				response *authoritypb.Response
				err      error
			}
			completed := make(chan result, 1)
			go func() {
				response, err := client.CallMutation(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Name: []byte("child")}}})
				completed <- result{response, err}
			}()
			select {
			case <-handler.afterExecution:
			case <-time.After(3 * time.Second):
				t.Fatal("mkdir did not record its outcome")
			}
			// A later chmod/access result must not change a retained observation.
			currentPermission.Store(!search)
			client.data.pendingMu.Lock()
			old := client.data.conn
			client.data.pendingMu.Unlock()
			client.failConnection(client.data, old, ErrTransportUncertain)
			close(handler.releaseFirst)
			select {
			case result := <-completed:
				want := mkdirTestReply(search)
				if result.err != nil || result.response.GetErrno() != 0 ||
					!proto.Equal(result.response.GetMkdir(), want.GetMkdir()) ||
					!proto.Equal(result.response.GetPostState(), want.GetPostState()) || result.response.GetMutation() == nil {
					t.Fatalf("replayed mkdir = %v, %v", result.response, result.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("lost mkdir reply did not replay")
			}
			if handler.mutationCalls.Load() != 2 || handler.applyCalls.Load() != 1 {
				t.Fatalf("wire calls=%d, apply calls=%d", handler.mutationCalls.Load(), handler.applyCalls.Load())
			}
		})
	}
}
