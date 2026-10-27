package authorityrpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

func directoryProofResult() (*authoritypb.Request, *authoritypb.Response) {
	return &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: bytes.Repeat([]byte{1}, 16), Flags: &authoritypb.OpenFlags{Read: true}, ReusableDirectoryReadIncarnation: 2}}},
		&authoritypb.Response{VolumeVersion: 4, Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: bytes.Repeat([]byte{2}, 16), DirectoryReadProof: &authoritypb.DirectoryReadProof{Reusable: true, StableIdentity: bytes.Repeat([]byte{1}, 16), Incarnation: 2, ObjectVersion: 3, SnapshotSequence: 4}}}}
}

func TestDirectoryReadProofExactGrammar(t *testing.T) {
	request, response := directoryProofResult()
	for _, tc := range []struct {
		name    string
		message proto.Message
		golden  string
	}{
		{"request tag", &authoritypb.OpenRequest{ReusableDirectoryReadIncarnation: 2}, "2802"},
		{"proof", response.GetOpen().GetDirectoryReadProof(), "0a10010101010101010101010101010101011002180320042801"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := proto.Marshal(tc.message)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(data) != tc.golden {
				t.Fatalf("wire=%x want=%s", data, tc.golden)
			}
		})
	}
	if err := validateDirectoryReadResult(request, response); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*authoritypb.Request, *authoritypb.Response)
	}{
		{"unrequested", func(q *authoritypb.Request, _ *authoritypb.Response) {
			q.GetOpen().ReusableDirectoryReadIncarnation = 0
		}},
		{"missing", func(_ *authoritypb.Request, r *authoritypb.Response) { r.GetOpen().DirectoryReadProof = nil }},
		{"identity", func(_ *authoritypb.Request, r *authoritypb.Response) {
			r.GetOpen().DirectoryReadProof.StableIdentity = make([]byte, 16)
		}},
		{"incarnation", func(_ *authoritypb.Request, r *authoritypb.Response) { r.GetOpen().DirectoryReadProof.Incarnation = 0 }},
		{"different incarnation", func(_ *authoritypb.Request, r *authoritypb.Response) { r.GetOpen().DirectoryReadProof.Incarnation = 3 }},
		{"version", func(_ *authoritypb.Request, r *authoritypb.Response) {
			r.GetOpen().DirectoryReadProof.ObjectVersion = 5
		}},
		{"snapshot", func(_ *authoritypb.Request, r *authoritypb.Response) { r.VolumeVersion = 5 }},
		{"failure", func(_ *authoritypb.Request, r *authoritypb.Response) { r.Errno = 5 }},
		{"cache capable", func(_ *authoritypb.Request, r *authoritypb.Response) { r.GetOpen().CacheCapable = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, r := directoryProofResult()
			tc.change(q, r)
			if validateDirectoryReadResult(q, r) == nil {
				t.Fatal("accepted invalid proof")
			}
		})
	}
}

func TestDirectoryReadProofOnlyLinuxReadOnly(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE, authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER} {
		request, _ := directoryProofResult()
		if got := requestAllowedForFrontend(request, profile); got != (profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX) {
			t.Fatalf("profile %v admitted=%v", profile, got)
		}
	}
	for _, change := range []func(*authoritypb.OpenRequest){
		func(o *authoritypb.OpenRequest) { o.Flags.Write = true }, func(o *authoritypb.OpenRequest) { o.Flags.Read = false },
		func(o *authoritypb.OpenRequest) { o.Flags.Append = true }, func(o *authoritypb.OpenRequest) { o.Flags.Truncate = true },
		func(o *authoritypb.OpenRequest) { o.Flags.Sync = true }, func(o *authoritypb.OpenRequest) { o.Flags.DataSync = true },
		func(o *authoritypb.OpenRequest) { o.WriteIntent = true }, func(o *authoritypb.OpenRequest) { o.CacheCapable = true },
	} {
		q, _ := directoryProofResult()
		change(q.GetOpen())
		if validDirectoryReadRequest(q.GetOpen()) {
			t.Fatal("accepted effectful reusable open")
		}
	}
}
