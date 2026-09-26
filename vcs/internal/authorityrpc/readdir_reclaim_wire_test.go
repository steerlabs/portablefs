package authorityrpc

import (
	"bytes"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestReadDirHeldIdentityAndReclaimBatchWireBounds(t *testing.T) {
	for _, count := range []int{MaxReadDirHeldIdentities, MaxReadDirHeldIdentities + 1} {
		request := &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{WantItems: true}}}
		for i := 0; i < count; i++ {
			request.GetReadDir().HeldIdentities = append(request.GetReadDir().HeldIdentities, bytes.Repeat([]byte{byte(i)}, 16))
		}
		encoded, err := canonicalBytes(request.ProtoReflect())
		if err != nil {
			t.Fatal(err)
		}
		err = validateWireMessage(encoded, request.ProtoReflect().Descriptor())
		if (err == nil) != (count == MaxReadDirHeldIdentities) {
			t.Fatalf("held count=%d grammar=%v", count, err)
		}
	}
	for _, count := range []int{MaxReclaimBatch, MaxReclaimBatch + 1} {
		request := &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{}}}
		for i := 0; i < count; i++ {
			request.GetReclaim().Items = append(request.GetReclaim().Items, bytes.Repeat([]byte{byte(i)}, 16))
		}
		encoded, err := canonicalBytes(request.ProtoReflect())
		if err != nil {
			t.Fatal(err)
		}
		err = validateWireMessage(encoded, request.ProtoReflect().Descriptor())
		if (err == nil) != (count == MaxReclaimBatch) {
			t.Fatalf("reclaim count=%d grammar=%v", count, err)
		}
	}

	readDir := (&authoritypb.ReadDirRequest{}).ProtoReflect().Descriptor().Fields()
	if readDir.ByName("held_identities").Number() != 6 {
		t.Fatal("ReadDirRequest.held_identities did not retain additive tag 6")
	}
	dirent := (&authoritypb.Dirent{}).ProtoReflect().Descriptor().Fields()
	if dirent.ByName("stable_identity").Number() != 7 {
		t.Fatal("Dirent.stable_identity did not retain additive tag 7")
	}
	reclaim := (&authoritypb.ReclaimRequest{}).ProtoReflect().Descriptor().Fields()
	if reclaim.ByName("item").Number() != 1 || reclaim.ByName("items").Number() != 2 {
		t.Fatal("ReclaimRequest singular/batch tags changed")
	}
}
