package authorityrpc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestKeepAliveProofCanonicalFrame(t *testing.T) {
	reply := &authoritypb.Response{RequestId: 1, SessionValidForNanos: uint64(MaxCacheProof)}
	raw, err := canonicalBytes(reply.ProtoReflect())
	if err != nil {
		t.Fatal(err)
	}
	const golden = "0801c00480b09dc2df01"
	if hex.EncodeToString(raw) != golden {
		t.Fatalf("canonical proof = %x", raw)
	}
	assertCanonicalRoundTrip(t, reply)
	assertFrameRoundTrip(t, reply)
	for _, value := range []uint64{0, 1, uint64(time.Millisecond) - 1, uint64(MaxCacheProof) + 1, math.MaxUint64} {
		raw := protowire.AppendTag(nil, 72, protowire.VarintType)
		raw = protowire.AppendVarint(raw, value)
		if err := validateWireMessage(raw, reply.ProtoReflect().Descriptor()); !errors.Is(err, ErrFrameEncoding) {
			t.Fatalf("proof %d grammar accepted: %v", value, err)
		}
	}
	for _, reply := range []*authoritypb.Response{
		{SessionValidForNanos: uint64(MaxCacheProof), Errno: 5},
		{SessionValidForNanos: uint64(MaxCacheProof), Body: &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{}}},
		{SessionValidForNanos: uint64(MaxCacheProof) + uint64(time.Millisecond)},
	} {
		var frame bytes.Buffer
		if err := writeFrame(&frame, 1<<20, reply); !errors.Is(err, ErrFrameEncoding) {
			t.Fatalf("invalid proof envelope accepted: %v", err)
		}
	}
}

func TestVersionedMetadataNegotiationCannotChangeAcrossRolesOrRecovery(t *testing.T) {
	for _, initial := range []bool{false, true} {
		r, err := newTransportRegistry(4)
		if err != nil {
			t.Fatal(err)
		}
		peer, set := volumeserver.PeerIdentity{1}, connectionSetID{2}
		entry, err := r.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_DATA, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR, func() {}, func() error { return nil }, false, initial)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, entry.profile, func() {}, func() error { return nil }, false, !initial); !errors.Is(err, ErrTransportBinding) {
			t.Fatalf("changed negotiation admitted: %v", err)
		}
		if _, err := r.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, entry.profile, func() {}, func() error { return nil }, false, initial); err != nil {
			t.Fatal(err)
		}
		r.mu.Lock()
		entry.pair.session = volumeserver.SessionID{3}
		entry.pair.state = authoritypb.SessionState_SESSION_STATE_ACTIVE
		r.mu.Unlock()
		if _, err := r.register(peer, set, entry.role, entry.profile, func() {}, func() error { return nil }, false, !initial); !errors.Is(err, ErrTransportBinding) {
			t.Fatalf("recovery changed negotiation: %v", err)
		}
		candidate, err := r.register(peer, set, entry.role, entry.profile, func() {}, func() error { return nil }, false, initial)
		if err != nil || candidate.versionedMetadata != initial {
			t.Fatalf("same-session recovery=%v, %v", candidate, err)
		}
	}
}
