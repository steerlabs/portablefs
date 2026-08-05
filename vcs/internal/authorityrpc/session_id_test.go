package authorityrpc

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// A strict frontend cannot recognise its own mutations in a visibility event
// without this, so it must refuse to run strict at all.
func TestClientExposesItsSessionID(t *testing.T) {
	handler := &strictContractHandler{epoch: make([]byte, 16), maxInFlight: 5}
	address, clientTLS, stop := startTestServer(t, handler, 5, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 4096, RepairBudget: 2 * time.Second,
		NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	id := client.SessionID()
	if len(id) != 16 || !bytes.Equal(id, make([]byte, 16)) {
		t.Fatalf("SessionID = %x, want the 16-byte attach-reply session ID", id)
	}
	id[0] = 0xff
	if client.SessionID()[0] != 0 {
		t.Fatal("SessionID handed out its internal buffer")
	}
}
