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
		Purpose:         authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES,
		Address:         address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	id := client.SessionID()
	want := bytes.Repeat([]byte{0x52}, 16)
	if len(id) != 16 || !bytes.Equal(id, want) {
		t.Fatalf("SessionID = %x, want the 16-byte attach-reply session ID", id)
	}
	id[0] = 0xff
	if client.SessionID()[0] != want[0] {
		t.Fatal("SessionID handed out its internal buffer")
	}
}
