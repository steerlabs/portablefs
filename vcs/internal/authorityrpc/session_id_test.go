package authorityrpc

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// The session identity lets consumers recognize their own authority changes.
func TestClientExposesItsSessionID(t *testing.T) {
	handler := &strictContractHandler{epoch: make([]byte, 16), maxInFlight: 9}
	address, clientTLS, stop := startTestServer(t, handler, 9, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Purpose:         authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX,
		Address:         address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 9, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 9,
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
