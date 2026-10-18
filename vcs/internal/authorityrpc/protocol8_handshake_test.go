package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestProtocol8TLSRefusesUnequalALPN(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS = serverTLS.Clone()
	clientTLS = clientTLS.Clone()
	serverTLS.NextProtos = []string{protocolALPN}
	clientTLS.NextProtos = []string{"portablefs-authority-unknown"}

	clientRaw, serverRaw := net.Pipe()
	client := newAuthorityTLSClient(clientRaw, clientTLS)
	server := newAuthorityTLSServer(serverRaw, serverTLS)
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	errors := make(chan error, 2)
	go func() { errors <- server.HandshakeContext(ctx) }()
	go func() { errors <- client.HandshakeContext(ctx) }()
	first, second := <-errors, <-errors
	if first == nil || second == nil {
		t.Fatalf("unequal ALPN handshake errors = (%v, %v), want both peers to refuse", first, second)
	}
	detail := first.Error() + "; " + second.Error()
	if !strings.Contains(detail, "application protocol") {
		t.Fatalf("unequal ALPN refusal = %q, want a clear application-protocol error", detail)
	}
}

func TestProtocol8BothTransportHandshakesRefuseUnequalMajor(t *testing.T) {
	for _, role := range []authoritypb.TransportRole{authoritypb.TransportRole_TRANSPORT_ROLE_DATA, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL} {
		for _, major := range []uint32{0, ProtocolMajor - 1, ProtocolMajor + 1, math.MaxUint32} {
			t.Run(fmt.Sprintf("%s/%d", role, major), func(t *testing.T) {
				address, clientTLS, stop := startWrongHelloEchoServer(t, func(reply *authoritypb.HelloReply) { reply.ProtocolMajor = major })
				defer stop()
				client := newReconnectTestClient(address, clientTLS)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				opened, err := client.openTransport(ctx, role)
				closeNegotiations(opened)
				if !errors.Is(err, ErrTransportBinding) {
					t.Fatalf("unequal major accepted: %v", err)
				}
			})
		}
	}
}

func TestDelegationReferenceIsPartOfMutationFingerprint(t *testing.T) {
	runtime, err := volumeserver.New("delegation-fingerprint", volumeserver.Config{
		ContinuousNow:  func() (time.Duration, error) { return 0, nil },
		SessionLease:   time.Minute,
		MaxReplaySlots: 1,
		MaxSessions:    1,
		MaxLockRecords: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	builders := []struct {
		name  string
		build func(*authoritypb.DelegationRef) *authoritypb.Request
	}{
		{
			name: "write",
			build: func(delegation *authoritypb.DelegationRef) *authoritypb.Request {
				return &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
					Handle: bytes.Repeat([]byte{0x11}, 16), Position: 9, Size: 3,
					Data: []byte("abc"), Delegation: delegation,
				}}}
			},
		},
		{
			name: "setattr",
			build: func(delegation *authoritypb.DelegationRef) *authoritypb.Request {
				return &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{
					Item: bytes.Repeat([]byte{0x22}, 16), Size: int64Pointer(17), Delegation: delegation,
				}}}
			},
		},
		{
			name: "fallocate",
			build: func(delegation *authoritypb.DelegationRef) *authoritypb.Request {
				return &authoritypb.Request{Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{
					Handle: bytes.Repeat([]byte{0x33}, 16), Offset: 1, Length: 4096, Delegation: delegation,
				}}}
			},
		},
	}
	for _, test := range builders {
		t.Run(test.name, func(t *testing.T) {
			fingerprint := func(id byte, generation uint64) volumeserver.RequestFingerprint {
				t.Helper()
				got, err := canonicalFingerprint(runtime, test.build(&authoritypb.DelegationRef{
					Id: bytes.Repeat([]byte{id}, 16), Generation: generation,
				}))
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			base := fingerprint(0x44, 7)
			if changedID := fingerprint(0x45, 7); changedID == base {
				t.Fatal("changing delegation id did not change the mutation fingerprint")
			}
			if changedGeneration := fingerprint(0x44, 8); changedGeneration == base {
				t.Fatal("changing delegation generation did not change the mutation fingerprint")
			}
		})
	}
}

func int64Pointer(value int64) *int64 {
	return &value
}
