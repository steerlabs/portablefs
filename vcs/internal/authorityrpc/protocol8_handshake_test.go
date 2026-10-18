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

// Exercise the server's real first-frame transition on each authenticated
// transport role, rather than just calling the role-independent major helper.
func TestProtocol8ServerBothRolesRefuseUnequalMajor(t *testing.T) {
	for _, role := range []authoritypb.TransportRole{authoritypb.TransportRole_TRANSPORT_ROLE_DATA, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL} {
		for _, major := range []uint32{0, ProtocolMajor - 1, ProtocolMajor + 1, math.MaxUint32} {
			t.Run(fmt.Sprintf("%s/%d", role, major), func(t *testing.T) {
				server := transportHelloTestServer(t, 9)
				if err := exchangeTransportHello(t, server, role, major); !errors.Is(err, ErrTransportBinding) || !strings.Contains(err.Error(), "protocol major") {
					t.Fatalf("unequal major accepted or refused for wrong reason: %v", err)
				}
				if len(server.registry.pairs) != 0 {
					t.Fatal("refused Hello published a transport binding")
				}
			})
		}
	}
}

func TestProtocol8LinuxClientRefusesInsufficientCapacityBeforeDial(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	for limit := 2; limit < MinimumLinuxInFlight; limit++ {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			cfg := coherentTestClientConfig("invalid address must never be dialed", clientTLS, "volume", uint32(limit), limit)
			client, err := DialClient(t.Context(), cfg)
			if client != nil || err == nil || !strings.Contains(err.Error(), "Linux max-in-flight must be at least 9") {
				t.Fatalf("limit=%d client=%v err=%v", limit, client, err)
			}
		})
	}
}

func TestProtocol8LinuxServerRefusesInsufficientCapacity(t *testing.T) {
	for _, role := range []authoritypb.TransportRole{authoritypb.TransportRole_TRANSPORT_ROLE_DATA, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL} {
		for limit := 2; limit < MinimumLinuxInFlight; limit++ {
			t.Run(fmt.Sprintf("%s/%d", role, limit), func(t *testing.T) {
				server := transportHelloTestServer(t, limit)
				if err := exchangeTransportHello(t, server, role, ProtocolMajor); !errors.Is(err, ErrTransportBinding) || !strings.Contains(err.Error(), "bound is below 9") {
					t.Fatalf("insufficient Linux capacity accepted or refused for wrong reason: %v", err)
				}
				if len(server.registry.pairs) != 0 {
					t.Fatal("refused Hello published a transport binding")
				}
			})
		}
	}
}

func transportHelloTestServer(t *testing.T, limit int) *Server {
	t.Helper()
	server := &Server{
		Handler:  clientTestHandler{epoch: bytes.Repeat([]byte{1}, 16), maxInFlight: limit},
		MaxFrame: testMaxFrame, MaxInFlight: limit, MaxConnections: 2,
		MaxFrameBytesInFlight: MinimumFrameBytesInFlight(testBounds(limit).MaxRequestFrame),
		HandshakeTimeout:      time.Second, WriteTimeout: time.Second,
	}
	server.initializeFrameBudget()
	if err := server.initializeTransportRegistry(); err != nil {
		t.Fatal(err)
	}
	return server
}

func exchangeTransportHello(t *testing.T, server *Server, role authoritypb.TransportRole, major uint32) error {
	t.Helper()
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	sent := make(chan error, 1)
	go func() {
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		sent <- writeFrame(client, testMaxFrame, &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{
			ProtocolMajor: major, Role: role, FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX,
			ConnectionSetId: bytes.Repeat([]byte{2}, 32),
		}}})
	}()
	_, _, err := server.acceptTransportHello(ctx, cancel, peer, server.Handler.Bounds(), volumeserver.PeerIdentity{3})
	if sendErr := <-sent; sendErr != nil {
		t.Fatal(sendErr)
	}
	return err
}
