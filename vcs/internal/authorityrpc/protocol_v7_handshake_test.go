package authorityrpc

import (
	"bytes"
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestProtocolV7TLSRefusesV6ALPN(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS = serverTLS.Clone()
	clientTLS = clientTLS.Clone()
	serverTLS.NextProtos = []string{protocolALPN}
	clientTLS.NextProtos = []string{"portablefs-authority-v6"}

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
		t.Fatalf("v6 ALPN handshake errors = (%v, %v), want both peers to refuse", first, second)
	}
	detail := first.Error() + "; " + second.Error()
	if !strings.Contains(detail, "application protocol") {
		t.Fatalf("v6 ALPN refusal = %q, want a clear application-protocol error", detail)
	}
}

func TestProtocolV7ClientRefusesV6Hello(t *testing.T) {
	address, clientTLS, stop := startWrongHelloEchoServer(t, func(reply *authoritypb.HelloReply) {
		reply.ProtocolMajor = 6
	})
	defer stop()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := DialClient(ctx, coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err == nil {
		_ = client.Close()
		t.Fatal("protocol-v7 client accepted a protocol-v6 Hello")
	}
	if !strings.Contains(err.Error(), "protocol handshake refused") {
		t.Fatalf("v6 Hello refusal = %v, want a clear protocol-handshake refusal", err)
	}
}

func TestProtocolV7FeatureSetsAreExact(t *testing.T) {
	commonHello := []string{
		"xfs-current-state",
		"session-exact-epoch",
		"framed-bulk-data-v1",
		"authority-keyed-replay-fingerprint-v1",
		"mandatory-dual-transport-v1",
		"exact-resource-acquisition",
	}
	commonActivate := []string{
		"no-history",
		"no-branches",
		"user-xattr-readonly",
		"single-principal",
		"stable-item-identity",
		"volume-syncfs-barrier",
		"exact-resource-acquisition",
	}
	tests := []struct {
		name     string
		profile  authoritypb.FrontendProfile
		hello    []string
		activate []string
	}{
		{
			name:     "cacheless",
			profile:  authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER,
			hello:    append(append([]string(nil), commonHello...), "cacheless-peer-reader-v1"),
			activate: append(append([]string(nil), commonActivate...), "cacheless-peer-reader-v1"),
		},
		{
			name:     "unspecified",
			profile:  authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED,
			hello:    commonHello,
			activate: commonActivate,
		},
		{
			name:    "linux",
			profile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES,
			hello: append(append([]string(nil), commonHello...),
				"direct-write", "volume-subscription-v1", "ordered-change-stream-v1", "file-write-delegation-v1"),
			activate: append(append([]string(nil), commonActivate...),
				"direct-io-no-file-mmap", "distributed-posix-locks", "delegation-control-v1",
				"session-durable-sequence-v1", "root-directory-barrier-v1", "bounded-control-replay-v1",
				"foreground-visibility-completion-v1"),
		},
		{
			name:    "fskit",
			profile: authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR,
			hello: append(append([]string(nil), commonHello...),
				"fskit-sync-repair-v1", "fskit-source-publication-v1", "fskit-fragmented-write-v1"),
			activate: append(append([]string(nil), commonActivate...),
				"write-through", "fskit-sync-repair-v1", "fskit-source-publication-v1",
				"fskit-fragmented-write-v1", "peer-complete-fifo-feedback"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hello, ok := helloFeatures(test.profile)
			if !ok || !slices.Equal(hello, test.hello) {
				t.Fatalf("Hello features = %v, valid=%t; want exactly %v", hello, ok, test.hello)
			}
			activate, ok := activateFeatures(test.profile)
			if !ok || !slices.Equal(activate, test.activate) {
				t.Fatalf("Activate features = %v, valid=%t; want exactly %v", activate, ok, test.activate)
			}
		})
	}
	if !slices.Equal(requiredHelloFeatures, tests[2].hello) {
		t.Fatalf("Linux Hello alias = %v, want exactly %v", requiredHelloFeatures, tests[2].hello)
	}
	if !slices.Equal(requiredAttachFeatures, commonActivate) {
		t.Fatalf("common Activate alias = %v, want exactly %v", requiredAttachFeatures, commonActivate)
	}
	wantStrict := tests[2].activate[len(commonActivate):]
	if !slices.Equal(requiredStrictAttachFeatures, wantStrict) {
		t.Fatalf("Linux strict Activate alias = %v, want exactly %v", requiredStrictAttachFeatures, wantStrict)
	}
}

func TestDelegationReferenceIsPartOfMutationFingerprint(t *testing.T) {
	runtime, err := volumeserver.New("protocol-v7-delegation-fingerprint", volumeserver.Config{
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
