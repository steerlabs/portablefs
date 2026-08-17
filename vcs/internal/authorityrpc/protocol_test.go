package authorityrpc

import (
	"bytes"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

var (
	benchmarkRequest *authoritypb.Request
	benchmarkValue   any
)

// BenchmarkWriteMutationEncoding keeps the large-write hot path visible. A
// write is already durable-current-state work; replay identity and framing may
// authenticate and encode those bytes, but should not manufacture additional
// payload-sized copies just to do so.
func BenchmarkWriteMutationEncoding(b *testing.B) {
	request := &authoritypb.Request{Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
		TransactionId: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
		Handle: make([]byte, 16), Data: make([]byte, 1<<20), FragmentOffset: 4096,
	}}}
	runtime, err := volumeserver.New("benchmark", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(1 << 20)
	b.Run("authority-fingerprint", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkValue, _ = canonicalFingerprint(runtime, request)
		}
	})
	b.Run("clone", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkRequest = proto.Clone(request).(*authoritypb.Request)
		}
	})
	b.Run("marshal", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkValue, _ = proto.MarshalOptions{Deterministic: true}.Marshal(request)
		}
	})
}

func TestCanonicalStreamMatchesFrozenEncoding(t *testing.T) {
	tests := []struct {
		name    string
		request *authoritypb.Request
		want    []byte
	}{
		{
			name: "write-transaction-data",
			request: &authoritypb.Request{Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
				TransactionId: 1, FragmentOffset: 129, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
				Handle: []byte{0x31, 0x32}, Data: []byte{0xA5, 0x5A},
			}}},
			// request field 46; WriteTransactionRequest fields 1, 2, 4, 10, 11.
			want: []byte{0xF2, 0x02, 0x0F, 0x08, 0x01, 0x12, 0x02, 0x31, 0x32, 0x20, 0x81, 0x01, 0x50, 0x02, 0x5A, 0x02, 0xA5, 0x5A},
		},
		{
			name: "setattr",
			request: &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{
				Item: []byte{0x42, 0x43}, Mode: proto.Uint32(0o755), MtimeNs: proto.Int64(-2),
			}}},
			// request field 22; SetAttrRequest fields 1, 3, and 8.
			want: []byte{0xB2, 0x01, 0x12, 0x0A, 0x02, 0x42, 0x43, 0x18, 0xED, 0x03, 0x40, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01},
		},
		{
			name:    "reclaim",
			request: &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: []byte{1, 2, 3}}}},
			want:    []byte{0xA2, 0x02, 0x05, 0x0A, 0x03, 0x01, 0x02, 0x03},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got bytes.Buffer
			if err := canonicalWrite(&got, test.request.ProtoReflect()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), test.want) {
				t.Fatalf("canonical encoding differs\n got %x\nwant %x", got.Bytes(), test.want)
			}
		})
	}
}

func TestAuthorityProtocolV5RequiresDualTransportAndExactResourceAcquisition(t *testing.T) {
	if ProtocolMajor != 5 || ProtocolALPN != "portablefs-authority-v5" {
		t.Fatalf("authority protocol=(major %d, ALPN %q), want (5, portablefs-authority-v5)", ProtocolMajor, ProtocolALPN)
	}
	required := []string{"exact-resource-acquisition", "mandatory-dual-transport-v1", strictWriteTransactionFeature, oneShotWriteFeature, strictLinuxMutationSuiteFeature, terminalAppliedDeliveryFeature, sequencedVisibilityRetryFeature, locklessNamespaceRepairFeature}
	if !hasFeatures(requiredHelloFeatures, required) {
		t.Fatalf("Hello features %v omit protocol-5 requirements %v", requiredHelloFeatures, required)
	}
	if !hasFeatures(requiredAttachFeatures, []string{"exact-resource-acquisition"}) {
		t.Fatalf("Attach features %v omit exact-resource-acquisition", requiredAttachFeatures)
	}
	postBinding := []string{"namespace-post-binding-identity"}
	if !hasFeatures(requiredHelloFeatures, postBinding) {
		t.Fatalf("Hello features %v omit namespace-post-binding-identity", requiredHelloFeatures)
	}
	if !hasFeatures(requiredStrictAttachFeatures, postBinding) {
		t.Fatalf("strict Attach features %v omit namespace-post-binding-identity", requiredStrictAttachFeatures)
	}
	sourceGate := []string{"source-publication-gate-v1"}
	if !hasFeatures(requiredHelloFeatures, sourceGate) {
		t.Fatalf("Hello features %v omit source-publication-gate-v1", requiredHelloFeatures)
	}
	if !hasFeatures(requiredStrictAttachFeatures, sourceGate) {
		t.Fatalf("strict Attach features %v omit source-publication-gate-v1", requiredStrictAttachFeatures)
	}
	if !hasFeatures(requiredStrictAttachFeatures, []string{sequencedVisibilityRetryFeature}) {
		t.Fatalf("strict Attach features %v omit %s", requiredStrictAttachFeatures, sequencedVisibilityRetryFeature)
	}
	if !hasFeatures(requiredAttachFeatures, []string{oneShotWriteFeature}) {
		t.Fatalf("Attach features %v omit %s", requiredAttachFeatures, oneShotWriteFeature)
	}
}

func TestSourcePublicationGatePresenceMatchesVisibleOperationMatrix(t *testing.T) {
	visible := []struct {
		name    string
		request *authoritypb.Request
	}{
		{name: "setattr", request: &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{}}}},
		{name: "fallocate", request: &authoritypb.Request{Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{}}}},
		{name: "copy-file-range", request: &authoritypb.Request{Body: &authoritypb.Request_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeRequest{}}}},
		{name: "one-shot-write", request: &authoritypb.Request{Body: &authoritypb.Request_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteRequest{}}}},
		{name: "create", request: &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{}}}},
		{name: "mkdir", request: &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{}}}},
		{name: "unlink", request: &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{}}}},
		{name: "rename", request: &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{}}}},
		{name: "link", request: &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{}}}},
		{name: "symlink", request: &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{}}}},
		{name: "setxattr", request: &authoritypb.Request{Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{}}}},
		{name: "removexattr", request: &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{}}}},
		{name: "open truncate", request: &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Flags: &authoritypb.OpenFlags{Truncate: true}}}}},
	}
	for _, test := range visible {
		t.Run(test.name, func(t *testing.T) {
			request := proto.Clone(test.request).(*authoritypb.Request)
			if validSourcePublicationGatePresence(request) {
				t.Fatal("visible mutation without source publication gate was accepted")
			}
			request.SourcePublicationGate = &authoritypb.SourcePublicationGate{}
			if !validSourcePublicationGatePresence(request) {
				t.Fatal("visible mutation with source publication gate was refused")
			}
		})
	}

	nonVisible := []struct {
		name    string
		request *authoritypb.Request
	}{
		{name: "lookup", request: &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{}}}},
		{name: "open", request: &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Flags: &authoritypb.OpenFlags{Read: true}}}}},
		{name: "close", request: &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{}}}},
		{name: "read", request: &authoritypb.Request{Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{}}}},
		{name: "tmpfile", request: &authoritypb.Request{Body: &authoritypb.Request_Tmpfile{Tmpfile: &authoritypb.TmpfileRequest{}}}},
		{name: "readdir", request: &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{}}}},
		{name: "reclaim", request: &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{}}}},
		{name: "setlock", request: &authoritypb.Request{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{}}}},
	}
	for _, test := range nonVisible {
		t.Run(test.name, func(t *testing.T) {
			request := proto.Clone(test.request).(*authoritypb.Request)
			if !validSourcePublicationGatePresence(request) {
				t.Fatal("non-visible operation without source publication gate was refused")
			}
			request.SourcePublicationGate = &authoritypb.SourcePublicationGate{}
			if validSourcePublicationGatePresence(request) {
				t.Fatal("non-visible operation carrying source publication gate was accepted")
			}
		})
	}
}

func TestVisibilityRetryRequestShapeAdmitsExactNamespaceGate(t *testing.T) {
	identity := make([]byte, 16)
	identity[0] = 1
	itemWire := &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{{
		Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
			Identity: identity, Attributes: true,
		}},
	}}}
	itemRequest := &authoritypb.Request{
		FrontendOperationId:          77,
		VisibilityRetryAfterSequence: 41,
		SourcePublicationGate:        itemWire,
		Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{
			Item: make([]byte, 16), Name: []byte("user.retry"), Value: []byte("v"),
		}},
	}
	decoded, err := decodeSourcePublicationGate(itemRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !validVisibilityRetryRequestShape(itemRequest, decoded) {
		t.Fatal("exact item retry proof was refused")
	}
	namespaceRequest := proto.Clone(itemRequest).(*authoritypb.Request)
	namespaceRequest.SourcePublicationGate = &authoritypb.SourcePublicationGate{
		Targets: []*authoritypb.SourcePublicationTarget{{
			Coordinate: &authoritypb.SourcePublicationTarget_Namespace{Namespace: &authoritypb.SourcePublicationNamespace{
				ParentIdentity: identity, Name: []byte("child"),
			}},
		}},
	}
	namespaceGate, err := decodeSourcePublicationGate(namespaceRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !validVisibilityRetryRequestShape(namespaceRequest, namespaceGate) {
		t.Fatal("exact namespace retry proof was refused")
	}

	for name, mutate := range map[string]func(*authoritypb.Request){
		"missing operation identity": func(request *authoritypb.Request) { request.FrontendOperationId = 0 },
		"read-only request": func(request *authoritypb.Request) {
			request.SourcePublicationGate = nil
			request.Body = &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := proto.Clone(itemRequest).(*authoritypb.Request)
			mutate(request)
			gate, err := decodeSourcePublicationGate(request)
			if err != nil {
				t.Fatal(err)
			}
			if validVisibilityRetryRequestShape(request, gate) {
				t.Fatal("invalid visibility retry request shape was accepted")
			}
		})
	}
}

func TestVisibilityRetryProofEntersReplayFingerprint(t *testing.T) {
	runtime, err := volumeserver.New("retry-proof-fingerprint", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, 16)
	identity[0] = 1
	request := &authoritypb.Request{
		SourcePublicationGate: &authoritypb.SourcePublicationGate{
			Targets: []*authoritypb.SourcePublicationTarget{
				{
					Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
						Identity: identity, Attributes: true,
					}},
				},
			},
		},
		Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{
			Item: make([]byte, 16), Name: []byte("user.retry"), Value: []byte("v"),
		}},
	}
	without, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	request.VisibilityRetryAfterSequence = 41
	with, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	if without == with {
		t.Fatal("visibility retry proof was omitted from the retained replay identity")
	}
}

// A blocking lock wait parks for as long as the conflicting holder chooses.
// Classifying it as a topology request would hold the coordinator's read
// guard across that unbounded park, so one waiter plus one queued ApplyRoutes
// writer would stall every guarded request on the volume. The wait never
// reaches XFS — the lock table is authority-epoch runtime state — so it is
// admitted through the ordinary session-routes check instead. Non-blocking
// lock calls complete immediately and keep the guard.
func TestRequestUsesTopologyReleasesBlockingLockWaits(t *testing.T) {
	setLock := func(wait, unlock bool) *authoritypb.Request {
		return &authoritypb.Request{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{
			Lock: &authoritypb.LockSpec{Write: true, Range: &authoritypb.LockRange{}}, Wait: wait, Unlock: unlock,
		}}}
	}
	if requestUsesTopology(setLock(true, false)) {
		t.Fatal("a blocking lock wait must not hold the topology read guard")
	}
	if !requestUsesTopology(setLock(false, false)) {
		t.Fatal("a non-blocking lock call completes immediately and keeps the guard")
	}
	if !requestUsesTopology(setLock(true, true)) {
		t.Fatal("an unlock never blocks and keeps the guard")
	}
	if !requestUsesTopology(&authoritypb.Request{Body: &authoritypb.Request_GetLock{GetLock: &authoritypb.GetLockRequest{}}}) {
		t.Fatal("a lock query completes immediately and keeps the guard")
	}
	for _, request := range []*authoritypb.Request{
		{Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}},
		{Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{}}},
		{Body: &authoritypb.Request_AbortAttach{AbortAttach: &authoritypb.AbortAttachRequest{}}},
	} {
		if requestUsesTopology(request) {
			t.Fatalf("lifecycle request %T must own its explicit topology boundary", request.GetBody())
		}
	}
}
