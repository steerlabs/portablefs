package authorityrpc

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

func TestEveryAuthorityRequestBodyHasExplicitFrontendProfileClassification(t *testing.T) {
	tests := []struct {
		body  any
		linux bool
		fskit bool
	}{
		{&authoritypb.Request_Hello{}, true, true},
		{&authoritypb.Request_Attach{}, true, true},
		{&authoritypb.Request_Resume{}, true, true},
		{&authoritypb.Request_KeepAlive{}, true, true},
		{&authoritypb.Request_Detach{}, true, true},
		{&authoritypb.Request_Cancel{}, true, true},
		{&authoritypb.Request_Reauthorize{}, true, true},
		{&authoritypb.Request_Lookup{}, true, true},
		{&authoritypb.Request_GetAttr{}, true, true},
		{&authoritypb.Request_SetAttr{}, true, true},
		{&authoritypb.Request_Create{}, true, true},
		{&authoritypb.Request_Mkdir{}, true, true},
		{&authoritypb.Request_Unlink{}, true, true},
		{&authoritypb.Request_Rename{}, true, true},
		{&authoritypb.Request_Link{}, true, true},
		{&authoritypb.Request_Symlink{}, true, true},
		{&authoritypb.Request_Readlink{}, true, true},
		{&authoritypb.Request_Open{}, true, true},
		{&authoritypb.Request_Close{}, true, true},
		{&authoritypb.Request_Read{}, true, true},
		{&authoritypb.Request_Fsync{}, true, true},
		{&authoritypb.Request_ReadDir{}, true, true},
		{&authoritypb.Request_Reclaim{}, true, true},
		{&authoritypb.Request_GetXattr{}, true, true},
		{&authoritypb.Request_SetXattr{}, true, true},
		{&authoritypb.Request_ListXattr{}, true, true},
		{&authoritypb.Request_RemoveXattr{}, true, true},
		{&authoritypb.Request_StatFs{}, true, true},
		{&authoritypb.Request_SyncFs{}, true, true},
		{&authoritypb.Request_ApplyRoutes{}, true, true},
		{&authoritypb.Request_Activate{}, true, true},
		{&authoritypb.Request_AbortAttach{}, true, true},
		{&authoritypb.Request_TerminalDeliveryReceipt{}, true, true},
		{&authoritypb.Request_Flush{}, true, false},
		{&authoritypb.Request_Fallocate{}, true, false},
		{&authoritypb.Request_CopyFileRange{}, true, false},
		{&authoritypb.Request_Tmpfile{}, true, false},
		{&authoritypb.Request_GetLock{}, true, false},
		{&authoritypb.Request_SetLock{}, true, false},
		{&authoritypb.Request_Write{}, true, false},
		{&authoritypb.Request_NextLeaseEvent{}, true, false},
		{&authoritypb.Request_AcknowledgeLeaseEvent{}, true, false},
		{&authoritypb.Request_RenewLeases{}, true, false},
		{&authoritypb.Request_AcknowledgeSourceLeaseDischarge{}, true, false},
		{&authoritypb.Request_NextFskitRepair{}, false, true},
		{&authoritypb.Request_AckFskitRepair{}, false, true},
		{&authoritypb.Request_FskitWrite{}, false, true},
	}
	descriptorBodies := (&authoritypb.Request{}).ProtoReflect().Descriptor().Oneofs().ByName("body").Fields().Len()
	if len(tests) != descriptorBodies {
		t.Fatalf("profile classifier lists %d bodies but schema has %d", len(tests), descriptorBodies)
	}
	seen := make(map[reflect.Type]struct{}, len(tests))
	for _, test := range tests {
		bodyType := reflect.TypeOf(test.body)
		if _, duplicate := seen[bodyType]; duplicate {
			t.Fatalf("duplicate profile classification for %v", bodyType)
		}
		seen[bodyType] = struct{}{}
		request := &authoritypb.Request{}
		reflect.ValueOf(request).Elem().FieldByName("Body").Set(reflect.ValueOf(test.body))
		if got := requestAllowedForFrontend(request, authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES); got != test.linux {
			t.Fatalf("%T Linux allowed=%t, want %t", test.body, got, test.linux)
		}
		if got := requestAllowedForFrontend(request, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR); got != test.fskit {
			t.Fatalf("%T FSKit allowed=%t, want %t", test.body, got, test.fskit)
		}
	}
}

func TestFskitWriteAccessClassificationProtectsStagingAndAllowsAbort(t *testing.T) {
	for _, phase := range []authoritypb.FskitWritePhase{
		authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN,
		authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA,
		authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT,
	} {
		request := &authoritypb.Request{Body: &authoritypb.Request_FskitWrite{FskitWrite: &authoritypb.FskitWriteRequest{Phase: phase}}}
		if !requestRequiresWrite(request) {
			t.Fatalf("FSKit phase %s can touch staging without write access", phase)
		}
	}
	abort := &authoritypb.Request{Body: &authoritypb.Request_FskitWrite{FskitWrite: &authoritypb.FskitWriteRequest{
		Phase: authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT,
	}}}
	if requestRequiresWrite(abort) {
		t.Fatal("FSKit ABORT must remain available after an access downgrade")
	}
}

var (
	benchmarkRequest *authoritypb.Request
	benchmarkValue   any
)

// BenchmarkWriteMutationEncoding keeps the large-write hot path visible. A
// write is already durable-current-state work; replay identity and framing may
// authenticate and encode those bytes, but should not manufacture additional
// payload-sized copies just to do so.
func BenchmarkWriteMutationEncoding(b *testing.B) {
	request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
		Handle: bytes.Repeat([]byte{1}, 16), Position: 4096, Size: 1 << 20, Data: make([]byte, 1<<20),
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

func TestAuthorityProtocolV6RequiresLeaseCoherenceAndExactResourceAcquisition(t *testing.T) {
	if ProtocolMajor != 6 || ProtocolALPN != "portablefs-authority-v6" {
		t.Fatalf("authority protocol=(major %d, ALPN %q), want (6, portablefs-authority-v6)", ProtocolMajor, ProtocolALPN)
	}
	required := []string{"exact-resource-acquisition", "mandatory-dual-transport-v1", leaseCoherenceFeature, directoryEnumerationLeaseFeature}
	if !hasFeatures(requiredHelloFeatures, required) {
		t.Fatalf("Hello features %v omit protocol-6 requirements %v", requiredHelloFeatures, required)
	}
	if !hasFeatures(requiredAttachFeatures, []string{"exact-resource-acquisition"}) {
		t.Fatalf("Attach features %v omit v6 filesystem requirements", requiredAttachFeatures)
	}
	if !hasFeatures(requiredStrictAttachFeatures, []string{leaseRecallFeature, leaseRenewalFeature, openByIdentityFeature}) {
		t.Fatalf("lease Attach features %v are incomplete", requiredStrictAttachFeatures)
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
