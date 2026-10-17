//go:build linux

package authorityrpc

import (
	"crypto/tls"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

func TestFskitVersionedMetadataHelloActivateAndKeepAliveOptIn(t *testing.T) {
	for _, negotiated := range []bool{false, true} {
		t.Run(map[bool]string{false: "old daemon", true: "negotiated"}[negotiated], func(t *testing.T) {
			h, _, _, _ := newProtocol5Handler(t, nil)
			h.MaxFrame, h.MaxRead, h.MaxWrite = testMaxFrame, 1<<20, 1<<20
			h.MaxRetainedReplyBytes = 8 << 20
			address, clientTLS, stop := startTestServer(t, h, int(h.MaxInFlight), time.Minute)
			defer stop()
			clientTLS = clientTLS.Clone()
			clientTLS.NextProtos = []string{protocolALPN}
			exchange := func(conn net.Conn, request *authoritypb.Request) *authoritypb.Response {
				t.Helper()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := writeFrame(conn, testMaxFrame, request); err != nil {
					t.Fatal(err)
				}
				response := new(authoritypb.Response)
				if err := readFrame(conn, testMaxFrame, nil, 0, response); err != nil {
					t.Fatal(err)
				}
				if response.GetRequestId() != request.GetRequestId() || response.GetErrno() != 0 {
					t.Fatalf("request %d: %v", request.GetRequestId(), response)
				}
				return response
			}
			features, _ := helloFeatures(authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR)
			if negotiated {
				features = append(features, fskitVersionedMetadataFeature)
			}
			var connections []net.Conn
			for i, role := range []authoritypb.TransportRole{authoritypb.TransportRole_TRANSPORT_ROLE_DATA, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL} {
				conn, err := tls.Dial("tcp", address, clientTLS)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				connections = append(connections, conn)
				set := connectionSetID{1}
				hello := exchange(conn, &authoritypb.Request{RequestId: uint64(i + 1), Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{
					ProtocolMajor: ProtocolMajor, FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR,
					Features: features, Role: role, ConnectionSetId: set[:],
				}}})
				if hasFeatures(hello.GetHello().GetFeatures(), []string{fskitVersionedMetadataFeature}) != negotiated {
					t.Fatalf("Hello negotiation: %v", hello)
				}
			}
			attach := exchange(connections[0], fskitAttachRequest(3))
			proof, epoch := proofFromAttach(attach), attach.GetEpoch()
			active := exchange(connections[1], &authoritypb.Request{RequestId: 4, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
				AttachAttemptId: testAttachAttempt(3), DataBindingGeneration: attach.GetAttach().GetDataBindingGeneration(), ControlBindingGeneration: attach.GetAttach().GetControlBindingGeneration(),
			}}})
			if hasFeatures(active.GetActivate().GetFeatures(), []string{fskitVersionedMetadataFeature}) != negotiated || !hasFeatures(active.GetActivate().GetFeatures(), []string{batchedCloseFeature}) {
				t.Fatalf("Activate negotiation: %v", active)
			}
			reply := exchange(connections[1], &authoritypb.Request{RequestId: 5, Epoch: epoch, Session: proof, Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
			if (reply.GetSessionValidForNanos() > 0) != negotiated || reply.GetSessionValidForNanos() > uint64(MaxCacheProof) {
				t.Fatalf("KeepAlive proof: %v", reply)
			}
			var id volumeserver.SessionID
			copy(id[:], proof.GetId())
			h.Runtime.FenceSession(id)
		})
	}
}

func TestFskitGetAttrItemAndHandleMustAgree(t *testing.T) {
	store := &versionedMetadataStore{}
	h, ctx, cred, root := resourceAdmissionFskitRequestHarness(t, store, 8, 8)
	if err := h.trackOpen(cred.ID, metadataHandle, false); err != nil {
		t.Fatal(err)
	}
	request := coherenceReadRequest(cred)
	request.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: root[:], Handle: metadataHandle[:]}}
	if reply := h.Handle(ctx, request); reply.GetErrno() != int32(syscall.EINVAL) {
		t.Fatalf("mismatched item/handle: %v", reply)
	}
}

type versionedMetadataStore struct{ resourceAdmissionFaultStore }

var metadataChild = xfsstore.Capability{0x33}
var metadataHandle = xfsstore.Capability{0x34}
var metadataDirectory = xfsstore.Capability{0x35}

func (s *versionedMetadataStore) CloseOpen(xfsstore.Capability) error { return nil }
func (s *versionedMetadataStore) IdentityOpen(handle xfsstore.Capability) ([16]byte, error) {
	if handle == metadataDirectory {
		return [16]byte{0x72}, nil
	}
	return [16]byte{metadataChild[0]}, nil
}
func (s *versionedMetadataStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if item == metadataChild {
		return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(item[0]), Size: 7, Nlink: 1, Mode: 0600}, nil
	}
	return s.resourceAdmissionFaultStore.Getattr(item)
}
func (s *versionedMetadataStore) GetattrOpen(handle xfsstore.Capability) (xfsstore.Attr, error) {
	if handle == metadataDirectory {
		return s.Getattr(xfsstore.Capability{0x72})
	}
	return s.Getattr(metadataChild)
}
func (s *versionedMetadataStore) LookupOpen(xfsstore.Capability, string) (xfsstore.Capability, xfsstore.Attr, error) {
	attr, err := s.Getattr(metadataChild)
	return metadataChild, attr, err
}
func (s *versionedMetadataStore) ReadDirOpen(xfsstore.Capability, uint64, int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	return []xfsstore.Dirent{{Name: "child", Ino: uint64(metadataChild[0]), Kind: xfsstore.KindRegular, NextCookie: 1}}, 1, [16]byte{1}, true, xfsstore.Capability{0x72}, nil
}
func TestMetadataSamplesPreserveActualObjectVersionAcrossProfiles(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR} {
		for _, operation := range []string{"lookup", "negative", "item getattr", "handle getattr", "item and handle getattr", "nonowning page", "owning page"} {
			t.Run(profile.String()+"/"+operation, func(t *testing.T) {
				store := &versionedMetadataStore{resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: metadataChild}}
				if operation == "negative" {
					store.lookupItem = xfsstore.Capability{}
				}
				h, ctx, cred, root := resourceAdmissionRequestHarnessForProfile(t, store, 16, 16, profile)
				h.coherenceCommitMu.Lock()
				h.coherenceVersion = 11
				h.coherenceCommitMu.Unlock()
				h.objectVersions = map[[16]byte]uint64{{metadataChild[0]}: 4}
				if err := h.trackItem(cred.ID, metadataChild, false); err != nil {
					t.Fatal(err)
				}
				for _, handle := range []xfsstore.Capability{metadataHandle, metadataDirectory} {
					if err := h.trackOpen(cred.ID, handle, false); err != nil {
						t.Fatal(err)
					}
				}
				request := coherenceReadRequest(cred)
				switch operation {
				case "lookup", "negative":
					request.Body = &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: root[:], Name: []byte("child")}}
					stampMutation(t, request, 0, 1)
				case "item getattr":
					request.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: metadataChild[:]}}
				case "handle getattr", "item and handle getattr":
					get := &authoritypb.GetAttrRequest{Handle: metadataHandle[:]}
					if operation == "item and handle getattr" {
						get.Item = metadataChild[:]
					}
					request.Body = &authoritypb.Request_GetAttr{GetAttr: get}
				default:
					request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: metadataDirectory[:], MaxEntries: 8, WantItems: operation == "owning page"}}
					stampMutation(t, request, 0, 1)
				}
				reply := h.Handle(ctx, request)
				if operation == "item and handle getattr" && profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES {
					if reply.GetErrno() != int32(syscall.EINVAL) {
						t.Fatalf("Linux accepted both fields: %v", reply)
					}
					return
				}
				if reply.GetErrno() != 0 {
					t.Fatalf("sample=%v", reply)
				}
				var v, s uint64
				switch operation {
				case "negative":
					if reply.GetLookup().GetNegativeSnapshotSequence() != 11 {
						t.Fatalf("negative storage cut=%v", reply)
					}
					return
				case "lookup":
					v, s = reply.GetLookup().GetItem().GetObjectVersion(), reply.GetLookup().GetItem().GetSnapshotSequence()
				case "item getattr", "handle getattr", "item and handle getattr":
					v, s = reply.GetGetAttr().GetObjectVersion(), reply.GetGetAttr().GetSnapshotSequence()
				default:
					entries := reply.GetReadDir().GetEntries()
					if len(entries) != 1 {
						t.Fatalf("page=%v", reply)
					}
					entry := entries[0]
					v, s = entry.GetObjectVersion(), entry.GetSnapshotSequence()
					if item := entry.GetItem(); item != nil && (item.ObjectVersion != v || item.SnapshotSequence != s || !proto.Equal(item.Attr, entry.Attr)) {
						t.Fatalf("nested page sample differs: %v", entry)
					}
				}
				if v != 4 || s != 11 {
					t.Fatalf("v=%d s=%d; want actual v=4, storage s=11", v, s)
				}
			})
		}
	}
}

type opaqueMetadataPageStore struct{ resourceAdmissionFaultStore }

func (s *opaqueMetadataPageStore) ReadDirOpen(xfsstore.Capability, uint64, int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	return []xfsstore.Dirent{{Name: "opaque", Ino: 99, Kind: xfsstore.KindOpaque, NextCookie: 1}}, 1, [16]byte{1}, true, xfsstore.Capability{0x72}, nil
}
func (s *opaqueMetadataPageStore) CloseOpen(xfsstore.Capability) error { return nil }

func TestFskitOpaqueReadDirWaitsForNameStabilization(t *testing.T) {
	h, ctx, cred, root := resourceAdmissionFskitRequestHarness(t, &opaqueMetadataPageStore{}, 8, 8)
	if err := h.trackOpen(cred.ID, root, false); err != nil {
		t.Fatal(err)
	}
	target := volumeserver.VisibilityTarget{Scope: volumeserver.VisibilityNamespace, ParentIdentity: [16]byte{root[0]}, ParentKernelIno: uint64(root[0]), Name: []byte("opaque")}
	gate := volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{{ParentIdentity: target.ParentIdentity, Name: target.Name}}}
	applying, proceed, applied := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	release := sync.OnceFunc(func() { close(proceed) })
	defer release()
	go func() {
		applied <- h.Visibility.ExecuteWithSourceGate(ctx, cred.ID, volumeserver.MutationID{Slot: 1, Sequence: 1}, h.Visibility.DeclareSourceGate(gate), gate, func() (volumeserver.SourcePublicationGate, error) { return gate, nil }, func() ([]volumeserver.VisibilityTarget, error) { return []volumeserver.VisibilityTarget{target}, nil }, func() ([]volumeserver.VisibilityTarget, bool) { close(applying); <-proceed; return nil, false }, func() ([]volumeserver.VisibilityResolution, error) { return nil, nil })
	}()
	select {
	case <-applying:
	case err := <-applied:
		t.Fatalf("open name barrier: %v", err)
	case <-time.After(time.Second):
		t.Fatal("name barrier missing")
	}
	request := coherenceReadRequest(cred)
	request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: root[:], MaxEntries: 8}}
	stampMutation(t, request, 0, 1)
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.Handle(ctx, request) }()
	select {
	case <-done:
		t.Fatal("opaque names escaped the pending name barrier")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	select {
	case reply := <-done:
		if reply.GetErrno() != 0 || len(reply.GetReadDir().GetEntries()) != 1 {
			t.Fatalf("opaque page: %v", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("opaque page did not finish")
	}
}
