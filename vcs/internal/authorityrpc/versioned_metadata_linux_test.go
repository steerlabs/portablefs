//go:build linux

package authorityrpc

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

func TestFskitVersionedMetadataHelloActivateAndKeepAliveOptIn(t *testing.T) {
	for _, negotiated := range []bool{false, true} {
		t.Run(map[bool]string{false: "old daemon", true: "negotiated"}[negotiated], func(t *testing.T) {
			h, ctx, cred, _ := resourceAdmissionFskitRequestHarness(t, &coherenceLookupStore{}, 8, 8)
			helloFeatures, _ := helloFeatures(authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR)
			if negotiated {
				helloFeatures = append(helloFeatures, fskitVersionedMetadataFeature)
			}
			hello := h.hello(1, &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor, FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR, Features: helloFeatures})
			if hello.GetErrno() != 0 || hasFeatures(hello.GetHello().GetFeatures(), []string{fskitVersionedMetadataFeature}) != negotiated {
				t.Fatalf("Hello feature=%v", hello)
			}
			h.resourcesMu.Lock()
			resources := h.resources[cred.ID]
			resources.versionedMetadata = negotiated
			h.resourcesMu.Unlock()
			if _, err := h.Runtime.CompatibilityExclusion(cred.ID); err != nil {
				t.Fatal(err)
			}
			active := h.newActivationReply(resources, xfsstore.Attr{Kind: xfsstore.KindDirectory}, [16]byte{1}, volumeserver.VisibilityCursor{})
			if hasFeatures(active.Features, []string{fskitVersionedMetadataFeature}) != negotiated || !hasFeatures(active.Features, []string{batchedCloseFeature}) {
				t.Fatalf("Activate features=%v", active.Features)
			}
			request := coherenceReadRequest(cred)
			request.Body = &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}
			reply := h.Handle(ctx, request)
			if reply.GetErrno() != 0 || (reply.GetSessionValidForNanos() > 0) != negotiated || reply.GetSessionValidForNanos() > uint64(MaxCacheProof) {
				t.Fatalf("KeepAlive=%v", reply)
			}
			assertFrameRoundTrip(t, reply)
		})
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
		for _, operation := range []string{"lookup", "negative", "item getattr", "handle getattr", "nonowning page", "owning page"} {
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
				case "handle getattr":
					request.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Handle: metadataHandle[:]}}
				default:
					request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: metadataDirectory[:], MaxEntries: 8, WantItems: operation == "owning page"}}
					stampMutation(t, request, 0, 1)
				}
				reply := h.Handle(ctx, request)
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
				case "item getattr", "handle getattr":
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
