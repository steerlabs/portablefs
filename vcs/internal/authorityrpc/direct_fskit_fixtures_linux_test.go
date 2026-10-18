//go:build linux

package authorityrpc

import (
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type fskitWriteTestStore struct {
	resourceAdmissionFaultStore
	mu      sync.Mutex
	targets []*fskitWriteTestTarget
}

func (s *fskitWriteTestStore) PinWriteTarget(handle xfsstore.Capability) (xfsstore.WriteTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.targets) == 0 || handle == (xfsstore.Capability{}) {
		return nil, syscall.ESTALE
	}
	target := s.targets[0]
	if target.sync == nil {
		target.sync = func() error { s.durableHandles.Add(1); return nil }
	}
	s.targets = s.targets[1:]
	return target, nil
}

func (*fskitWriteTestStore) CloseOpen(xfsstore.Capability) error { return nil }

type fskitWriteTestTarget struct {
	closed    atomic.Bool
	commitErr error
	sync      func() error
	mu        sync.Mutex
	payloads  [][]byte
}

func (*fskitWriteTestTarget) Coordinate() xfsstore.ObjectCoordinate {
	return xfsstore.ObjectCoordinate{Stable: [16]byte{0x41}, Ino: 0x41, DeviceMinor: 1}
}

func (*fskitWriteTestTarget) CommitWriteData([]byte, xfsstore.WriteCommit) (uint64, uint64, xfsstore.Attr, error) {
	return 0, 0, xfsstore.Attr{}, syscall.EOPNOTSUPP
}

func (t *fskitWriteTestTarget) Sync() error {
	if t.closed.Load() {
		return xfsstore.ErrClosed
	}
	if t.sync != nil {
		return t.sync()
	}
	return nil
}
func (t *fskitWriteTestTarget) Close() error { t.closed.Store(true); return nil }

func (t *fskitWriteTestTarget) snapshot() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.payloads...)
}

func newFskitWriteHarness(t *testing.T) (*VolumeHandler, volumeserver.SessionCredential, *fskitWriteTestStore, <-chan struct{}) {
	return newFskitWriteHarnessWithAccess(t, volumeserver.AccessRead|volumeserver.AccessWrite)
}

func newFskitWriteHarnessWithAccess(t *testing.T, access volumeserver.Access) (*VolumeHandler, volumeserver.SessionCredential, *fskitWriteTestStore, <-chan struct{}) {
	t.Helper()
	runtime, err := volumeserver.New("fskit-write", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{1}, volumeserver.Authorization{
		Access: access, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := runtime.SessionTerminal(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewWriterRegistry(volumeserver.WriterRegistryConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Fencer: runtime,
	})
	if err != nil {
		t.Fatal(err)
	}
	exclusion, err := runtime.WriterExclusion(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Activate(credential.ID, terminal, exclusion, func() error { return nil }, func() {}); err != nil {
		t.Fatal(err)
	}

	store := &fskitWriteTestStore{}
	h := testVolumeHandler()
	h.Runtime, h.Store, h.Writers = runtime, store, visibility
	h.Authorizer = allowAuthorizer{access: access}
	h.Routes = &RoutesController{}
	if err := h.startSessionResourcesForProfile(
		credential.ID, xfsstore.Capability{0x70}, 2, [32]byte{}, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE,
	); err != nil {
		t.Fatal(err)
	}
	handle := xfsstore.Capability{0x41}
	if err := h.trackOpen(credential.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.closeSessionResources(credential.ID) })
	return h, credential, store, terminal
}
