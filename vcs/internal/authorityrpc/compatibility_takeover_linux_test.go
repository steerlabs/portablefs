//go:build linux

package authorityrpc

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/restorefixture"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

func openTakeoverTestStore(t *testing.T, root string) *xfsstore.Volume {
	t.Helper()
	project, err := strconv.ParseUint(os.Getenv("PORTABLEFS_XFS_TEST_PROJECT"), 10, 32)
	if err != nil {
		t.Skip("privileged XFS gate is not configured")
	}
	store, err := xfsstore.Open(root, xfsstore.Config{ExpectedProjectID: uint32(project), ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestCompatibilityPriorMembershipMappingOnXFS(t *testing.T) {
	for _, kind := range []string{"legacy", "compatibility", "Linux only"} {
		t.Run(kind, func(t *testing.T) {
			root := restorefixture.Root(t)
			store := openTakeoverTestStore(t, root)
			path := filepath.Join(t.TempDir(), "membership")
			if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			old := volumeserver.SessionID{1}
			if kind == "legacy" {
				raw := "PFS-VISIBILITY-1\n" + hex.EncodeToString([]byte("vol")) + "\n" + hex.EncodeToString(old[:]) + "\n"
				if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				membership, _, err := volumeserver.OpenFileVisibilityMembership(path, "vol", false)
				if err != nil {
					t.Fatal(err)
				}
				profile := volumeserver.MembershipCompatibility
				if kind == "Linux only" {
					profile = volumeserver.MembershipLinuxV7
				}
				if err := membership.ActivateProfile(old, profile); err != nil {
					t.Fatal(err)
				}
				if err := membership.Close(); err != nil {
					t.Fatal(err)
				}
			}
			membership, prior, err := volumeserver.OpenFileVisibilityMembership(path, "vol", false)
			if err != nil {
				t.Fatal(err)
			}
			defer membership.Close()
			compatibility, linux := membership.PriorCacheState()
			wantLinux := kind == "Linux only"
			wantCompatibility := volumeserver.PriorEpochUnproven
			if wantLinux {
				wantCompatibility = volumeserver.PriorEpochStrictMountsFenced
			}
			if linux != wantLinux || compatibility != wantCompatibility {
				t.Fatalf("prior mapping: %v Linux=%v", compatibility, linux)
			}
			var elapsed atomic.Int64
			c, err := NewCoordination(CoordinationConfig{Store: store, Fencer: noopFencer{}, Locks: volumeserver.NewLockTable(16, 16, time.Now), Membership: membership, Prior: prior, MaxCachedNameCapacity: 16, MaxRepairBudget: time.Second, ContinuousNow: func() (time.Duration, error) { return time.Duration(elapsed.Load()), nil }})
			if err != nil {
				t.Fatal(err)
			}
			writer := volumeserver.SessionID{2}
			err = c.Visibility.CheckCompatibilityWriter(writer)
			if wantLinux {
				// No takeover sample and no 61.06s wait may be needed for
				// compatibility admission when only Linux subscribed before.
				if err != nil {
					t.Fatalf("Linux-only history engaged writer grace: %v", err)
				}
				wait, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
				defer cancel()
				if err := c.Coherence.WaitPriorCacheHorizon(wait); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("lost independent Linux prior horizon: %v", err)
				}
			} else {
				if !errors.Is(err, volumeserver.ErrCompatibilityWriterLease) {
					t.Fatalf("unproven writer=%v", err)
				}
				if err := c.Visibility.StartCompatibilityWriterGrace(); err != nil {
					t.Fatal(err)
				}
				elapsed.Store(int64(volumeserver.CompatibilityRestartGrace - time.Nanosecond))
				if err := c.Visibility.CheckCompatibilityWriter(writer); !errors.Is(err, volumeserver.ErrCompatibilityWriterLease) {
					t.Fatalf("early writer=%v", err)
				}
				elapsed.Store(int64(volumeserver.CompatibilityRestartGrace))
				if err := c.Visibility.CheckCompatibilityWriter(writer); err != nil {
					t.Fatal(err)
				}
				commitment := volumeserver.VisibilityCommitment{CachedNameCapacity: 16, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairCallbackSerializedPipelined, CompatibilityWriter: true}
				if err := c.Visibility.Register(writer, volumeserver.CoherenceStrict, make(chan struct{}), commitment); !errors.Is(err, volumeserver.ErrVisibilityStartup) {
					t.Fatalf("Mac activation=%v", err)
				}
			}
			if err := c.Lifecycle.RequireCleanRouteAbsence(); !errors.Is(err, volumeserver.ErrRoutesLive) {
				t.Fatalf("grace changed topology obligation: %v", err)
			}
			quiesced := false
			if err := membership.SetQuiescing("test", func() error { quiesced = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if quiesced {
				t.Fatal("grace proved archive absence")
			}
		})
	}
}

type handoffApplyStore struct {
	*xfsstore.Volume
	entered, release chan struct{}
	once             sync.Once
}
type handoffApplyTarget struct {
	xfsstore.WriteTarget
	store *handoffApplyStore
}

func (s *handoffApplyStore) PinWriteTarget(handle xfsstore.Capability) (xfsstore.WriteTarget, error) {
	target, err := s.Volume.PinWriteTarget(handle)
	if err != nil {
		return nil, err
	}
	return &handoffApplyTarget{WriteTarget: target, store: s}, nil
}
func (t *handoffApplyTarget) CommitWriteData(data []byte, spec xfsstore.WriteCommit) (uint64, uint64, xfsstore.Attr, error) {
	t.store.once.Do(func() { close(t.store.entered) })
	<-t.store.release
	return t.WriteTarget.CommitWriteData(data, spec)
}

func TestCompatibilitySafeTakeoverWaitsForPendingApplyOnXFS(t *testing.T) {
	root := restorefixture.Root(t)
	store := openTakeoverTestStore(t, root)
	path := filepath.Join(t.TempDir(), "membership")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	membership, prior, err := volumeserver.OpenFileVisibilityMembership(path, "handoff", false)
	if err != nil {
		t.Fatal(err)
	}
	defer membership.Close()
	runtime, err := volumeserver.New("handoff", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 8, MaxSessions: 4, MaxLockRecords: 16})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordination(CoordinationConfig{Store: store, Fencer: runtime, Locks: runtime.Locks(), Membership: membership, Prior: prior, MaxCachedNameCapacity: 1024, MaxRepairBudget: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Visibility.StartCompatibilityWriterGrace(); err != nil {
		t.Fatal(err)
	}
	backend := &handoffApplyStore{Volume: store, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(backend.release) })
	defer release()
	h := testVolumeHandler()
	c.Bind(h)
	h.Store, h.Runtime, h.Authorizer = backend, runtime, allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
	h.MaxFrame, h.MaxRead, h.MaxWrite = testMaxFrame, 1<<20, 1<<20
	h.MaxRetainedReplyBytes = 8 << 20
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	server := &Server{Handler: h, MaxFrame: h.MaxFrame, MaxInFlight: int(h.MaxInFlight), MaxConnections: 8, MaxFrameBytesInFlight: controlFrameReserve() + 8<<20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(ctx, listener, serverTLS) }()
	joined := false
	defer func() {
		release()
		cancel()
		if !joined {
			if err := <-stopped; err != nil {
				t.Error(err)
			}
		}
	}()
	clientConfig := coherentTestClientConfig(listener.Addr().String(), clientTLS, "handoff", 8, int(h.MaxInFlight))
	clientConfig.RoutesRevision = routesRevisionOf("")
	client, err := DialClient(t.Context(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	subscribed, err := client.CallRead(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_Subscribe{Subscribe: &authoritypb.SubscribeRequest{}}})
	if err != nil || subscribed.GetErrno() != 0 {
		t.Fatalf("subscribe: %v %v", subscribed, err)
	}
	created, err := client.CallMutation(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: client.Root().GetToken(), Name: []byte("pending"), Mode: 0600, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}})
	if err != nil || created.GetErrno() != 0 {
		t.Fatalf("create: %v %v", created, err)
	}
	writeCtx, cancelWrite := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelWrite()
	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = client.CallMutation(writeCtx, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: created.GetCreate().GetHandle(), Data: []byte("x"), Size: 1}}})
	}()
	select {
	case <-backend.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("write did not enter apply")
	}
	cancel()
	// Close renewal permanently while the previously admitted apply is still
	// parked. Session fencing alone must not relinquish storage ownership.
	runtime.FenceSession(client.AuthorizationSessionID())
	select {
	case err := <-stopped:
		joined = true
		t.Fatalf("Serve returned with pending apply: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if second, err := xfsstore.Open(root, xfsstore.Config{ExpectedProjectID: storeProject(t), ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())}); !errors.Is(err, syscall.EWOULDBLOCK) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("takeover with pending apply: %v", err)
	}
	if second, _, err := volumeserver.OpenFileVisibilityMembership(path, "handoff", false); err == nil {
		second.Close()
		t.Fatal("membership ownership escaped before apply drain")
	}
	release()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	joined = true
	_ = client.Close()
	<-written
	data, err := os.ReadFile(filepath.Join(root, "pending"))
	if err != nil || string(data) != "x" {
		t.Fatalf("pending apply did not complete before handoff: bytes=%d error=%v", len(data), err)
	}
	// This is main's shutdown order: Serve joins storage workers before
	// membership/root close. Only now may a successor sample takeover S.
	if err := membership.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	next := openTakeoverTestStore(t, root)
	nextMembership, nextPrior, err := volumeserver.OpenFileVisibilityMembership(path, "handoff", false)
	if err != nil {
		t.Fatal(err)
	}
	defer nextMembership.Close()
	var samples atomic.Int64
	nextC, err := NewCoordination(CoordinationConfig{Store: next, Fencer: noopFencer{}, Locks: volumeserver.NewLockTable(16, 16, time.Now), Membership: nextMembership, Prior: nextPrior, MaxCachedNameCapacity: 16, MaxRepairBudget: time.Second, ContinuousNow: func() (time.Duration, error) { samples.Add(1); return time.Second, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if samples.Load() != 0 {
		t.Fatal("takeover sampled during construction")
	}
	if err := nextC.Visibility.StartCompatibilityWriterGrace(); err != nil {
		t.Fatal(err)
	}
	if samples.Load() != 1 {
		t.Fatal("missing safe takeover sample")
	}
}

func storeProject(t *testing.T) uint32 {
	t.Helper()
	project, err := strconv.ParseUint(os.Getenv("PORTABLEFS_XFS_TEST_PROJECT"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(project)
}
