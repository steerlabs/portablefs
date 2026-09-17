//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"io/fs"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type coherenceExistingCreateStore struct {
	resourceAdmissionFaultStore
	item, handle xfsstore.Capability
	openErr      error
}

func (s *coherenceExistingCreateStore) Create(_ xfsstore.Capability, _ string, _ fs.FileMode, exclusive bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.create.Add(1)
	if exclusive {
		return xfsstore.Capability{}, xfsstore.Attr{}, syscall.EEXIST
	}
	return s.item, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Size: 7, Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
}

func (s *coherenceExistingCreateStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.open.Add(1)
	if s.openErr != nil {
		return xfsstore.Capability{}, s.openErr
	}
	return s.handle, nil
}

func (s *coherenceExistingCreateStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if item == s.item {
		return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Size: 7, Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
	}
	return xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: uint64(item[0]), Mode: 0o755, Nlink: 2, DeviceMinor: 1}, nil
}

func (s *coherenceExistingCreateStore) GetattrOpen(handle xfsstore.Capability) (xfsstore.Attr, error) {
	if handle != s.handle {
		return xfsstore.Attr{}, syscall.EBADF
	}
	return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Size: 7, Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
}

func (*coherenceExistingCreateStore) CloseOpen(xfsstore.Capability) error { return nil }

func coherenceExistingCreateRequest(credential volumeserver.SessionCredential, parent xfsstore.Capability) *authoritypb.Request {
	request := coherenceReadRequest(credential)
	request.RequestId = 83
	request.Mutation = &authoritypb.Mutation{Sequence: 1}
	request.Body = &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: parent[:], Name: []byte("existing"), Mode: 0o600,
		Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true,
	}}
	return request
}

func TestCoherenceExistingCreatePromotesLiveDelegationOnlyAfterSuccess(t *testing.T) {
	item := xfsstore.Capability{0x33}
	store := &coherenceExistingCreateStore{
		resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: item},
		item:                        item, handle: xfsstore.Capability{0x44},
	}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	response := h.Handle(ctx, coherenceExistingCreateRequest(credential, root))
	delegation := response.GetCreate().GetDelegation()
	if response.GetErrno() != 0 || delegation == nil {
		t.Fatalf("existing CREATE = %+v", response)
	}
	id, err := parseCoherenceDelegationID(delegation.GetId())
	if err != nil {
		t.Fatal(err)
	}
	live, ok := h.Coherence.LookupDelegation([16]byte{item[0]})
	if !ok || live.ID != id || live.Generation != delegation.GetGeneration() {
		t.Fatalf("reply delegation = %+v, live delegation = %+v, present %t", delegation, live, ok)
	}
}

func TestCoherenceExistingCreateFailureLeavesNoDelegation(t *testing.T) {
	item := xfsstore.Capability{0x34}
	store := &coherenceExistingCreateStore{
		resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: item},
		item:                        item, handle: xfsstore.Capability{0x45}, openErr: syscall.EIO,
	}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	response := h.Handle(ctx, coherenceExistingCreateRequest(credential, root))
	if response.GetErrno() != int32(syscall.EIO) || response.GetCreate().GetDelegation() != nil {
		t.Fatalf("failed existing CREATE = %+v", response)
	}
	if live, ok := h.Coherence.LookupDelegation([16]byte{item[0]}); ok {
		t.Fatalf("failed existing CREATE retained delegation %+v", live)
	}
	if store.create.Load() != 1 || store.open.Load() != 1 {
		t.Fatalf("storage calls = create %d open %d", store.create.Load(), store.open.Load())
	}
}

func TestCoherenceExclusiveCreateDoesNotCutExistingDelegation(t *testing.T) {
	item := xfsstore.Capability{0x36}
	store := &coherenceExistingCreateStore{
		resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: item},
		item:                        item, handle: xfsstore.Capability{0x47},
	}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 128, 8)
	source, err := h.coherenceToken(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := h.Coherence.Subscribe(volumeserver.SessionID{9})
	if err != nil {
		t.Fatal(err)
	}
	sourceCursor, peerCursor := uint64(0), uint64(0)
	drain := func(token volumeserver.SubscriptionToken, cursor *uint64) {
		t.Helper()
		events, pollErr := h.Coherence.Poll(t.Context(), token, *cursor, nil, 16)
		if pollErr != nil {
			t.Fatal(pollErr)
		}
		if len(events) == 0 {
			t.Fatal("coordinator returned an empty nonblocking poll")
		}
		*cursor = events[len(events)-1].Position
		if ackErr := h.Coherence.Ack(token, *cursor); ackErr != nil {
			t.Fatal(ackErr)
		}
	}

	for race := 0; race < 100; race++ {
		reservation, err := h.Coherence.ReserveNew(peer.Token, [16]byte{item[0]})
		if err != nil {
			t.Fatalf("race %d reserve: %v", race, err)
		}
		drain(source, &sourceCursor)
		drain(peer.Token, &peerCursor)
		var grant volumeserver.Delegation
		if race%2 != 0 {
			grant, err = reservation.Grant(t.Context())
			if err != nil {
				t.Fatalf("race %d grant: %v", race, err)
			}
		}

		request := coherenceExistingCreateRequest(credential, root)
		request.RequestId = uint64(race + 1)
		request.Mutation.Sequence = uint64(race + 1)
		request.GetCreate().Exclusive = true
		done := make(chan *authoritypb.Response, 1)
		go func() { done <- h.Handle(ctx, request) }()
		select {
		case response := <-done:
			if response.GetErrno() != int32(syscall.EEXIST) || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED || response.GetUncertain() {
				t.Fatalf("race %d exclusive CREATE = %+v", race, response)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("race %d exclusive CREATE waited on the existing delegation", race)
		}

		pollCtx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
		events, pollErr := h.Coherence.Poll(pollCtx, peer.Token, peerCursor, nil, 16)
		cancel()
		if len(events) != 0 || !errors.Is(pollErr, context.DeadlineExceeded) {
			t.Fatalf("race %d exclusive CREATE emitted control cut: events=%+v err=%v", race, events, pollErr)
		}
		if race%2 == 0 {
			reservation.Abort()
			continue
		}
		pin, err := h.Coherence.BeginFlush(peer.Token, [16]byte{item[0]}, grant.ID, grant.Generation)
		if err != nil {
			t.Fatalf("race %d winner delegation no longer flushes: %v", race, err)
		}
		pin.End(0)
		if _, err := h.Coherence.ReleaseBatch(peer.Token, []volumeserver.Delegation{grant}); err != nil {
			t.Fatalf("race %d release: %v", race, err)
		}
		drain(source, &sourceCursor)
		drain(peer.Token, &peerCursor)
	}
}

func TestCoherenceCreateKeepsReplyGrantReservedThroughWithdrawal(t *testing.T) {
	item := xfsstore.Capability{0x35}
	store := &coherenceExistingCreateStore{
		resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: item},
		item:                        item, handle: xfsstore.Capability{0x46},
	}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	peer, err := h.Coherence.Subscribe(volumeserver.SessionID{9})
	if err != nil {
		t.Fatal(err)
	}
	// The peer has cached this binding and its target's attributes/data. A
	// subscription with no affected fact is intentionally outside the wait set.
	if err := h.Coherence.AdmitCache(peer.Token, volumeserver.CacheAdmission{
		Directories: [][16]byte{{root[0]}}, Attributes: [][16]byte{{item[0]}}, Data: [][16]byte{{item[0]}},
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan *authoritypb.Response, 1)
	request := coherenceExistingCreateRequest(credential, root)
	request.GetCreate().Flags.Truncate = true
	go func() { done <- h.Handle(ctx, request) }()
	events, err := h.Coherence.Poll(t.Context(), peer.Token, peer.Position, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	position := events[len(events)-1].Position
	if err := h.Coherence.Ack(peer.Token, position); err != nil {
		t.Fatal(err)
	}
	events, err = h.Coherence.Poll(t.Context(), peer.Token, position, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	position = events[len(events)-1].Position
	// The storage mutation is published, but its peer withdrawal is held. A
	// pending READ must sample it without waiting for an unreported grant's cut.
	type result struct {
		guard *volumeserver.DataGuard
		err   error
	}
	read := make(chan result, 1)
	go func() {
		guard, err := h.Coherence.DataConsumed(t.Context(), peer.Token, [16]byte{item[0]})
		read <- result{guard, err}
	}()
	var guard *volumeserver.DataGuard
	select {
	case got := <-read:
		if got.err != nil {
			t.Fatal(got.err)
		}
		guard = got.guard
	case <-time.After(time.Second):
		t.Fatal("pending reader waited for a break before the grant reply")
	}
	defer guard.Release()
	select {
	case response := <-done:
		t.Fatalf("CREATE passed unacknowledged withdrawal: %v", response)
	default:
	}
	if err := h.Coherence.Ack(peer.Token, position); err != nil {
		t.Fatal(err)
	}
	guard.Release()
	select {
	case response := <-done:
		if response.GetErrno() != 0 || response.GetCreate().GetDelegation() == nil {
			t.Fatalf("CREATE reply: %v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("CREATE did not grant after withdrawal and reader drain")
	}
}
