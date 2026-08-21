package volumeserver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type leaseTestFencer struct {
	mu     sync.Mutex
	fenced []SessionID
}

func (f *leaseTestFencer) FenceSession(id SessionID) {
	f.mu.Lock()
	f.fenced = append(f.fenced, id)
	f.mu.Unlock()
}

func (f *leaseTestFencer) count(id SessionID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, fenced := range f.fenced {
		if fenced == id {
			count++
		}
	}
	return count
}

func leaseTestID(value byte) SessionID {
	var id SessionID
	id[0] = value
	return id
}

func leaseTestIdentity(value byte) [16]byte {
	var id [16]byte
	id[0] = value
	return id
}

func leaseTestCoordinate(family LeaseFamily, value byte) LeaseCoordinate {
	if family == LeaseFamilyName {
		return LeaseCoordinate{Family: family, ParentIdentity: leaseTestIdentity(value), Name: []byte("entry")}
	}
	return LeaseCoordinate{Family: family, Identity: leaseTestIdentity(value)}
}

func newLeaseTestCoordinator(t *testing.T, ttl, budget time.Duration) (*LeaseCoordinator, *leaseTestFencer) {
	t.Helper()
	fencer := &leaseTestFencer{}
	coordinator, err := NewLeaseCoordinator(LeaseConfig{
		TTL: ttl, RecallBudget: budget, MaxPerHolder: 4096, MaxTotal: 16384, PriorGrantsFenced: true, Fencer: fencer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, fencer
}

// tryLeaseRead probes whether a coordinate is closed to a metadata read
// without parking the test on it. BeginRead waits for the whole recall barrier
// by design, so a short deadline is the observation, and its expiry is reported
// as the block it stands for.
func tryLeaseRead(coordinator *LeaseCoordinator, id SessionID, coordinates ...LeaseCoordinate) (*LeaseReadAdmission, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	admission, err := coordinator.BeginRead(ctx, id, coordinates...)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, ErrLeaseBlocked
	}
	return admission, err
}

func activateLeaseTestHolder(t *testing.T, coordinator *LeaseCoordinator, id SessionID) chan struct{} {
	t.Helper()
	terminal := make(chan struct{})
	if err := coordinator.ActivateHolder(id, terminal); err != nil {
		t.Fatal(err)
	}
	return terminal
}

func completeLeaseTest(transaction *LeaseRecallTransaction, ctx context.Context, post []VisibilityObjectPostState, snapshot uint64, changed bool) error {
	_, err := transaction.CompletePeers(ctx, post, snapshot, changed)
	return err
}

func TestLeaseStartupGraceBlocksMutationsUntilExactPriorTTL(t *testing.T) {
	now := time.Unix(100, 0)
	ttl := 20 * time.Second
	coordinator, err := NewLeaseCoordinator(LeaseConfig{
		TTL: ttl, RecallBudget: time.Second, MaxPerHolder: 4096, MaxTotal: 16384, StartupGrace: ttl,
		Now: func() time.Time { return now }, Fencer: &leaseTestFencer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	holder := leaseTestID(1)
	activateLeaseTestHolder(t, coordinator, holder)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	if _, err := coordinator.Grant(context.Background(), holder, coordinate, LeaseRightDataRead); err != nil {
		t.Fatalf("tracked post-restart grant: %v", err)
	}
	if _, err := coordinator.PrepareRecall(context.Background(), holder, []LeaseRecallTarget{{Coordinate: coordinate}}); !errors.Is(err, ErrLeaseStartup) {
		t.Fatalf("PrepareRecall before grace = %v, want %v", err, ErrLeaseStartup)
	}
	now = now.Add(ttl - time.Nanosecond)
	if _, err := coordinator.PrepareRecall(context.Background(), holder, []LeaseRecallTarget{{Coordinate: coordinate}}); !errors.Is(err, ErrLeaseStartup) {
		t.Fatalf("PrepareRecall before exact boundary = %v, want %v", err, ErrLeaseStartup)
	}
	now = now.Add(time.Nanosecond)
	transaction, err := coordinator.PrepareRecall(context.Background(), holder, []LeaseRecallTarget{{Coordinate: coordinate}})
	if err != nil {
		t.Fatalf("PrepareRecall at grace boundary: %v", err)
	}
	transaction.Abort()
}

func TestLeaseGrantPolicyAndConflicts(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	one, two := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, one)
	activateLeaseTestHolder(t, coordinator, two)

	tests := []struct {
		name       string
		coordinate LeaseCoordinate
		right      LeaseRight
		wantErr    error
	}{
		{name: "name read", coordinate: leaseTestCoordinate(LeaseFamilyName, 1), right: LeaseRightNameRead},
		{name: "name exclusive reserved", coordinate: leaseTestCoordinate(LeaseFamilyName, 2), right: LeaseRightNameExclusive, wantErr: ErrLeaseRight},
		{name: "attribute read", coordinate: leaseTestCoordinate(LeaseFamilyAttributes, 3), right: LeaseRightAttributesRead},
		{name: "attribute exclusive reserved", coordinate: leaseTestCoordinate(LeaseFamilyAttributes, 4), right: LeaseRightAttributesExclusive, wantErr: ErrLeaseRight},
		{name: "data read", coordinate: leaseTestCoordinate(LeaseFamilyData, 5), right: LeaseRightDataRead},
		{name: "data exclusive", coordinate: leaseTestCoordinate(LeaseFamilyData, 6), right: LeaseRightDataExclusive},
		{name: "enumeration read", coordinate: leaseTestCoordinate(LeaseFamilyEnumeration, 7), right: LeaseRightEnumerationRead},
		{name: "enumeration mismatch", coordinate: leaseTestCoordinate(LeaseFamilyEnumeration, 8), right: LeaseRightDataRead, wantErr: ErrLeaseRight},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := coordinator.Grant(context.Background(), one, test.coordinate, test.right)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Grant() error = %v, want %v", err, test.wantErr)
			}
		})
	}

	shared := leaseTestCoordinate(LeaseFamilyData, 9)
	first, err := coordinator.Grant(context.Background(), one, shared, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	second, err := coordinator.Grant(context.Background(), two, shared, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	if first.Epoch == 0 || second.Epoch != 1 {
		t.Fatalf("first grant epochs = %d, %d; want nonzero holder-global epochs and fresh-holder epoch 1", first.Epoch, second.Epoch)
	}
	if _, err := coordinator.Grant(context.Background(), two, shared, LeaseRightDataExclusive); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("exclusive Grant() error = %v, want %v", err, ErrLeaseConflict)
	}
}

func TestLeaseHolderCoordinateChurnRetainsOnlyLiveRecordsAndScalarEpoch(t *testing.T) {
	now := time.Unix(100, 0)
	coordinator, err := NewLeaseCoordinator(LeaseConfig{
		TTL: time.Second, RecallBudget: time.Second, MaxPerHolder: 4096, MaxTotal: 16384, PriorGrantsFenced: true,
		Now: func() time.Time { return now }, Fencer: &leaseTestFencer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	holderID := leaseTestID(1)
	activateLeaseTestHolder(t, coordinator, holderID)
	const coordinateCount = 1024
	for index := 0; index < coordinateCount; index++ {
		value := index + 1
		var identity [16]byte
		identity[0] = byte(value)
		identity[1] = byte(value >> 8)
		if _, err := coordinator.Grant(context.Background(), holderID, LeaseCoordinate{
			Family: LeaseFamilyAttributes, Identity: identity,
		}, LeaseRightAttributesRead); err != nil {
			t.Fatalf("Grant(%d): %v", index, err)
		}
	}
	coordinator.mu.Lock()
	holder := coordinator.holders[holderID]
	if got := len(holder.leases); got != coordinateCount {
		coordinator.mu.Unlock()
		t.Fatalf("live records = %d, want %d", got, coordinateCount)
	}
	if holder.nextEpoch != coordinateCount {
		coordinator.mu.Unlock()
		t.Fatalf("scalar epoch = %d, want %d", holder.nextEpoch, coordinateCount)
	}
	coordinator.mu.Unlock()

	now = now.Add(time.Second)
	if held := coordinator.Held(holderID); len(held) != 0 {
		t.Fatalf("expired grants retained: %+v", held)
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if got := len(coordinator.holders[holderID].leases); got != 0 {
		t.Fatalf("expired coordinate state = %d records, want 0", got)
	}
}

func TestLeaseGrantCapacityRefusesCachingWithoutEviction(t *testing.T) {
	fencer := &leaseTestFencer{}
	coordinator, err := NewLeaseCoordinator(LeaseConfig{
		TTL: time.Second, RecallBudget: time.Second, MaxPerHolder: 2, MaxTotal: 3,
		PriorGrantsFenced: true, Fencer: fencer,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, second := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, first)
	activateLeaseTestHolder(t, coordinator, second)
	for value := byte(1); value <= 2; value++ {
		if _, err := coordinator.Grant(context.Background(), first, leaseTestCoordinate(LeaseFamilyAttributes, value), LeaseRightAttributesRead); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := coordinator.Grant(context.Background(), first, leaseTestCoordinate(LeaseFamilyAttributes, 3), LeaseRightAttributesRead); !errors.Is(err, ErrLeaseCapacity) {
		t.Fatalf("per-holder overflow = %v, want %v", err, ErrLeaseCapacity)
	}
	if got := len(coordinator.Held(first)); got != 2 {
		t.Fatalf("first holder retained %d grants, want 2", got)
	}
	if _, err := coordinator.Grant(context.Background(), second, leaseTestCoordinate(LeaseFamilyAttributes, 3), LeaseRightAttributesRead); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Grant(context.Background(), second, leaseTestCoordinate(LeaseFamilyAttributes, 4), LeaseRightAttributesRead); !errors.Is(err, ErrLeaseCapacity) {
		t.Fatalf("worker overflow = %v, want %v", err, ErrLeaseCapacity)
	}
	if got := len(coordinator.Held(first)); got != 2 {
		t.Fatalf("capacity pressure evicted tracked authority records: got %d, want 2", got)
	}
}

func TestLeaseGrantBatchIsAllOrNoneAtCapacity(t *testing.T) {
	coordinator, err := NewLeaseCoordinator(LeaseConfig{
		TTL: time.Second, RecallBudget: time.Second, MaxPerHolder: 1, MaxTotal: 1,
		PriorGrantsFenced: true, Fencer: &leaseTestFencer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	holder := leaseTestID(1)
	activateLeaseTestHolder(t, coordinator, holder)
	name := leaseTestCoordinate(LeaseFamilyName, 1)
	attr := leaseTestCoordinate(LeaseFamilyAttributes, 2)
	admission, err := coordinator.BeginRead(context.Background(), holder, name, attr)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Release()
	if _, err := admission.GrantBatch([]LeaseGrantRequest{
		{Coordinate: name, Right: LeaseRightNameRead},
		{Coordinate: attr, Right: LeaseRightAttributesRead},
	}); !errors.Is(err, ErrLeaseCapacity) {
		t.Fatalf("GrantBatch = %v, want %v", err, ErrLeaseCapacity)
	}
	if got := coordinator.Held(holder); len(got) != 0 {
		t.Fatalf("partial grant escaped failed batch: %+v", got)
	}
}

func TestLeaseRecallSelfExemptionAndExactDischarge(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	sourceGrant, err := coordinator.Grant(context.Background(), source, coordinate, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	peerGrant, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}

	prepared := make(chan *LeaseRecallTransaction, 1)
	prepareErr := make(chan error, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err == nil {
			prepared <- transaction
		}
		prepareErr <- err
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if revoke.Cursor.Phase != LeaseEventRevoke || len(revoke.Recalls) != 1 || revoke.Recalls[0].GrantEpoch != peerGrant.Epoch || revoke.Recalls[0].RevokeEpoch != peerGrant.Epoch+1 {
		t.Fatalf("unexpected revoke: %+v", revoke)
	}
	if held := coordinator.Held(source); len(held) != 1 || held[0].Epoch != sourceGrant.Epoch {
		t.Fatalf("source grant was not retained through reply publication: %+v", held)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-prepareErr; err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared
	renewed, withdrawn, err := coordinator.Renew(source, []LeaseRenewal{{Coordinate: coordinate, Epoch: sourceGrant.Epoch}})
	if err != nil {
		t.Fatal(err)
	}
	if len(withdrawn) != 0 {
		t.Fatalf("blocked source renewal withdrawn: %+v", withdrawn)
	}
	if len(renewed) != 1 || !renewed[0].ExpiresAt.Equal(sourceGrant.ExpiresAt) {
		t.Fatalf("source renewal extended a blocked grant: %+v, original expiry %v", renewed, sourceGrant.ExpiresAt)
	}

	grantCtx, cancelGrant := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancelGrant()
	if _, err := coordinator.Grant(grantCtx, source, coordinate, LeaseRightDataRead); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Grant() during recall error = %v, want deadline", err)
	}

	type completeResult struct {
		source *LeaseSourceDischarge
		err    error
	}
	completeResultCh := make(chan completeResult, 1)
	post := []VisibilityObjectPostState{{StableIdentity: coordinate.Identity, ObjectVersion: 4}}
	go func() {
		source, err := transaction.CompletePeers(context.Background(), post, 8, true)
		completeResultCh <- completeResult{source: source, err: err}
	}()
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Cursor.Phase != LeaseEventComplete || len(complete.PostState) != 1 || complete.SnapshotSequence != 8 {
		t.Fatalf("unexpected complete: %+v", complete)
	}
	discharge := LeaseDischarge{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{discharge}); err != nil {
		t.Fatal(err)
	}
	result := <-completeResultCh
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.source == nil || result.source.Sequence != transaction.Sequence() || len(result.source.Recalls) != 1 {
		t.Fatalf("source discharge = %+v, want retained source grant", result.source)
	}
	peerPrepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), peer, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			panic(err)
		}
		peerPrepared <- transaction
	}()
	select {
	case next := <-peerPrepared:
		next.Abort()
		t.Fatal("peer mutation passed source barrier before physical-reply discharge")
	case <-time.After(10 * time.Millisecond):
	}
	if err := coordinator.DischargeSource(source, result.source.Sequence); err != nil {
		t.Fatal(err)
	}
	select {
	case next := <-peerPrepared:
		if err := completeLeaseTest(next, context.Background(), nil, 0, false); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer mutation stayed blocked after source discharge")
	}
	if held := coordinator.Held(peer); len(held) != 0 {
		t.Fatalf("peer retained discharged grant: %+v", held)
	}
	refreshed, err := coordinator.Grant(context.Background(), source, coordinate, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Epoch != peerGrant.Epoch+2 {
		// Source's grant epoch also advanced once for revoke, then once for grant.
		t.Fatalf("source refreshed epoch = %d, want %d", refreshed.Epoch, peerGrant.Epoch+2)
	}
}

func TestLeaseRecallFromExternalSourceRecallsPeerWithoutSourceObligation(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	external, peer := leaseTestID(1), leaseTestID(2)
	terminal := make(chan struct{})
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightDataRead); err != nil {
		t.Fatal(err)
	}

	prepared := make(chan *LeaseRecallTransaction, 1)
	prepareErr := make(chan error, 1)
	go func() {
		transaction, err := coordinator.PrepareRecallFromExternalSource(
			context.Background(), external, terminal, []LeaseRecallTarget{{Coordinate: coordinate}},
		)
		if err == nil {
			prepared <- transaction
		}
		prepareErr <- err
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if revoke.Initiator != external || len(revoke.Recalls) != 1 {
		t.Fatalf("external-source revoke = %+v", revoke)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-prepareErr; err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared

	type completion struct {
		discharge *LeaseSourceDischarge
		err       error
	}
	completed := make(chan completion, 1)
	go func() {
		discharge, err := transaction.CompletePeers(context.Background(), []VisibilityObjectPostState{{
			StableIdentity: coordinate.Identity, ObjectVersion: 2,
		}}, 2, true)
		completed <- completion{discharge: discharge, err: err}
	}()
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	result := <-completed
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.discharge != nil {
		t.Fatalf("external source received source discharge: %+v", result.discharge)
	}
}

func TestLeaseRecallFromExternalSourceFenceBeforeAndDuringRecall(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	external, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyAttributes, 1)
	closed := make(chan struct{})
	close(closed)
	if _, err := coordinator.PrepareRecallFromExternalSource(
		context.Background(), external, closed, []LeaseRecallTarget{{Coordinate: coordinate}},
	); !errors.Is(err, ErrLeaseHolder) {
		t.Fatalf("PrepareRecallFromExternalSource with fenced source = %v, want %v", err, ErrLeaseHolder)
	}

	if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightAttributesRead); err != nil {
		t.Fatal(err)
	}
	terminal := make(chan struct{})
	prepareErr := make(chan error, 1)
	go func() {
		_, err := coordinator.PrepareRecallFromExternalSource(
			context.Background(), external, terminal, []LeaseRecallTarget{{Coordinate: coordinate}},
		)
		prepareErr <- err
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	close(terminal)
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if complete.SnapshotSequence != 0 || len(complete.PostState) != 0 {
		t.Fatalf("fenced external source published post-state: %+v", complete)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-prepareErr; !errors.Is(err, ErrLeaseHolder) {
		t.Fatalf("PrepareRecallFromExternalSource after in-flight fence = %v, want %v", err, ErrLeaseHolder)
	}
}

func TestLeaseCanceledCompleteCannotReopenAdmission(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightDataRead); err != nil {
		t.Fatal(err)
	}

	prepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			panic(err)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	completeErr := make(chan error, 1)
	go func() { completeErr <- completeLeaseTest(transaction, canceled, nil, 0, false) }()
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-completeErr:
		t.Fatalf("Complete() returned before discharge after cancellation: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	grantCtx, cancelGrant := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancelGrant()
	if _, err := coordinator.Grant(grantCtx, source, coordinate, LeaseRightDataRead); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Grant() while canceled COMPLETE is pending error = %v, want deadline", err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Grant(context.Background(), source, coordinate, LeaseRightDataRead); err != nil {
		t.Fatalf("Grant() after discharge: %v", err)
	}
}

func TestLeaseDischargeRejectsContinuityAndStaleEpoch(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightDataRead); err != nil {
		t.Fatal(err)
	}

	prepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			panic(err)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared
	completeErr := make(chan error, 1)
	go func() { completeErr <- completeLeaseTest(transaction, context.Background(), nil, 0, false) }()
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	continuity := LeaseDischarge{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch,
		Mode: LeaseDischargeContinuity, SuccessorRight: LeaseRightDataRead,
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{continuity}); !errors.Is(err, ErrLeaseDischarge) {
		t.Fatalf("continuity Discharge() error = %v, want %v", err, ErrLeaseDischarge)
	}
	stale := LeaseDischarge{Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch - 1, Mode: LeaseDischargeToNone}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{stale}); !errors.Is(err, ErrLeaseEpoch) {
		t.Fatalf("stale Discharge() error = %v, want %v", err, ErrLeaseEpoch)
	}
	exact := LeaseDischarge{Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{exact}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseRenewalReturnsExactCoordinateWithdrawals(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	holder := leaseTestID(1)
	activateLeaseTestHolder(t, coordinator, holder)
	name := leaseTestCoordinate(LeaseFamilyName, 1)
	attr := leaseTestCoordinate(LeaseFamilyAttributes, 2)
	nameGrant, err := coordinator.Grant(context.Background(), holder, name, LeaseRightNameRead)
	if err != nil {
		t.Fatal(err)
	}
	attrGrant, err := coordinator.Grant(context.Background(), holder, attr, LeaseRightAttributesRead)
	if err != nil {
		t.Fatal(err)
	}
	renewed, withdrawn, err := coordinator.Renew(holder, []LeaseRenewal{
		{Coordinate: name, Epoch: nameGrant.Epoch},
		{Coordinate: attr, Epoch: attrGrant.Epoch + 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(renewed) != 1 || renewed[0].Epoch != nameGrant.Epoch || len(withdrawn) != 1 ||
		withdrawn[0].Coordinate.key() != attr.key() || withdrawn[0].Epoch != attrGrant.Epoch+1 {
		t.Fatalf("mixed renewal = grants %+v withdrawals %+v", renewed, withdrawn)
	}
	renewed, withdrawn, err = coordinator.Renew(holder, []LeaseRenewal{{Coordinate: name, Epoch: nameGrant.Epoch}, {Coordinate: attr, Epoch: attrGrant.Epoch}})
	if err != nil {
		t.Fatal(err)
	}
	if len(renewed) != 2 || len(withdrawn) != 0 || renewed[1].ExpiresAt != renewed[0].ExpiresAt {
		t.Fatalf("unexpected renewal result: %+v", renewed)
	}
}

func TestLeaseRepeatedReadGrantKeepsRenewableEpoch(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	holder := leaseTestID(1)
	activateLeaseTestHolder(t, coordinator, holder)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)

	first, err := coordinator.Grant(context.Background(), holder, coordinate, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	second, err := coordinator.Grant(context.Background(), holder, coordinate, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	if second.Epoch != first.Epoch {
		t.Fatalf("second read epoch = %d, want still-live epoch %d", second.Epoch, first.Epoch)
	}
	if !second.ExpiresAt.After(first.ExpiresAt) && !second.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("second read expiry = %v, want no earlier than %v", second.ExpiresAt, first.ExpiresAt)
	}
	if _, withdrawn, err := coordinator.Renew(holder, []LeaseRenewal{{Coordinate: coordinate, Epoch: first.Epoch}}); err != nil || len(withdrawn) != 0 {
		t.Fatalf("renewing earlier reordered response epoch: %v", err)
	}
}

func TestLeaseRenewalLosingToRecallIsNonfatalWithdrawal(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	grant, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	prepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, prepareErr := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if prepareErr != nil {
			panic(prepareErr)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	renewed, withdrawn, err := coordinator.Renew(peer, []LeaseRenewal{{Coordinate: coordinate, Epoch: grant.Epoch}})
	if err != nil {
		t.Fatalf("renewal racing REVOKE was terminal: %v", err)
	}
	if len(renewed) != 0 || len(withdrawn) != 1 || withdrawn[0].Epoch != grant.Epoch || withdrawn[0].Coordinate.key() != coordinate.key() {
		t.Fatalf("racing renewal = grants %+v withdrawals %+v", renewed, withdrawn)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared
	completed := make(chan error, 1)
	go func() { completed <- completeLeaseTest(transaction, context.Background(), nil, 0, false) }()
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseRenewalRestampsAdmissionGenerationAfterDisjointRecall(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, reader := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, reader)
	stable := leaseTestCoordinate(LeaseFamilyData, 1)
	recalled := leaseTestCoordinate(LeaseFamilyAttributes, 2)
	stableGrant, err := coordinator.Grant(context.Background(), reader, stable, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	recalledGrant, err := coordinator.Grant(context.Background(), reader, recalled, LeaseRightAttributesRead)
	if err != nil {
		t.Fatal(err)
	}
	prepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, prepareErr := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: recalled}})
		if prepareErr != nil {
			panic(prepareErr)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), reader, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(reader, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared
	completed := make(chan error, 1)
	go func() { completed <- completeLeaseTest(transaction, context.Background(), nil, 0, false) }()
	complete, err := coordinator.Next(context.Background(), reader, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(reader, complete.Cursor, []LeaseDischarge{{
		Coordinate: recalled, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	renewed, withdrawn, err := coordinator.Renew(reader, []LeaseRenewal{{Coordinate: stable, Epoch: stableGrant.Epoch}})
	if err != nil {
		t.Fatal(err)
	}
	if len(withdrawn) != 0 || len(renewed) != 1 {
		t.Fatalf("stable renewal = grants %+v withdrawals %+v", renewed, withdrawn)
	}
	if renewed[0].IssuedAt < revoke.Cursor.Sequence || renewed[0].IssuedAt <= stableGrant.IssuedAt {
		t.Fatalf("renewed admission generation = %d, want at least recall %d and newer than original %d", renewed[0].IssuedAt, revoke.Cursor.Sequence, stableGrant.IssuedAt)
	}
	if recalledGrant.Epoch == 0 {
		t.Fatal("recalled grant unexpectedly had zero epoch")
	}
}

func TestLeaseDisjointSourceMutationsDischargeOutOfOrder(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, reader := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, reader)
	firstCoordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	secondCoordinate := leaseTestCoordinate(LeaseFamilyData, 2)
	for _, coordinate := range []LeaseCoordinate{firstCoordinate, secondCoordinate} {
		if _, err := coordinator.Grant(context.Background(), source, coordinate, LeaseRightDataRead); err != nil {
			t.Fatal(err)
		}
	}

	first, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: firstCoordinate}})
	if err != nil {
		t.Fatal(err)
	}
	secondReady := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, prepareErr := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: secondCoordinate}})
		if prepareErr != nil {
			panic(prepareErr)
		}
		secondReady <- transaction
	}()
	var second *LeaseRecallTransaction
	select {
	case second = <-secondReady:
	case <-time.After(time.Second):
		t.Fatal("disjoint mutation from the same source was globally serialized")
	}
	firstDischarge, err := first.CompletePeers(context.Background(), nil, first.AssignCommitSequence(), true)
	if err != nil {
		t.Fatal(err)
	}
	secondDischarge, err := second.CompletePeers(context.Background(), nil, second.AssignCommitSequence(), true)
	if err != nil {
		t.Fatal(err)
	}
	if firstDischarge == nil || secondDischarge == nil || firstDischarge.Sequence >= secondDischarge.Sequence {
		t.Fatalf("source discharges = %+v, %+v, want two ordered tokens", firstDischarge, secondDischarge)
	}

	if err := coordinator.DischargeSource(source, secondDischarge.Sequence); err != nil {
		t.Fatalf("higher source discharge: %v", err)
	}
	if admission, err := tryLeaseRead(coordinator, reader, secondCoordinate); err != nil {
		t.Fatalf("second coordinate remained blocked: %v", err)
	} else {
		admission.Release()
	}
	if _, err := tryLeaseRead(coordinator, reader, firstCoordinate); !errors.Is(err, ErrLeaseBlocked) {
		t.Fatalf("first coordinate error = %v, want still blocked", err)
	}
	if err := coordinator.DischargeSource(source, firstDischarge.Sequence); err != nil {
		t.Fatalf("lower out-of-order source discharge: %v", err)
	}
	if admission, err := tryLeaseRead(coordinator, reader, firstCoordinate); err != nil {
		t.Fatalf("first coordinate remained blocked: %v", err)
	} else {
		admission.Release()
	}
}

func TestLeaseRouteChangeRequiresCleanMountAbsence(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	one, two := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, one)
	activateLeaseTestHolder(t, coordinator, two)
	next := RoutesChange{Revision: [32]byte{1}, Canonical: []byte("node_modules\n")}
	committed := false
	commit := func() (RoutesChange, error) {
		committed = true
		return next, nil
	}
	if _, err := coordinator.ExecuteRoutes(context.Background(), next, commit); !errors.Is(err, ErrLeaseRoutesLive) {
		t.Fatalf("ExecuteRoutes() with mounted holders = %v, want %v", err, ErrLeaseRoutesLive)
	}
	if committed {
		t.Fatal("route committed while an old-revision holder remained")
	}
	coordinator.FenceHolder(one)
	if _, err := coordinator.ExecuteRoutes(context.Background(), next, commit); !errors.Is(err, ErrLeaseRoutesLive) {
		t.Fatalf("ExecuteRoutes() with fenced holder = %v, want clean-absence refusal", err)
	}
	if err := coordinator.RemoveHolder(one); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RemoveHolder(two); err != nil {
		t.Fatal(err)
	}
	acknowledged, err := coordinator.ExecuteRoutes(context.Background(), next, commit)
	if err != nil || acknowledged != 0 || !committed {
		t.Fatalf("ExecuteRoutes() after clean absence = %d, %v, committed=%v", acknowledged, err, committed)
	}
}

func TestLeaseRecallExpiryFencesAndImplicitlyDischarges(t *testing.T) {
	coordinator, fencer := newLeaseTestCoordinator(t, 30*time.Millisecond, 5*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyName, 1)
	if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightNameRead); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	transaction, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("recall returned before the grant could expire: %v", elapsed)
	}
	if fencer.count(peer) != 1 {
		t.Fatalf("FenceSession calls = %d, want 1", fencer.count(peer))
	}
	if held := coordinator.Held(peer); len(held) != 0 {
		t.Fatalf("expired holder retained grants: %+v", held)
	}
	if err := completeLeaseTest(transaction, context.Background(), nil, 0, false); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseIndependentCoordinatesRecallConcurrently(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	sourceOne, sourceTwo, peerOne, peerTwo := leaseTestID(1), leaseTestID(2), leaseTestID(3), leaseTestID(4)
	for _, id := range []SessionID{sourceOne, sourceTwo, peerOne, peerTwo} {
		activateLeaseTestHolder(t, coordinator, id)
	}
	coordinateOne := leaseTestCoordinate(LeaseFamilyAttributes, 1)
	coordinateTwo := leaseTestCoordinate(LeaseFamilyAttributes, 2)
	if _, err := coordinator.Grant(context.Background(), peerOne, coordinateOne, LeaseRightAttributesRead); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Grant(context.Background(), peerTwo, coordinateTwo, LeaseRightAttributesRead); err != nil {
		t.Fatal(err)
	}

	prepare := func(source SessionID, coordinate LeaseCoordinate, result chan<- *LeaseRecallTransaction) {
		transaction, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			panic(err)
		}
		result <- transaction
	}
	resultOne, resultTwo := make(chan *LeaseRecallTransaction, 1), make(chan *LeaseRecallTransaction, 1)
	go prepare(sourceOne, coordinateOne, resultOne)
	go prepare(sourceTwo, coordinateTwo, resultTwo)
	revokeOne, err := coordinator.Next(context.Background(), peerOne, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	revokeTwo, err := coordinator.Next(context.Background(), peerTwo, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if revokeOne.Cursor.Sequence == revokeTwo.Cursor.Sequence {
		t.Fatalf("independent recalls reused sequence %d", revokeOne.Cursor.Sequence)
	}
	if err := coordinator.AcknowledgeRevoke(peerOne, revokeOne.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(peerTwo, revokeTwo.Cursor); err != nil {
		t.Fatal(err)
	}
	transactionOne, transactionTwo := <-resultOne, <-resultTwo
	completeOne, completeTwo := make(chan error, 1), make(chan error, 1)
	go func() { completeOne <- completeLeaseTest(transactionOne, context.Background(), nil, 0, false) }()
	go func() { completeTwo <- completeLeaseTest(transactionTwo, context.Background(), nil, 0, false) }()
	eventOne, err := coordinator.Next(context.Background(), peerOne, revokeOne.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	eventTwo, err := coordinator.Next(context.Background(), peerTwo, revokeTwo.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peerOne, eventOne.Cursor, []LeaseDischarge{{Coordinate: coordinateOne, RevokeEpoch: eventOne.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone}}); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peerTwo, eventTwo.Cursor, []LeaseDischarge{{Coordinate: coordinateTwo, RevokeEpoch: eventTwo.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeOne; err != nil {
		t.Fatal(err)
	}
	if err := <-completeTwo; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseSameHolderSerializesAcrossRevokeCompleteGap(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	sourceOne, sourceTwo, peer := leaseTestID(1), leaseTestID(2), leaseTestID(3)
	for _, id := range []SessionID{sourceOne, sourceTwo, peer} {
		activateLeaseTestHolder(t, coordinator, id)
	}
	coordinateOne := leaseTestCoordinate(LeaseFamilyAttributes, 1)
	coordinateTwo := leaseTestCoordinate(LeaseFamilyAttributes, 2)
	for _, coordinate := range []LeaseCoordinate{coordinateOne, coordinateTwo} {
		if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightAttributesRead); err != nil {
			t.Fatal(err)
		}
	}

	preparedOne := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), sourceOne, []LeaseRecallTarget{{Coordinate: coordinateOne}})
		if err != nil {
			panic(err)
		}
		preparedOne <- transaction
	}()
	revokeOne, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revokeOne.Cursor); err != nil {
		t.Fatal(err)
	}
	transactionOne := <-preparedOne

	preparedTwo := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), sourceTwo, []LeaseRecallTarget{{Coordinate: coordinateTwo}})
		if err != nil {
			panic(err)
		}
		preparedTwo <- transaction
	}()
	select {
	case transaction := <-preparedTwo:
		transaction.Abort()
		t.Fatal("second recall passed the holder lane between first REVOKE and COMPLETE")
	case <-time.After(10 * time.Millisecond):
	}

	completeOneErr := make(chan error, 1)
	go func() { completeOneErr <- completeLeaseTest(transactionOne, context.Background(), nil, 0, false) }()
	completeOne, err := coordinator.Next(context.Background(), peer, revokeOne.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case transaction := <-preparedTwo:
		transaction.Abort()
		t.Fatal("second recall passed the holder lane before first COMPLETE discharge")
	case <-time.After(10 * time.Millisecond):
	}
	if err := coordinator.Discharge(peer, completeOne.Cursor, []LeaseDischarge{{
		Coordinate: coordinateOne, RevokeEpoch: completeOne.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeOneErr; err != nil {
		t.Fatal(err)
	}

	revokeTwo, err := coordinator.Next(context.Background(), peer, completeOne.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revokeTwo.Cursor); err != nil {
		t.Fatal(err)
	}
	transactionTwo := <-preparedTwo
	completeTwoErr := make(chan error, 1)
	go func() { completeTwoErr <- completeLeaseTest(transactionTwo, context.Background(), nil, 0, false) }()
	completeTwo, err := coordinator.Next(context.Background(), peer, revokeTwo.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, completeTwo.Cursor, []LeaseDischarge{{
		Coordinate: coordinateTwo, RevokeEpoch: completeTwo.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeTwoErr; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseReadAdmissionMakesStaleReplyGrantPartOfRecall(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyAttributes, 1)

	// This admission represents a storage read that has already produced the old
	// attributes but has not yet installed the grant carried by its response.
	admission, err := coordinator.BeginRead(context.Background(), peer, coordinate)
	if err != nil {
		t.Fatal(err)
	}
	prepared := make(chan *LeaseRecallTransaction, 1)
	prepareErr := make(chan error, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			prepareErr <- err
			return
		}
		prepared <- transaction
	}()
	select {
	case transaction := <-prepared:
		transaction.Abort()
		t.Fatal("mutation prepared while a stale read was still admitted")
	case err := <-prepareErr:
		t.Fatal(err)
	case <-time.After(10 * time.Millisecond):
	}

	grant, err := admission.Grant(coordinate, LeaseRightAttributesRead)
	if err != nil {
		t.Fatal(err)
	}
	admission.Release()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if len(revoke.Recalls) != 1 || revoke.Recalls[0].GrantEpoch != grant.Epoch {
		t.Fatalf("REVOKE = %+v, want stale response grant epoch %d", revoke.Recalls, grant.Epoch)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	var transaction *LeaseRecallTransaction
	select {
	case transaction = <-prepared:
	case err := <-prepareErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("mutation did not prepare after stale grant entered recall")
	}
	completeErr := make(chan error, 1)
	go func() { completeErr <- completeLeaseTest(transaction, context.Background(), nil, 0, false) }()
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseReadAdmissionCannotGrantAfterRelease(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	holder := leaseTestID(1)
	activateLeaseTestHolder(t, coordinator, holder)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)

	for range 100 {
		admission, err := coordinator.BeginRead(context.Background(), holder, coordinate)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		grantErr := make(chan error, 1)
		go func() {
			<-start
			_, err := admission.Grant(coordinate, LeaseRightDataRead)
			grantErr <- err
		}()
		close(start)
		admission.Release()
		if err := <-grantErr; err != nil && !errors.Is(err, ErrLeaseEpoch) {
			t.Fatalf("concurrent Grant() error = %v, want success-before-release or %v", err, ErrLeaseEpoch)
		}
		if _, err := admission.Grant(coordinate, LeaseRightDataRead); !errors.Is(err, ErrLeaseEpoch) {
			t.Fatalf("Grant() after Release error = %v, want %v", err, ErrLeaseEpoch)
		}
	}
}

func TestLeasePrepareCancellationCannotSkipDispatchedRevoke(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyName, 1)
	if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightNameRead); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	prepared := make(chan *LeaseRecallTransaction, 1)
	prepareErr := make(chan error, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(ctx, source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			prepareErr <- err
			return
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case transaction := <-prepared:
		transaction.Abort()
		t.Fatal("PrepareRecall returned before dispatched REVOKE acknowledgement")
	case err := <-prepareErr:
		t.Fatalf("PrepareRecall returned cancellation after dispatch: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	var transaction *LeaseRecallTransaction
	select {
	case transaction = <-prepared:
	case err := <-prepareErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("PrepareRecall did not complete after REVOKE acknowledgement")
	}
	completeErr := make(chan error, 1)
	go func() { completeErr <- completeLeaseTest(transaction, context.Background(), nil, 0, false) }()
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseNewReadWaitsUntilOldCacheIsDischarged(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, oldHolder, newReader := leaseTestID(1), leaseTestID(2), leaseTestID(3)
	for _, id := range []SessionID{source, oldHolder, newReader} {
		activateLeaseTestHolder(t, coordinator, id)
	}
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	if _, err := coordinator.Grant(context.Background(), oldHolder, coordinate, LeaseRightDataRead); err != nil {
		t.Fatal(err)
	}
	prepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			panic(err)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), oldHolder, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(oldHolder, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared // Filesystem apply occurs after this point.
	if _, err := tryLeaseRead(coordinator, newReader, coordinate); !errors.Is(err, ErrLeaseBlocked) {
		t.Fatalf("read during recall error = %v, want %v", err, ErrLeaseBlocked)
	}

	readReady := make(chan *LeaseReadAdmission, 1)
	go func() {
		admission, err := coordinator.BeginRead(context.Background(), newReader, coordinate)
		if err != nil {
			panic(err)
		}
		readReady <- admission
	}()
	select {
	case admission := <-readReady:
		admission.Release()
		t.Fatal("post-apply read entered while an old cache holder was not discharged")
	case <-time.After(10 * time.Millisecond):
	}

	completeErr := make(chan error, 1)
	go func() { completeErr <- completeLeaseTest(transaction, context.Background(), nil, 1, false) }()
	complete, err := coordinator.Next(context.Background(), oldHolder, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case admission := <-readReady:
		admission.Release()
		t.Fatal("post-apply read entered before COMPLETE discharge")
	case <-time.After(10 * time.Millisecond):
	}
	if err := coordinator.Discharge(oldHolder, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
	select {
	case admission := <-readReady:
		admission.Release()
	case <-time.After(time.Second):
		t.Fatal("post-apply read did not enter after old cache discharge")
	}
}

func TestLeaseFencePreventsGrantAndRenewal(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	holder := leaseTestID(1)
	activateLeaseTestHolder(t, coordinator, holder)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	grant, err := coordinator.Grant(context.Background(), holder, coordinate, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := coordinator.BeginRead(context.Background(), holder, leaseTestCoordinate(LeaseFamilyAttributes, 1))
	if err != nil {
		t.Fatal(err)
	}
	coordinator.FenceHolder(holder)
	if _, err := admission.Grant(leaseTestCoordinate(LeaseFamilyAttributes, 1), LeaseRightAttributesRead); !errors.Is(err, ErrLeaseHolder) {
		t.Fatalf("admitted Grant after FenceHolder error = %v, want %v", err, ErrLeaseHolder)
	}
	admission.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := coordinator.BeginRead(ctx, holder, coordinate); !errors.Is(err, ErrLeaseHolder) {
		t.Fatalf("BeginRead after FenceHolder error = %v, want %v", err, ErrLeaseHolder)
	}
	if _, _, err := coordinator.Renew(holder, []LeaseRenewal{{Coordinate: coordinate, Epoch: grant.Epoch}}); !errors.Is(err, ErrLeaseHolder) {
		t.Fatalf("Renew after FenceHolder error = %v, want %v", err, ErrLeaseHolder)
	}
	if renewed := coordinator.RenewHeld(holder); len(renewed) != 0 {
		t.Fatalf("RenewHeld after FenceHolder = %+v, want none", renewed)
	}
	if held := coordinator.Held(holder); len(held) != 1 || held[0].Epoch != grant.Epoch || !held[0].ExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatalf("FenceHolder changed existing expiry: %+v", held)
	}
}

func TestLeaseFencedSourceKeepsBarrierUntilOriginalGrantExpiry(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, 100*time.Millisecond, 10*time.Millisecond)
	source, peer, reader := leaseTestID(1), leaseTestID(2), leaseTestID(3)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	activateLeaseTestHolder(t, coordinator, reader)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	grant, err := coordinator.Grant(context.Background(), source, coordinate, LeaseRightDataRead)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightDataRead); err != nil {
		t.Fatal(err)
	}

	prepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, prepareErr := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if prepareErr != nil {
			panic(prepareErr)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared
	coordinator.FenceHolder(source)

	completeResult := make(chan *LeaseSourceDischarge, 1)
	completeErr := make(chan error, 1)
	go func() {
		discharge, completeError := transaction.CompletePeers(context.Background(), nil, 1, true)
		completeResult <- discharge
		completeErr <- completeError
	}()
	complete, err := coordinator.Next(context.Background(), peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if discharge := <-completeResult; discharge != nil {
		t.Fatalf("fenced source received wire discharge: %+v", discharge)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
	if _, err := tryLeaseRead(coordinator, reader, coordinate); !errors.Is(err, ErrLeaseBlocked) {
		t.Fatalf("read before fenced source expiry error = %v, want %v", err, ErrLeaseBlocked)
	}

	deadline := time.Now().Add(time.Second)
	for {
		admission, err := tryLeaseRead(coordinator, reader, coordinate)
		if err == nil {
			admission.Release()
			break
		}
		if !errors.Is(err, ErrLeaseBlocked) {
			t.Fatalf("read while waiting for source expiry: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("source barrier outlived original grant expiry %v", grant.ExpiresAt)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLeaseNoopPreservesSourceGrantForLaterPeerRecall(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyAttributes, 1)
	grant, err := coordinator.Grant(context.Background(), source, coordinate, LeaseRightAttributesRead)
	if err != nil {
		t.Fatal(err)
	}
	noop, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
	if err != nil {
		t.Fatal(err)
	}
	if err := completeLeaseTest(noop, context.Background(), nil, 0, false); err != nil {
		t.Fatal(err)
	}
	held := coordinator.Held(source)
	if len(held) != 1 || held[0].Epoch != grant.Epoch || !held[0].ExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatalf("no-op changed source grant: %+v", held)
	}

	prepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), peer, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			panic(err)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), source, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if len(revoke.Recalls) != 1 || revoke.Recalls[0].GrantEpoch != grant.Epoch {
		t.Fatalf("later peer recall = %+v, want preserved source epoch %d", revoke.Recalls, grant.Epoch)
	}
	if err := coordinator.AcknowledgeRevoke(source, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	transaction := <-prepared
	completeErr := make(chan error, 1)
	go func() {
		completeErr <- completeLeaseTest(transaction, context.Background(), nil, transaction.Sequence(), false)
	}()
	complete, err := coordinator.Next(context.Background(), source, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(source, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseEventCursorIsExactTokenNotMonotonicSequence(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinateA := leaseTestCoordinate(LeaseFamilyData, 1)
	coordinateB := leaseTestCoordinate(LeaseFamilyData, 2)
	for _, coordinate := range []LeaseCoordinate{coordinateA, coordinateB} {
		if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightDataRead); err != nil {
			t.Fatal(err)
		}
	}
	admission, err := coordinator.BeginRead(context.Background(), source, coordinateA)
	if err != nil {
		t.Fatal(err)
	}
	preparedA := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, prepareErr := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinateA}})
		if prepareErr != nil {
			panic(prepareErr)
		}
		preparedA <- transaction
	}()
	deadline := time.Now().Add(time.Second)
	for {
		coordinator.mu.Lock()
		blocked := coordinator.blocked[coordinateA.key()] != nil
		coordinator.mu.Unlock()
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first recall never reserved its coordinate")
		}
		time.Sleep(time.Millisecond)
	}

	preparedB := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, prepareErr := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinateB}})
		if prepareErr != nil {
			panic(prepareErr)
		}
		preparedB <- transaction
	}()
	revokeB, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revokeB.Cursor); err != nil {
		t.Fatal(err)
	}
	transactionB := <-preparedB
	completedB := make(chan error, 1)
	go func() { completedB <- completeLeaseTest(transactionB, context.Background(), nil, 0, false) }()
	completeB, err := coordinator.Next(context.Background(), peer, revokeB.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, completeB.Cursor, []LeaseDischarge{{
		Coordinate: coordinateB, RevokeEpoch: completeB.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completedB; err != nil {
		t.Fatal(err)
	}

	admission.Release()
	revokeA, err := coordinator.Next(context.Background(), peer, completeB.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if revokeA.Cursor.Sequence >= revokeB.Cursor.Sequence {
		t.Fatalf("delayed cursor sequence = %d, want less than already completed %d", revokeA.Cursor.Sequence, revokeB.Cursor.Sequence)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revokeA.Cursor); err != nil {
		t.Fatal(err)
	}
	transactionA := <-preparedA
	completedA := make(chan error, 1)
	go func() { completedA <- completeLeaseTest(transactionA, context.Background(), nil, 0, false) }()
	completeA, err := coordinator.Next(context.Background(), peer, revokeA.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, completeA.Cursor, []LeaseDischarge{{
		Coordinate: coordinateA, RevokeEpoch: completeA.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completedA; err != nil {
		t.Fatal(err)
	}
}

func TestLeaseConstructorRejectsTTLBeyondProtocolHorizon(t *testing.T) {
	// StartupGrace >= TTL is what makes an unclean authority restart safe, and
	// that argument only bounds anything because no configuration may name a TTL
	// longer than the frozen protocol horizon.
	base := LeaseConfig{
		TTL: Protocol6MaxLeaseTTL, RecallBudget: time.Second, MaxPerHolder: 16, MaxTotal: 64,
		StartupGrace: Protocol6MaxLeaseTTL, Fencer: &leaseTestFencer{},
	}
	if _, err := NewLeaseCoordinator(base); err != nil {
		t.Fatalf("TTL at the protocol horizon was rejected: %v", err)
	}
	beyond := base
	beyond.TTL = Protocol6MaxLeaseTTL + time.Nanosecond
	beyond.StartupGrace = beyond.TTL
	if _, err := NewLeaseCoordinator(beyond); err == nil {
		t.Fatal("a TTL past the protocol horizon was accepted; restart recovery can no longer bound prior grants")
	}
	short := base
	short.StartupGrace = base.TTL - time.Nanosecond
	if _, err := NewLeaseCoordinator(short); err == nil {
		t.Fatal("a startup grace shorter than the TTL was accepted")
	}
}

// leaseRecallToApply drives one transaction to the point where the peer has
// acknowledged REVOKE and the caller owns the pre-apply window.
func leaseRecallToApply(t *testing.T, coordinator *LeaseCoordinator, source, peer SessionID,
	coordinate LeaseCoordinate) (*LeaseRecallTransaction, LeaseEventCursor) {
	t.Helper()
	prepared := make(chan *LeaseRecallTransaction, 1)
	go func() {
		transaction, err := coordinator.PrepareRecall(context.Background(), source, []LeaseRecallTarget{{Coordinate: coordinate}})
		if err != nil {
			panic(err)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), peer, LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	return <-prepared, revoke.Cursor
}

func TestLeaseDataReadWaitsForApplyAndThenMissesUntilDischarge(t *testing.T) {
	// The blocking read(2) case. A data read may not be refused, and it may not
	// wait past apply either: the callback holds the folio the recall's own purge
	// needs. So it parks until apply, then is answered with no cache authority.
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 200*time.Millisecond)
	source, peer, reader := leaseTestID(1), leaseTestID(2), leaseTestID(3)
	for _, id := range []SessionID{source, peer, reader} {
		activateLeaseTestHolder(t, coordinator, id)
	}
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	// The source holds the coordinate too, so the transaction mints a source
	// discharge obligation and the coordinate stays closed past COMPLETE.
	for _, id := range []SessionID{peer, source} {
		if _, err := coordinator.Grant(context.Background(), id, coordinate, LeaseRightDataRead); err != nil {
			t.Fatal(err)
		}
	}
	transaction, revokeCursor := leaseRecallToApply(t, coordinator, source, peer, coordinate)

	type admitted struct {
		admission *LeaseReadAdmission
		err       error
	}
	readReady := make(chan admitted, 1)
	go func() {
		// The peer is the holder under recall: its own purge is still pending,
		// so this is the one reader that may not be given fresh authority.
		admission, err := coordinator.BeginDataRead(context.Background(), peer, coordinate)
		readReady <- admitted{admission: admission, err: err}
	}()
	select {
	case result := <-readReady:
		if result.admission != nil {
			result.admission.Release()
		}
		t.Fatalf("data read entered mid-apply (err = %v); it must observe the applied bytes", result.err)
	case <-time.After(25 * time.Millisecond):
	}

	completeErr := make(chan error, 1)
	go func() { completeErr <- completeLeaseTest(transaction, context.Background(), nil, 1, true) }()

	// Apply is over the moment COMPLETE is composed, and the peer has not
	// discharged yet: the read must enter here, because the peer's purge is what
	// this read would otherwise be waiting behind.
	var result admitted
	select {
	case result = <-readReady:
	case <-time.After(2 * time.Second):
		t.Fatal("data read did not enter after apply; the recall and its readers can now deadlock")
	}
	if result.err != nil {
		t.Fatalf("post-apply data read = %v, want admission", result.err)
	}
	if _, err := result.admission.Grant(coordinate, LeaseRightDataRead); !errors.Is(err, ErrLeaseBlocked) {
		t.Fatalf("grant to the holder still discharging = %v, want %v", err, ErrLeaseBlocked)
	}
	result.admission.Release()

	// A mount that is not part of this recall is served under fresh authority.
	// Answering it without a grant would leave pages in a kernel that no later
	// recall could reach, because that mount would hold no lease to recall.
	thirdParty, err := coordinator.BeginDataRead(context.Background(), reader, coordinate)
	if err != nil {
		t.Fatalf("post-apply read by an uninvolved mount = %v, want admission", err)
	}
	if _, err := thirdParty.Grant(coordinate, LeaseRightDataRead); err != nil {
		t.Fatalf("post-apply grant to an uninvolved mount: %v", err)
	}
	thirdParty.Release()

	complete, err := coordinator.Next(context.Background(), peer, revokeCursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
	// The peer has discharged, so it holds no record this recall still owns.
	// The source's receipt is still outstanding, but that closes nothing against
	// a mount whose cache is already proven clean.
	admission, err := coordinator.BeginDataRead(context.Background(), peer, coordinate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.Grant(coordinate, LeaseRightDataRead); err != nil {
		t.Fatalf("grant to a discharged peer before the source receipt: %v", err)
	}
	admission.Release()
	if err := coordinator.DischargeSource(source, transaction.Sequence()); err != nil {
		t.Fatal(err)
	}
	admission, err = coordinator.BeginDataRead(context.Background(), reader, coordinate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.Grant(coordinate, LeaseRightDataRead); err != nil {
		t.Fatalf("grant after full discharge: %v", err)
	}
	admission.Release()
}

func TestLeaseSourceDataReadWaitsForItsOwnApplyThenSeesAppliedState(t *testing.T) {
	// The single-mount shape of the same rule: a second thread reading the file
	// this mount is writing waits for the apply, and is admitted for the whole
	// pre-receipt window afterwards, under the source's own receipt exception.
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 200*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	for _, id := range []SessionID{source, peer} {
		if _, err := coordinator.Grant(context.Background(), id, coordinate, LeaseRightDataRead); err != nil {
			t.Fatal(err)
		}
	}
	transaction, revokeCursor := leaseRecallToApply(t, coordinator, source, peer, coordinate)
	if _, err := tryLeaseRead(coordinator, source, coordinate); !errors.Is(err, ErrLeaseBlocked) {
		t.Fatalf("source read mid-apply = %v, want the barrier to hold it", err)
	}
	sourceRead := make(chan error, 1)
	go func() {
		admission, err := coordinator.BeginDataRead(context.Background(), source, coordinate)
		if admission != nil {
			admission.Release()
		}
		sourceRead <- err
	}()
	select {
	case err := <-sourceRead:
		t.Fatalf("source data read entered mid-apply: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	completeErr := make(chan error, 1)
	go func() { completeErr <- completeLeaseTest(transaction, context.Background(), nil, 1, true) }()
	select {
	case err := <-sourceRead:
		if err != nil {
			t.Fatalf("source data read after apply = %v, want admission", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("source data read did not enter after its own apply")
	}
	complete, err := coordinator.Next(context.Background(), peer, revokeCursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
	// Post-COMPLETE, pre-receipt: the source owes the receipt, so the coordinate
	// is not closed against the source and its read is cacheable again.
	admission, err := coordinator.BeginDataRead(context.Background(), source, coordinate)
	if err != nil {
		t.Fatalf("source read before its own receipt = %v, want admission", err)
	}
	if _, err := admission.Grant(coordinate, LeaseRightDataRead); err != nil {
		t.Fatalf("source grant before its own receipt: %v", err)
	}
	admission.Release()
	if err := coordinator.DischargeSource(source, transaction.Sequence()); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseDataReadWakesWhenTheRecallAborts(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 200*time.Millisecond)
	source, peer, reader := leaseTestID(1), leaseTestID(2), leaseTestID(3)
	for _, id := range []SessionID{source, peer, reader} {
		activateLeaseTestHolder(t, coordinator, id)
	}
	coordinate := leaseTestCoordinate(LeaseFamilyData, 1)
	if _, err := coordinator.Grant(context.Background(), peer, coordinate, LeaseRightDataRead); err != nil {
		t.Fatal(err)
	}
	transaction, revokeCursor := leaseRecallToApply(t, coordinator, source, peer, coordinate)
	readReady := make(chan error, 1)
	go func() {
		admission, err := coordinator.BeginDataRead(context.Background(), reader, coordinate)
		if admission != nil {
			admission.Release()
		}
		readReady <- err
	}()
	aborted := make(chan struct{})
	go func() { transaction.Abort(); close(aborted) }()
	complete, err := coordinator.Next(context.Background(), peer, revokeCursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	<-aborted
	select {
	case err := <-readReady:
		if err != nil {
			t.Fatalf("data read after an aborted recall = %v, want admission", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an aborted recall left its data readers parked")
	}
}

func TestLeaseSourcePostStateGrantRejectsAnUnpreparedCoordinate(t *testing.T) {
	coordinator, _ := newLeaseTestCoordinator(t, time.Second, 100*time.Millisecond)
	source, peer := leaseTestID(1), leaseTestID(2)
	activateLeaseTestHolder(t, coordinator, source)
	activateLeaseTestHolder(t, coordinator, peer)
	prepared := leaseTestCoordinate(LeaseFamilyAttributes, 1)
	unprepared := leaseTestCoordinate(LeaseFamilyAttributes, 2)
	if _, err := coordinator.Grant(context.Background(), peer, prepared, LeaseRightAttributesRead); err != nil {
		t.Fatal(err)
	}
	transaction, revokeCursor := leaseRecallToApply(t, coordinator, source, peer, prepared)
	t.Cleanup(func() {
		go func() {
			complete, err := coordinator.Next(context.Background(), peer, revokeCursor)
			if err != nil {
				return
			}
			_ = coordinator.Discharge(peer, complete.Cursor, []LeaseDischarge{{
				Coordinate: prepared, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: LeaseDischargeToNone,
			}})
		}()
		transaction.Abort()
	})

	if grants := transaction.GrantSourcePostState([]LeaseGrantRequest{
		{Coordinate: prepared, Right: LeaseRightAttributesRead},
	}); len(grants) != 1 {
		t.Fatalf("successor over a recalled coordinate = %+v, want one grant", grants)
	}
	// A created identity is the one legal absence: no peer could have held a
	// lease on an identity that did not exist before this transaction.
	if grants := transaction.GrantSourcePostState([]LeaseGrantRequest{
		{Coordinate: unprepared, Right: LeaseRightAttributesRead, Created: true},
	}); len(grants) != 1 {
		t.Fatalf("successor over a created identity = %+v, want one grant", grants)
	}
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("a successor over a coordinate this transaction never recalled was minted silently")
		}
	}()
	transaction.GrantSourcePostState([]LeaseGrantRequest{{Coordinate: unprepared, Right: LeaseRightAttributesRead}})
}
