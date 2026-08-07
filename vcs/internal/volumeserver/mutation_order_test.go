package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func waitForMutationOrderQueue(t *testing.T, order *mutationOrder, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for order.queued() != want {
		if time.Now().After(deadline) {
			t.Fatalf("queued mutation turns = %d, want %d", order.queued(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMutationOrderIsFIFOWithoutLeapfrog(t *testing.T) {
	order := newMutationOrder()
	owner, err := order.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan int, 4)
	release := []chan struct{}{nil, make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})}
	start := func(id int) {
		go func() {
			turn, err := order.acquire(context.Background())
			if err != nil {
				acquired <- -id
				return
			}
			acquired <- id
			<-release[id]
			turn.release()
		}()
	}
	for id := 1; id <= 3; id++ {
		start(id)
		waitForMutationOrderQueue(t, order, id)
	}

	owner.release()
	if got := <-acquired; got != 1 {
		t.Fatalf("first grant = %d, want 1", got)
	}
	start(4)
	waitForMutationOrderQueue(t, order, 3)
	for want := 2; want <= 4; want++ {
		close(release[want-1])
		if got := <-acquired; got != want {
			t.Fatalf("grant after %d = %d, want %d", want-1, got, want)
		}
	}
	close(release[4])
	waitForMutationOrderQueue(t, order, 0)
}

func TestMutationOrderCancellationRemovesMiddleWithoutReordering(t *testing.T) {
	order := newMutationOrder()
	owner, err := order.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	contexts := []context.Context{ctx1, ctx2, ctx3}
	acquired := make(chan int, 3)
	errorsSeen := make(chan error, 3)
	release := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	for id := 0; id < 3; id++ {
		id := id
		go func() {
			turn, err := order.acquire(contexts[id])
			if err != nil {
				errorsSeen <- err
				return
			}
			acquired <- id + 1
			<-release[id]
			turn.release()
		}()
		waitForMutationOrderQueue(t, order, id+1)
	}

	cancel2()
	select {
	case err := <-errorsSeen:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("middle cancellation = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("middle waiter did not cancel")
	}
	waitForMutationOrderQueue(t, order, 2)

	owner.release()
	if got := <-acquired; got != 1 {
		t.Fatalf("first surviving grant = %d, want 1", got)
	}
	close(release[0])
	if got := <-acquired; got != 3 {
		t.Fatalf("second surviving grant = %d, want 3", got)
	}
	close(release[2])
	waitForMutationOrderQueue(t, order, 0)
}

func TestMutationOrderGrantCancellationCannotLeakOwnership(t *testing.T) {
	for range 1_000 {
		order := newMutationOrder()
		owner, err := order.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			turn, err := order.acquire(ctx)
			if err == nil {
				turn.release()
			}
			result <- err
		}()
		waitForMutationOrderQueue(t, order, 1)
		cancel()
		owner.release()
		<-result
		probe, err := order.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		probe.release()
	}
}

func TestMutationOrderReservationNeverBlocksAbsentClaimant(t *testing.T) {
	order := newMutationOrder()
	_ = order.reserveOrdinal()
	turn, err := order.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	turn.release()
	if got := order.queued(); got != 0 {
		t.Fatalf("unclaimed reservation left %d queued waiters", got)
	}
}

func TestMutationOrderClaimReusesReservedOrdinal(t *testing.T) {
	order := newMutationOrder()
	owner, err := order.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reserved := order.reserveOrdinal()
	later := order.enqueueFor(0)
	claimant := order.enqueueFor(reserved)

	owner.release()
	select {
	case <-claimant.ready:
	case <-later.ready:
		t.Fatal("later traffic leapfrogged the reserved claimant")
	case <-time.After(2 * time.Second):
		t.Fatal("reserved claimant was not granted")
	}
	claimant.release()
	select {
	case <-later.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("later waiter was not granted after claimant")
	}
	later.release()
}
