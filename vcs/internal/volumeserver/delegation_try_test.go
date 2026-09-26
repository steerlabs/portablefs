package volumeserver

import "testing"

func TestTryDataConsumedNeverWaitsWhileStorageIsHeld(t *testing.T) {
	c, _ := cv2Coordinator(t)
	reader := cv2Subscribe(t, c, 1)
	owner := cv2Subscribe(t, c, 2)
	id := [16]byte{8}
	grant := cv2Grant(t, c, owner, id, reader)
	if guard, ok, err := c.TryDataConsumed(t.Context(), reader, id); err != nil || ok || guard != nil {
		t.Fatalf("foreign grant entered nonblocking path: %v %v", ok, err)
	}
	guard, ok, err := c.TryDataConsumed(t.Context(), owner, id)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	guard.Release()
	if got, _ := c.LookupDelegation(id); got.ID != grant.ID || got.State != DelegationActive {
		t.Fatal("try admission initiated a peer break")
	}
	free := [16]byte{9}
	turn, err := c.requests.acquire(t.Context(), delegationDependencies(free))
	if err != nil {
		t.Fatal(err)
	}
	if guard, ok, err := c.TryDataConsumed(t.Context(), reader, free); err != nil || ok || guard != nil {
		t.Fatalf("queued turn blocked probe: %v %v", ok, err)
	}
	if c.requests.queued() != 0 {
		t.Fatal("failed try admission leaked waiter")
	}
	turn.release()
	guard, ok, err = c.TryDataConsumed(t.Context(), reader, free)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	guard.Release()
}
