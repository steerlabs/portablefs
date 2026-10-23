//go:build linux

package mountcontrol

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func awakeRequest(t *testing.T) Request {
	t.Helper()
	q := request("workspace-suspend", 1, 1)
	x := suspension(t)
	x.AwakeRecovery = true
	var err error
	q.Workspace.Transaction, err = EncodeTransaction(x)
	if err != nil {
		t.Fatal(err)
	}
	q.Workspace.HostRequestID = "7"
	q.Workspace.DrainBudgetNanos = "0"
	return q
}
func TestAwakeCutHasNoPowerDeadlineAndNewPermitCancelsActualWorker(t *testing.T) {
	entered := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if !j.DrainDeadline().IsZero() {
			t.Error("awake cut inherited power deadline")
		}
		if _, ok := ctx.Deadline(); ok {
			t.Error("awake worker inherited socket budget")
		}
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	var permitted atomic.Bool
	permitted.Store(true)
	o.CheckPermit = func(Workspace) bool { return permitted.Load() }
	q := awakeRequest(t)
	if err := q.ValidateWorkspace(); err != nil {
		t.Fatal(err)
	}
	j := start(t, o, q)
	<-entered
	permitted.Store(false)
	o.PollPermit()
	select {
	case <-j.done:
	case <-time.After(time.Second):
		t.Fatal("obsolete cold worker not joined")
	}
	if !j.lifecycleOwner.Overtaken() {
		t.Fatal("permit cancellation lost lifecycle owner")
	}
}
func TestAwakeCutCannotSmuggleOrDropPowerBudget(t *testing.T) {
	q := awakeRequest(t)
	q.Workspace.DrainBudgetNanos = "1"
	if q.ValidateWorkspace() == nil {
		t.Fatal("awake work received power budget")
	}
	q = request("workspace-suspend", 1, 1)
	transaction(t, &q)
	q.Workspace.DrainBudgetNanos = "0"
	if q.ValidateWorkspace() == nil {
		t.Fatal("power work escaped its budget")
	}
}
