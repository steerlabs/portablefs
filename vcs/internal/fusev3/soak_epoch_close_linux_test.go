//go:build linux

package fusev3

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type soakEndedEpochRPC struct {
	delegationFakeRPC
	releaseStarted chan struct{}
	once           sync.Once
}

func (f *soakEndedEpochRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetDelegationRelease() != nil {
		f.once.Do(func() { close(f.releaseStarted) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.delegationFakeRPC.CallIdempotent(ctx, request)
}

func (f *soakEndedEpochRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		return nil, errors.New("durability withheld for epoch replacement")
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

// This is the deterministic manager-level reduction of the real two-mount
// epoch-replacement hang in test/soak. The RPC applies WRITE but the old epoch
// cannot supply a durability receipt. EpochChanged must end that wait itself.
func TestSoakEpochChangeUnblocksPendingClose(t *testing.T) {
	if os.Getenv("PORTABLEFS_SOAK_TEST") != "1" {
		t.Skip("known soak finding; enable PORTABLEFS_SOAK_TEST=1 to reproduce")
	}
	fake := &soakEndedEpochRPC{releaseStarted: make(chan struct{})}
	m := newDelegationTestManager(t, fake)
	var reportMu sync.Mutex
	var reports []writeback.DropReport
	m.SetDropReporter(func(report writeback.DropReport) {
		reportMu.Lock()
		reports = append(reports, report)
		reportMu.Unlock()
	})
	id := installDelegationForTest(t, m, 41, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("old-epoch-undurable"), false); err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- m.CloseHandles(context.Background(), []delegationClose{{identity: id, handle: delegationTestToken(41, 2)}})
	}()
	select {
	case <-fake.releaseStarted:
	case <-time.After(time.Second):
		t.Fatal("old-epoch close did not park at delegation release")
	}
	epochDone := make(chan struct{})
	go func() { m.EpochChanged("soak epoch replacement"); close(epochDone) }()
	select {
	case <-epochDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("EpochChanged waits behind an RPC-parked CloseHandles; buffer=%+v", m.buf.Stats())
	}
	select {
	case err := <-closeDone:
		if !errors.Is(err, writeback.ErrLost) {
			t.Fatalf("CloseHandles error = %v, want ErrLost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not return after epoch cancellation")
	}
	reportMu.Lock()
	defer reportMu.Unlock()
	if len(reports) != 1 || reports[0].Entries != 1 {
		t.Fatalf("epoch loss reports = %+v, want one retained record", reports)
	}
}
