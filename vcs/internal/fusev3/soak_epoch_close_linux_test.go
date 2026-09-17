//go:build linux

package fusev3

import (
	"context"
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

type soakEndedEpochRPC struct{ delegationFakeRPC }

func (f *soakEndedEpochRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		return nil, authorityrpc.ErrAuthorityChanged
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
	m := newDelegationTestManager(t, &soakEndedEpochRPC{})
	id := installDelegationForTest(t, m, 41, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("old-epoch-undurable"), false); err != nil {
		t.Fatal(err)
	}
	closeCtx, cancelClose := context.WithCancel(context.Background())
	defer cancelClose()
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- m.CloseHandles(closeCtx, []delegationClose{{identity: id, handle: []byte{41, 2}}})
	}()
	waitUntil(t, time.Second, "old-epoch close to wait on applied bytes", func() bool { return m.buf.Stats().Applied == 1 })
	epochDone := make(chan struct{})
	go func() { m.EpochChanged("soak epoch replacement"); close(epochDone) }()
	select {
	case <-epochDone:
	case <-time.After(250 * time.Millisecond):
		t.Errorf("EpochChanged waits behind CloseHandles epoch read lock; buffer=%+v", m.buf.Stats())
		_ = pprof.Lookup("goroutine").WriteTo(os.Stdout, 2)
	}
	// This cancellation is test containment, not the recovery being asserted.
	cancelClose()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("close did not release after explicit test cancellation")
	}
	select {
	case <-epochDone:
	case <-time.After(time.Second):
		t.Fatal("epoch did not complete after explicit test cancellation")
	}
}
