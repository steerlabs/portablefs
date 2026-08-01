package cli

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fusefrontend"
)

// TestFUSEWriteUnwindPassesShareOneAbsoluteDeadline is the operation-bound
// contract on the FUSE write path.
//
// A write's lane is resolved before the volume call and can be invalidated
// during it; the frontend unwinds and re-classifies. Volume.AdmitWrite installs
// the operation deadline IDEMPOTENTLY — it will not extend a deadline the caller
// already carries — so the bound is only a bound if the caller installs it once,
// outside the loop. The loop used to hand AdmitWrite a fresh, deadline-free
// context on every pass, which meant every pass got its own full
// operationAdmissionBudget and the passes COMPOSED.
//
// That is not a two-pass problem bounded by arithmetic. The force-authority pass
// is not a guaranteed terminator: its token's coverage check can fail when a
// concurrent rename moves the operand or an acquisition holds a conflicting
// identity, and the operation unwinds again. N passes at 50s each is unbounded
// under a 60s kernel ceiling; one absolute deadline is the terminator.
func TestFUSEWriteUnwindPassesShareOneAbsoluteDeadline(t *testing.T) {
	node := &fuseNode{replyGate: &fusefrontend.ReplyGate{}}

	const passes = 5
	var deadlines []time.Time
	restore := fuseWritePass
	t.Cleanup(func() { fuseWritePass = restore })
	fuseWritePass = func(
		_ *fuseNode,
		ctx context.Context,
		_ fs.FileHandle,
		_ []byte,
		_ int64,
		_ bool,
	) (uint32, syscall.Errno, bool) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Errorf("pass %d received a context with NO deadline: the loop is "+
				"relying on Volume.AdmitWrite to install one per pass, so every "+
				"pass gets a fresh %s bound and the passes compose",
				len(deadlines)+1, clientcore.OperationAdmissionBudget())
			deadlines = append(deadlines, time.Time{})
		} else {
			deadlines = append(deadlines, deadline)
		}
		if len(deadlines) < passes {
			return 0, 0, true // ErrLaneChanged: unwind and re-admit
		}
		return 1, 0, false
	}

	before := time.Now()
	if cnt, eno := node.Write(context.Background(), nil, []byte("x"), 0); eno != 0 || cnt != 1 {
		t.Fatalf("write = (%d, %v), want (1, 0)", cnt, eno)
	}
	if len(deadlines) != passes {
		t.Fatalf("the loop ran %d passes, want %d", len(deadlines), passes)
	}
	for i, d := range deadlines {
		if d.IsZero() {
			t.Fatalf("pass %d carried no operation deadline", i+1)
		}
		if !d.Equal(deadlines[0]) {
			t.Fatalf("pass %d has deadline %s but pass 1 has %s: a bound that "+
				"resets on every unwind is not a bound on the operation",
				i+1, d, deadlines[0])
		}
	}
	if got := deadlines[0].Sub(before); got > clientcore.OperationAdmissionBudget()+time.Second {
		t.Fatalf("the whole %d-pass write is bounded at %s out, want at most one "+
			"operationAdmissionBudget (%s)",
			passes, got, clientcore.OperationAdmissionBudget())
	}
}
