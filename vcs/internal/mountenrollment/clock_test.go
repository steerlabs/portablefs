package mountenrollment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

func TestManagerClockPrerequisiteIncludesClose(t *testing.T) {
	denied := errors.New("clock unavailable")
	c := &Client{awaitTLS: func(context.Context) error { return denied }}
	if err := c.do(t.Context(), "POST", "close", "test", struct{}{}, nil); !errors.Is(err, denied) {
		t.Fatal(err)
	}
}
func TestWallCorrectionPreservesPendingSequenceAndTerminalLatch(t *testing.T) {
	now := time.Now()
	r := &Renewer{Now: func() time.Time { return now }, initialized: true, session: "s", sequence: 7, authorizedAt: now, deadline: now.Add(time.Minute), pending: &controlplane.MountAuthorization{Sequence: 7, Capability: "test"}}
	r.WallCorrected()
	if r.sequence != 7 || r.pending == nil || !r.status.NextAttempt.IsZero() {
		t.Fatal("correction replaced pending exact grant")
	}
	r.terminal = errors.New("latched cutoff")
	now = now.Add(-time.Hour)
	r.WallCorrected()
	if r.Failure() == nil || r.readiness.State == "installed" {
		t.Fatal("backward correction revived permission")
	}
}
