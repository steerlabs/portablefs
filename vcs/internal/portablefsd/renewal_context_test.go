package portablefsd

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

// The fake Go clock proves a blocking renewal ends at its context budget;
// advancing the independent cache clock cannot supply or extend that budget.
func TestP4RenewalContextBudgetBoundsWaiting(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		authorization, parent, want time.Duration
	}{
		{name: "lease", want: 6 * time.Second},
		{name: "authorization", authorization: 2 * time.Second, want: 2 * time.Second},
		{name: "parent", authorization: 2 * time.Second, parent: time.Second, want: time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := newFakeV3DataClient()
				c.lease = 6 * time.Second
				clock := newFakeV3Clock()
				d := &v3DataPlane{client: c, clock: clock.read}
				start := time.Now()
				if tc.authorization != 0 {
					d.authorizationDeadline = start.Add(tc.authorization).Round(0)
				}
				parent := context.Background()
				if tc.parent != 0 {
					var cancel context.CancelFunc
					parent, cancel = context.WithDeadline(parent, start.Add(tc.parent))
					defer cancel()
				}
				c.keepAlive = func(ctx context.Context) (time.Duration, error) {
					clock.advance(time.Hour)
					if err := ctx.Err(); err != nil {
						t.Fatalf("cache clock jump canceled context: %v", err)
					}
					<-ctx.Done()
					return 0, ctx.Err()
				}
				if err := d.renewHorizon(parent); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("renewal result: %v", err)
				}
				if elapsed := time.Since(start); elapsed != tc.want {
					t.Fatalf("wait=%s, want %s", elapsed, tc.want)
				}
				if d.horizon != 0 {
					t.Fatal("timeout fabricated a horizon")
				}
			})
		})
	}
}
