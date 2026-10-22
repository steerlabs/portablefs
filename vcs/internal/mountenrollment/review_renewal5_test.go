package mountenrollment

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

type o5Clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *o5Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *o5Clock) Jump(to time.Time) {
	c.mu.Lock()
	if to.After(c.now) {
		c.now = to
	}
	c.mu.Unlock()
}

func o5Proof(p RenewalReadiness) string {
	return fmt.Sprintf("%s/seq=%d", p.State, p.InstalledSequence)
}

// After an obsolete installation, later successful installations must publish
// their own proof (liveness), and readiness must never name the obsolete or an
// older sequence.
func TestO5ObsoleteThenSuccessPublishesNewProof(t *testing.T) {
	for _, managed := range []bool{true, false} {
		t.Run(fmt.Sprintf("managed=%v", managed), func(t *testing.T) {
			start := time.Unix(1_800_000_000, 0)
			clock := &o5Clock{now: start}
			r := &Renewer{Managed: managed, Now: clock.Now, CheckPermit: func(Permit) bool { return true }}
			r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
				return grantFor(s, n, clock.Now().Add(10*time.Minute).Truncate(time.Second)), nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var mu sync.Mutex
			var seen []string
			var installs uint64
			r.waitHook = func(c context.Context, target time.Time, wake <-chan struct{}) error {
				if c.Err() != nil {
					return c.Err()
				}
				mu.Lock()
				seen = append(seen, fmt.Sprintf("after#%d:%s", installs, o5Proof(r.Readiness())))
				n := installs
				mu.Unlock()
				if n >= 4 {
					cancel()
					return c.Err()
				}
				if !target.IsZero() {
					clock.Jump(target)
				}
				return nil
			}
			if managed {
				if err := r.Resume(Permit{GateSerial: 1}); err != nil {
					t.Fatal(err)
				}
			}
			err := r.Run(ctx, "session", start.Add(5*time.Minute), func(_ context.Context, _ string, seq uint64, _ []byte) (time.Time, error) {
				mu.Lock()
				installs = seq
				mu.Unlock()
				d := time.Unix(clock.Now().Add(10*time.Minute).Truncate(time.Second).Unix(), 0)
				if seq == 2 {
					return d, ErrSessionChangedInstallation
				}
				return d, nil
			})
			t.Logf("managed=%v run=%v readiness trace=%v", managed, err, seen)
			want := map[string]bool{"after#1:installed/seq=1": true, "after#2:pending/seq=0": true, "after#3:installed/seq=3": true}
			for _, s := range seen {
				delete(want, s)
				if s == "after#2:installed/seq=1" || s == "after#2:installed/seq=2" {
					t.Errorf("obsolete/old proof published: %s", s)
				}
			}
			if len(want) != 0 {
				t.Errorf("missing expected readiness transitions: %v", want)
			}
		})
	}
}

// Park/Resume after an obsolete installation must not republish the earlier or
// obsolete proof under the new permit.
func TestO5ResumeAfterObsoleteStaysPending(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	clock := &o5Clock{now: start}
	r := &Renewer{Managed: true, Now: clock.Now, CheckPermit: func(Permit) bool { return true }}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		return grantFor(s, n, clock.Now().Add(10*time.Minute).Truncate(time.Second)), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secondDone := make(chan struct{})
	var once sync.Once
	r.waitHook = func(c context.Context, target time.Time, wake <-chan struct{}) error {
		r.mu.Lock()
		seq := r.installed.InstalledSequence
		r.mu.Unlock()
		if seq >= 2 {
			once.Do(func() { close(secondDone) })
			select {
			case <-c.Done():
				return c.Err()
			case <-wake:
				return nil
			}
		}
		if !target.IsZero() {
			clock.Jump(target)
		}
		return nil
	}
	_ = r.Resume(Permit{GateSerial: 1})
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "session", start.Add(5*time.Minute), func(_ context.Context, _ string, seq uint64, _ []byte) (time.Time, error) {
			d := time.Unix(clock.Now().Add(10*time.Minute).Truncate(time.Second).Unix(), 0)
			if seq == 2 {
				return d, ErrSessionChangedInstallation
			}
			return d, nil
		})
	}()
	<-secondDone
	before := r.Readiness()
	parkErr := r.Park(context.Background())
	resumeErr := r.Resume(Permit{GateSerial: 2})
	after := r.Readiness()
	t.Logf("obsolete then Park/Resume: before=%s park=%v resume=%v after=%s", o5Proof(before), parkErr, resumeErr, o5Proof(after))
	if before.State == "installed" || after.State == "installed" {
		t.Errorf("obsolete or older proof republished")
	}
	cancel()
	<-done
}
