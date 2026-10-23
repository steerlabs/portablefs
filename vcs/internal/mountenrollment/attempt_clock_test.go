package mountenrollment

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

func awaitAttempt[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("renewal attempt did not settle promptly")
		var zero T
		return zero
	}
}

// Port of Opus's r2 repro. Only the injected clock steps; no real clock changes.
func TestForwardStepDuringAttemptReportsCutoffPromptly(t *testing.T) {
	var offset atomic.Int64
	changes := make(chan struct{})
	next := make(chan struct{})
	var current atomic.Pointer[chan struct{}]
	current.Store(&changes)
	r := &Renewer{Now: func() time.Time { return time.Now().Round(0).Add(time.Duration(offset.Load())) }, Timeout: time.Minute,
		WallChanges: func() <-chan struct{} { return *current.Load() }}
	entered := make(chan struct{})
	r.Source = sourceFunc(func(ctx context.Context, _ string, _ uint64) (controlplane.MountAuthorization, error) {
		close(entered)
		<-ctx.Done()
		return controlplane.MountAuthorization{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	initial := time.Now().Add(10 * time.Second)
	done := make(chan error, 1)
	events := make(chan RenewalEvent, 1)
	r.Observe = func(e RenewalEvent) { events <- e }
	go func() {
		done <- r.Run(ctx, "s", initial, func(context.Context, string, uint64, []byte) (time.Time, error) { return initial, nil })
	}()
	awaitAttempt(t, entered)
	offset.Store(int64(6 * time.Second))
	current.Store(&next)
	close(changes)
	// This observation alone cannot latch: no installation exists yet.
	if r.Readiness().State == "installed" {
		t.Fatal("serving")
	}
	if err := awaitAttempt(t, done); err == nil || r.Failure() != err {
		t.Fatal("missing retained cutoff", err)
	}
	if e := awaitAttempt(t, events); e.Kind != RenewalCutoff {
		t.Fatal("missing cutoff event", e.Kind)
	}
}

func TestAttemptCutoffCancellationJoinsDisposition(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, observer := range []bool{false, true} {
			t.Run(fmt.Sprintf("managed=%t/observer=%t", managed, observer), func(t *testing.T) {
				base := time.Now().Truncate(time.Second)
				deadline := base.Add(100 * time.Second)
				replacement := base.Add(5 * time.Minute)
				var offset atomic.Int64
				offset.Store(int64(80 * time.Second)) // after refresh, before cutoff at +90s
				changes := make(chan struct{})
				next := make(chan struct{})
				var current atomic.Pointer[chan struct{}]
				current.Store(&changes)
				p := Permit{Generation: 1, GateSerial: 1}
				inst := RenewalReadiness{State: "installed", InstalledSequence: 1, Permit: p, SessionID: "s", AuthorizationDeadline: deadline}
				r := &Renewer{Managed: managed, CheckPermit: func(Permit) bool { return true },
					Now:         func() time.Time { return time.Now().Round(0).Add(time.Duration(offset.Load())) },
					WallChanges: func() <-chan struct{} { return *current.Load() }, Timeout: time.Minute,
					initialized: true, session: "s", sequence: 2, authorizedAt: base, deadline: deadline,
					installed: inst, readiness: inst, installedDisposition: installationCurrent, permit: p}
				r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
					return grantFor(s, n, replacement), nil
				})
				entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				defer close(release)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				events := make(chan RenewalEvent, 2)
				r.Observe = func(e RenewalEvent) { events <- e }
				go func() {
					done <- r.Run(ctx, "s", deadline, func(ctx context.Context, _ string, _ uint64, _ []byte) (time.Time, error) {
						close(entered)
						<-ctx.Done()
						close(cancelled)
						<-release
						// A remote success survives cancellation and must keep its sequence.
						return replacement, nil
					})
				}()
				awaitAttempt(t, entered)
				offset.Store(int64(91 * time.Second))
				if observer {
					if r.Readiness().State == "installed" {
						t.Fatal("observer retained serving")
					}
				} else {
					current.Store(&next)
					close(changes)
				}
				awaitAttempt(t, cancelled)
				offset.Store(int64(70 * time.Second))
				r.WallCorrected()
				parkCtx, stop := context.WithTimeout(t.Context(), 10*time.Millisecond)
				defer stop()
				if err := r.Park(parkCtx); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("Park did not join the installer", err)
				}
				if r.Resume(p) == nil || r.Readiness().State == "installed" {
					t.Fatal("cancelled attempt republished")
				}
				select {
				case <-done:
					t.Fatal("Run escaped before disposition joined")
				default:
				}
				r.mu.Lock()
				pending, sequence := r.pending, r.sequence
				r.mu.Unlock()
				if pending == nil || pending.Sequence != 2 || sequence != 2 {
					t.Fatal("pending grant lost before join")
				}
				release <- struct{}{}
				if err := awaitAttempt(t, done); err == nil {
					t.Fatal("missing cutoff")
				}
				if e := awaitAttempt(t, events); e.Kind != RenewalCutoff {
					t.Fatal("wrong event", e.Kind)
				}
				r.mu.Lock()
				pending, sequence, installed, disposition := r.pending, r.sequence, r.installed, r.installedDisposition
				r.mu.Unlock()
				if pending != nil || sequence != 3 || installed.InstalledSequence != 2 || disposition != installationCurrent {
					t.Fatal("joined remote disposition lost", sequence, installed, disposition)
				}
				if r.Readiness().State == "installed" {
					t.Fatal("backward correction revived cancelled installation")
				}
			})
		}
	}
}

func TestAttemptCutoffRearmsAfterBackwardCorrection(t *testing.T) {
	for _, backward := range []bool{false, true} {
		t.Run(fmt.Sprint(backward), func(t *testing.T) {
			var offset atomic.Int64
			changes := make(chan struct{})
			next := make(chan struct{})
			var current atomic.Pointer[chan struct{}]
			current.Store(&changes)
			entered, cancelled := make(chan struct{}), make(chan struct{})
			r := &Renewer{Now: func() time.Time { return time.Now().Round(0).Add(time.Duration(offset.Load())) },
				WallChanges: func() <-chan struct{} { return *current.Load() }, Timeout: time.Minute}
			r.Source = sourceFunc(func(ctx context.Context, _ string, _ uint64) (controlplane.MountAuthorization, error) {
				close(entered)
				<-ctx.Done()
				close(cancelled)
				return controlplane.MountAuthorization{}, ctx.Err()
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			initial := time.Now().Add(5250 * time.Millisecond)
			done := make(chan error, 1)
			go func() {
				done <- r.Run(ctx, "s", initial, func(context.Context, string, uint64, []byte) (time.Time, error) { return initial, nil })
			}()
			awaitAttempt(t, entered)
			if backward {
				offset.Store(-int64(2 * time.Second))
				current.Store(&next)
				close(changes)
				select {
				case <-cancelled:
					t.Fatal("stale cutoff timer cancelled after backward correction")
				case <-time.After(350 * time.Millisecond):
				}
				offset.Store(int64(time.Second))
				newer := make(chan struct{})
				current.Store(&newer)
				close(next)
			}
			awaitAttempt(t, cancelled)
			if err := awaitAttempt(t, done); err == nil {
				t.Fatal("wall-domain cutoff did not terminate renewal")
			}
		})
	}
}

func TestAttemptCutoffRemainsWatchedUntilInstallerJoins(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	deadline := base.Add(100 * time.Second)
	replacement := base.Add(5 * time.Minute)
	var offset atomic.Int64
	offset.Store(int64(80 * time.Second))
	changes := make(chan struct{})
	next := make(chan struct{})
	var current atomic.Pointer[chan struct{}]
	current.Store(&changes)
	p := Permit{Generation: 1, GateSerial: 1}
	inst := RenewalReadiness{State: "installed", InstalledSequence: 1, Permit: p, SessionID: "s", AuthorizationDeadline: deadline}
	r := &Renewer{Managed: true, CheckPermit: func(Permit) bool { return true },
		Now:         func() time.Time { return time.Now().Round(0).Add(time.Duration(offset.Load())) },
		WallChanges: func() <-chan struct{} { return *current.Load() }, Timeout: 20 * time.Millisecond,
		initialized: true, session: "s", sequence: 2, authorizedAt: base, deadline: deadline,
		installed: inst, readiness: inst, installedDisposition: installationCurrent, permit: p}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		return grantFor(s, n, replacement), nil
	})
	timedOut, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "s", deadline, func(ctx context.Context, _ string, _ uint64, _ []byte) (time.Time, error) {
			<-ctx.Done()
			close(timedOut)
			<-release
			return replacement, nil
		})
	}()
	awaitAttempt(t, timedOut)
	offset.Store(int64(91 * time.Second))
	current.Store(&next)
	close(changes)
	limit := time.Now().Add(time.Second)
	for r.Failure() == nil && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if r.Failure() == nil {
		t.Fatal("attempt timeout stopped the cutoff watcher before the installer joined")
	}
	offset.Store(int64(70 * time.Second))
	r.WallCorrected()
	release <- struct{}{}
	if err := awaitAttempt(t, done); err == nil || r.Readiness().State == "installed" {
		t.Fatal("late remote success erased cutoff", err)
	}
	if r.sequence != 3 || r.installed.InstalledSequence != 2 || r.pending != nil {
		t.Fatal("late remote success lost its joined disposition")
	}
}
