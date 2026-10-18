//go:build darwin

package portablefsd

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// startV3RenewalBudget uses a relative continuous-time kernel timer. Go's
// monotonic timers pause during sleep on Darwin, so they cannot bound this wait.
// Arming before the proof's clock sample makes the budget conservative at t0.
func startV3RenewalBudget(budget time.Duration, expire func()) (func(), error) {
	queue, err := unix.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("create renewal deadline queue: %w", err)
	}
	unix.CloseOnExec(queue)
	changes := []unix.Kevent_t{
		{Ident: 1, Filter: unix.EVFILT_TIMER, Flags: unix.EV_ADD | unix.EV_ONESHOT,
			Fflags: unix.NOTE_NSECONDS | unix.NOTE_MACH_CONTINUOUS_TIME, Data: max(1, int64(budget))},
		{Ident: 2, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR},
	}
	if _, err := unix.Kevent(queue, changes, nil, nil); err != nil {
		_ = unix.Close(queue)
		return nil, fmt.Errorf("arm continuous renewal deadline: %w", err)
	}
	var mu sync.Mutex
	closed := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		var events [1]unix.Kevent_t
		var n int
		var err error
		for {
			n, err = unix.Kevent(queue, nil, events[:], nil)
			if err != unix.EINTR {
				break
			}
		}
		// Serialize descriptor retirement with stop: a late stop must never
		// trigger an unrelated kqueue that reused this descriptor number.
		mu.Lock()
		closed = true
		_ = unix.Close(queue)
		mu.Unlock()
		if err != nil || n != 1 || events[0].Flags&unix.EV_ERROR != 0 || events[0].Filter == unix.EVFILT_TIMER {
			expire()
		}
	}()
	return func() {
		mu.Lock()
		if !closed {
			for {
				_, err := unix.Kevent(queue, []unix.Kevent_t{{Ident: 2, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}}, nil, nil)
				if err != unix.EINTR {
					break
				}
			}
		}
		mu.Unlock()
		<-done
	}, nil
}
