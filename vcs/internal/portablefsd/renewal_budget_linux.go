//go:build linux

package portablefsd

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// BOOTTIME keeps the wait budget on the same suspend-inclusive time domain as H.
func startV3RenewalBudget(budget time.Duration, expire func()) (func(), error) {
	fd, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC|unix.TFD_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("create renewal deadline timer: %w", err)
	}
	if err := unix.TimerfdSettime(fd, 0, &unix.ItimerSpec{Value: unix.NsecToTimespec(max(1, int64(budget)))}, nil); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("arm continuous renewal deadline: %w", err)
	}
	// The nonblocking descriptor participates in Go's poller. Close wakes its
	// reader instead of leaving one goroutine behind per successful renewal.
	file := os.NewFile(uintptr(fd), "renewal-deadline")
	done := make(chan struct{})
	go func() {
		defer close(done)
		var expirations [8]byte
		_, err := file.Read(expirations[:])
		if !errors.Is(err, os.ErrClosed) {
			// Timerfd read errors other than our stop end local waiting too.
			expire()
		}
		_ = file.Close()
	}()
	return func() { _ = file.Close(); <-done }, nil
}
