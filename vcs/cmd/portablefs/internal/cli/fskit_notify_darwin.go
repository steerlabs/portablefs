//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

const fsKitVQMount = 0x0008
const fsKitVQUnmount = 0x0010

type fsKitKernelWatcher struct {
	fd   int
	wake chan error
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func newFSKitMountWatcher() (fsKitMountWatcher, error) {
	fd, err := unix.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("kqueue: %w", err)
	}
	unix.CloseOnExec(fd)
	changes := []unix.Kevent_t{
		{Ident: 0, Filter: unix.EVFILT_FS, Flags: unix.EV_ADD | unix.EV_CLEAR, Fflags: fsKitVQMount | fsKitVQUnmount},
		{Ident: 1, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR},
	}
	if _, err := unix.Kevent(fd, changes, nil, nil); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("register global mount-table notification: %w", err)
	}
	watcher := &fsKitKernelWatcher{fd: fd, wake: make(chan error, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go watcher.run()
	return watcher, nil
}

func (w *fsKitKernelWatcher) events() <-chan error { return w.wake }

func (w *fsKitKernelWatcher) run() {
	defer close(w.done)
	defer close(w.wake)
	var events [2]unix.Kevent_t
	for {
		count, err := unix.Kevent(w.fd, nil, events[:], nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			select {
			case w.wake <- err:
			case <-w.stop:
			}
			return
		}
		for _, event := range events[:count] {
			if event.Filter == unix.EVFILT_USER {
				return
			}
			if event.Flags&unix.EV_ERROR != 0 {
				select {
				case w.wake <- fmt.Errorf("global mount notification: errno %d", event.Data):
				case <-w.stop:
				}
				return
			}
			if event.Filter == unix.EVFILT_FS && event.Fflags&(fsKitVQMount|fsKitVQUnmount) != 0 {
				select {
				case w.wake <- nil:
				default:
				}
			}
		}
	}
}

func (w *fsKitKernelWatcher) close() error {
	var result error
	w.once.Do(func() {
		close(w.stop)
		// EVFILT_USER interrupts the blocking kevent without a timer or a mount
		// descriptor. Closing the kqueue alone need not wake a blocked waiter.
		_, err := unix.Kevent(w.fd, []unix.Kevent_t{{Ident: 1, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}}, nil, nil)
		if err != nil {
			result = err
			_ = unix.Close(w.fd)
			return
		}
		<-w.done
		result = unix.Close(w.fd)
	})
	return result
}
