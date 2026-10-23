//go:build linux

package workspaceclock

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const clockSeals = unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_FUTURE_WRITE | unix.F_SEAL_SEAL | unix.F_SEAL_EXEC

// A seqlock publishes one multiword measurement. Every payload access is atomic;
// readers never combine readiness from one generation with another's interval.
func clockWord(page []byte, n int) *atomic.Uint64 {
	return (*atomic.Uint64)(unsafe.Pointer(&page[128+8*n]))
}
func (o *Owner) share() (err error) {
	if os.Geteuid() != 0 {
		return errors.New("shared workspace clock requires root owner")
	}
	fd, err := unix.MemfdCreate("portablefs-workspace-tls-clock", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_NOEXEC_SEAL)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "workspace shared TLS clock")
	var page []byte
	defer func() {
		if err != nil {
			if page != nil {
				unix.Munmap(page)
			}
			f.Close()
		}
	}()
	if err = unix.Fchmod(fd, 0400); err != nil {
		return err
	}
	if err = unix.Ftruncate(fd, int64(os.Getpagesize())); err != nil {
		return err
	}
	page, err = unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	copy(page, "PFS-TLS-CLOCK")
	binary.LittleEndian.PutUint64(page[16:], 8)
	if _, err = rand.Read(o.binding[:]); err != nil {
		return err
	}
	copy(page[32:], o.binding[:])
	if _, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, clockSeals); err != nil {
		return err
	}
	o.publish = func() {
		sequence := clockWord(page, 0).Load()
		if sequence > ^uint64(0)-3 {
			clockWord(page, 5).Store(0)
			return
		}
		clockWord(page, 0).Store(sequence + 1)
		clockWord(page, 1).Store(o.generation)
		clockWord(page, 2).Store(uint64(o.measured))
		clockWord(page, 3).Store(uint64(o.low.UnixNano()))
		clockWord(page, 4).Store(uint64(o.high.UnixNano()))
		ready := uint64(0)
		if o.active && o.ready && !o.closed {
			ready = 1
		}
		clockWord(page, 5).Store(ready)
		clockWord(page, 6).Store(o.correctionRevision)
		clockWord(page, 0).Store(sequence + 2)
	}
	o.childFile = func() (*os.File, error) {
		fd, e := unix.Open(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		return os.NewFile(uintptr(fd), "workspace TLS clock reader"), nil
	}
	o.dispose = func() error { return errors.Join(unix.Munmap(page), f.Close()) }
	o.publish()
	return nil
}

type Reader struct {
	mu                              sync.RWMutex
	stop, done, changed, correction chan struct{}
	file                            *os.File
	page                            []byte
}

// OpenReader consumes only the root's read-only sealed descriptor. The binding
// arrives with the existing authenticated startup handoff, never from the page.
func OpenReader(f *os.File, binding [16]byte) (*Reader, error) {
	if f == nil || binding == [16]byte{} {
		return nil, ErrUnavailable
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, ErrUnavailable
	}
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&clockSeals != clockSeals {
		return nil, ErrUnavailable
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Size != int64(os.Getpagesize()) {
		return nil, ErrUnavailable
	}
	page, err := unix.Mmap(int(f.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(page[:13], []byte("PFS-TLS-CLOCK")) || binary.LittleEndian.Uint64(page[16:]) != 8 || !bytes.Equal(page[32:48], binding[:]) {
		unix.Munmap(page)
		return nil, ErrUnavailable
	}
	r := &Reader{file: f, page: page, stop: make(chan struct{}), done: make(chan struct{}), changed: make(chan struct{}), correction: make(chan struct{})}
	go r.observe()
	return r, nil
}
func (r *Reader) Changed() <-chan struct{} { r.mu.RLock(); defer r.mu.RUnlock(); return r.changed }
func (r *Reader) Corrections() <-chan struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.correction
}

// This observer delivers local readiness/schedule notifications. Every actual
// use still reads the sealed page synchronously, so a delayed timer grants none.
func (r *Reader) observe() {
	defer close(r.done)
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	var version, correction uint64
	for {
		select {
		case <-r.stop:
			return
		case <-timer.C:
		}
		r.mu.Lock()
		v, c := clockWord(r.page, 0).Load(), clockWord(r.page, 6).Load()
		if v&1 == 0 && v != version {
			version = v
			close(r.changed)
			r.changed = make(chan struct{})
		}
		if c != correction {
			correction = c
			close(r.correction)
			r.correction = make(chan struct{})
		}
		r.mu.Unlock()
	}
}
func (r *Reader) Check(generation uint64) error {
	if r == nil {
		return ErrUnavailable
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.page == nil {
		return ErrUnavailable
	}
	for tries := 0; tries < 16; tries++ {
		version := clockWord(r.page, 0).Load()
		if version&1 != 0 {
			continue
		}
		g := clockWord(r.page, 1).Load()
		measured := time.Duration(clockWord(r.page, 2).Load())
		low := time.Unix(0, int64(clockWord(r.page, 3).Load()))
		high := time.Unix(0, int64(clockWord(r.page, 4).Load()))
		ready := clockWord(r.page, 5).Load()
		if version != clockWord(r.page, 0).Load() {
			continue
		}
		if generation != g {
			return ErrObsolete
		}
		if ready != 1 {
			return ErrUnavailable
		}
		var now unix.Timespec
		if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
			return ErrUnavailable
		}
		age := time.Duration(now.Sec)*time.Second + time.Duration(now.Nsec) - measured
		if age < 0 || age >= MaxMeasurementInterval || !fits(time.Now(), low.Add(age), high.Add(age)) {
			return ErrUnavailable
		}
		return nil
	}
	return ErrUnavailable
}
func (r *Reader) Close() error {
	close(r.stop)
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	err := unix.Munmap(r.page)
	r.page = nil
	return errors.Join(err, r.file.Close())
}
