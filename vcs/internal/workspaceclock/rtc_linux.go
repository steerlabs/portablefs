//go:build linux

package workspaceclock

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type RTC struct{ file *os.File }

// Open pins the sole RTC opening for the owner's lifetime. Never reopen on an
// ioctl failure: rtc_dev_open's busy bit makes per-mount openings invalid.
func Open(unavailable func()) (*Owner, error) {
	fd, err := unix.Open("/dev/rtc0", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open pinned workspace RTC: %w", err)
	}
	f := os.NewFile(uintptr(fd), "workspace RTC")
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		f.Close()
		return nil, errors.New("workspace RTC is not a character device")
	}
	owner, err := NewShared(&RTC{file: f}, unavailable)
	if err != nil {
		f.Close()
		return nil, err
	}
	return owner, nil
}
func (r *RTC) ReadUTC() (time.Time, error) {
	raw, err := unix.IoctlGetRTCTime(int(r.file.Fd()))
	if err != nil {
		return time.Time{}, err
	}
	y, m, d := int(raw.Year)+1900, time.Month(raw.Mon+1), int(raw.Mday)
	h, min, sec := int(raw.Hour), int(raw.Min), int(raw.Sec)
	t := time.Date(y, m, d, h, min, sec, 0, time.UTC)
	if t.Year() != y || t.Month() != m || t.Day() != d || t.Hour() != h || t.Minute() != min || t.Second() != sec {
		return time.Time{}, errors.New("malformed RTC calendar")
	}
	return t, nil
}
func (r *RTC) CorrectWall(t time.Time) error {
	return unix.ClockSettime(unix.CLOCK_REALTIME, &unix.Timespec{Sec: t.Unix(), Nsec: int64(t.Nanosecond())})
}
func (r *RTC) Wall() time.Time { return time.Now() }
func (r *RTC) Elapsed() time.Duration {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t); err != nil {
		return -1
	}
	return time.Duration(t.Sec)*time.Second + time.Duration(t.Nsec)
}
func (r *RTC) Close() error { return r.file.Close() }

// RTCFile exposes the retained description to the owner's duplication boundary.
// Injected backends may supply a test description; a real child independently
// validates the character device before it can use it for admission.
func (r *RTC) RTCFile() *os.File { return r.file }

// DuplicateRTC shares the sole read-only device opening with one managed
// daemon. Duplication never calls rtc_dev_open and cannot acquire set rights.
func (o *Owner) DuplicateRTC() (*os.File, error) {
	o.sampleMu.Lock()
	defer o.sampleMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	r, ok := o.backend.(interface{ RTCFile() *os.File })
	if o.closed || !ok || r.RTCFile() == nil {
		return nil, ErrUnavailable
	}
	file := r.RTCFile()
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, ErrUnavailable
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate workspace RTC: %w", err)
	}
	return os.NewFile(uintptr(fd), "workspace RTC reader"), nil
}

// AdoptRTC validates an inherited read-only RTC descriptor without reopening
// the device. The private parent launch binds its provenance; rdev binds rtc0.
func AdoptRTC(f *os.File) (*RTC, error) {
	if f == nil {
		return nil, ErrUnavailable
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	var inherited, device unix.Stat_t
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY ||
		unix.Fstat(int(f.Fd()), &inherited) != nil || inherited.Mode&unix.S_IFMT != unix.S_IFCHR ||
		unix.Stat("/dev/rtc0", &device) != nil || inherited.Rdev != device.Rdev {
		return nil, fmt.Errorf("%w: inherited RTC descriptor", ErrUnavailable)
	}
	unix.CloseOnExec(int(f.Fd()))
	return &RTC{file: f}, nil
}
