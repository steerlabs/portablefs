//go:build linux

package workspaceclock

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSharedClockReadOnlyGenerationAndFreshness(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root shared clock owner")
	}
	var elapsed unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &elapsed); err != nil {
		t.Fatal(err)
	}
	b := &backend{rtc: time.Now().UTC().Truncate(time.Second), wall: time.Now(), elapsed: time.Duration(elapsed.Sec)*time.Second + time.Duration(elapsed.Nsec)}
	o := New(b, nil)
	if err := o.share(); err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err := o.Begin(0); err != nil {
		t.Fatal(err)
	}
	f, binding, err := o.ChildFile()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("x")); err == nil {
		t.Fatal("read-only clock handoff writable")
	}
	if mapping, err := unix.Mmap(int(f.Fd()), 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err == nil {
		unix.Munmap(mapping)
		t.Fatal("clock writable mapping accepted")
	}
	wrong := binding
	wrong[0] ^= 1
	if _, err = OpenReader(f, wrong); err == nil {
		t.Fatal("foreign clock binding accepted")
	}
	r, err := OpenReader(f, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !errors.Is(r.Check(0), ErrUnavailable) {
		t.Fatal("uncorrected shared result ready")
	}
	if _, err = o.Measure(); err != nil {
		t.Fatal(err)
	}
	if err = r.Check(0); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Check(1), ErrObsolete) {
		t.Fatal("shared result crossed generation")
	}
	o.Pause()
	if err = r.Check(0); err == nil {
		t.Fatal("paused shared result ready")
	}
	if err = o.Begin(1); err != nil {
		t.Fatal(err)
	}
	if err = r.Check(1); err == nil {
		t.Fatal("new generation reused old correction")
	}
	if _, err = o.Measure(); err != nil {
		t.Fatal(err)
	}
	if err = r.Check(1); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.elapsed -= MaxMeasurementInterval
	b.mu.Unlock()
	if _, err = o.Measure(); err != nil {
		t.Fatal(err)
	}
	if err = r.Check(1); err == nil {
		t.Fatal("overdue shared measurement ready")
	}
}
