package permissionclock

import (
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
)

type readFunc func() (time.Time, error)

func (f readFunc) ReadUTC() (time.Time, error) { return f() }
func fixed(t time.Time) UTCReader              { return readFunc(func() (time.Time, error) { return t, nil }) }
func permission() Permission {
	b := time.Unix(100, 0)
	r := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	return Permission{Time: b.Add(10 * time.Second), Started: b, RTC: r, Horizon: 10 * time.Second}
}

func TestDeadlineSchedulesAndEquality(t *testing.T) {
	p := permission()
	for _, tc := range []struct {
		name            string
		boot, rtc, want time.Duration
	}{
		{"fresh", 0, 0, 6 * time.Second},
		{"rtc-cutoff-below", time.Second, 5 * time.Second, time.Second},
		{"rtc-equality", time.Second, 6 * time.Second, 0},
		{"boot-equality", 9 * time.Second, time.Second, 0},
		{"schedule-1", 8500 * time.Millisecond, 10 * time.Second, 0},
		{"boottime-only-expiry", 11 * time.Second, time.Second, 0},
		{"stopped-boottime", time.Second, 30 * time.Second, 0},
		{"backward-under-anchor", time.Second, -time.Second, 0},
		{"backward-above-anchor", 2 * time.Second, 3 * time.Second, 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Remaining(p.Started.Add(tc.boot), fixed(p.RTC.Add(tc.rtc)), time.Second); got != tc.want {
				t.Fatalf("remaining %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFullEndpointEnvelopeAndOneSecondCadence(t *testing.T) {
	p := permission()
	for phase := time.Duration(0); phase < time.Second; phase += 10 * time.Millisecond {
		for _, e0 := range []time.Duration{-time.Second, 0, time.Second} {
			for _, e1 := range []time.Duration{-time.Second, 0, time.Second} {
				for elapsed := time.Duration(0); elapsed <= 11*time.Second; elapsed += 100 * time.Millisecond {
					q := p
					q.RTC = p.RTC.Add(phase + e0).Truncate(time.Second)
					rtc := p.RTC.Add(phase + elapsed + e1).Truncate(time.Second)
					for _, boot := range []time.Duration{0, elapsed} {
						remaining := q.Remaining(q.Started.Add(boot), fixed(rtc), time.Second)
						if remaining > 0 && elapsed+remaining > 9*time.Second {
							t.Fatalf("unsafe envelope phase=%v errors=%v/%v elapsed=%v remaining=%v", phase, e0, e1, elapsed, remaining)
						}
					}
					// One second plus 1.9 s accumulated queue/reply age survives every
					// endpoint phase/error combination. Three seconds does not.
					if elapsed == 2900*time.Millisecond && q.Remaining(q.Started.Add(elapsed), fixed(rtc), time.Second) <= 0 {
						t.Fatal("one-second cadence exhausted envelope", phase, e0, e1)
					}
				}
			}
		}
	}
	q := p
	q.RTC = p.RTC.Add(-time.Second)
	if q.Remaining(q.Started.Add(3060*time.Millisecond), fixed(p.RTC.Add(5*time.Second)), time.Second) != 0 {
		t.Fatal("three-second counterexample admitted")
	}
}

func TestInvalidEvidenceAndShortHorizons(t *testing.T) {
	p := permission()
	for _, rtc := range []time.Time{time.Time{}, p.RTC.Add(time.Nanosecond), time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if p.Remaining(p.Started, fixed(rtc), time.Second) != 0 {
			t.Fatal("invalid calendar admitted", rtc)
		}
	}
	if p.Remaining(p.Started, readFunc(func() (time.Time, error) { return time.Time{}, errors.New("ioctl") }), time.Second) != 0 {
		t.Fatal("read failure admitted")
	}
	for _, h := range []time.Duration{-1, 0, time.Second, 3 * time.Second, 4 * time.Second} {
		q := p
		q.Horizon = h
		q.Time = q.Started.Add(h)
		if q.Remaining(q.Started, fixed(p.RTC), time.Second) != 0 {
			t.Fatal("short horizon admitted", h)
		}
	}
	q := p
	q.Time = q.Time.Add(time.Second)
	if q.Remaining(q.Started, fixed(p.RTC), time.Second) != 0 {
		t.Fatal("inconsistent anchor admitted")
	}
	if p.Remaining(p.Started.Add(-time.Second), fixed(p.RTC), time.Second) != 0 {
		t.Fatal("backward boottime admitted")
	}
}

func TestDenialPreservesFailingSampleAndCause(t *testing.T) {
	p := permission()
	for _, tc := range []struct {
		name, detail string
		boot, rtc    time.Duration
		failure      error
	}{
		{name: "interrupted-ioctl", detail: "RTC sample", failure: syscall.EINTR},
		{name: "device-failure", detail: "RTC sample", failure: syscall.EIO},
		{name: "RTC-expiry", detail: "RTC elapsed=6s", rtc: 6 * time.Second},
		{name: "BOOTTIME-expiry", detail: "BOOTTIME elapsed=9s", boot: 9 * time.Second},
		{name: "backward-RTC", detail: "RTC before anchor", rtc: -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			r := readFunc(func() (time.Time, error) {
				reads++
				return p.RTC.Add(tc.rtc), tc.failure
			})
			remaining, err := p.RemainingWithCause(p.Started.Add(tc.boot), r, time.Second)
			if remaining != 0 || !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("denial remaining=%s cause=%v", remaining, err)
			}
			if tc.failure != nil && !errors.Is(err, tc.failure) {
				t.Fatal("sample errno lost", err)
			}
			wantReads := 1
			if tc.boot == 9*time.Second {
				wantReads = 0
			}
			if reads != wantReads {
				t.Fatal("diagnostic resampled the failed use", reads, wantReads)
			}
		})
	}
}
