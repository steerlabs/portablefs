//go:build linux

package workspaceclock

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/permissionclock"
	"golang.org/x/sys/unix"
)

func rtcCalendar() *unix.RTCTime {
	return &unix.RTCTime{Year: 126, Mon: 9, Mday: 27, Hour: 15, Min: 30, Sec: 17}
}

func TestRTCReadRestartsInterruptedIoctls(t *testing.T) {
	for _, interrupted := range []int{1, 8, 65536} {
		t.Run(fmt.Sprint(interrupted), func(t *testing.T) {
			attempts := 0
			const descriptor = 37
			got, err := readRTCUTC(descriptor, func(fd int) (*unix.RTCTime, error) {
				if fd != descriptor {
					t.Fatal("restart changed the retained descriptor", fd)
				}
				attempts++
				if attempts <= interrupted {
					// Failed output is deliberately unusable, even when non-nil.
					return &unix.RTCTime{Year: -1, Mon: 200}, fmt.Errorf("interrupted: %w", unix.EINTR)
				}
				if attempts != interrupted+1 {
					t.Fatal("successful acquisition retried", attempts)
				}
				return rtcCalendar(), nil
			})
			want := time.Date(2026, 10, 27, 15, 30, 17, 0, time.UTC)
			if err != nil || !got.Equal(want) || attempts != interrupted+1 {
				t.Fatal("fresh RTC acquisition", got, err, attempts)
			}
		})
	}
}

func TestRTCReadPreservesNonInterruptedErrors(t *testing.T) {
	for _, errno := range []error{unix.EIO, unix.EBADF, unix.ENODEV, unix.EPERM, unix.EINVAL, unix.EAGAIN} {
		t.Run(errno.Error(), func(t *testing.T) {
			attempts := 0
			failure := fmt.Errorf("device refusal: %w", errno)
			got, err := readRTCUTC(37, func(int) (*unix.RTCTime, error) {
				attempts++
				if attempts <= 3 {
					return rtcCalendar(), unix.EINTR
				}
				if attempts > 4 {
					t.Fatal("non-EINTR error retried")
				}
				return rtcCalendar(), failure
			})
			if !got.IsZero() || err != failure || !errors.Is(err, errno) || attempts != 4 {
				t.Fatal("error or failed output changed", got, err, attempts)
			}
		})
	}
}

func TestRTCReadValidatesOnlySuccessfulCalendar(t *testing.T) {
	for _, field := range []string{"month", "day", "hour", "minute", "second", "year-low", "year-high"} {
		t.Run(field, func(t *testing.T) {
			raw := rtcCalendar()
			switch field {
			case "month":
				raw.Mon = 12
			case "day":
				raw.Mday = 32
			case "hour":
				raw.Hour = 24
			case "minute":
				raw.Min = 60
			case "second":
				raw.Sec = 60
			case "year-low":
				raw.Year = 119
			case "year-high":
				raw.Year = 201
			}
			attempts := 0
			reader := rtcReadFunc(func() (time.Time, error) {
				return readRTCUTC(37, func(int) (*unix.RTCTime, error) {
					attempts++
					if attempts == 1 {
						return rtcCalendar(), unix.EINTR
					}
					if attempts != 2 {
						t.Fatal("invalid calendar retried")
					}
					return raw, nil
				})
			})
			got, err := permissionclock.SampleUTC(reader)
			if !got.IsZero() || !errors.Is(err, permissionclock.ErrUnavailable) || attempts != 2 {
				t.Fatal("invalid successful calendar admitted", got, err, attempts)
			}
		})
	}
}

type rtcReadFunc func() (time.Time, error)

func (f rtcReadFunc) ReadUTC() (time.Time, error) { return f() }

func TestRTCReadRetriesPreservePermissionAnchors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		second  int32
		want    time.Duration
	}{
		{"live", time.Second, 1, 5 * time.Second},
		{"RTC-equality", time.Second, 6, 0},
		{"expiry-during-restarts", 10 * time.Second, 10, 0},
		{"backward-RTC", time.Second, -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Unix(100, 0)
			anchor := time.Date(2026, 10, 27, 15, 30, 17, 0, time.UTC)
			permission := permissionclock.Permission{Time: start.Add(10 * time.Second), Started: start, RTC: anchor, Horizon: 10 * time.Second}
			original := permission
			attempts := 0
			reader := rtcReadFunc(func() (time.Time, error) {
				return readRTCUTC(37, func(int) (*unix.RTCTime, error) {
					attempts++
					if attempts < 5 {
						return rtcCalendar(), unix.EINTR
					}
					raw := rtcCalendar()
					raw.Sec += tc.second
					return raw, nil
				})
			})
			// The use starts before the interrupted acquisition. Its eventual
			// RTC sample includes all time spent restarting under the same anchor.
			remaining := permission.Remaining(start, reader, time.Second)
			if remaining != tc.want || permission != original || attempts != 5 {
				t.Fatal("restarts changed permission", remaining, permission, attempts)
			}
			if tc.elapsed >= 9*time.Second && permission.Remaining(start.Add(tc.elapsed), reader, time.Second) != 0 {
				t.Fatal("expired BOOTTIME granted permission")
			}
		})
	}
}
