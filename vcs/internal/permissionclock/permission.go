package permissionclock

import (
	"errors"
	"fmt"
	"time"
)

// UTCReader samples the retained RTC description synchronously at each use.
// It is separate from TLS readiness, whose Check performs no device I/O.
type UTCReader interface {
	ReadUTC() (time.Time, error)
}

// Permission carries the original request anchors through queueing, replay and
// pagination. A renewal is a candidate until its owner checks the old interval.
// Time is the ordinary BOOTTIME deadline; RTC is zero on ordinary mounts.
type Permission struct {
	time.Time
	Started time.Time
	RTC     time.Time
	Horizon time.Duration
}

var ErrUnavailable = errors.New("workspace RTC permission unavailable")

const PermissionUncertainty = 3 * time.Second

func validUTC(t time.Time) bool {
	return !t.IsZero() && t.Nanosecond() == 0 && t.Year() >= 2020 && t.Year() <= 2100
}

func SampleUTC(r UTCReader) (time.Time, error) {
	if r == nil {
		return time.Time{}, ErrUnavailable
	}
	t, err := r.ReadUTC()
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: RTC sample: %w", ErrUnavailable, err)
	}
	if !validUTC(t) {
		return time.Time{}, fmt.Errorf("%w: invalid RTC calendar %s", ErrUnavailable, t)
	}
	return t, nil
}

// Remaining denies equality and charges endpoint source variation and integer
// quantization before the withdrawal lead. The source bound applies at the
// register sample; an operation frozen after that sample has the native Linux
// sampling/use residual, including a read frozen before it returns.
func (p Permission) Remaining(now time.Time, r UTCReader, lead time.Duration) time.Duration {
	remaining, _ := p.RemainingWithCause(now, r, lead)
	return remaining
}

// RemainingWithCause preserves the denial sample for the interval's closure
// owner. A later diagnostic read could succeed or observe a different deadline,
// obscuring the event which actually closed admission.
func (p Permission) RemainingWithCause(now time.Time, r UTCReader, lead time.Duration) (time.Duration, error) {
	boot := p.Time.Add(-lead).Sub(now)
	if boot <= 0 {
		return 0, fmt.Errorf("%w: BOOTTIME elapsed=%s horizon=%s lead=%s", ErrUnavailable, now.Sub(p.Started), p.Horizon, lead)
	}
	if r == nil {
		return boot, nil
	}
	if now.Before(p.Started) || !validUTC(p.RTC) || p.Started.IsZero() || p.Horizon <= 0 || lead < 0 || lead >= p.Horizon || !p.Time.Equal(p.Started.Add(p.Horizon)) {
		return 0, fmt.Errorf("%w: invalid permission anchors", ErrUnavailable)
	}
	rtc, err := SampleUTC(r)
	if err != nil {
		return 0, err
	}
	if rtc.Before(p.RTC) {
		return 0, fmt.Errorf("%w: RTC before anchor delta=%s", ErrUnavailable, rtc.Sub(p.RTC))
	}
	// The validated calendar span fits time.Duration. Subtract the budget
	// before comparing elapsed time, so addition cannot overflow.
	budget := p.Horizon - lead
	if budget <= PermissionUncertainty {
		return 0, fmt.Errorf("%w: horizon=%s lead=%s uncertainty=%s", ErrUnavailable, p.Horizon, lead, PermissionUncertainty)
	}
	budget -= PermissionUncertainty
	delta := rtc.Sub(p.RTC)
	if delta >= budget {
		return 0, fmt.Errorf("%w: RTC elapsed=%s BOOTTIME elapsed=%s horizon=%s lead=%s uncertainty=%s", ErrUnavailable, delta, now.Sub(p.Started), p.Horizon, lead, PermissionUncertainty)
	}
	return min(boot, budget-delta), nil
}
