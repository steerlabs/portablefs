// Package workspaceclock disciplines TLS wall time. It does not supply elapsed
// lease time or implement RTC admission. The source error budget needs separate
// exact-image qualification before supported workspace mounts can be enabled.
package workspaceclock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
)

const (
	MaxUTCError            = 3 * time.Second
	SourceError            = time.Second
	Quantization           = time.Second
	MaxSampleAge           = 250 * time.Millisecond
	DriftBudget            = 250 * time.Millisecond
	MaxMeasurementInterval = 60 * time.Second
)

var ErrUnavailable = errors.New("workspace TLS clock unavailable")
var ErrObsolete = errors.New("workspace TLS clock generation or close serial obsolete")

// Backend is the measurement seam used by deterministic tests. Production has
// one retained read-only RTC opening and one privileged wall-clock setter.
type Backend interface {
	ReadUTC() (time.Time, error)
	CorrectWall(time.Time) error
	Wall() time.Time
	Elapsed() time.Duration
	Close() error
}
type Measurement struct {
	ElapsedEnd time.Duration `json:"elapsed_end_ns"`
	Generation uint64        `json:"generation"`
	RTC        time.Time     `json:"rtc"`
	WallBefore time.Time     `json:"wall_before"`
	WallAfter  time.Time     `json:"wall_after"`
	SampleAge  time.Duration `json:"sample_age_ns"`
	Correction time.Duration `json:"correction_ns"`
	Contention time.Duration `json:"contention_ns"`
}
type Owner struct {
	wake                  chan struct{}
	correction            chan struct{}
	mu                    sync.Mutex
	sampleMu              sync.Mutex
	backend               Backend
	generation            uint64
	active, ready, closed bool
	measured              time.Duration
	low, high             time.Time
	changed               chan struct{}
	revision              uint64
	correctionRevision    uint64
	// Called outside mu, after readiness clears. Must close serving admission
	// synchronously and must not wait for workers or reenter the clock owner.
	publish     func()
	dispose     func() error
	childFile   func() (*os.File, error)
	binding     [16]byte
	unavailable func()
}

func New(backend Backend, unavailable func()) *Owner {
	return &Owner{backend: backend, wake: make(chan struct{}, 1), correction: make(chan struct{}), changed: make(chan struct{}), unavailable: unavailable}
}
func (o *Owner) signalLocked() {
	if o.publish != nil {
		o.publish()
	}
	close(o.changed)
	o.changed = make(chan struct{})
}
func (o *Owner) invalidateLocked() bool {
	was := o.ready
	o.ready = false
	if was {
		o.signalLocked()
	}
	return was
}
func (o *Owner) notify(was bool) {
	if was && o.unavailable != nil {
		o.unavailable()
	}
}

// Begin invalidates the old generation before starting any correction. Suspend
// calls Pause even for repeated closure, defeating an in-flight measurement.
func (o *Owner) Begin(generation uint64) error {
	o.mu.Lock()
	if o.closed || generation < o.generation || o.active && generation == o.generation {
		o.mu.Unlock()
		return ErrObsolete
	}
	was := o.invalidateLocked()
	o.generation = generation
	o.active = true
	o.revision++
	select {
	case o.wake <- struct{}{}:
	default:
	}
	o.signalLocked()
	o.mu.Unlock()
	o.notify(was)
	return nil
}
func (o *Owner) Pause() {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	was := o.invalidateLocked()
	o.active = false
	o.revision++
	select {
	case o.wake <- struct{}{}:
	default:
	}
	o.signalLocked()
	o.mu.Unlock()
	o.notify(was)
}
func (o *Owner) Close() error {
	o.Pause()
	o.sampleMu.Lock()
	defer o.sampleMu.Unlock()
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	o.signalLocked()
	o.mu.Unlock()
	if o.dispose != nil {
		return errors.Join(o.dispose(), o.backend.Close())
	}
	return o.backend.Close()
}
func (o *Owner) Corrections() <-chan struct{} { o.mu.Lock(); defer o.mu.Unlock(); return o.correction }
func (o *Owner) Changed() <-chan struct{}     { o.mu.Lock(); defer o.mu.Unlock(); return o.changed }
func distance(a, b time.Time) time.Duration {
	d := a.Sub(b)
	if d < 0 {
		return -d
	}
	return d
}
func fits(wall, low, high time.Time) bool {
	return max(distance(wall, low), distance(wall, high))+DriftBudget <= MaxUTCError
}

// Measure serializes sampling and setting, never stepping to a rounded-down
// second. An RTC sample describes an interval; midpoint correction minimizes
// its worst-case error. All elapsed age, including setting/verifying, counts.
func (o *Owner) Measure() (m Measurement, err error) {
	queued := o.backend.Elapsed()
	o.sampleMu.Lock()
	defer o.sampleMu.Unlock()
	defer func() {
		if err != nil && !errors.Is(err, ErrObsolete) {
			o.mu.Lock()
			was := o.invalidateLocked()
			o.mu.Unlock()
			o.notify(was)
		}
	}()
	start := o.backend.Elapsed()
	m.Contention = start - queued
	if start < 0 || queued < 0 {
		return m, ErrUnavailable
	}
	o.mu.Lock()
	g, rev, active := o.generation, o.revision, o.active && !o.closed
	o.mu.Unlock()
	if !active {
		return m, ErrObsolete
	}
	m.Generation = g
	rtc, e := o.backend.ReadUTC()
	if e != nil {
		return m, fmt.Errorf("%w: RTC read", ErrUnavailable)
	}
	if rtc.IsZero() || rtc.Nanosecond() != 0 || rtc.Year() < 2020 || rtc.Year() > 2100 {
		return m, fmt.Errorf("%w: malformed RTC UTC", ErrUnavailable)
	}
	m.RTC = rtc
	m.WallBefore = o.backend.Wall()
	age := o.backend.Elapsed() - start
	if age < 0 || age > MaxSampleAge {
		return m, fmt.Errorf("%w: RTC sample age", ErrUnavailable)
	}
	low, high := rtc.Add(-SourceError), rtc.Add(Quantization+SourceError+age)
	if !fits(m.WallBefore, low, high) {
		target := low.Add(high.Sub(low) / 2)
		if e = o.backend.CorrectWall(target); e != nil {
			return m, fmt.Errorf("%w: wall set", ErrUnavailable)
		}
		m.Correction = target.Sub(m.WallBefore)
	}
	end := o.backend.Elapsed()
	m.SampleAge = end - start
	m.WallAfter = o.backend.Wall()
	if m.SampleAge < 0 || m.SampleAge > MaxSampleAge {
		return m, fmt.Errorf("%w: correction age", ErrUnavailable)
	}
	low = rtc.Add(-SourceError)
	high = rtc.Add(Quantization + SourceError + m.SampleAge)
	if !fits(m.WallAfter, low, high) {
		return m, fmt.Errorf("%w: correction verification", ErrUnavailable)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.active || o.closed || o.generation != g || o.revision != rev {
		return m, ErrObsolete
	}
	m.ElapsedEnd = end
	o.measured = end
	o.low = low
	o.high = high
	o.ready = true
	if m.Correction != 0 {
		o.correctionRevision++
		close(o.correction)
		o.correction = make(chan struct{})
	}
	o.signalLocked()
	return m, nil
}
func (o *Owner) Check(generation uint64) error {
	o.mu.Lock()
	if o.closed || !o.active || generation != o.generation {
		o.mu.Unlock()
		return ErrObsolete
	}
	age := o.backend.Elapsed() - o.measured
	available := o.ready && age >= 0 && age < MaxMeasurementInterval && fits(o.backend.Wall(), o.low.Add(age), o.high.Add(age))
	if available {
		o.mu.Unlock()
		return nil
	}
	was := o.invalidateLocked()
	o.mu.Unlock()
	o.notify(was)
	return ErrUnavailable
}
func (o *Owner) Wait(ctx context.Context, generation uint64) error {
	for {
		ch := o.Changed()
		err := o.Check(generation)
		if err == nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrObsolete) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		}
	}
}

// Maintain samples early enough to allow scheduler latency; synchronous Check
// owns the hard 60-second limit. Failures retry without retaining readiness.
func (o *Owner) Maintain(ctx context.Context, observe func(Measurement, error)) {
	for {
		m, err := o.Measure()
		if observe != nil {
			observe(m, err)
		}
		delay := 30 * time.Second
		if err != nil {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-o.wake:
			timer.Stop()
		}
	}
}

// Binding combines one shared generation result with a mount's exact closed
// serial. No mount owns an RTC opening or can set wall time independently.
type Source interface {
	Check(uint64) error
	Changed() <-chan struct{}
}
type Binding struct {
	Owner Source
	// Generation belongs to the mount owner, including cleanup after Close.
	Generation func() uint64
	Current    func(mountenrollment.Permit) bool
}

func (b Binding) Check(p mountenrollment.Permit) error {
	if b.Owner == nil || b.Current == nil || !b.Current(p) {
		return ErrObsolete
	}
	if err := b.Owner.Check(p.Generation); err != nil {
		return err
	}
	if !b.Current(p) {
		return ErrObsolete
	}
	return nil
}
func (b Binding) Wait(ctx context.Context, p mountenrollment.Permit) error {
	if b.Owner == nil || b.Current == nil {
		return ErrObsolete
	}
	for {
		if !b.Current(p) {
			return ErrObsolete
		}
		err := b.Owner.Check(p.Generation)
		if err == nil {
			return b.Check(p)
		}
		if errors.Is(err, ErrObsolete) {
			return err
		}
		ch := b.Owner.Changed()
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-ch:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// AwaitTLS gates all transport work, including background receipts and cleanup.
// Serving permission stays at admission; Close cannot make cleanup undialable.
func (b Binding) AwaitTLS(ctx context.Context) error {
	if b.Owner == nil || b.Generation == nil {
		return ErrObsolete
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		changed := b.Owner.Changed()
		generation := b.Generation()
		if b.Owner.Check(generation) == nil && b.Generation() == generation {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// ChildFile hands the future root driver a read-only view of the shared result.
// It carries no timestamp request protocol, key, or independent clock setter.
func (o *Owner) ChildFile() (*os.File, [16]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.childFile == nil {
		return nil, [16]byte{}, ErrUnavailable
	}
	f, err := o.childFile()
	return f, o.binding, err
}
