package volumeserver

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func restartWriterRegistry(t *testing.T, clock *exclusionTestClock) *WriterRegistry {
	t.Helper()
	c, err := NewWriterRegistry(WriterRegistryConfig{Prior: PriorEpochUnproven, ContinuousNow: clock.continuous})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWriterRestartGraceOnlyReleasesWriters(t *testing.T) {
	if WriterRestartGrace != 61060*time.Millisecond {
		t.Fatalf("frozen grace=%v", WriterRestartGrace)
	}
	for _, kind := range []string{"fskit-exclusive"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "mount.membership")
			old := SessionID{1}

			m, _, err := OpenFileMountMembership(path, "vol", false)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.ActivateProfile(old, MembershipFSKitExclusive); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			m, prior, err := OpenFileMountMembership(path, "vol", false)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			if prior != PriorEpochUnproven {
				t.Fatal("prior membership lost")
			}
			clock := &exclusionTestClock{}
			clock.elapsed.Store(int64(100 * time.Second))
			c := restartWriterRegistry(t, clock)
			// No presumed process age or downtime establishes safe takeover.
			if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
				t.Fatalf("unsampled takeover=%v", err)
			}
			if err := c.StartWriterGrace(); err != nil {
				t.Fatal(err)
			}
			for _, elapsed := range []time.Duration{0, WriterRestartGrace - time.Nanosecond} {
				clock.elapsed.Store(int64(100*time.Second + elapsed))
				clock.wall.Store(int64(24 * time.Hour))
				if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
					t.Fatalf("early writer at %v: %v", elapsed, err)
				}
			}
			// A continuous jump models suspend: only a fresh admission sample counts.
			clock.elapsed.Store(int64(100*time.Second + WriterRestartGrace))
			clock.wall.Store(-int64(24 * time.Hour))
			if err := c.CheckWriter(SessionID{2}); err != nil {
				t.Fatalf("boundary writer=%v", err)
			}
			if c.startupReady {
				t.Fatal("writer grace changed Mac readiness")
			}
			if err := c.Activate(SessionID{3}, make(chan struct{}), &WriterExclusion{now: clock.continuous}, func() error { return nil }, func() {}); !errors.Is(err, ErrWriterExcluded) {
				t.Fatalf("Mac activated after grace: %v", err)
			}
			l, err := NewMountLifecycle(MountLifecycleConfig{Membership: m, Prior: prior})
			if err != nil {
				t.Fatal(err)
			}
			if err := l.RequireCleanRouteAbsence(); !errors.Is(err, ErrRoutesLive) {
				t.Fatalf("route gate=%v", err)
			}
			proofWritten := false
			if err := m.SetQuiescing("test", func() error { proofWritten = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if proofWritten || len(m.active) != 1 {
				t.Fatal("grace cleared archive/topology membership")
			}
			// A further restart, with a new boot clock and a shorter lease, owes
			// the full grace again; no old clock or configured L is consulted.
			clock.elapsed.Store(int64(time.Second))
			next := restartWriterRegistry(t, clock)
			if err := next.StartWriterGrace(); err != nil {
				t.Fatal(err)
			}
			if err := next.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
				t.Fatalf("repeated restart=%v", err)
			}
		})
	}
}

func TestWriterRestartClockFailuresStayFenced(t *testing.T) {
	for _, fault := range []string{"initial failure", "overflow", "regression", "later failure"} {
		t.Run(fault, func(t *testing.T) {
			clock := &exclusionTestClock{}
			clock.elapsed.Store(int64(time.Second))
			if fault == "initial failure" {
				clock.failed.Store(true)
			}
			if fault == "overflow" {
				clock.elapsed.Store(math.MaxInt64)
			}
			c := restartWriterRegistry(t, clock)
			err := c.StartWriterGrace()
			if fault == "initial failure" || fault == "overflow" {
				if err == nil {
					t.Fatal("invalid initial clock accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if fault == "regression" {
				clock.elapsed.Store(0)
			}
			if fault == "later failure" {
				clock.failed.Store(true)
			}
			if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
				t.Fatalf("fault admitted writer=%v", err)
			}
			clock.failed.Store(false)
			clock.elapsed.Store(int64(time.Hour))
			if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
				t.Fatalf("fault was not sticky=%v", err)
			}
		})
	}
}

func TestWriterRestartStillHonorsCurrentExclusionAndDrain(t *testing.T) {
	clock := &exclusionTestClock{}
	clock.elapsed.Store(int64(time.Second))
	c := restartWriterRegistry(t, clock)
	if err := c.StartWriterGrace(); err != nil {
		t.Fatal(err)
	}
	old := SessionID{1}
	e := &WriterExclusion{now: clock.continuous, stopped: true, deadline: 2 * WriterRestartGrace}
	c.exclusions[old] = e
	clock.elapsed.Store(int64(time.Second + WriterRestartGrace))
	if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
		t.Fatal("restart grace bypassed retained promise")
	}
	clock.elapsed.Store(int64(2 * WriterRestartGrace))
	if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
		t.Fatal("restart grace bypassed apply drain")
	}
	e.drain()
	if err := c.CheckWriter(SessionID{2}); err != nil {
		t.Fatal(err)
	}
}
