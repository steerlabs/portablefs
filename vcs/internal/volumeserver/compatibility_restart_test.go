package volumeserver

import (
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func restartCompatibilityCoordinator(t *testing.T, clock *exclusionTestClock, membership DurableVisibilityMembership) *VisibilityCoordinator {
	t.Helper()
	c, err := NewVisibilityCoordinator(VisibilityConfig{Prior: PriorEpochUnproven, Membership: membership, Fencer: newTestFencer(), MaxCachedNameCapacity: 16, MaxRepairBudget: time.Second, Now: clock.now, ContinuousNow: clock.continuous})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCompatibilityRestartGraceOnlyReleasesWriters(t *testing.T) {
	if CompatibilityRestartGrace != 61060*time.Millisecond {
		t.Fatalf("frozen grace=%v", CompatibilityRestartGrace)
	}
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "compatibility", true: "legacy"}[legacy], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "membership")
			old := SessionID{1}
			if legacy {
				if err := os.WriteFile(path, []byte("PFS-VISIBILITY-1\n"+hex.EncodeToString([]byte("vol"))+"\n"+hex.EncodeToString(old[:])+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				m, _, err := OpenFileVisibilityMembership(path, "vol", false)
				if err != nil {
					t.Fatal(err)
				}
				if err := m.ActivateProfile(old, MembershipCompatibility); err != nil {
					t.Fatal(err)
				}
				if err := m.Close(); err != nil {
					t.Fatal(err)
				}
			}
			m, prior, err := OpenFileVisibilityMembership(path, "vol", false)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			if prior != PriorEpochUnproven {
				t.Fatal("prior membership lost")
			}
			clock := &exclusionTestClock{}
			clock.elapsed.Store(int64(100 * time.Second))
			c := restartCompatibilityCoordinator(t, clock, m)
			// No presumed process age or downtime establishes safe takeover.
			if err := c.CheckCompatibilityWriter(SessionID{2}); !errors.Is(err, ErrCompatibilityWriterLease) {
				t.Fatalf("unsampled takeover=%v", err)
			}
			if err := c.StartCompatibilityWriterGrace(); err != nil {
				t.Fatal(err)
			}
			for _, elapsed := range []time.Duration{0, CompatibilityRestartGrace - time.Nanosecond} {
				clock.elapsed.Store(int64(100*time.Second + elapsed))
				clock.wall.Store(int64(24 * time.Hour))
				if err := c.CheckCompatibilityWriter(SessionID{2}); !errors.Is(err, ErrCompatibilityWriterLease) {
					t.Fatalf("early writer at %v: %v", elapsed, err)
				}
			}
			// A continuous jump models suspend: only a fresh admission sample counts.
			clock.elapsed.Store(int64(100*time.Second + CompatibilityRestartGrace))
			clock.wall.Store(-int64(24 * time.Hour))
			if err := c.CheckCompatibilityWriter(SessionID{2}); err != nil {
				t.Fatalf("boundary writer=%v", err)
			}
			if c.startupReady {
				t.Fatal("writer grace changed Mac readiness")
			}
			commitment := VisibilityCommitment{CachedNameCapacity: 16, RepairBudget: time.Second, NamespaceRepair: NamespaceRepairCallbackSerializedPipelined, CompatibilityWriter: true}
			if err := c.Register(SessionID{3}, CoherenceStrict, make(chan struct{}), commitment); !errors.Is(err, ErrVisibilityStartup) {
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
			next := restartCompatibilityCoordinator(t, clock, m)
			if err := next.StartCompatibilityWriterGrace(); err != nil {
				t.Fatal(err)
			}
			if err := next.CheckCompatibilityWriter(SessionID{2}); !errors.Is(err, ErrCompatibilityWriterLease) {
				t.Fatalf("repeated restart=%v", err)
			}
		})
	}
}

func TestCompatibilityRestartClockFailuresStayFenced(t *testing.T) {
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
			c := restartCompatibilityCoordinator(t, clock, newTestDurableVisibilityMembership())
			err := c.StartCompatibilityWriterGrace()
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
			if err := c.CheckCompatibilityWriter(SessionID{2}); !errors.Is(err, ErrCompatibilityWriterLease) {
				t.Fatalf("fault admitted writer=%v", err)
			}
			clock.failed.Store(false)
			clock.elapsed.Store(int64(time.Hour))
			if err := c.CheckCompatibilityWriter(SessionID{2}); !errors.Is(err, ErrCompatibilityWriterLease) {
				t.Fatalf("fault was not sticky=%v", err)
			}
		})
	}
}

func TestCompatibilityRestartStillHonorsCurrentExclusionAndDrain(t *testing.T) {
	clock := &exclusionTestClock{}
	clock.elapsed.Store(int64(time.Second))
	c := restartCompatibilityCoordinator(t, clock, newTestDurableVisibilityMembership())
	if err := c.StartCompatibilityWriterGrace(); err != nil {
		t.Fatal(err)
	}
	old := SessionID{1}
	e := &CompatibilityExclusion{now: clock.continuous, stopped: true, deadline: 2 * CompatibilityRestartGrace}
	c.exclusions[old] = e
	clock.elapsed.Store(int64(time.Second + CompatibilityRestartGrace))
	if err := c.CheckCompatibilityWriter(SessionID{2}); !errors.Is(err, ErrCompatibilityWriterLease) {
		t.Fatal("restart grace bypassed retained promise")
	}
	clock.elapsed.Store(int64(2 * CompatibilityRestartGrace))
	if err := c.CheckCompatibilityWriter(SessionID{2}); !errors.Is(err, ErrCompatibilityWriterLease) {
		t.Fatal("restart grace bypassed apply drain")
	}
	e.drain()
	if err := c.CheckCompatibilityWriter(SessionID{2}); err != nil {
		t.Fatal(err)
	}
}
