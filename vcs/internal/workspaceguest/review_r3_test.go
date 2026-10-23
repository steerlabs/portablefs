package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

func r3W(id *pb.MountID) Witness { return Witness{Process: "pid/" + id.VolumeId, Kernel: "k"} }

func r3Proof(id *pb.MountID) CleanupProof {
	return CleanupProof{Witness: r3W(id), ProcessExited: true, KernelAbsent: true}
}

func r3AckAll(t *testing.T, s *Supervisor) {
	t.Helper()
	for {
		page := s.Status().Retired
		if len(page) == 0 {
			return
		}
		if err := s.AcknowledgeRetired(page[len(page)-1].RetirementSequence); err != nil {
			t.Fatal(err)
		}
	}
}

func r3Capacity(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "acknowledgement") || strings.Contains(m, "capacity") || strings.Contains(m, "exhausted")
}

// A=64 active with R=64 unacknowledged: Replace must retire the old mount, and
// only the new incarnation may wait, with something acknowledgeable.
func TestR3ReplaceAtFullActiveAndReservations(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	for i := range control.MaxMounts {
		if err := s.AcceptJob(jobRequest(1, retirementVolume(100+i, 4), "mount")); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return len(s.Retired()) == control.MaxMounts })
	for i := range control.MaxMounts {
		m := retirementVolume(i, 4)
		if err := s.Register(context.Background(), m, r3W(m), &fakeMount{}); err != nil {
			t.Fatal(i, err)
		}
	}
	old := retirementVolume(0, 4)
	if err := s.Terminal(old, "ended", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(old, r3Proof(old)); err != nil {
		t.Fatal(err)
	}
	next := retirementVolume(0, 5)
	nm := &fakeMount{}
	err = s.Replace(context.Background(), old, next, r3W(next), nm)
	r := s.Retired()
	t.Logf("replace at saturation: err=%v retired=%d newCleaned=%v", err, len(r), nm.cleaned)
	if err == nil || !strings.Contains(err.Error(), "acknowledgement") || len(r) != control.MaxMounts+1 || r[len(r)-1].MountStatus == nil || !nm.cleaned {
		t.Fatalf("expected old retired and only new admission waiting: %v", err)
	}
	// A retry must name the already absent old incarnation and the continuation.
	again := s.Replace(context.Background(), old, next, r3W(next), &fakeMount{})
	if again == nil || !strings.Contains(again.Error(), "old incarnation already absent; Register") {
		t.Fatalf("misleading retry: %v", again)
	}
	r3AckAll(t, s)
	if err := s.Register(context.Background(), next, r3W(next), &fakeMount{}); err != nil {
		t.Fatalf("register new incarnation after ack: %v", err)
	}
}

// Same saturation, but the old key also carries a joined Mount job from a
// registering driver: retirement is one combined record, no extra capacity.
func TestR3ReplaceJobOwnedMountAtSaturation(t *testing.T) {
	var s *Supervisor
	s, _ = New(id(1), id(2), id(3), true, jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		if strings.HasPrefix(j.Mount.VolumeId, "rv1") && len(j.Mount.VolumeId) == 5 { // rv1xx: job-only failures
			return errors.New("boom")
		}
		return s.Register(ctx, j.Mount, r3W(j.Mount), &fakeMount{})
	}))
	t.Cleanup(s.ChannelLost)
	for i := range control.MaxMounts {
		if err := s.AcceptJob(jobRequest(1, retirementVolume(100+i, 4), "mount")); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return len(s.Retired()) == control.MaxMounts })
	for i := range control.MaxMounts {
		if err := s.AcceptJob(jobRequest(1, retirementVolume(i, 4), "mount")); err != nil {
			t.Fatal(i, err)
		}
	}
	waitDesiredJobsJoined(t, s)
	writtenStatus(t, s, s.Status())
	if st := s.Status(); len(st.Mounts) != 64 || len(st.Jobs) != 64 {
		t.Fatalf("setup mounts=%d jobs=%d", len(st.Mounts), len(st.Jobs))
	}
	// Existing-key retry and Umount at saturation.
	if err := s.AcceptJob(jobRequest(2, retirementVolume(1, 4), "mount")); err != nil {
		t.Fatalf("retry at saturation: %v", err)
	}
	if err := s.AcceptJob(jobRequest(2, retirementVolume(2, 4), "umount")); err != nil {
		t.Fatalf("umount at saturation: %v", err)
	}
	old := retirementVolume(0, 4)
	_ = s.Terminal(old, "ended", nil)
	_ = s.Cleanup(old, r3Proof(old))
	err := s.Replace(context.Background(), old, retirementVolume(0, 5), r3W(old), &fakeMount{})
	r := s.Retired()
	last := r[len(r)-1]
	if err == nil || last.MountStatus == nil || last.Job == nil || !proto.Equal(last.Job.Mount, old) {
		t.Fatalf("combined record missing: %v", err)
	}
	encodable(t, s.Status())
}

func TestR3SequenceNearMaxReplaceAndDrainAll(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	s.retirementSequence, s.acknowledgedSequence = math.MaxUint64-64, math.MaxUint64-64
	for i := range control.MaxMounts {
		m := retirementVolume(i, 4)
		if err := s.Register(context.Background(), m, r3W(m), &fakeMount{}); err != nil {
			t.Fatal(i, err)
		}
	}
	old := retirementVolume(0, 4)
	_ = s.Terminal(old, "x", nil)
	_ = s.Cleanup(old, r3Proof(old))
	err = s.Replace(context.Background(), old, retirementVolume(0, 5), r3W(old), &fakeMount{})
	if err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("replace near max: %v", err)
	}
	rid := uint64(10)
	for i := 1; i < control.MaxMounts; i++ {
		m := retirementVolume(i, 4)
		_ = s.Terminal(m, "x", nil)
		_ = s.Cleanup(m, r3Proof(m))
		rid++
		if err := s.AcceptJob(jobRequest(rid, m, "umount")); err != nil {
			t.Fatal(i, err)
		}
		waitDesiredJobsJoined(t, s)
		writtenStatus(t, s, s.Status())
		r3AckAll(t, s)
	}
	if s.retirementSequence != math.MaxUint64 || len(s.mounts) != 0 || len(s.jobs) != 0 {
		t.Fatalf("seq=%d mounts=%d jobs=%d", s.retirementSequence, len(s.mounts), len(s.jobs))
	}
	if err := s.AcceptJob(jobRequest(1, retirementVolume(200, 4), "mount")); err == nil {
		t.Fatal("admission after exhaustion")
	}
}

// Removal unproven forever: the key and its reservation stay; every existing-key
// operation remains admissible; membership full refuses genuinely new volumes.
func TestR3UnprovenRemovalHoldsReservationOnly(t *testing.T) {
	var s *Supervisor
	s, _ = New(id(1), id(2), id(3), true, jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		if j.Operation == "mount" && j.RequestId == 1 {
			return s.Register(ctx, j.Mount, r3W(j.Mount), &fakeMount{cold: ColdResult{ColdComplete: true}})
		}
		return errors.New("cleanup not proven")
	}))
	t.Cleanup(s.ChannelLost)
	for i := range control.MaxMounts {
		if err := s.AcceptJob(jobRequest(1, retirementVolume(i, 4), "mount")); err != nil {
			t.Fatal(err)
		}
	}
	waitDesiredJobsJoined(t, s)
	writtenStatus(t, s, s.Status())
	for rid := uint64(2); rid < 200; rid++ {
		if err := s.AcceptJob(jobRequest(rid, retirementVolume(int(rid)%64, 4), "umount")); err != nil {
			t.Fatal(rid, err)
		}
		waitDesiredJobsJoined(t, s)
		writtenStatus(t, s, s.Status())
	}
	if err := s.AcceptJob(jobRequest(1, retirementVolume(99, 4), "mount")); err == nil || !strings.Contains(err.Error(), "desired mount capacity") {
		t.Fatalf("new key: %v", err)
	}
	if n := len(s.Retired()); n != 0 {
		t.Fatalf("retired=%d", n)
	}
	encodable(t, s.Status())
	if _, err := s.Suspend(context.Background(), suspension(s), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

// Randomized single-owner walk with asynchronous drivers. Invariants:
// existing-key work is never refused for capacity; a new key is refused for
// acknowledgement only while a record exists; A<=64, A+R<=128.
func TestR3RandomWalkNoCapacityCycle(t *testing.T) {
	for seed := int64(1); seed <= 6; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			var dmu sync.Mutex
			fail := map[string]bool{}
			var s *Supervisor
			s, _ = New(id(1), id(2), id(3), true, jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
				dmu.Lock()
				f := fail[control.MountKey(j.Mount)]
				dmu.Unlock()
				if f {
					return errors.New("driver failed")
				}
				switch j.Operation {
				case "mount":
					err := s.Register(ctx, j.Mount, r3W(j.Mount), &fakeMount{cold: ColdResult{ColdComplete: true}})
					if err != nil && strings.Contains(err.Error(), "duplicate") {
						return nil
					}
					return err
				case "umount":
					_ = s.Terminal(j.Mount, "removed", nil)
					return s.Cleanup(j.Mount, r3Proof(j.Mount))
				}
				return nil
			}))
			defer s.ChannelLost()
			rids := map[string]uint64{}
			var maxA, maxR, ackWaits int
			defer func() { t.Logf("maxA=%d maxR=%d newKeyAckWaits=%d", maxA, maxR, ackWaits) }()
			incs := map[int]byte{}
			for step := 0; step < 4000; step++ {
				vol := rng.Intn(160)
				if incs[vol] == 0 {
					incs[vol] = 4
				}
				m := retirementVolume(vol, incs[vol])
				k := control.MountKey(m)
				dmu.Lock()
				fail[k] = rng.Intn(5) == 0
				dmu.Unlock()
				s.mu.Lock()
				existing := s.mounts[k] != nil || s.jobs[k] != nil
				A, R := len(s.activeKeysLocked()), len(s.retired)
				var cleaned bool
				if e := s.mounts[k]; e != nil {
					cleaned = e.cleaned
				}
				s.mu.Unlock()
				maxA, maxR = max(maxA, A), max(maxR, R)
				if A > 64 || A+R > MaxReservations {
					t.Fatalf("bound broken A=%d R=%d", A, R)
				}
				switch op := rng.Intn(10); {
				case op < 6:
					// Join this key between sampling and admission to exercise a
					// job-only retirement in the old classifier's race window.
					s.mu.Lock()
					inflight := s.jobs[k]
					s.mu.Unlock()
					if inflight != nil {
						<-inflight.done
					}
					rids[k]++
					operation := []string{"mount", "umount", "provision"}[rng.Intn(3)]
					err := s.AcceptJob(jobRequest(rids[k]+uint64(step)*1000, m, operation))
					// A capacity refusal dispatches nothing. Re-read under the
					// lock: an existing key with a running job skips capacity
					// and is lane-occupied, so it cannot disappear after such
					// a refusal and conceal an existing-key capacity bug.
					s.mu.Lock()
					existing = s.mounts[k] != nil || s.jobs[k] != nil
					A, R = len(s.activeKeysLocked()), len(s.retired)
					s.mu.Unlock()
					if err != nil && existing && r3Capacity(err) {
						t.Fatalf("existing key refused for capacity A=%d R=%d: %v", A, R, err)
					}
					if err != nil && !existing && strings.Contains(err.Error(), "acknowledgement") {
						ackWaits++
					}
					if err != nil && !existing && strings.Contains(err.Error(), "acknowledgement") && R == 0 {
						t.Fatalf("new key waits with nothing acknowledgeable: %v", err)
					}
				case op < 7:
					if cleaned {
						nxt := retirementVolume(vol, incs[vol]+1)
						err := s.Replace(context.Background(), m, nxt, r3W(nxt), &fakeMount{cold: ColdResult{ColdComplete: true}})
						if err == nil {
							incs[vol]++
						} else {
							s.mu.Lock()
							gone := s.mounts[k] == nil
							s.mu.Unlock()
							if gone {
								incs[vol]++ // old retired, new admission waited
							}
						}
					}
				case op < 9:
					if existing {
						_ = s.Terminal(m, "ended", nil)
						_ = s.Cleanup(m, r3Proof(m))
					}
				default:
					if (step/600)%2 == 1 {
						if page := s.Status().Retired; len(page) > 0 {
							if err := s.AcknowledgeRetired(page[len(page)-1].RetirementSequence); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
				if step%50 == 0 {
					waitDesiredJobsJoined(t, s)
					writtenStatus(t, s, s.Status())
					encodable(t, s.Status())
				}
			}
			waitDesiredJobsJoined(t, s)
			writtenStatus(t, s, s.Status())
			if _, err := s.Suspend(context.Background(), suspension(s), time.Now().Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
