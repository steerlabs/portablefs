package workspaceguest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

type randomWalkMount struct {
	mu         sync.Mutex
	rng        *rand.Rand
	generation uint64
	gateSerial uint64
	open       bool
	w          Witness
}

func (m *randomWalkMount) bindProof(r *Recovery) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.GateSerial = m.gateSerial
	r.Renewal.Permit = mountenrollment.Permit{Generation: r.Generation, GateSerial: m.gateSerial}
}
func (m *randomWalkMount) r() int { m.mu.Lock(); defer m.mu.Unlock(); return m.rng.Intn(1000) }
func (m *randomWalkMount) CloseAdmission(g uint64) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g >= m.generation {
		m.generation = g
		m.open = false
	}
	m.gateSerial++
	return m.gateSerial
}
func (m *randomWalkMount) OpenAdmission(g, serial uint64) error {
	if m.r() < 100 {
		return errors.New("open refused")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if g != m.generation || serial != m.gateSerial {
		return ErrState
	}
	m.open = true
	return nil
}
func (m *randomWalkMount) delay(ctx context.Context) {
	d := time.Duration(m.r()%3) * time.Millisecond
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}
func randomWalkLoss(n int) []*pb.Loss {
	var out []*pb.Loss
	for i := 1; i <= n; i++ {
		out = append(out, &pb.Loss{Sequence: uint64(i), Reason: "lost"})
	}
	return out
}
func (m *randomWalkMount) proof(ctx context.Context, g uint64) (Recovery, error) {
	m.delay(ctx)
	r := ready()
	r.Generation = g
	m.bindProof(&r)
	switch m.r() % 13 {
	case 0:
		return r, nil
	case 1:
		return Recovery{}, errors.New("authority unreachable \xff")
	case 2:
		r.Generation = g + 1
	case 3:
		r.SessionValidated = false
	case 4:
		r.Renewal.State = "pending"
	case 5:
		r.State = "terminal"
	case 6:
		r.State = "authorization-required"
		r.Reason = ""
	case 7:
		r.State = "closed"
	case 8:
		r.Loss = []*pb.Loss{{Sequence: 0}}
	case 9:
		r.Loss = randomWalkLoss(129)
	case 10:
		r.Loss = randomWalkLoss(3)
	case 11:
		return r, ctx.Err()
	default:
		return r, nil
	}
	return r, nil
}
func (m *randomWalkMount) Prepare(ctx context.Context, g uint64) (Recovery, error) {
	return m.proof(ctx, g)
}
func (m *randomWalkMount) Recover(ctx context.Context, t *pb.ResumeToken) (Recovery, error) {
	return m.proof(ctx, t.Suspension.Generation)
}
func (m *randomWalkMount) Suspend(ctx context.Context, x *pb.Suspension) (ColdResult, error) {
	m.delay(ctx)
	r := ColdResult{Generation: x.Generation, ColdComplete: true}
	switch m.r() % 8 {
	case 0:
		r.ColdComplete = false
	case 1:
		return r, errors.New("withdraw failed")
	case 2:
		r.Loss = randomWalkLoss(5)
	case 3:
		r.Loss = randomWalkLoss(129)
	case 4:
		r.Generation++
	case 5:
		r.Loss = []*pb.Loss{{Sequence: 0}}
	}
	return r, nil
}
func (m *randomWalkMount) Cleanup(_ context.Context, w Witness) (CleanupProof, error) {
	return CleanupProof{Witness: w, ProcessExited: m.r() < 800, KernelAbsent: m.r() < 800}, nil
}

func replyEncodingError(body any) error {
	e := &pb.Envelope{Version: 8, RequestId: 1}
	switch v := body.(type) {
	case *pb.StatusReply:
		e.Body = &pb.Envelope_StatusReply{StatusReply: v}
	case *pb.SuspendAck:
		e.Body = &pb.Envelope_SuspendAck{SuspendAck: v}
	case *pb.ResumeAck:
		e.Body = &pb.Envelope_ResumeAck{ResumeAck: v}
	}
	_, err := control.Encode(e)
	return err
}

func TestGuestConcurrentRandomWalkRepliesEncode(t *testing.T) {
	// Fixed seeds bound runtime while exercising concurrent API schedules.
	for _, seed := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 41, 73, 127, 199, 251, 311, 347, 399, 400, 599} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(seed)))
			var rmu sync.Mutex
			R := func(n int) int { rmu.Lock(); defer rmu.Unlock(); return rng.Intn(n) }
			s, _ := New(id(1), id(2), id(3), true, nil)
			var inc atomic.Uint32
			inc.Store(20)
			fresh := func(vol int) *pb.MountID {
				n := inc.Add(1)
				return &pb.MountID{AuthorityId: bytes.Repeat([]byte{1}, 32), VolumeId: fmt.Sprintf("v%d", vol), Incarnation: bytes.Repeat([]byte{byte(n), byte(n >> 8)}, 8)}
			}
			var fail atomic.Value
			check := func(where string, body any) {
				if err := replyEncodingError(body); err != nil {
					fail.CompareAndSwap(nil, fmt.Sprintf("%s: %v: %v", where, err, body))
				}
			}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						check("background status", s.Status())
						time.Sleep(100 * time.Microsecond)
					}
				}
			}()
			var async sync.WaitGroup
			for step := 0; step < 120; step++ {
				st := s.Status()
				var mounts []*pb.MountID
				for _, m := range st.Mounts {
					mounts = append(mounts, m.Mount)
				}
				pick := func() *pb.MountID {
					if len(mounts) == 0 {
						return fresh(9)
					}
					return mounts[R(len(mounts))]
				}
				switch R(10) {
				case 0, 1:
					m := &randomWalkMount{rng: rand.New(rand.NewSource(int64(R(1 << 30))))}
					_ = s.Register(context.Background(), fresh(R(4)), Witness{}, m)
				case 2, 3:
					id := pick()
					g := s.Status().Generation
					async.Add(1)
					go func() {
						defer async.Done()
						ctx, cancel := context.WithTimeout(context.Background(), time.Duration(R(4))*time.Millisecond)
						defer cancel()
						_ = s.Activate(ctx, id, g)
					}()
				case 4, 5:
					x := suspension(s)
					if R(10) == 0 {
						x.Generation += 2
					}
					fixed, err := s.BeginSuspend(x)
					check("after begin", s.Status())
					if err != nil {
						break
					}
					ok := true
					for _, mid := range fixed.Roster {
						ctx, cancel := context.WithTimeout(context.Background(), time.Duration(R(5))*time.Millisecond)
						if err := s.Drain(ctx, fixed, mid); err != nil {
							ok = false
						}
						cancel()
						check("after drain", s.Status())
						if !ok && R(2) == 0 {
							break
						}
					}
					ack, err := s.SuspendAck(fixed)
					if err == nil {
						check("suspend ack", ack)
						check("after ack", s.Status())
						if R(5) > 0 {
							ra, err := s.Resume(context.Background(), token(fixed))
							if err == nil {
								check("resume ack", ra)
							}
						}
					}
				case 6:
					_ = s.Terminal(pick(), "explicit", randomWalkLoss(R(4)))
				case 7:
					mid := pick()
					s.mu.Lock()
					var w Witness
					if e := s.mounts[control.MountKey(mid)]; e != nil {
						w = e.witness
					}
					s.mu.Unlock()
					_ = s.Cleanup(mid, CleanupProof{Witness: w, ProcessExited: R(4) > 0, KernelAbsent: R(4) > 0})
				case 8:
					old := pick()
					next := fresh(0)
					next.AuthorityId, next.VolumeId = old.AuthorityId, old.VolumeId
					m := &randomWalkMount{rng: rand.New(rand.NewSource(int64(R(1 << 30))))}
					_ = s.Replace(context.Background(), old, next, Witness{}, m)
				case 9:
					s.mu.Lock()
					top := s.retirementSequence
					s.mu.Unlock()
					_ = s.AcknowledgeRetired(uint64(R(int(top) + 3)))
				}
				check(fmt.Sprintf("step %d", step), s.Status())
				if R(3) == 0 {
					time.Sleep(time.Duration(R(3)) * time.Millisecond)
				}
				if f := fail.Load(); f != nil {
					break
				}
			}
			s.ChannelLost()
			check("channel lost", s.Status())
			async.Wait()
			time.Sleep(5 * time.Millisecond)
			check("final", s.Status())
			close(stop)
			wg.Wait()
			if f := fail.Load(); f != nil {
				t.Fatal(f)
			}
		})
	}
}
