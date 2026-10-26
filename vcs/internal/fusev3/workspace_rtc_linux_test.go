//go:build linux

package fusev3

import (
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/permissionclock"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type injectedRTC struct {
	second  atomic.Int64
	failure atomic.Bool
	anchor  time.Time
}

func (r *injectedRTC) ReadUTC() (time.Time, error) {
	if r.failure.Load() {
		return time.Time{}, errors.New("injected RTC ioctl failure")
	}
	return r.anchor.Add(time.Duration(r.second.Load()) * time.Second), nil
}
func workspaceRTCFixture(t *testing.T) (*stockFixture, *subscriptionTestClock, *injectedRTC) {
	t.Helper()
	f := newStockFixture(t)
	f.lookup(t, 1, "cached")
	bindWorkspaceTestGate(t, f.mount)
	s := f.mount.subscription
	clock := &subscriptionTestClock{now: s.config.clock.Now()}
	rtc := &injectedRTC{anchor: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)}
	s.config.clock = clock
	s.horizon = clock.Now().Add(10 * time.Second)
	s.cacheUntil = clock.Now().Add(9 * time.Second)
	s.permission = permissionclock.Permission{Time: s.horizon, Started: clock.Now(), RTC: rtc.anchor, Horizon: 10 * time.Second}
	f.mount.workspaceRTC = rtc
	return f, clock, rtc
}

func TestWorkspaceRTCScheduleOneDeniesBeforeRoundTrip(t *testing.T) {
	f, clock, rtc := workspaceRTCFixture(t)
	// Exact schedule 1: authority anchor 0, guest BOOTTIME 8.5, VZ pause 2,
	// independent expiry 10, peer completion 10.25, resume 10.5. No renewal,
	// CONTROL delivery, host recovery or console round trip intervenes.
	clock.advance(8500 * time.Millisecond)
	rtc.second.Store(10)
	before := f.rpcCalls()
	unique := f.unique.Add(2)
	status := testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{})
	if status != fuse.EIO || f.rpcCalls() != before || f.raw.ReplyWriteTracked(unique) {
		t.Fatal("schedule 1 published or dispatched after peer completion", status, f.rpcCalls(), before)
	}
	if f.mount.workspaceServing() || !f.mount.subscription.rtcClosed {
		t.Fatal("denial did not synchronously close interval")
	}
	t.Log("anchor=0 boottime=8.5 pause=2 expiry=10 peer=10.25 resume=10.5 first-request=denied rpc-delta=0")
}

func TestWorkspaceRTCFailureLatchesUntilColdPermission(t *testing.T) {
	for _, cause := range []string{"read", "backward", "equality", "boot-expiry"} {
		t.Run(cause, func(t *testing.T) {
			f, clock, rtc := workspaceRTCFixture(t)
			s := f.mount.subscription
			switch cause {
			case "read":
				rtc.failure.Store(true)
			case "backward":
				rtc.second.Store(-1)
			case "equality":
				rtc.second.Store(6)
			default:
				clock.advance(9 * time.Second)
			}
			if f.mount.workspaceServing() {
				t.Fatal("failed evidence served")
			}
			rtc.failure.Store(false)
			rtc.second.Store(0)
			candidate := permissionclock.Permission{Time: clock.Now().Add(10 * time.Second), Started: clock.Now(), RTC: rtc.anchor, Horizon: 10 * time.Second}
			if f.mount.workspaceServing() || s.acceptRenewal(s.incarnation, candidate) || !s.rtcClosed {
				t.Fatal("successful read or renewal resurrected interval")
			}
		})
	}
}

func TestWorkspaceRTCRenewalChecksOldIntervalAndIdentity(t *testing.T) {
	f, clock, rtc := workspaceRTCFixture(t)
	s := f.mount.subscription
	clock.advance(time.Second)
	rtc.second.Store(1)
	candidate := permissionclock.Permission{Time: clock.Now().Add(10 * time.Second), Started: clock.Now(), RTC: rtc.anchor.Add(time.Second), Horizon: 10 * time.Second}
	if s.acceptRenewal(s.incarnation+1, candidate) || s.rtcClosed {
		t.Fatal("stale generation changed current interval")
	}
	// The response is current and fresh, but the old interval expired while
	// it waited for installation. A candidate cannot reset away that pause.
	rtc.second.Store(6)
	if s.acceptRenewal(s.incarnation, candidate) || !s.rtcClosed {
		t.Fatal("renewal reset expired old anchor")
	}
}

func TestWorkspaceRTCFinalPreparationChecksCachedArenaAndCapsTTL(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "clamp", true: "deny"}[expire], func(t *testing.T) {
			f, _, rtc := workspaceRTCFixture(t)
			unique := f.unique.Add(2)
			out := &fuse.EntryOut{}
			if status := testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", out); status != fuse.OK {
				t.Fatal(status)
			}
			defer f.raw.ReplyWritten(unique, fuse.EIO)
			p := f.raw.replyPublications[unique]
			if p == nil || !p.cachedArena || !p.originalFinalized {
				t.Fatal("not the finalized cached shortcut")
			}
			bytes := make([]byte, 128)
			binary.LittleEndian.PutUint64(bytes[16:24], 9)
			binary.LittleEndian.PutUint64(bytes[24:32], 9)
			rtc.second.Store(5)
			if expire {
				rtc.second.Store(6)
			}
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, 1, 1, bytes, nil, 0)
			if expire {
				if reply != fuse.EIO || prepare != fuse.OK {
					t.Fatal("expired retained reply escaped", reply, prepare)
				}
			} else {
				if reply != fuse.OK || prepare != fuse.OK || binary.LittleEndian.Uint64(bytes[16:24]) != 1 || binary.LittleEndian.Uint64(bytes[24:32]) != 1 {
					t.Fatal("cached TTL not capped at RTC remaining", reply, prepare, bytes[:40])
				}
			}
		})
	}
}

func TestWorkspaceRTCCapacityWaitResamplesBeforeAcceptance(t *testing.T) {
	for _, kind := range []string{"write", "truncate", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			f, _, rtc := workspaceRTCFixture(t)
			unique := f.unique.Add(2)
			p, status := f.mount.workspaceFS().beginWorkspaceEntry(unique)
			if status != fuse.OK {
				t.Fatal(status)
			}
			defer func() { f.mount.workspaceFS().finishWorkspaceEntry(unique, p); f.raw.ReplyWritten(unique, fuse.EIO) }()
			ctx := workspaceAdmissionContext(context.WithValue(t.Context(), mutationCallbackKey{}, &mutationCallback{publication: *p}))
			b, err := writeback.New(clockAdmissionFlusher{}, writeback.Options{MaxEntries: 1})
			if err != nil {
				t.Fatal(err)
			}
			first, next := writeback.Identity{1}, writeback.Identity{2}
			if _, err = b.Write(t.Context(), first, 0, []byte("owned")); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch kind {
				case "write":
					_, err = b.Write(ctx, next, 0, []byte("denied"))
				case "truncate":
					_, err = b.Truncate(ctx, next, 10)
				default:
					_, err = b.SetAttr(ctx, next, writeback.Attributes{HasMode: true, Mode: 0600})
				}
				done <- err
			}()
			deadline := time.Now().Add(time.Second)
			for b.Stats().WaitingAdmissions != 1 {
				if time.Now().After(deadline) {
					t.Fatal("no capacity waiter")
				}
				time.Sleep(time.Millisecond)
			}
			rtc.second.Store(6)
			b.Drop(first, "release captured capacity")
			if err := <-done; !errors.Is(err, workspaceadmission.ErrClosed) {
				t.Fatal("expired waiter accepted", err)
			}
			if b.Stats().Entries != 0 || !f.mount.subscription.rtcClosed {
				t.Fatal("failed acceptance retained data or open permission")
			}
		})
	}
}

func TestWorkspaceRTCCadenceLeavesNativeThreeSeconds(t *testing.T) {
	f, _, _ := workspaceRTCFixture(t)
	if got := f.mount.subscription.renewInterval(); got != time.Second {
		t.Fatal(got)
	}
	f.mount.workspaceRTC = nil
	if got := f.mount.subscription.renewInterval(); got != 3*time.Second {
		t.Fatal(got)
	}
}

type rtcColdRPC struct {
	*coldTestRPC
	clock *subscriptionTestClock
	rtc   *injectedRTC
}

func (r rtcColdRPC) Subscribe(ctx context.Context, a, b []byte) (*authoritypb.SubscribeReply, permissionclock.Permission, error) {
	started := r.clock.Now()
	sample, err := r.rtc.ReadUTC()
	if err != nil {
		return nil, permissionclock.Permission{}, err
	}
	reply, _, err := r.coldTestRPC.Subscribe(ctx, a, b)
	return reply, permissionclock.Permission{Time: started.Add(time.Duration(reply.HorizonNanos)), Started: started, RTC: sample, Horizon: time.Duration(reply.HorizonNanos)}, err
}
func TestWorkspaceRTCOnlyColdWithdrawalAndFreshPermissionClearLatch(t *testing.T) {
	f, g, base := coldFixture(t)
	s := f.mount.subscription
	clock := &subscriptionTestClock{now: s.config.clock.Now()}
	rtc := &injectedRTC{anchor: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)}
	s.config.clock = clock
	f.mount.workspaceRTC = rtc
	s.horizon = clock.Now().Add(10 * time.Second)
	s.cacheUntil = clock.Now().Add(9 * time.Second)
	s.permission = permissionclock.Permission{Time: s.horizon, Started: clock.Now(), RTC: rtc.anchor, Horizon: 10 * time.Second}
	f.mount.rpc.(*epochRPC).rpc = rtcColdRPC{coldTestRPC: base, clock: clock, rtc: rtc}
	rtc.failure.Store(true)
	if f.mount.workspaceServing() {
		t.Fatal("read failure served")
	}
	rtc.failure.Store(false)
	if f.mount.workspaceServing() {
		t.Fatal("read success cleared latch")
	}
	serial := g.Close(1)
	cold, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, clock.Now().Add(5*time.Second))
	if err != nil || !cold.ColdComplete {
		t.Fatal("cold withdrawal", cold, err)
	}
	fresh, err := f.mount.RecoverWorkspace(t.Context(), 1, serial)
	if err != nil || !fresh.Prepared || s.rtcClosed {
		t.Fatal("fresh permission did not clear completed cold latch", fresh, err)
	}
}

type cutRTC struct {
	reader         *injectedRTC
	calls          int
	before, inside func(int)
}

func (r *cutRTC) ReadUTC() (time.Time, error) {
	r.calls++
	if r.before != nil {
		r.before(r.calls)
	}
	sampled, err := r.reader.ReadUTC()
	if r.inside != nil {
		r.inside(r.calls)
	}
	return sampled, err
}
func TestWorkspaceRTCFreezePublicationCutsDenyDifferentRequest(t *testing.T) {
	for _, cut := range []string{"before-final-sample", "inside-read-before-return", "after-return", "after-prepare", "before-physical-write", "inside-physical-write"} {
		t.Run(cut, func(t *testing.T) {
			f, _, rtc := workspaceRTCFixture(t)
			unique := f.unique.Add(2)
			if status := testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{}); status != fuse.OK {
				t.Fatal(status)
			}
			sampled := &cutRTC{reader: rtc}
			f.mount.workspaceRTC = sampled
			// Four entry/TTL samples precede the retained-answer stamp's final sample.
			const final = 5
			freeze := func(n int) {
				if n == final {
					rtc.second.Store(31)
				}
			}
			switch cut {
			case "before-final-sample":
				sampled.before = freeze
			case "inside-read-before-return":
				sampled.inside = freeze
			case "after-return":
				f.mount.subscription.config.afterWorkspaceSample = func() { freeze(sampled.calls) }
			}
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, 1, 1, make([]byte, 128), nil, 0)
			if prepare != fuse.OK || sampled.calls != final {
				t.Fatal("final sample cut moved", prepare, sampled.calls)
			}
			if cut == "before-final-sample" && reply != fuse.EIO {
				t.Fatal("fresh expired sample admitted", reply)
			}
			if cut != "before-final-sample" && reply != fuse.OK {
				t.Fatal("in-flight residual control failed", reply)
			}
			rtc.second.Store(31)
			f.raw.ReplyWritten(unique, fuse.OK)
			next := f.unique.Add(2)
			p, status := f.mount.workspaceFS().tryWorkspaceEntry(next)
			if p != nil || status == fuse.OK {
				t.Fatal("another post-resume request borrowed in-flight sample", status)
			}
			t.Logf("request=%d anchor=0 cut=%s expiry=10 peer=10.25 physical-completion=31 reply=%v; request=%d denied", unique, cut, reply, next)
		})
	}
}

func TestWorkspaceRTCReadFrozenAfterPreparationStillPurges(t *testing.T) {
	f, _, rtc := workspaceRTCFixture(t)
	entry := f.lookup(t, 1, "cached")
	opened := f.openForData(t, entry.NodeId)
	f.rpc.mu.Lock()
	f.rpc.fileData = []byte("data")
	f.rpc.mu.Unlock()
	unique := f.unique.Add(2)
	result, status := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 4}, make([]byte, 4))
	if status != fuse.OK {
		t.Fatal(status)
	}
	defer result.Done()
	_, reply, prepare := f.raw.PrepareReplyPayload(unique, entry.NodeId, 15, nil, nil, 0)
	if reply != fuse.OK || prepare != fuse.OK {
		t.Fatal(reply, prepare)
	}
	before := len(f.notify.snapshot())
	rtc.second.Store(31)
	f.raw.ReplyWritten(unique, fuse.OK)
	if len(f.notify.snapshot()) <= before || f.raw.ReplyWriteTracked(unique) {
		t.Fatal("late successful READ lost its physical purge/settlement")
	}
	if !f.mount.subscription.rtcClosed {
		t.Fatal("physical settlement did not latch expired evidence")
	}
}

func TestWorkspaceRTCRepeatedPausesAndBackwardCorrectionAboveAnchor(t *testing.T) {
	f, _, rtc := workspaceRTCFixture(t)
	for _, second := range []int64{1, 2, 3, 4, 5, 4, 5} {
		rtc.second.Store(second)
		if !f.mount.workspaceServing() {
			t.Fatal("bounded live interval denied", second)
		}
	}
	rtc.second.Store(6)
	if f.mount.workspaceServing() {
		t.Fatal("small pauses reset elapsed deadline")
	}
	rtc.second.Store(4)
	if f.mount.workspaceServing() {
		t.Fatal("backward correction resurrected closure")
	}
}

func TestWorkspaceRTCRenewalSampleCannotInstallAcrossNewClose(t *testing.T) {
	f, clock, rtc := workspaceRTCFixture(t)
	s := f.mount.subscription
	// Recover the gate owner from this fixture's installed proof through a new
	// real binding, so Close changes its seqlock independently of the use lock.
	gate := bindWorkspaceTestGate(t, f.mount)
	clock.advance(time.Second)
	rtc.second.Store(1)
	old := s.permission
	reader := &cutRTC{reader: rtc, inside: func(n int) {
		if n == 2 {
			gate.Close(2)
		}
	}}
	f.mount.workspaceRTC = reader
	candidate := permissionclock.Permission{Time: clock.Now().Add(10 * time.Second), Started: clock.Now(), RTC: rtc.anchor.Add(time.Second), Horizon: 10 * time.Second}
	if s.acceptRenewal(s.incarnation, candidate) || s.permission != old {
		t.Fatal("obsolete candidate installed across host Close", reader.calls, s.permission)
	}
}

func TestWorkspaceRTCCutoffPauseMatrix(t *testing.T) {
	for _, pause := range []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second} {
		for _, cutoff := range []time.Duration{6 * time.Second, 10 * time.Second} {
			for _, offset := range []time.Duration{-time.Millisecond, 0, time.Millisecond} {
				for _, phase := range []time.Duration{0, 500 * time.Millisecond, 999 * time.Millisecond} {
					f, clock, rtc := workspaceRTCFixture(t)
					elapsed := cutoff + offset
					clock.advance(elapsed - pause)
					rtc.second.Store(int64((phase + elapsed) / time.Second))
					remaining := f.mount.subscription.workspaceRemaining()
					if elapsed >= 9*time.Second && remaining != 0 {
						t.Fatal("authority/lead cutoff admitted", pause, cutoff, offset, phase)
					}
					if phase == 0 && cutoff == 6*time.Second && offset < 0 && remaining <= 0 {
						t.Fatal("below reduced cutoff refused without source variation")
					}
					if phase == 0 && cutoff == 6*time.Second && offset >= 0 && remaining > 0 {
						t.Fatal("RTC equality or later admitted")
					}
					if remaining > 0 && remaining+elapsed > 9*time.Second {
						t.Fatal("unsafe remaining after pause")
					}
					f.mount.cancel()
					f.mount.delegations.Stop()
				}
			}
		}
	}
}

func TestWorkspaceRTCAcceptedMutationKeepsAssignedOutcome(t *testing.T) {
	for _, delegated := range []bool{false, true} {
		t.Run(map[bool]string{false: "authority", true: "delegated"}[delegated], func(t *testing.T) {
			var f *stockFixture
			var item *fuse.EntryOut
			if delegated {
				f, item = dirtyHolderMetadataFixture(t)
			} else {
				f = newStockFixture(t)
				item = f.lookup(t, 1, "cached")
			}
			bindWorkspaceTestGate(t, f.mount)
			s := f.mount.subscription
			clock := &subscriptionTestClock{now: s.config.clock.Now()}
			rtc := &injectedRTC{anchor: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)}
			s.config.clock = clock
			s.horizon = clock.Now().Add(10 * time.Second)
			s.cacheUntil = clock.Now().Add(9 * time.Second)
			s.permission = permissionclock.Permission{Time: s.horizon, Started: clock.Now(), RTC: rtc.anchor, Horizon: 10 * time.Second}
			f.mount.workspaceRTC = rtc
			unique := f.unique.Add(2)
			in := &fuse.SetAttrIn{}
			in.Unique = unique
			in.NodeId = item.NodeId
			in.Valid = fuse.FATTR_MODE
			in.Mode = 0640
			if status := f.raw.SetAttr(nil, in, &fuse.AttrOut{}); status != fuse.OK {
				t.Fatal(status)
			}
			p := f.raw.replyPublications[unique]
			if p == nil || !p.workspaceBound || p.source == nil {
				t.Fatal("assigned effect not owned by physical reply")
			}
			pin := p.holderAdmission
			rtc.second.Store(31)
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, item.NodeId, 4, nil, nil, 0)
			f.raw.ReplyWritten(unique, fuse.OK)
			if reply != fuse.OK || prepare != fuse.OK || f.mount.isRevoked() {
				t.Fatal("expiry fabricated a definite no-change result", reply, prepare)
			}
			assertMetadataPinReleased(t, pin)
		})
	}
}
