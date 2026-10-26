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
