//go:build linux

package fusev3

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/permissionclock"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceclock"
	"golang.org/x/sys/unix"
)

// Only the disposable native qualification initramfs runs this entry point.
// The product image and daemons have no injected clock or pause controls.
func TestMain(m *testing.M) {
	native := os.Getpid() == 1
	if native {
		for _, v := range []struct{ path, kind string }{{"/dev", "devtmpfs"}, {"/proc", "proc"}, {"/sys", "sysfs"}} {
			if err := unix.Mount(v.kind, v.path, v.kind, 0, ""); err != nil {
				panic(err)
			}
		}
		os.Args = []string{os.Args[0], "-test.run=^TestNativeWorkspaceRTCPauseMatrix$", "-test.v", "-test.timeout=180s"}
	}
	result := m.Run()
	if !native {
		os.Exit(result)
	}
	fmt.Printf("G0_NATIVE_DONE=%d\n", result)
	for {
		time.Sleep(time.Hour)
	}
}

func nativePause(t *testing.T, name string, duration time.Duration, fields map[string]any) {
	t.Helper()
	fields["case"] = name
	fields["pause_ns"] = int64(duration)
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("G0_PAUSE_ARMED=" + string(raw))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || line != "probe\n" {
		t.Fatal("prequeued operation", line, err)
	}
}
func nativeCase(t *testing.T, name string, fields map[string]any) {
	t.Helper()
	fields["case"] = name
	fields["pass"] = true
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("G0_NATIVE_CASE=" + string(raw))
}

func TestNativeWorkspaceRTCPauseMatrix(t *testing.T) {
	if os.Getpid() != 1 {
		t.Skip("native VZ qualification initramfs only")
	}
	owner, err := workspaceclock.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	file, err := owner.DuplicateRTC()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := workspaceclock.AdoptRTC(file)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	defer reader.Close()
	t.Run("schedule-1", func(t *testing.T) {
		f, clock, _ := workspaceRTCFixture(t)
		anchor, err := reader.ReadUTC()
		if err != nil {
			t.Fatal(err)
		}
		s := f.mount.subscription
		s.permission = permissionclock.Permission{Time: s.horizon, Started: clock.Now(), RTC: anchor, Horizon: 10 * time.Second}
		f.mount.workspaceRTC = reader
		// The independently advancing register has a real 8.5-second head start.
		// Only the injected guest BOOTTIME is retained at exactly 8.5 on resume.
		time.Sleep(8500 * time.Millisecond)
		clock.advance(8500 * time.Millisecond)
		nativePause(t, "g0-vz-schedule-1", 2*time.Second, map[string]any{"anchor": anchor, "boottime_ns": int64(8500 * time.Millisecond), "authority_expiry": 10, "peer_completion": 10.25, "resume": 10.5})
		calls := f.rpcCalls()
		unique := f.unique.Add(2)
		status := testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{})
		if status != fuse.EIO || f.rpcCalls() != calls || !s.rtcClosed {
			t.Fatal("first resumed operation admitted or dispatched", status)
		}
		sampled, err := reader.ReadUTC()
		if err != nil || sampled.Sub(anchor) < 10*time.Second {
			t.Fatal("independent RTC did not cover authority expiry", anchor, sampled, err)
		}
		nativeCase(t, "g0-vz-schedule-1", map[string]any{"request": unique, "anchor": anchor, "first_after_resume": sampled, "status": int(status), "rpc_delta": f.rpcCalls() - calls, "closed": s.rtcClosed, "no_host_round_trip_after_resume": true})
	})
	for _, pause := range []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second} {
		for _, cutoff := range []time.Duration{6 * time.Second, 10 * time.Second} {
			for _, offset := range []time.Duration{-time.Millisecond, 0, time.Millisecond} {
				for phaseIndex, phase := range []time.Duration{0, 500 * time.Millisecond, 999 * time.Millisecond} {
					offsetName := map[time.Duration]string{-time.Millisecond: "below", 0: "equal", time.Millisecond: "above"}[offset]
					name := fmt.Sprintf("g0-vz-cutoff-%dms-%ds-%s-phase%d", pause/time.Millisecond, cutoff/time.Second, offsetName, phaseIndex)
					t.Run(name, func(t *testing.T) {
						f, clock, rtc := workspaceRTCFixture(t)
						elapsed := cutoff + offset
						clock.advance(elapsed - pause)
						before, err := reader.ReadUTC()
						if err != nil {
							t.Fatal(err)
						}
						nativePause(t, name, pause, map[string]any{"injected_resume_age_ns": int64(elapsed), "boottime_ns": int64(elapsed - pause), "phase_ns": int64(phase), "register_before": before})
						after, err := reader.ReadUTC()
						if err != nil || after.Before(before) {
							t.Fatal("first post-resume register read", after, err)
						}
						rtc.second.Store(int64((elapsed + phase) / time.Second))
						calls := f.rpcCalls()
						remaining := f.mount.subscription.workspaceRemaining()
						wantLive := rtc.second.Load() < 6 && elapsed-pause < 9*time.Second
						if (remaining > 0) != wantLive || f.rpcCalls() != calls {
							t.Fatal("cutoff admission mismatch", remaining, wantLive)
						}
						if !wantLive {
							rtc.second.Store(0)
							if f.mount.workspaceServing() {
								t.Fatal("successful read resurrected closed interval")
							}
						}
						nativeCase(t, name, map[string]any{"injected_elapsed_ns": int64(elapsed), "injected_boottime_ns": int64(elapsed - pause), "phase_ns": int64(phase), "register_before": before, "first_register_after_resume": after, "remaining_ns": int64(remaining), "live": wantLive, "rpc_delta": 0, "no_host_round_trip_after_resume": true})
					})
				}
			}
		}
	}
}
