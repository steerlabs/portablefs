package writeback

// A daemon killed while a delegation release is mid-drain must lose nothing.
//
// The live battery observed 74 MiB of acknowledged-but-unfsynced data failing to
// replay after kill -9 when a forced detach had timed out. The forced detach
// timing out is the wedge (the release drain was unbounded and umount --force
// queued behind it), and the park it was supposed to perform therefore never
// ran — so the tail's fate rested entirely on what the WAL had on disk at the
// moment of the kill.
//
// That is the property under test here, and it is the one that has to hold with
// or without a clean park: whatever the engine acknowledged locally is on disk,
// and attach-time recovery replays it EXACTLY ONCE — including when the kill
// lands with a scope parked in a release drain.

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

// killEngine models process death: the flusher's goroutines stop and the
// store's exclusive flock is released, which is all the kernel does for a
// SIGKILLed process. Nothing is flushed, nothing is parked, no release is
// finished — that is the point. A clean shutdown would test the shutdown path;
// this tests the WAL.
func killEngine(e *Engine) {
	e.fl.stop()
	if e.lock != nil {
		_ = e.lock.Close()
	}
	e.cancelCtx()
}

// TestAdmittedDataSurvivesAKillMidReleaseDrain simulates the kill by abandoning
// the engine without any clean shutdown at all — no Close, no ForceClose, no
// park — while a release is outstanding against an authority that has stopped
// applying. A fresh Open over the same state directory is exactly what the next
// attach does, and it must recover the acknowledged tail.
func TestAdmittedDataSurvivesAKillMidReleaseDrain(t *testing.T) {
	pinCreditTimings(t, 150*time.Millisecond, 25*time.Second, 200*time.Millisecond)
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushGate = make(chan struct{})
	auth.flushEntered = make(chan struct{}, 1)
	auth.mu.Unlock()

	stateDir := t.TempDir()
	cfg := Config{
		StateDir: stateDir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 8 << 20,
	}
	e, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	ctx := context.Background()

	payload := []byte("acknowledged locally, never shipped")
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, _, err := e.WriteAppend(ctx, "d/f", payload); err != nil {
		t.Fatalf("append: %v", err)
	}
	if !e.Covers("d/f") {
		t.Skip("fixture did not acquire the delegation the interleaving needs")
	}

	// Trigger the release and let it park in its drain. With the uplink shut it
	// reaches the watchdog's verdict rather than waiting forever, but the tail is
	// still unshipped either way — which is the state the kill has to survive.
	relCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	_ = e.ReleaseFor(relCtx, "d/f")
	cancel()

	// THE KILL. No Close, no ForceClose, no park: the process simply stops. This
	// models exactly what the OS does and nothing more — the goroutines stop and
	// the descriptors (including the store's flock) are released. Only what the
	// WAL already made durable exists from here on.
	killEngine(e)

	// The next attach. Let it ship.
	auth.mu.Lock()
	gate := auth.flushGate
	auth.flushGate = nil
	auth.mu.Unlock()
	if gate != nil {
		close(gate)
	}

	recovered, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("the next attach could not recover the killed stream: %v", err)
	}
	t.Cleanup(func() { _, _ = recovered.ForceClose("teardown") })

	deadline := time.Now().Add(20 * time.Second)
	for {
		auth.mu.Lock()
		got, ok := auth.files["d/f"]
		auth.mu.Unlock()
		if ok && bytes.Equal(got, payload) {
			break
		}
		if time.Now().After(deadline) {
			auth.mu.Lock()
			have := fmt.Sprintf("%q (present=%v)", got, ok)
			auth.mu.Unlock()
			t.Fatalf("data acknowledged locally before a kill mid-release-drain did "+
				"not replay: authority has %s, want %q", have, payload)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// EXACTLY once. A replay that appended a second copy would double the file.
	auth.mu.Lock()
	final := append([]byte(nil), auth.files["d/f"]...)
	auth.mu.Unlock()
	if len(final) != len(payload) {
		t.Fatalf("recovery replayed the tail more than once: authority holds %d "+
			"bytes for a %d-byte payload (%q)", len(final), len(payload), final)
	}
}
