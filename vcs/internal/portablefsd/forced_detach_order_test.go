package portablefsd

// Forced detach is the escape hatch. It must not queue behind the work it
// exists to abandon.
//
// attach.detach took a.frontendSerial.Lock() and a.nsMu.Lock() UNCONDITIONALLY,
// before it looked at the force flag. Live, with a delegation release parked in
// an unbounded drain, one namespace writer held nsMu for twelve minutes with
// about a hundred frontend goroutines behind it — and every `umount --force`
// joined the same queue. The hatch could not open the door it was for; only
// killing the daemon recovered the mount.

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestForcedDetachDoesNotQueueBehindTheNamespaceLock pins the ordering. With the
// mount-wide namespace lock held by a stuck operation, a forced detach must
// still reach its fence — that is what gives the stuck operation a definite
// outcome in the first place.
func TestForcedDetachDoesNotQueueBehindTheNamespaceLock(t *testing.T) {
	a := newAttach("att-forced-detach", "key", ensureAttachRequest{
		VolumeID: "vol-forced-detach", Branch: "main",
		MountPath: "/Volumes/ForcedDetach",
	}, privateTestDir(t))

	// A wedged namespace writer: exactly the shape a release parked in an
	// unbounded drain produces one layer down.
	wedged := make(chan struct{})
	held := make(chan struct{})
	go func() {
		a.frontendSerial.Lock()
		a.nsMu.Lock()
		close(held)
		<-wedged
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
	}()
	<-held
	var release sync.Once
	unwedge := func() { release.Do(func() { close(wedged) }) }
	t.Cleanup(unwedge)

	// There is no Volume, so the fence is a no-op and the only thing under test
	// is whether the forced path reaches its terminal transition. It cannot,
	// while the wedged writer holds the locks — but it MUST get past the point
	// where the fence would run, which is what the pre-lock structure buys.
	reached := make(chan struct{})
	a.testForcedDetachFenced = func() { close(reached) }

	done := make(chan struct{})
	go func() {
		_, _ = a.detach(context.Background(), true)
		close(done)
	}()

	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("umount --force never reached its fence: attach.detach takes the " +
			"mount-wide frontendSerial and nsMu locks before it looks at the force " +
			"flag, so the one operation that exists to abandon in-flight work " +
			"queues behind that work")
	}

	// Releasing the wedged writer lets the terminal transition complete.
	unwedge()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forced detach did not complete after the namespace lock was released")
	}
}
