//go:build linux

package fusev3

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// rawWrite/rawRead never register with the Go netpoller, so the in-process
// server cannot self-deadlock on FUSE_POLL for the peer mount.
func opusRawWrite(path, data string) error {
	fd, err := unix.Open(path, unix.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, werr := unix.Pwrite(fd, []byte(data), 0)
	if werr == nil && n != len(data) {
		werr = io.ErrShortWrite
	}
	serr := unix.Fsync(fd)
	cerr := unix.Close(fd)
	return errors.Join(werr, serr, cerr)
}

// R3 coherence: after the authority retires the lapsed subscriber (grant
// dropped), a peer writes the same files. When readiness returns, the old
// holder's accepted-but-unapplied writes must never be applied over the
// peer's newer data. Authority content is sampled throughout the gap.
func opusR3LateApplyChild(t *testing.T) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	clock := &workspaceTestClockOwner{refused: make(chan struct{})}
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: clock, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v0", 0644)
	c.write(f.join(0, "g"), "g0", 0644)
	c.recover(c.suspend())
	authority := func(name string) string {
		data, err := os.ReadFile(filepath.Join(f.volumeRoot, name))
		if err != nil {
			return "ERR:" + err.Error()
		}
		return string(data)
	}
	held, err := os.OpenFile(f.join(0, "e"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Write([]byte("w1")); err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenFile(f.join(0, "g"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Pwrite(int(other.Fd()), []byte("g1"), 0); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("LA pre-gap authority e=%q g=%q\n", authority("e"), authority("g"))
	clock.unavailable.Store(true)
	begin := time.Now()
	fmt.Printf("LA gap-start authority e=%q g=%q\n", authority("e"), authority("g"))
	closed, synced := make(chan error, 1), make(chan error, 1)
	go func() { closed <- held.Close() }()
	go func() { synced <- other.Sync() }()
	sample := func(label string) {
		fmt.Printf("LA +%v %s authority e=%q g=%q loss=%d\n", time.Since(begin).Round(100*time.Millisecond), label, authority("e"), authority("g"), c.m.delegations.LossSequence())
	}
	time.Sleep(time.Second)
	sample("early")
	time.Sleep(14 * time.Second)
	sample("after TTL")
	peerStart := time.Now()
	perrE := opusRawWrite(f.join(1, "e"), "Q1")
	perrG := opusRawWrite(f.join(1, "g"), "P1")
	fmt.Printf("LA peer writes took %v: e=%v g=%v\n", time.Since(peerStart).Round(10*time.Millisecond), perrE, perrG)
	if err := errors.Join(perrE, perrG); err != nil {
		t.Fatal("peer write/fsync/close must succeed before readiness returns", err)
	}
	sample("after peer")
	for time.Since(begin) < 45*time.Second {
		time.Sleep(500 * time.Millisecond)
	}
	clock.unavailable.Store(false)
	cerr, serr := <-closed, <-synced
	fmt.Printf("LA readiness restored; close(e)=%v fsync(g)=%v\n", cerr, serr)
	time.Sleep(3 * time.Second)
	sample("after readiness")
	// A later lifecycle cycle must not resurrect the dropped writes either.
	_ = other.Close()
	c.recover(c.suspend())
	time.Sleep(time.Second)
	sample("after Suspend/Recover")
	e, g := authority("e"), authority("g")
	if e != "Q1" {
		c.fail("LATE APPLY: peer's newer e=Q1 overwritten; authority e=%q", e)
	}
	if g != "P1" {
		c.fail("LATE APPLY: peer's newer g=P1 overwritten; authority g=%q", g)
	}
	if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil {
		c.fail("terminal: revoked=%v session=%v", c.m.isRevoked(), c.m.rpc.SessionEndCause())
	}
	for _, b := range c.bad {
		t.Error(b)
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}

func TestOpusR3KernelLateApplyCoherence(t *testing.T) {
	opusKernelParent(t, opusR3LateApplyChild)
}
