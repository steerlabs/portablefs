//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// Initial pairs open DATA then CONTROL, and mounts attach sequentially. Reject
// replacement sockets while preserving every other established transport.
type controlFaultListener struct {
	net.Listener
	mu          sync.Mutex
	connections []net.Conn
	blocked     bool
}

func (l *controlFaultListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		blocked := l.blocked
		if !blocked {
			l.connections = append(l.connections, conn)
		}
		l.mu.Unlock()
		if blocked {
			conn.Close()
			continue
		}
		return conn, nil
	}
}
func (l *controlFaultListener) partition(t *testing.T, mount int) {
	t.Helper()
	l.mu.Lock()
	if len(l.connections) != 4 {
		l.mu.Unlock()
		t.Fatal("fixture did not establish exactly two transport pairs")
	}
	l.blocked = true
	conn := l.connections[2*mount+1]
	l.mu.Unlock()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}
func (l *controlFaultListener) heal() { l.mu.Lock(); l.blocked = false; l.mu.Unlock() }

type recordingKernelNotifier struct {
	kernelNotifier
	mu      sync.Mutex
	entries map[nameKey]bool
	inodes  map[uint64]bool
}

func (n *recordingKernelNotifier) EntryNotify(parent uint64, name string) fuse.Status {
	status := n.kernelNotifier.EntryNotify(parent, name)
	if status.Ok() || status == fuse.ENOENT {
		n.mu.Lock()
		n.entries[nameKey{parent: parent, name: name}] = true
		n.mu.Unlock()
	}
	return status
}
func (n *recordingKernelNotifier) InodeNotify(inode uint64, off, length int64) fuse.Status {
	status := n.kernelNotifier.InodeNotify(inode, off, length)
	if status.Ok() || status == fuse.ENOENT {
		n.mu.Lock()
		n.inodes[inode] = true
		n.mu.Unlock()
	}
	return status
}

func TestControlTransportLossWithdrawsEveryCacheAtHorizon(t *testing.T) {
	var listener *controlFaultListener
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, wrapListener: func(l net.Listener) net.Listener {
		listener = &controlFaultListener{Listener: l}
		return listener
	}})
	defer listener.heal()
	enableBaselineOpenTracking(f.counter)
	old, fresh := []byte("before control loss"), []byte("after control loss!")
	mustWrite(t, f.join(0, "payload"), old, 0600)
	drainBaselineOpens(t, f.counter)
	f.waitForDelegationReleases(t)
	retained := mustOpenFile(t, f.join(1, "payload"), os.O_RDONLY, 0)
	defer retained.Close()
	if got := readExactlyAt(t, retained, 0, len(old), "warm reader"); !bytes.Equal(got, old) {
		t.Fatal("initial data")
	}
	if _, err := os.Stat(f.join(1, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	mount := f.mounts[1]
	raw := mount.raw
	notify := &recordingKernelNotifier{kernelNotifier: mount.notifier(), entries: make(map[nameKey]bool), inodes: make(map[uint64]bool)}
	mount.setNotifier(notify)
	raw.mu.Lock()
	names := make(map[nameKey]bool)
	for key := range raw.cachedNames {
		if parent := raw.directoryLocked(key.parent); parent != nil {
			names[nameKey{parent: parent.id, name: key.name}] = true
		}
	}
	for key := range raw.cachedNegatives {
		if parent := raw.directoryLocked(key.parent); parent != nil {
			names[nameKey{parent: parent.id, name: key.name}] = true
		}
	}
	inodes := make(map[uint64]bool)
	for _, record := range raw.cachedAttrs {
		inodes[record.id] = true
	}
	for _, record := range raw.cachedData {
		inodes[record.id] = true
	}
	raw.mu.Unlock()
	if len(names) < 2 || len(inodes) == 0 {
		t.Fatalf("insufficient cache coverage: names=%d inodes=%d", len(names), len(inodes))
	}
	incarnation := mount.subscription.stamp().incarnation
	listener.partition(t, 1)
	// This peer still has both transports. Its write must wait out the reader's
	// permission while the reader process and its DATA socket remain alive.
	written := make(chan error, 1)
	go func() { written <- os.WriteFile(f.join(0, "payload"), fresh, 0600) }()
	waitUntil(t, 15*time.Second, "CONTROL-only horizon withdrawal", func() bool {
		return mount.subscription.stamp() == (subscriptionStamp{}) && mount.delegations.incarnation() == 0
	})
	notify.mu.Lock()
	for key := range names {
		if !notify.entries[key] {
			t.Errorf("no EntryNotify for cached name %+v", key)
		}
	}
	for inode := range inodes {
		if !notify.inodes[inode] {
			t.Errorf("no InodeNotify for cached inode %d", inode)
		}
	}
	notify.mu.Unlock()
	raw.mu.Lock()
	if len(raw.cachedNames)+len(raw.cachedNegatives)+len(raw.cachedAttrs)+len(raw.cachedAttrPayloads) != 0 {
		t.Error("daemon cache survived horizon")
	}
	raw.mu.Unlock()
	buf := make([]byte, len(old))
	if _, err := retained.ReadAt(buf, 0); !errors.Is(err, syscall.EIO) {
		t.Fatalf("post-horizon read = %q, %v", buf, err)
	}
	if bytes.Equal(buf, old) {
		t.Fatal("post-horizon read served stale kernel pages")
	}
	// An ordinary request on the still-connected DATA socket is fenced by the
	// Authority too; successful keepalive would conceal a missing server fence.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waitUntil(t, 3*time.Second, "authority horizon", func() bool {
		response, err := f.clients[1].Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: f.clients[1].Root().GetToken()}}})
		if err != nil {
			t.Logf("fenced DATA call: %v", err)
		}
		return err == nil && response.GetErrno() == int32(syscall.EIO)
	})
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("peer write did not pass reader horizon")
	}
	if mount.isRevoked() || f.clients[1].SessionEndCause() != nil {
		t.Fatal("CONTROL loss ended mount or session")
	}
	listener.heal()
	waitUntil(t, 15*time.Second, "cold resubscribe", func() bool { return mount.subscription.stamp().incarnation > incarnation })
	if got := readExactlyAt(t, retained, 0, len(fresh), "read after cold resubscribe"); !bytes.Equal(got, fresh) {
		t.Fatalf("stale after resubscribe: %q", got)
	}
}
