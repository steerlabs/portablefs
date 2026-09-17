//go:build linux

package fusev3

import (
	"context"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestFullDelegationFlushIsLocalUnlessPOSIXOwnerNeedsDischarge(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode authoritypb.DelegationMode
		lock bool
		want int
	}{
		{"full-unlocked", authoritypb.DelegationMode_DELEGATION_MODE_FULL, false, 0},
		{"full-posix", authoritypb.DelegationMode_DELEGATION_MODE_FULL, true, 1},
		{"writethrough", authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mount, rpc := testMount(t, 8)
			n := testNode(mount)
			handle := &fileHandle{node: n, token: testToken(100)}
			if err := mount.delegations.Install(n.item.GetStableIdentity(), n.item.GetToken(), handle.token, delegationTestGrant(44, tc.mode)); err != nil {
				t.Fatal(err)
			}
			if tc.lock {
				ctx, finish := testMutationContext(t, mount)
				errno := n.Setlk(ctx, 41, &fuse.FileLock{Typ: syscall.F_WRLCK, End: 1}, 0)
				finish(errno == 0)
				if errno != 0 {
					t.Fatal(errno)
				}
			}
			for range 2 {
				if errno := n.Flush(context.Background(), handle, 41); errno != 0 {
					t.Fatal(errno)
				}
			}
			rpc.mu.Lock()
			defer rpc.mu.Unlock()
			if len(rpc.flushes) != tc.want {
				t.Fatalf("Authority FLUSH calls=%d, want %d", len(rpc.flushes), tc.want)
			}
			for _, flush := range rpc.flushes {
				if flush.LockOwner != 41 {
					t.Fatal(flush)
				}
			}
		})
	}
}

func TestPOSIXFlushReceiptCannotEraseLaterAcquisition(t *testing.T) {
	m := &Mount{}
	key := posixLockKey{identity: publicationIdentity{1}, owner: 41}
	m.notePOSIXLock(key)
	first := m.possiblePOSIXLock(key)
	m.notePOSIXLock(key)
	m.dischargePOSIXLock(key, first)
	second := m.possiblePOSIXLock(key)
	if second == 0 || second == first {
		t.Fatal("receipt erased concurrent acquisition")
	}
	m.dischargePOSIXLock(key, second)
	m.notePOSIXLock(key)
	m.dischargePOSIXLock(key, first)
	if m.possiblePOSIXLock(key) == 0 {
		t.Fatal("generation reuse erased reacquisition")
	}
}
