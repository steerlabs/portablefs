//go:build linux

package fusev3

import (
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// O1: ordinary (non-workspace) mounts across a real lease expiry. The authority
// is unreachable for longer than the lease, its sweeper removes both sessions,
// and it returns with the same epoch. Record what each mount observes and how
// fast, so head and main can be compared under the identical schedule.
func TestOpusR2OrdinaryLeaseExpiryOverOutage(t *testing.T) {
	const lease = 20 * time.Second
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: lease})
	mustWrite(t, f.join(0, "e"), []byte("v"), 0o644)
	clean := mustOpenFile(t, f.join(0, "e"), os.O_RDONLY, 0)
	dirty := mustOpenFile(t, f.join(0, "e"), os.O_RDWR, 0)
	if _, err := unix.Pwrite(int(dirty.Fd()), []byte("D"), 0); err != nil {
		t.Fatal(err)
	}
	f.stopAuthority()
	time.Sleep(lease + 6*time.Second) // real elapsed lease; no renewal can reach the authority
	removed := f.sweepSessions()
	f.resumeAuthority()
	begin := time.Now()
	t.Logf("authority back; swept %d sessions", removed)
	verdict := "none within 60s"
	select {
	case <-f.clients[0].SessionDone():
		verdict = time.Since(begin).Round(100 * time.Millisecond).String()
	case <-time.After(60 * time.Second):
	}
	t.Logf("mount0 session verdict after %s: SessionError=%v SessionEndCause=%v revoked=%v", verdict, f.clients[0].SessionError(), f.clients[0].SessionEndCause(), f.mounts[0].isRevoked())
	stat := func(path string) (time.Duration, error) {
		s := time.Now()
		_, err := os.Stat(path)
		return time.Since(s).Round(10 * time.Millisecond), err
	}
	d, err := stat(f.join(0, "e"))
	t.Logf("stat on mount0: %v after %v", err, d)
	s := time.Now()
	_, rerr := unix.Pread(int(clean.Fd()), make([]byte, 4), 0)
	t.Logf("held clean fd pread: %v after %v", rerr, time.Since(s).Round(10*time.Millisecond))
	s = time.Now()
	ferr := dirty.Sync()
	t.Logf("held dirty fd fsync: %v after %v", ferr, time.Since(s).Round(10*time.Millisecond))
	s = time.Now()
	cerr := dirty.Close()
	t.Logf("held dirty fd close: %v after %v", cerr, time.Since(s).Round(10*time.Millisecond))
	_ = clean.Close()
	time.Sleep(2 * time.Second)
	t.Logf("mount0 mounted=%v revoked=%v fatal=%v; mount1 mounted=%v revoked=%v sessionEnd=%v", isMounted(t, f.mountPath(0)), f.mounts[0].isRevoked(), f.mounts[0].fatalError(), isMounted(t, f.mountPath(1)), f.mounts[1].isRevoked(), f.clients[1].SessionEndCause())
	if !errors.Is(f.clients[0].SessionEndCause(), authorityrpc.ErrSessionEnded) || rerr == nil || ferr == nil {
		t.Error("expired ordinary mount did not enforce its terminal session", f.clients[0].SessionEndCause(), rerr, ferr)
	}
	if verdict == "none within 60s" {
		t.Errorf("ordinary mount never reached a session verdict after real lease expiry")
	}
}
