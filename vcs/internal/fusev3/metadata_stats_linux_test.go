//go:build linux

package fusev3

import (
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestMetadataObserverPreservesNotificationFailures(t *testing.T) {
	mount := &Mount{}
	notifier := &fakeNotifier{inodeST: fuse.EIO, entryST: fuse.ENOENT}
	if status := mount.inodeNotify(notifier, 7, -1, 0); status != fuse.EIO {
		t.Fatalf("inode notification status changed: %v", status)
	}
	if status := mount.entryNotify(notifier, 9, "child"); status != fuse.ENOENT {
		t.Fatalf("entry notification status changed: %v", status)
	}
	if mount.metadataFUSE.notifications.Load() != 2 || mount.metadataFUSE.notificationFailures.Load() != 1 {
		t.Fatalf("notification observations: attempts=%d failures=%d", mount.metadataFUSE.notifications.Load(), mount.metadataFUSE.notificationFailures.Load())
	}
	calls := notifier.snapshot()
	if len(calls) != 2 || calls[0].inode != 7 || calls[0].off != -1 || calls[1].parent != 9 || calls[1].name != "child" {
		t.Fatalf("notification arguments changed: %+v", calls)
	}
	// Fixed refusals and no-reply requests must share the same finite inventory.
	mount.metadataFUSE.Add("FORGET", time.Microsecond)
	mount.metadataFUSE.Add("future-operation", time.Microsecond)
	counts := mount.metadataFUSE.snapshot()
	if counts[2] != 1 || counts[0] != 1 {
		t.Fatalf("no-reply/unknown operation counters: %v", counts)
	}
}
