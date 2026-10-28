//go:build linux

package fusev3

import (
	"sync/atomic"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/mountlog"
)

// The maintained go-fuse statistics hook covers requests without a physical
// reply (FORGET) and fixed refusals as well as cache publications. Unknown
// operation names remain bounded in bucket zero. Notification indexes are the
// pinned library's diagnostic indexes, not additional kernel protocol opcodes.
type metadataFUSECounter struct {
	upstream                                               fuse.LatencyMap
	operations                                             [mountlog.FUSEOperationSlots]atomic.Uint64
	notifications, notificationNanos, notificationFailures atomic.Uint64
}

var metadataFUSEOpcodes = map[string]int{
	"LOOKUP":             1,
	"FORGET":             2,
	"BATCH_FORGET":       42,
	"GETATTR":            3,
	"SETATTR":            4,
	"READLINK":           5,
	"SYMLINK":            6,
	"MKNOD":              8,
	"MKDIR":              9,
	"UNLINK":             10,
	"RMDIR":              11,
	"RENAME":             12,
	"LINK":               13,
	"OPEN":               14,
	"READ":               15,
	"WRITE":              16,
	"STATFS":             17,
	"RELEASE":            18,
	"FSYNC":              20,
	"SETXATTR":           21,
	"GETXATTR":           22,
	"LISTXATTR":          23,
	"REMOVEXATTR":        24,
	"FLUSH":              25,
	"INIT":               26,
	"OPENDIR":            27,
	"READDIR":            28,
	"RELEASEDIR":         29,
	"FSYNCDIR":           30,
	"GETLK":              31,
	"SETLK":              32,
	"SETLKW":             33,
	"ACCESS":             34,
	"CREATE":             35,
	"INTERRUPT":          36,
	"BMAP":               37,
	"DESTROY":            38,
	"IOCTL":              39,
	"POLL":               40,
	"NOTIFY_REPLY":       41,
	"NOTIFY_INVAL_ENTRY": 100,
	"NOTIFY_INVAL_INODE": 101,
	"NOTIFY_STORE":       102,
	"NOTIFY_RETRIEVE":    103,
	"NOTIFY_DELETE":      104,
	"FALLOCATE":          43,
	"READDIRPLUS":        44,
	"RENAME2":            45,
	"LSEEK":              46,
	"COPY_FILE_RANGE":    47,
	"SETUPMAPPING":       48,
	"REMOVEMAPPING":      49,
	"SYNCFS":             50,
	"TMPFILE":            51,
	"COPY_FILE_RANGE_64": 53,
}

func (c *metadataFUSECounter) Add(name string, dt time.Duration) {
	c.operations[metadataFUSEOpcodes[name]].Add(1)
	if c.upstream != nil {
		c.upstream.Add(name, dt)
	}
}

func (c *metadataFUSECounter) snapshot() []uint64 {
	values := make([]uint64, len(c.operations))
	for i := range values {
		values[i] = c.operations[i].Load()
	}
	return values
}

// Reverse notifications use a separate synchronous path in go-fuse, outside
// RecordLatencies. Count their completed transport attempts without changing
// the result or the caller's withdrawal/acknowledgement order.
func (m *Mount) inodeNotify(notifier kernelNotifier, inode uint64, offset, length int64) fuse.Status {
	started := time.Now()
	status := notifier.InodeNotify(inode, offset, length)
	m.recordNotification(status, started)
	return status
}

func (m *Mount) entryNotify(notifier kernelNotifier, parent uint64, name string) fuse.Status {
	started := time.Now()
	status := notifier.EntryNotify(parent, name)
	m.recordNotification(status, started)
	return status
}

func (m *Mount) recordNotification(status fuse.Status, started time.Time) {
	m.metadataFUSE.notifications.Add(1)
	m.metadataFUSE.notificationNanos.Add(uint64(time.Since(started)))
	if !status.Ok() && status != fuse.ENOENT {
		m.metadataFUSE.notificationFailures.Add(1)
	}
}
