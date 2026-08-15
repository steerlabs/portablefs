// Copyright 2016 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Random odds and ends.

package fuse

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"time"
)

func (code Status) String() string {
	if code <= 0 {
		switch code {
		case OK:
			return "OK"
		case -1:
			return "NOTIFY_POLL"
		case NOTIFY_INVAL_INODE:
			return "NOTIFY_INVAL_INODE"
		case NOTIFY_INVAL_ENTRY:
			return "NOTIFY_INVAL_ENTRY"
		case NOTIFY_STORE_CACHE:
			return "NOTIFY_STORE_CACHE"
		case NOTIFY_RETRIEVE_CACHE:
			return "NOTIFY_RETRIEVE_CACHE"
		case NOTIFY_DELETE:
			return "NOTIFY_DELETE"
		case NOTIFY_RESEND:
			return "NOTIFY_RESEND"
		case NOTIFY_PRUNE:
			return "NOTIFY_PRUNE"
		case NOTIFY_PFS_SIZE:
			return "NOTIFY_PFS_SIZE"
		}
		return fmt.Sprintf("NOTIFY_%d", -int(code))
	}
	return fmt.Sprintf("%d=%v", int(code), syscall.Errno(code))
}

func (code Status) Ok() bool {
	return code == OK
}

// ToStatus extracts an errno number from Go error objects.  If it
// fails, it logs an error and returns ENOSYS.
func ToStatus(err error) Status {
	switch err {
	case nil:
		return OK
	case os.ErrPermission:
		return EPERM
	case os.ErrExist:
		return Status(syscall.EEXIST)
	case os.ErrNotExist:
		return ENOENT
	case os.ErrInvalid:
		return EINVAL
	}

	switch t := err.(type) {
	case syscall.Errno:
		return Status(t)
	case *os.SyscallError:
		return Status(t.Err.(syscall.Errno))
	case *os.PathError:
		return ToStatus(t.Err)
	case *os.LinkError:
		return ToStatus(t.Err)
	}
	log.Println("can't convert error type:", err)
	return ENOSYS
}

func CurrentOwner() *Owner {
	return &Owner{
		Uid: uint32(os.Getuid()),
		Gid: uint32(os.Getgid()),
	}
}

// UtimeToTimespec converts a "Time" pointer as passed to Utimens to a
// "Timespec" that can be passed to the utimensat syscall.
// A nil pointer is converted to the special UTIME_OMIT value.
//
// Deprecated: use unix.TimeToTimespec from the x/sys/unix package instead.
func UtimeToTimespec(t *time.Time) (ts syscall.Timespec) {
	if t == nil {
		ts.Nsec = _UTIME_OMIT
	} else {
		ts = syscall.NsecToTimespec(t.UnixNano())
		// Go bug https://github.com/golang/go/issues/12777
		if ts.Nsec < 0 {
			ts.Nsec = 0
		}
	}
	return ts
}
