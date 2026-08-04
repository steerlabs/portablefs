// Package errnos is the single source of the Linux-numbered wire errno space
// shared by PortableFS protocols. Both the frozen v2 path and the current v3
// same-epoch replay path retain encoded outcomes, so a replay and its original
// reply must use one mapping.
package errnos

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
)

// Errno values carried in protocol responses; 0 is success. The wire space is
// Linux-numbered (ESTALE 116, ENOTEMPTY 39, EOPNOTSUPP 95, EDQUOT 122);
// non-Linux frontends translate to their local numbering at the boundary.
const (
	OK           int32 = 0
	EPERM        int32 = 1
	EINTR        int32 = 4
	ENOENT       int32 = 2
	E2BIG        int32 = 7
	EIO          int32 = 5
	EAGAIN       int32 = 11
	EBUSY        int32 = 16
	EEXIST       int32 = 17
	ENOTDIR      int32 = 20
	EISDIR       int32 = 21
	EINVAL       int32 = 22
	ENOSPC       int32 = 28
	EROFS        int32 = 30
	ERANGE       int32 = 34
	ENAMETOOLONG int32 = 36
	ENOTEMPTY    int32 = 39
	ENODATA      int32 = 61 // xattr not present (Linux ENODATA == ENOATTR)
	EOPNOTSUPP   int32 = 95
	ESTALE       int32 = 116
	EDQUOT       int32 = 122
)

// Of maps a Go filesystem error to a wire errno. It is the canonical mapping
// for live replies and any retained replay outcome.
func Of(err error) int32 {
	switch {
	case err == nil:
		return OK
	case errors.Is(err, os.ErrNotExist):
		return ENOENT
	case errors.Is(err, os.ErrExist):
		return EEXIST
	case errors.Is(err, os.ErrPermission):
		return EPERM
	case errors.Is(err, context.Canceled):
		return EINTR
	case errors.Is(err, syscall.ENAMETOOLONG):
		return ENAMETOOLONG
	case errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP):
		return EOPNOTSUPP
	case errors.Is(err, syscall.ENOSPC):
		return ENOSPC
	case errors.Is(err, syscall.EDQUOT):
		return EDQUOT
	case errors.Is(err, syscall.ENODATA):
		return ENODATA
	case errors.Is(err, syscall.E2BIG):
		return E2BIG
	case errors.Is(err, syscall.ERANGE):
		return ERANGE
	}
	switch msg := err.Error(); {
	case strings.Contains(msg, "not empty"):
		return ENOTEMPTY
	case strings.Contains(msg, "not a directory"):
		return ENOTDIR
	case strings.Contains(msg, "is a directory"):
		return EISDIR
	case strings.Contains(msg, "invalid argument"):
		return EINVAL
	default:
		return EIO
	}
}
