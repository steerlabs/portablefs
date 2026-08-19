//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"math"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"golang.org/x/sys/unix"
)

func (r *rawFileSystem) writeStock(input *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	if input == nil {
		return 0, fuse.EINVAL
	}
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return 0, fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if handleRecord.inode == nil || input.NodeId != handleRecord.inode.id || handleRecord.inode.key.kind != authoritypb.Attr_REGULAR || handle.node != handleRecord.inode.node {
		return 0, fuse.EBADF
	}
	inode := handleRecord.inode.key.inode
	placement := resolveAppendPlacement(input.Flags&uint32(syscall.O_APPEND) != 0, input.Offset)
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return 0, lifecycle
	}
	defer finish()
	gate, err := itemSourceGate(handle.node.item, true)
	if err != nil {
		return 0, fuse.EIO
	}
	response, errno := handle.node.mutateWithSource(ctx, &authoritypb.Request{
		Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
			Handle: cloneBytes(handle.token), Position: placement.position, LockOwner: input.LockOwner,
			Size: input.Size, WriteFlags: input.WriteFlags, Data: data,
			Append:   placement.append,
			Sync:     input.Flags&uint32(syscall.O_SYNC) == uint32(syscall.O_SYNC),
			DataSync: input.Flags&uint32(syscall.O_SYNC) != uint32(syscall.O_SYNC) && input.Flags&uint32(unix.O_DSYNC) != 0,
		}},
	}, gate)
	if errno != 0 {
		return 0, fuse.Status(errno)
	}
	if response == nil || response.GetUncertain() || response.GetWrite() == nil {
		r.mount.revoke(errors.New("fusev3: stock write returned no definite result"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	reply := response.GetWrite()
	if reply.GetCommittedSize() == 0 {
		if reply.GetError() >= -4095 && reply.GetError() < 0 {
			if err := completeDefiniteNoChangePublication(ctx); err != nil {
				r.mount.revoke(err)
				return 0, fuse.Status(syscall.ENOTCONN)
			}
			return 0, fuse.Status(-reply.GetError())
		}
		r.mount.revoke(errors.New("fusev3: stock write returned neither bytes nor an errno"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if reply.GetCommittedSize() > uint64(input.Size) || reply.GetError() != 0 {
		r.mount.revoke(errors.New("fusev3: stock write returned invalid result geometry"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	postAttr := reply.GetPostAttr()
	assigned := reply.GetAssignedOffset()
	if placement.append {
		// The authority owns an append's placement, so the only thing this mount
		// can check is that the reply is self-consistent: the bytes end exactly
		// at the object's new end.
		if assigned > math.MaxInt64 || reply.GetCommittedSize() > math.MaxInt64-assigned {
			r.mount.revoke(errors.New("fusev3: stock append returned an out-of-range assigned offset"))
			return 0, fuse.Status(syscall.ENOTCONN)
		}
	} else if assigned != placement.position {
		r.mount.revoke(errors.New("fusev3: stock write relocated a positioned request"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	end := assigned + reply.GetCommittedSize()
	if postAttr == nil || postAttr.GetKind() != authoritypb.Attr_REGULAR || postAttr.GetInode() != inode || postAttr.GetSize() < 0 || uint64(postAttr.GetSize()) < end {
		r.mount.revoke(errors.New("fusev3: stock write omitted exact post attributes"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if placement.append && uint64(postAttr.GetSize()) != end {
		r.mount.revoke(errors.New("fusev3: stock append did not land at the object's end"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if err := expectPostStateRecord(ctx, handleRecord.inode, postStateRoleTarget); err != nil {
		r.mount.revoke(err)
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(fmt.Errorf("fusev3: complete stock write publication: %w", err))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	return uint32(reply.GetCommittedSize()), fuse.OK
}
