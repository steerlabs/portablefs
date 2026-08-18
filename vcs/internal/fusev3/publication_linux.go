//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"math"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
)

var publicationProtocolError = fuse.Status(syscall.EPROTO)

// PFSPublish is the sole local post-VFS publication receipt. The kernel sends
// it only after completing all requester-side inode/dentry/file-position work
// for an original response carrying PFS_UNIQUE_PUBLISH. An early request is
// valid: fuse_request_end wakes the requester before the daemon's original
// write(2) returns, so this method waits without go-fuse's write mutex until
// ReplyWritten records that physical completion.
func (r *rawFileSystem) PFSPublish(_ <-chan struct{}, input *fuse.PFSPublishIn, out *fuse.PFSPublishOut) fuse.Status {
	if input == nil || out == nil || input.Unique == 0 || input.Unique&1 != 0 || input.RequestUnique == 0 ||
		input.Unique >= fuse.PFS_UNIQUE_PUBLISH || input.RequestUnique >= fuse.PFS_UNIQUE_PUBLISH ||
		input.PublicationID == 0 || input.PublicationID > math.MaxInt64 || input.PublicationID&1 == 0 ||
		input.RequestUnique&1 != 0 || input.PublicationID == input.RequestUnique ||
		input.Nodeid == 0 || input.Opcode == 0 || input.Flags != 0 {
		return publicationProtocolError
	}

	r.mu.Lock()
	if r.replyTerminal || r.replyTerminalizing {
		r.mu.Unlock()
		return fuse.Status(syscall.ENOTCONN)
	}
	publication := r.replyPublications[input.RequestUnique]
	if publication == nil || !publication.marked || publication.requestUnique != input.RequestUnique ||
		publication.nodeid != input.Nodeid || publication.opcode != input.Opcode ||
		publication.publishUnique != 0 || publication.publicationID != 0 ||
		r.replyPublications[input.Unique] != nil || r.publishAcks[input.Unique] != nil {
		r.mu.Unlock()
		r.mount.revoke(fmt.Errorf("fusev3: PFS_PUBLISH did not match retained request %d", input.RequestUnique))
		if publication != nil {
			publication.consumeAuthorityResponse()
		}
		return fuse.Status(syscall.ENOTCONN)
	}
	publication.publicationID = input.PublicationID
	publication.publishUnique = input.Unique
	// Claim the kernel request unique before waiting for the original write.
	// This closes the otherwise-small window in which a malformed second request
	// could reuse that unique while an early PFS_PUBLISH is parked here.
	r.publishAcks[input.Unique] = publication
	originalDone := publication.originalDone
	r.mu.Unlock()

	select {
	case <-originalDone:
	case <-r.mount.ctx.Done():
		r.mu.Lock()
		if r.replyTerminal || r.replyTerminalizing {
			r.mu.Unlock()
			return fuse.Status(syscall.ENOTCONN)
		}
		if r.publishAcks[input.Unique] == publication {
			delete(r.publishAcks, input.Unique)
		}
		r.mu.Unlock()
		r.mount.revoke(errors.New("fusev3: mount ended before the original publication response write completed"))
		publication.consumeAuthorityResponse()
		return fuse.Status(syscall.ENOTCONN)
	}

	r.mu.Lock()
	if r.replyTerminal || r.replyTerminalizing {
		r.mu.Unlock()
		return fuse.Status(syscall.ENOTCONN)
	}
	if r.replyPublications[input.RequestUnique] != publication || !publication.originalWrote ||
		!publication.originalStatus.Ok() || r.publishAcks[input.Unique] != publication {
		if r.publishAcks[input.Unique] == publication {
			delete(r.publishAcks, input.Unique)
		}
		r.mu.Unlock()
		r.mount.revoke(fmt.Errorf("fusev3: PFS_PUBLISH %d lost its physically written original response", input.PublicationID))
		publication.consumeAuthorityResponse()
		return fuse.Status(syscall.ENOTCONN)
	}
	r.mu.Unlock()

	*out = fuse.PFSPublishOut{
		RequestUnique: input.RequestUnique,
		PublicationID: input.PublicationID,
		Nodeid:        input.Nodeid,
		Opcode:        input.Opcode,
		Flags:         fuse.PFS_PUBLISH_ACK,
	}
	return fuse.OK
}
