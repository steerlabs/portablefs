//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// An applied mutation and its subsequent peer visibility wait have different
// outcomes. Keep the definite response through local result validation and
// source-publication completion even when the later wait fails. Otherwise a
// routine cold subscription reset becomes an uncompleted source mutation and
// incorrectly ends the mount. This never retries or replays that mutation.
type appliedVisibilityError struct{ cause error }

func (e *appliedVisibilityError) Error() string {
	return fmt.Sprintf("applied mutation visibility: %v", e.cause)
}
func (e *appliedVisibilityError) Unwrap() error { return e.cause }

func (m *Mount) appliedVisibilityStatus(e *appliedVisibilityError) fuse.Status {
	if e == nil {
		return fuse.OK
	}
	var cleanup delegationCleanupError
	recoverable := errors.As(e.cause, &cleanup) && cleanup.failure == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE ||
		authorityrpc.TransientTransport(e.cause) || errors.Is(e.cause, context.Canceled) || errors.Is(e.cause, context.DeadlineExceeded) ||
		errors.Is(e.cause, errSubscriptionExpired) || errors.Is(e.cause, authorityrpc.ErrSubscriptionReset) || errors.Is(e.cause, authorityrpc.ErrDispatchExpired)
	if recoverable {
		// The known commit can be discharged, but its failed visibility
		// proof grants no further cache admission. The existing cold owner
		// withdraws retained pages before any successor subscription serves.
		m.subscription.deactivate()
	} else {
		m.revoke(e)
	}
	return fuse.Status(delegationErrno(e.cause))
}

// OPEN/CREATE have already validated their result and installed the returned
// grant before waiting for peer visibility. On failure, keep descriptor cleanup
// with its existing owner and settle the definite local commit without handing
// a new handle to the kernel. A failed wait cannot cancel this local discharge.
func (n *node) failedOpenedVisibility(ctx context.Context, item *authoritypb.Item, name *string, cause error) syscall.Errno {
	if lease := sourceLeaseFromContext(ctx); lease != nil {
		if name != nil {
			parent, parentOK := publicationIdentityFromItem(n.item)
			child, childOK := publicationIdentityFromItem(item)
			if !parentOK || !childOK {
				n.mount.revoke(errors.New("applied CREATE lost its validated identity"))
				return syscall.EIO
			}
			namespace := publicationNamespace{parent: parent, name: *name}
			if err := lease.attachBinding(n.mount.ctx, namespace, child); err != nil {
				n.mount.revoke(err)
				return syscall.EIO
			}
			raw := n.mount.raw
			raw.mu.Lock()
			key := nameKey{parent: n.item.GetAttr().GetInode(), name: *name}
			raw.dropCachedNameLocked(key)
			raw.supersedeNegativeNameLocked(key, publicationCoordinate{kind: publicationNamespaceName, parent: parent, name: *name})
			raw.mu.Unlock()
		}
		if err := completeSourcePublication(ctx); err != nil {
			n.mount.revoke(err)
			return syscall.EIO
		}
	}
	return syscall.Errno(n.mount.appliedVisibilityStatus(&appliedVisibilityError{cause: cause}))
}
