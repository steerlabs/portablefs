//go:build linux

package authorityrpc

import (
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// .portablefs/ is a protected namespace: mounts may read it and may not change
// it. The declaration inside it decides which subtrees every machine can see,
// so a mount that could edit it could skew the volume's topology with an
// ordinary write - no barrier, no revision change, no other mount informed.
// ApplyRoutes exists precisely so that change goes through the barrier, and it
// is only reachable with admin scope.
//
// Protection is tracked by capability rather than by path, because a path is
// not what the protocol carries. A capability is an epoch-local bearer token
// resolved only for the session it was issued to, so marking it is exact: the
// only way to obtain one under .portablefs/ is to look it up under a parent
// that is already marked, and creating, linking or renaming into that subtree
// is refused before a capability could be minted. That closes the set at every
// depth without the authority having to reconstruct paths.
//
// Reading stays open on purpose. Every client has to read the declaration to
// learn the revision it must present at attach, so making the subtree
// unreadable would make the handshake unsatisfiable.

// protectedChild reports whether resolving this name under this parent enters
// the protected namespace.
func (h *VolumeHandler) protectedChild(id volumeserver.SessionID, parent xfsstore.Capability, name []byte) bool {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	return h.protectedChildLocked(id, parent, name)
}

func (h *VolumeHandler) protectedChildLocked(id volumeserver.SessionID, parent xfsstore.Capability, name []byte) bool {
	resources := h.resources[id]
	if resources == nil || resources.ended {
		return false
	}
	if resources.items[parent] {
		return true
	}
	return parent == resources.root && string(name) == localroutes.ProtectedPortableFS
}

// protectedCapability reports whether this session holds this item or handle as
// part of the protected namespace.
func (h *VolumeHandler) protectedCapability(id volumeserver.SessionID, capability xfsstore.Capability) bool {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		return false
	}
	return resources.items[capability] || resources.opens[capability]
}

// refuseProtectedNamespace is the single gate every mutating request passes
// through. It is written as one classification of the request, in the same
// shape as requestRequiresWrite, so a new mutating body cannot be added with
// its own private idea of what is protected: it either appears here or it is
// refused by the default arm.
//
// Errors resolving a capability are deliberately not reported here. This runs
// before the operation, and reporting a stale-capability error from a
// protection check would give the two failures the same voice; the operation's
// own resolution reports it a moment later with the right one.
func (h *VolumeHandler) refuseProtectedNamespace(id volumeserver.SessionID, req *authoritypb.Request) error {
	parent := func(raw []byte, name []byte) error {
		capability, err := h.item(id, raw)
		if err != nil {
			return nil
		}
		if h.protectedChild(id, capability, name) {
			return syscall.EPERM
		}
		return nil
	}
	object := func(raw []byte) error {
		capability, err := capability(raw)
		if err != nil {
			return nil
		}
		if h.protectedCapability(id, capability) {
			return syscall.EPERM
		}
		return nil
	}
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Create:
		return parent(body.Create.GetParent(), body.Create.GetName())
	case *authoritypb.Request_Mkdir:
		return parent(body.Mkdir.GetParent(), body.Mkdir.GetName())
	case *authoritypb.Request_Symlink:
		return parent(body.Symlink.GetParent(), body.Symlink.GetName())
	case *authoritypb.Request_Unlink:
		return parent(body.Unlink.GetParent(), body.Unlink.GetName())
	case *authoritypb.Request_Rename:
		// Both ends. Moving something out of the protected subtree is as much a
		// change to it as deleting it, and moving something in would put
		// unprotected state where nothing may be written.
		if err := parent(body.Rename.GetOldParent(), body.Rename.GetOldName()); err != nil {
			return err
		}
		return parent(body.Rename.GetNewParent(), body.Rename.GetNewName())
	case *authoritypb.Request_Link:
		// A hard link out of the protected subtree would leave the declaration
		// writable through a name outside it, which is the protection removed
		// rather than evaded.
		if err := object(body.Link.GetExistingItem()); err != nil {
			return err
		}
		return parent(body.Link.GetNewParent(), body.Link.GetNewName())
	case *authoritypb.Request_SetAttr:
		if err := object(body.SetAttr.GetItem()); err != nil {
			return err
		}
		return object(body.SetAttr.GetHandle())
	case *authoritypb.Request_SetXattr:
		return object(body.SetXattr.GetItem())
	case *authoritypb.Request_RemoveXattr:
		return object(body.RemoveXattr.GetItem())
	case *authoritypb.Request_WriteTransaction:
		// BEGIN resolves and pins the caller's handle. Later phases address the
		// already-authorized session transaction; ABORT must remain available
		// after an authorization downgrade.
		if body.WriteTransaction.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN {
			return object(body.WriteTransaction.GetHandle())
		}
		return nil
	case *authoritypb.Request_Fallocate:
		return object(body.Fallocate.GetHandle())
	case *authoritypb.Request_CopyFileRange:
		return object(body.CopyFileRange.GetOutputHandle())
	case *authoritypb.Request_Tmpfile:
		return object(body.Tmpfile.GetParent())
	case *authoritypb.Request_Open:
		flags := body.Open.GetFlags()
		if flags == nil || !(flags.GetWrite() || flags.GetAppend() || flags.GetTruncate()) {
			// A read-only open is how a mount learns the topology it must agree
			// with, so it stays available.
			return nil
		}
		return object(body.Open.GetItem())
	default:
		return nil
	}
}
