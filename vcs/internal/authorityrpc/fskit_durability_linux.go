//go:build linux

package authorityrpc

import (
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type fskitDurabilityStore interface {
	PinSyncHandle(xfsstore.Capability) (xfsstore.SyncTarget, error)
	PinSyncObject(xfsstore.Capability) (xfsstore.SyncTarget, error)
	SyncMutationFS() error
}

type fskitDurabilityTarget struct {
	handle bool
	raw    []byte
}

// The last transaction is operation-specific: CREATE/MKDIR finish with child
// chmod, whereas namespace-only operations finish in the parent transaction.
// Visibility targets deliberately do not define a durability plan.
func fskitDurabilityTargets(req *authoritypb.Request, reply *authoritypb.Response) []fskitDurabilityTarget {
	object := func(raw []byte) []fskitDurabilityTarget { return []fskitDurabilityTarget{{raw: raw}} }
	handle := func(raw []byte) []fskitDurabilityTarget { return []fskitDurabilityTarget{{handle: true, raw: raw}} }
	itemOrHandle := func(item, opened []byte) []fskitDurabilityTarget {
		if len(opened) != 0 {
			return handle(opened)
		}
		return object(item)
	}
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Write:
		return handle(body.Write.GetHandle())
	case *authoritypb.Request_FskitWrite:
		return handle(body.FskitWrite.GetHandle())
	case *authoritypb.Request_Open:
		return handle(reply.GetOpen().GetHandle())
	case *authoritypb.Request_SetAttr:
		return itemOrHandle(body.SetAttr.GetItem(), body.SetAttr.GetHandle())
	case *authoritypb.Request_RemoveXattr:
		return itemOrHandle(body.RemoveXattr.GetItem(), body.RemoveXattr.GetHandle())
	case *authoritypb.Request_Create:
		return handle(reply.GetCreate().GetHandle())
	case *authoritypb.Request_Mkdir:
		return object(reply.GetLookup().GetItem().GetToken())
	case *authoritypb.Request_Symlink:
		return object(body.Symlink.GetParent())
	case *authoritypb.Request_Link:
		return object(body.Link.GetNewParent())
	case *authoritypb.Request_Unlink:
		return object(body.Unlink.GetParent())
	case *authoritypb.Request_Rename:
		return []fskitDurabilityTarget{{raw: body.Rename.GetNewParent()}, {raw: body.Rename.GetOldParent()}}
	default:
		return []fskitDurabilityTarget{{}}
	}
}

// This runs only after storage and visibility turns and withdrawal waits have
// ended, but before replay records the outcome. No request context may cancel
// storage's obligation once the operation may have applied.
func (h *VolumeHandler) syncFskitMutation(req *authoritypb.Request, reply *authoritypb.Response) error {
	store, ok := h.Store.(fskitDurabilityStore)
	if !ok {
		return &xfsstore.DurabilityError{Cause: syscall.EOPNOTSUPP}
	}
	targets := fskitDurabilityTargets(req, reply)
	seen := make(map[[16]byte]struct{}, len(targets))
	for _, target := range targets {
		var cap xfsstore.Capability
		copy(cap[:], target.raw)
		var pinned xfsstore.SyncTarget
		var err error
		var identity [16]byte
		if len(target.raw) != len(cap) || cap == (xfsstore.Capability{}) {
			err = syscall.ESTALE
		} else if target.handle {
			identity, err = h.Store.IdentityOpen(cap)
		} else {
			identity, err = h.Store.Identity(cap)
		}
		if err == nil {
			if _, exists := seen[identity]; exists {
				continue
			}
			seen[identity] = struct{}{}
			if target.handle {
				pinned, err = store.PinSyncHandle(cap)
			} else {
				pinned, err = store.PinSyncObject(cap)
			}
		}
		if err != nil {
			// Permission, descriptor exhaustion and concurrent retirement all
			// select the exact root barrier; they are not storage failures.
			started := time.Now()
			err = store.SyncMutationFS()
			h.Metrics.ObserveFskitDurability("syncfs", time.Since(started))
			if err != nil {
				return &xfsstore.DurabilityError{Cause: err}
			}
			return nil // syncfs covers every target in this operation.
		}
		kind := "object"
		if target.handle {
			kind = "handle"
		}
		started := time.Now()
		err = pinned.Sync()
		h.Metrics.ObserveFskitDurability(kind, time.Since(started))
		_ = pinned.Close()
		if err != nil {
			return &xfsstore.DurabilityError{Cause: err}
		}
	}
	return nil
}

func markFskitMutationPostApplyFailure(response *authoritypb.Response, cause error) bool {
	return markWritePostApplyFailure(response, cause) || markFskitWritePostApplyFailure(response, cause)
}
