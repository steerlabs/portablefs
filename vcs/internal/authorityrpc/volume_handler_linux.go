//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var errInternal = errors.New("authorityrpc: internal handler failure")

// readDirReplyOverhead bounds the fixed part of a directory reply: the 16-byte
// verifier, the EOF flag, and the protobuf tags wrapping the reply inside a
// Response. Entries are budgeted against the remainder.
const readDirReplyOverhead uint32 = 64

// Authorizer validates a short-lived control-plane capability. Implementations
// must bind it to the authenticated TLS peer and exact volume; the data-plane
// handler has no development-token or anonymous mode.
type Authorizer interface {
	Authorize(context.Context, string, []byte) (volumeserver.Authorization, error)
}

type VolumeHandler struct {
	Store       *xfsstore.Volume
	Runtime     *volumeserver.Authority
	Authorizer  Authorizer
	MaxFrame    uint32
	MaxRead     uint32
	MaxWrite    uint32
	MaxInFlight uint32
	// Descriptor-backed capabilities have independent per-session and
	// per-worker admission bounds. These limits exclude the one shared root
	// descriptor owned by xfsstore.
	MaxItemsPerSession uint32
	MaxOpensPerSession uint32
	MaxItems           uint32
	MaxOpens           uint32
	// MaxRetainedReplyBytes bounds the real quantity the replay cache consumes:
	// the total encoded bytes retained across every live session's replay
	// slots. Slot counts are not a proxy for it; one directory listing is five
	// orders of magnitude larger than one create.
	MaxRetainedReplyBytes uint64
	// OnStorageFailure is called once after an EIO fences the store. Production
	// uses it to terminate this epoch instead of remaining deceptively ready.
	OnStorageFailure func(error)

	cleanupOnce        sync.Once
	storageFailureOnce sync.Once
	resourcesMu        sync.Mutex
	resources          map[volumeserver.SessionID]*sessionResources
	totalItems         uint32
	totalOpens         uint32
	// retainedReplyBytes is the exact number of bytes currently held in replay
	// slots; reservedReplyBytes covers mutations that are executing and whose
	// reply size is not yet known.
	retainedReplyBytes uint64
	reservedReplyBytes uint64
}

type sessionResources struct {
	ended bool
	// root is the one shared volume-root capability. It is owned by xfsstore,
	// not by this session, so it is never forgotten during cleanup.
	root  xfsstore.Capability
	items map[xfsstore.Capability]struct{}
	opens map[xfsstore.Capability]struct{}
	// reply holds the retained reply size for each of this session's replay
	// slots. Its length is the slot count the runtime admitted.
	reply []uint32
}

// Epoch implements Handler. It is what the transport stamps on any response it
// has to synthesize itself.
func (h *VolumeHandler) Epoch() []byte {
	if h.Runtime == nil {
		return nil
	}
	epoch := h.Runtime.Epoch()
	return append([]byte(nil), epoch[:]...)
}

// Bounds implements Handler. These are exactly the values advertised in Hello,
// so the server refuses to run with a transport that enforces anything else.
func (h *VolumeHandler) Bounds() TransportBounds {
	request := uint64(h.MaxWrite) + uint64(FramePayloadReserve)
	if request > uint64(h.MaxFrame) {
		request = uint64(h.MaxFrame)
	}
	return TransportBounds{MaxFrame: h.MaxFrame, MaxRequestFrame: uint32(request), MaxInFlight: int(h.MaxInFlight)}
}

// maxReplyBytes is the largest operation reply this authority can both retain
// and put on the wire: whatever fits in a frame once the response envelope the
// transport adds back is accounted for.
func (h *VolumeHandler) maxReplyBytes() uint32 { return h.MaxFrame - responseEnvelopeReserve }

func (h *VolumeHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if h.Runtime != nil {
		h.cleanupOnce.Do(func() { h.Runtime.OnSessionEnd(h.closeSessionResources) })
	}
	if req == nil {
		return h.errorResponse(0, fs.ErrInvalid, false)
	}
	if hello := req.GetHello(); hello != nil {
		return h.hello(req.GetRequestId(), hello)
	}
	if attach := req.GetAttach(); attach != nil {
		return h.attach(ctx, req.GetRequestId(), attach)
	}
	if h.Store == nil || h.Runtime == nil || h.Authorizer == nil {
		return h.errorResponse(req.GetRequestId(), errInternal, false)
	}
	if req.GetCancel() != nil {
		return h.cancelAcknowledgment(ctx, req)
	}
	cred, err := h.credential(ctx, req)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	use, err := h.Runtime.Begin(cred)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	defer use.End()
	access := use.Access()
	if access&volumeserver.AccessRead == 0 {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}
	if requestRequiresWrite(req) && access&volumeserver.AccessWrite == 0 {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}

	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Resume, *authoritypb.Request_KeepAlive:
		if err := h.Runtime.Resume(cred); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_Detach:
		if err := h.Runtime.Detach(cred); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_Lookup:
		parent, err := h.item(cred.ID, body.Lookup.GetParent())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		item, attr, err := h.Store.Lookup(parent, string(body.Lookup.GetName()))
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.trackItem(cred.ID, item); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemProto(item, attr)}}
		return resp
	case *authoritypb.Request_GetAttr:
		attr, err := h.getattr(cred.ID, body.GetAttr)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: attrProto(attr)}}
		return resp
	case *authoritypb.Request_SetAttr:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			set := body.SetAttr
			if set.Mode == nil && set.Uid == nil && set.Gid == nil && set.Size == nil && set.AtimeNs == nil && set.MtimeNs == nil && !set.GetAtimeNow() && !set.GetMtimeNow() {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			var item, handle xfsstore.Capability
			changed := false
			var err error
			if len(set.GetItem()) != 0 {
				item, err = h.item(cred.ID, set.GetItem())
				if err != nil {
					return h.errorResponse(0, err, false)
				}
			}
			if len(set.GetHandle()) != 0 {
				handle, err = h.open(cred.ID, set.GetHandle())
				if err != nil {
					return h.errorResponse(0, err, false)
				}
			}
			if item == (xfsstore.Capability{}) && handle == (xfsstore.Capability{}) {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			var mode fs.FileMode
			if set.Mode != nil {
				var valid bool
				mode, valid = modeFromProtocol(set.GetMode())
				if !valid || item == (xfsstore.Capability{}) {
					return h.errorResponse(0, syscall.EINVAL, false)
				}
			}
			if (set.Uid != nil || set.Gid != nil) && (item == (xfsstore.Capability{}) ||
				(set.Uid != nil && set.GetUid() == ^uint32(0)) || (set.Gid != nil && set.GetGid() == ^uint32(0))) {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			if set.Size != nil && set.GetSize() < 0 {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			if set.AtimeNs != nil && set.GetAtimeNow() || set.MtimeNs != nil && set.GetMtimeNow() {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			if (set.AtimeNs != nil || set.MtimeNs != nil || set.GetAtimeNow() || set.GetMtimeNow()) && item == (xfsstore.Capability{}) {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			if set.Mode != nil {
				err = h.Store.Chmod(item, mode)
				if err != nil {
					return h.errorResponse(0, err, changed)
				}
				changed = true
			}
			if set.Uid != nil || set.Gid != nil {
				uid, gid := -1, -1
				if set.Uid != nil {
					uid = int(set.GetUid())
				}
				if set.Gid != nil {
					gid = int(set.GetGid())
				}
				err = h.Store.Chown(item, uid, gid)
				if err != nil {
					return h.errorResponse(0, err, changed)
				}
				changed = true
			}
			if set.Size != nil {
				if handle != (xfsstore.Capability{}) {
					err = h.Store.Truncate(handle, set.GetSize())
				} else {
					err = h.Store.TruncateObject(item, set.GetSize())
				}
				if err != nil {
					return h.errorResponse(0, err, changed)
				}
				changed = true
			}
			if set.AtimeNs != nil || set.MtimeNs != nil || set.GetAtimeNow() || set.GetMtimeNow() {
				err = h.Store.SetTimes(item, set.AtimeNs, set.MtimeNs, set.GetAtimeNow(), set.GetMtimeNow())
				if err != nil {
					return h.errorResponse(0, err, changed)
				}
				changed = true
			}
			var attr xfsstore.Attr
			if handle != (xfsstore.Capability{}) {
				attr, err = h.Store.GetattrOpen(handle)
			} else {
				attr, err = h.Store.Getattr(item)
			}
			if err != nil {
				return h.errorResponse(0, err, true)
			}
			resp := h.success(0)
			resp.PostAttr = attrProto(attr)
			return resp
		})
	case *authoritypb.Request_Create:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			parent, err := h.item(cred.ID, body.Create.GetParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			mode, valid := modeFromProtocol(body.Create.GetMode())
			if !valid {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			item, attr, err := h.Store.Create(parent, string(body.Create.GetName()), mode, body.Create.GetExclusive())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			handle, err := h.Store.OpenFile(item, openFlags(body.Create.GetFlags()))
			if err != nil {
				h.forgetItem(item)
				return h.errorResponse(0, err, true)
			}
			if err := h.trackItemAndOpen(cred.ID, item, handle); err != nil {
				return h.errorResponse(0, err, true)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: itemProto(item, attr), Handle: handle[:]}}
			return resp
		})
	case *authoritypb.Request_Mkdir:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			parent, err := h.item(cred.ID, body.Mkdir.GetParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			mode, valid := modeFromProtocol(body.Mkdir.GetMode())
			if !valid {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			item, attr, err := h.Store.Mkdir(parent, string(body.Mkdir.GetName()), mode)
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := h.trackItem(cred.ID, item); err != nil {
				return h.errorResponse(0, err, true)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemProto(item, attr)}}
			return resp
		})
	case *authoritypb.Request_Unlink:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			parent, err := h.item(cred.ID, body.Unlink.GetParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := h.Store.Unlink(parent, string(body.Unlink.GetName()), body.Unlink.GetDirectory()); err != nil {
				return h.errorResponse(0, err, false)
			}
			return h.success(0)
		})
	case *authoritypb.Request_Rename:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			oldParent, err := h.item(cred.ID, body.Rename.GetOldParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			newParent, err := h.item(cred.ID, body.Rename.GetNewParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			var flags xfsstore.RenameFlags
			if body.Rename.GetNoReplace() {
				flags |= xfsstore.RenameNoReplace
			}
			if body.Rename.GetExchange() {
				flags |= xfsstore.RenameExchange
			}
			if err := h.Store.Rename(oldParent, string(body.Rename.GetOldName()), newParent, string(body.Rename.GetNewName()), flags); err != nil {
				return h.errorResponse(0, err, false)
			}
			return h.success(0)
		})
	case *authoritypb.Request_Link:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			source, err := h.item(cred.ID, body.Link.GetExistingItem())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			parent, err := h.item(cred.ID, body.Link.GetNewParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			attr, err := h.Store.Link(source, parent, string(body.Link.GetNewName()))
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: itemProto(source, attr)}}
			return resp
		})
	case *authoritypb.Request_Symlink:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			parent, err := h.item(cred.ID, body.Symlink.GetParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			item, attr, err := h.Store.Symlink(parent, string(body.Symlink.GetName()), string(body.Symlink.GetTarget()))
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := h.trackItem(cred.ID, item); err != nil {
				return h.errorResponse(0, err, true)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemProto(item, attr)}}
			return resp
		})
	case *authoritypb.Request_Readlink:
		item, err := h.item(cred.ID, body.Readlink.GetItem())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		target, err := h.Store.Readlink(item)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_Readlink{Readlink: &authoritypb.ReadlinkReply{Target: []byte(target)}}
		return resp
	case *authoritypb.Request_Open:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			item, err := h.item(cred.ID, body.Open.GetItem())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			handle, err := h.Store.OpenFile(item, openFlags(body.Open.GetFlags()))
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := h.trackOpen(cred.ID, handle); err != nil {
				uncertain := body.Open.GetFlags() != nil && body.Open.GetFlags().GetTruncate()
				return h.errorResponse(0, err, uncertain)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: handle[:]}}
			return resp
		})
	case *authoritypb.Request_Close:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			handle, err := h.open(cred.ID, body.Close.GetHandle())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if body.Close.GetFlockUnlock() {
				if err := h.unlockOpenOwner(cred, handle, body.Close.GetLockOwner(), true); err != nil {
					return h.errorResponse(0, err, false)
				}
			}
			if err := h.Store.CloseOpen(handle); err != nil {
				return h.errorResponse(0, err, false)
			}
			h.untrackOpen(cred.ID, handle)
			return h.success(0)
		})
	case *authoritypb.Request_Flush:
		handle, err := h.open(cred.ID, body.Flush.GetHandle())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.unlockOpenOwner(cred, handle, body.Flush.GetLockOwner(), false); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_Read:
		if body.Read.GetLength() > h.MaxRead {
			return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
		}
		handle, err := h.open(cred.ID, body.Read.GetHandle())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		buf := make([]byte, body.Read.GetLength())
		n, err := h.Store.ReadAt(handle, buf, int64(body.Read.GetOffset()))
		if err != nil && !errors.Is(err, io.EOF) {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: buf[:n]}}
		return resp
	case *authoritypb.Request_Write:
		if uint32(len(body.Write.GetData())) > h.MaxWrite {
			return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
		}
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			handle, err := h.open(cred.ID, body.Write.GetHandle())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			var n int
			var assigned int64
			if body.Write.GetAppend() {
				if body.Write.GetOffset() != 0 {
					return h.errorResponse(0, syscall.EINVAL, false)
				}
				n, assigned, err = h.Store.Append(handle, body.Write.GetData())
			} else {
				n, err = h.Store.WriteAt(handle, body.Write.GetData(), int64(body.Write.GetOffset()))
			}
			return h.writeOutcome(n, assigned, err)
		})
	case *authoritypb.Request_Fsync:
		handle, err := h.open(cred.ID, body.Fsync.GetHandle())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.Store.Fsync(handle, body.Fsync.GetDataOnly()); err != nil {
			return h.errorResponse(req.GetRequestId(), err, true)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_ReadDir:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			if body.ReadDir.GetMaxEntries() == 0 || body.ReadDir.GetMaxEntries() > 4096 {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			handle, err := h.open(cred.ID, body.ReadDir.GetHandle())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			cookie, err := decodeCookie(body.ReadDir.GetCookie())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			var verifier [16]byte
			if len(body.ReadDir.GetVerifier()) != 0 {
				if len(body.ReadDir.GetVerifier()) != len(verifier) {
					return h.errorResponse(0, syscall.EINVAL, false)
				}
				copy(verifier[:], body.ReadDir.GetVerifier())
			}
			entries, _, current, eof, _, err := h.Store.ReadDirOpen(handle, cookie, verifier, int(body.ReadDir.GetMaxEntries()))
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			result := &authoritypb.ReadDirReply{Verifier: current[:], Eof: eof}
			// The reply is built to the same byte budget that was reserved for
			// it, so a directory listing can never be the reply that does not
			// fit in a frame. Stopping early is an ordinary short readdir: the
			// caller resumes from the last entry's cookie.
			budget := h.readDirEntryBudget(body.ReadDir.GetMaxEntries())
			used := uint64(0)
			for i, entry := range entries {
				attr, err := h.Store.StatOpenDirChild(handle, entry.Name)
				if err != nil {
					return h.errorResponse(0, syscall.ESTALE, false)
				}
				dirent := &authoritypb.Dirent{Name: []byte(entry.Name), Attr: attrProto(attr), NextCookie: encodeCookie(cookie + uint64(i) + 1)}
				cost := direntCost(dirent)
				if used+cost > uint64(budget) {
					result.Eof = false
					break
				}
				used += cost
				result.Entries = append(result.Entries, dirent)
			}
			if len(entries) != 0 && len(result.Entries) == 0 {
				// A single entry larger than the whole budget would make this
				// directory unreadable at any cookie. Say so instead of
				// returning an empty page forever.
				return h.errorResponse(0, syscall.EOVERFLOW, false)
			}
			parentAttr, err := h.Store.GetattrOpen(handle)
			if err != nil || !verifierMatches(current, parentAttr) {
				return h.errorResponse(0, syscall.ESTALE, false)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_ReadDir{ReadDir: result}
			return resp
		})
	case *authoritypb.Request_Reclaim:
		item, err := h.item(cred.ID, body.Reclaim.GetItem())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.Store.Forget(item); err != nil && !errors.Is(err, xfsstore.ErrStaleObject) {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		h.untrackItem(cred.ID, item)
		return h.success(req.GetRequestId())
	case *authoritypb.Request_GetXattr:
		item, err := h.item(cred.ID, body.GetXattr.GetItem())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		value, err := h.Store.GetXattr(item, string(body.GetXattr.GetName()))
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_GetXattr{GetXattr: &authoritypb.GetXattrReply{Value: value}}
		return resp
	case *authoritypb.Request_SetXattr:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			item, err := h.item(cred.ID, body.SetXattr.GetItem())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			mode, valid := xattrMode(body.SetXattr.GetMode())
			if !valid {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			if err := h.Store.SetXattr(item, string(body.SetXattr.GetName()), body.SetXattr.GetValue(), mode); err != nil {
				return h.errorResponse(0, err, false)
			}
			return h.success(0)
		})
	case *authoritypb.Request_RemoveXattr:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			item, err := h.item(cred.ID, body.RemoveXattr.GetItem())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := h.Store.RemoveXattr(item, string(body.RemoveXattr.GetName())); err != nil {
				return h.errorResponse(0, err, false)
			}
			return h.success(0)
		})
	case *authoritypb.Request_ListXattr:
		item, err := h.item(cred.ID, body.ListXattr.GetItem())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		names, err := h.Store.ListXattr(item)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		encoded := make([][]byte, len(names))
		for i := range names {
			encoded[i] = []byte(names[i])
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_ListXattr{ListXattr: &authoritypb.ListXattrReply{Names: encoded}}
		return resp
	case *authoritypb.Request_StatFs:
		stat, err := h.Store.StatFS()
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{BlockSize: stat.BlockSize, Blocks: stat.Blocks, BlocksFree: stat.BlocksFree, BlocksAvailable: stat.BlocksAvailable, Files: stat.Files, FilesFree: stat.FilesFree, NameMax: stat.NameMax}}
		return resp
	case *authoritypb.Request_GetLock:
		return h.getLock(req.GetRequestId(), cred, body.GetLock)
	case *authoritypb.Request_SetLock:
		return h.setLock(ctx, req, cred, body.SetLock)
	default:
		return h.errorResponse(req.GetRequestId(), syscall.EOPNOTSUPP, false)
	}
}

// cancelAcknowledgment answers a cancellation without pinning or renewing the
// session. The transport has already delivered the cancellation to the target
// operation on this authenticated connection; the reply is only an
// acknowledgment, and running it through the ordinary lease-renewing path would
// let a peer hold a session open indefinitely using cancels alone.
func (h *VolumeHandler) cancelAcknowledgment(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if _, ok := PeerIdentity(ctx); !ok {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}
	var epoch volumeserver.Epoch
	if len(req.GetEpoch()) != len(epoch) {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	copy(epoch[:], req.GetEpoch())
	if epoch != h.Runtime.Epoch() {
		return h.errorResponse(req.GetRequestId(), volumeserver.ErrEpochMismatch, false)
	}
	return h.success(req.GetRequestId())
}

// writeOutcome turns one store write into exactly one reported outcome. A
// write that made partial progress reports the short count and nothing else:
// n bytes are already durable in XFS, so reporting a count together with an
// errno would let the application conclude that nothing was written while the
// file has already grown. The next write on the same range re-encounters the
// condition and reports it with a zero count, which is what Linux does.
func (h *VolumeHandler) writeOutcome(n int, assigned int64, err error) *authoritypb.Response {
	if n == 0 {
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		// A zero-length write is a legal no-op, not a failure.
		resp := h.success(0)
		resp.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{}}
		return resp
	}
	h.recordStorageFailure(err)
	resp := h.success(0)
	resp.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Count: uint32(n), AssignedOffset: uint64(assigned)}}
	if uncertainFailure(err) {
		// The store itself is gone. The count is still exact, but this mount
		// cannot continue, so the outcome stays explicitly uncertain.
		resp.Uncertain = true
		resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_STORAGE
	}
	return resp
}

func direntCost(dirent *authoritypb.Dirent) uint64 {
	size := uint64(proto.Size(dirent))
	return 1 + uint64(protowire.SizeVarint(size)) + size
}

func decodeCookie(raw []byte) (uint64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	if len(raw) != 8 {
		return 0, syscall.EINVAL
	}
	return binary.BigEndian.Uint64(raw), nil
}

func encodeCookie(value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return raw[:]
}

func verifierMatches(verifier [16]byte, attr xfsstore.Attr) bool {
	return binary.BigEndian.Uint64(verifier[0:8]) == attr.Ino && binary.BigEndian.Uint64(verifier[8:16]) == uint64(attr.CTimeNS)
}

func (h *VolumeHandler) hello(requestID uint64, hello *authoritypb.HelloRequest) *authoritypb.Response {
	if hello.GetProtocolMajor() != ProtocolMajor {
		return h.errorResponse(requestID, syscall.EOPNOTSUPP, false)
	}
	if !h.validBounds() {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	bounds := h.Bounds()
	resp := h.success(requestID)
	resp.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
		ProtocolMajor: ProtocolMajor, Features: append([]string(nil), requiredHelloFeatures...),
		MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: h.MaxRead, MaxWriteBytes: h.MaxWrite,
		MaxInFlight: uint32(bounds.MaxInFlight),
	}}
	return resp
}

func (h *VolumeHandler) attach(ctx context.Context, requestID uint64, attach *authoritypb.AttachRequest) *authoritypb.Response {
	if h.Store == nil || h.Runtime == nil || h.Authorizer == nil || attach.GetVolumeId() != h.Runtime.VolumeID() {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	if !h.validResourceLimits() || !h.validBounds() {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	authorization, err := h.Authorizer.Authorize(ctx, attach.GetVolumeId(), attach.GetAccessToken())
	if err != nil {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	peer, ok := PeerIdentity(ctx)
	if !ok {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	root, err := h.Store.Root()
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	cred, err := h.Runtime.Attach(attach.GetReplaySlots(), volumeserver.PeerIdentity(peer), authorization)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	attached := true
	defer func() {
		if attached {
			_ = h.Runtime.Detach(cred)
		}
	}()
	// The runtime accepted this exact slot count, so the per-slot reply
	// accounting has the same length as the session's replay slots.
	if err := h.startSessionResources(cred.ID, root, attach.GetReplaySlots()); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	attr, err := h.Store.Getattr(root)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	resp := h.success(requestID)
	resp.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{SessionId: cred.ID[:], SessionGeneration: cred.Generation, ResumeSecret: cred.Secret[:], Root: itemProto(root, attr), Features: append([]string(nil), requiredAttachFeatures...), SessionLeaseMilliseconds: uint64(h.Runtime.SessionLease() / time.Millisecond)}}
	attached = false
	return resp
}

func (h *VolumeHandler) validResourceLimits() bool {
	return h.MaxItemsPerSession > 0 && h.MaxOpensPerSession > 0 && h.MaxItems > 0 && h.MaxOpens > 0 &&
		h.MaxItemsPerSession <= h.MaxItems && h.MaxOpensPerSession <= h.MaxOpens
}

func (h *VolumeHandler) validBounds() bool {
	return h.MaxFrame >= MinimumFrameBytes && h.MaxRead > 0 && h.MaxWrite > 0 && h.MaxInFlight >= 2 &&
		uint64(h.MaxRead)+uint64(FramePayloadReserve) <= uint64(h.MaxFrame) &&
		uint64(h.MaxWrite)+uint64(FramePayloadReserve) <= uint64(h.MaxFrame) &&
		h.MaxRetainedReplyBytes >= uint64(h.maxReplyBytes())
}

// readDirEntryBudget is the byte budget available to directory entries. It is
// a pure function of the request, so the reservation taken before the operation
// runs and the budget the reply is built to are necessarily the same number.
func (h *VolumeHandler) readDirEntryBudget(maxEntries uint32) uint32 {
	return h.replyReserve(maxEntries) - readDirReplyOverhead
}

// replyReserve bounds the reply of one directory listing. Every other mutation
// reply has a fixed shape (an item, an attribute block, a handle, a count).
func (h *VolumeHandler) replyReserve(readDirMaxEntries uint32) uint32 {
	if readDirMaxEntries == 0 {
		return fixedMutationReplyBytes
	}
	budget := uint64(readDirMaxEntries)*uint64(maxDirentBytes) + uint64(readDirReplyOverhead)
	if budget < uint64(fixedMutationReplyBytes) {
		budget = uint64(fixedMutationReplyBytes)
	}
	if limit := uint64(h.maxReplyBytes()); budget > limit {
		budget = limit
	}
	return uint32(budget)
}

func (h *VolumeHandler) requestReplyReserve(req *authoritypb.Request) uint32 {
	if dir := req.GetReadDir(); dir != nil {
		return h.replyReserve(dir.GetMaxEntries())
	}
	return fixedMutationReplyBytes
}

func (h *VolumeHandler) mutate(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential, apply func() *authoritypb.Response) *authoritypb.Response {
	access, err := h.Runtime.Access(cred)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	if requestRequiresWrite(req) && access&volumeserver.AccessWrite == 0 {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}
	mutation := req.GetMutation()
	if mutation == nil || len(mutation.GetRequestHash()) != sha256.Size {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	hash, err := canonicalHash(req)
	if err != nil || !bytes.Equal(hash[:], mutation.GetRequestHash()) {
		return h.errorResponse(req.GetRequestId(), volumeserver.ErrRequestMismatch, false)
	}
	// Admission is taken against the bytes this outcome may retain, before the
	// operation reaches XFS. Refusing here is retryable; refusing after the
	// filesystem changed would not be.
	reserve := h.requestReplyReserve(req)
	id := volumeserver.MutationID{Slot: mutation.GetSlot(), Sequence: mutation.GetSequence(), Hash: hash}
	reserved, err := h.reserveReplyBytes(cred.ID, id.Slot, reserve)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	settled := false
	defer func() {
		if !settled {
			h.releaseReplyReservation(reserved)
		}
	}()
	out, err := h.Runtime.ExecuteMutation(ctx, cred, id, func(context.Context) volumeserver.Outcome {
		resp := apply()
		encoded, encodeErr := marshalOutcome(resp)
		if encodeErr != nil || uint32(len(encoded)) > reserve {
			resp = h.errorResponse(0, syscall.EOVERFLOW, true)
			encoded, encodeErr = marshalOutcome(resp)
			if encodeErr != nil || uint32(len(encoded)) > reserve {
				return volumeserver.Outcome{Errno: errnos.EIO}
			}
		}
		h.settleReplyBytes(cred.ID, id.Slot, uint32(len(encoded)), reserved)
		settled = true
		return volumeserver.Outcome{Errno: resp.GetErrno(), Reply: encoded}
	})
	if err != nil {
		// Nothing was recorded for this identity, so the response deliberately
		// carries no MutationState and the peer's slot stays where it is.
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	resp := new(authoritypb.Response)
	if err := proto.Unmarshal(out.Reply, resp); err != nil {
		return h.errorResponse(req.GetRequestId(), errInternal, true)
	}
	epoch := h.Runtime.Epoch()
	resp.RequestId, resp.Epoch, resp.Errno = req.GetRequestId(), epoch[:], out.Errno
	// ExecuteMutation returning without error means this exact identity is the
	// one recorded in the slot, whether it just executed or replayed. Reporting
	// it is what keeps the peer's slot state a copy rather than an inference.
	resp.Mutation = &authoritypb.MutationState{Slot: id.Slot, AcceptedSequence: id.Sequence}
	return resp
}

// marshalOutcome encodes the retained form of a reply: the envelope the
// transport restores on every delivery is stripped, so a replay and its
// original are byte-identical bodies.
func marshalOutcome(resp *authoritypb.Response) ([]byte, error) {
	resp.RequestId, resp.Epoch, resp.Mutation = 0, nil, nil
	return proto.MarshalOptions{Deterministic: true}.Marshal(resp)
}

// reserveReplyBytes admits one mutation against the bytes its outcome may add
// to the replay cache. The slot's current outcome is replaced, not appended to,
// so only the growth beyond what that slot already holds has to be reserved:
// re-running an operation on a slot that is already at the budget is admitted,
// while a slot that would grow the total past it is refused.
func (h *VolumeHandler) reserveReplyBytes(id volumeserver.SessionID, slot, n uint32) (uint32, error) {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	held := uint32(0)
	if resources := h.resources[id]; resources != nil && !resources.ended && uint64(slot) < uint64(len(resources.reply)) {
		held = resources.reply[slot]
	}
	if held >= n {
		return 0, nil
	}
	growth := n - held
	if h.retainedReplyBytes+h.reservedReplyBytes+uint64(growth) > h.MaxRetainedReplyBytes {
		return 0, volumeserver.ErrAdmission
	}
	h.reservedReplyBytes += uint64(growth)
	return growth, nil
}

func (h *VolumeHandler) releaseReplyReservation(n uint32) {
	h.resourcesMu.Lock()
	h.reservedReplyBytes -= uint64(n)
	h.resourcesMu.Unlock()
}

// settleReplyBytes converts a reservation into the exact retained size of the
// outcome now held in the slot. A session that ended while the operation ran
// has already had its whole slot array released, so its bytes are not counted.
func (h *VolumeHandler) settleReplyBytes(id volumeserver.SessionID, slot uint32, size, reserve uint32) {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	h.reservedReplyBytes -= uint64(reserve)
	resources := h.resources[id]
	if resources == nil || resources.ended || uint64(slot) >= uint64(len(resources.reply)) {
		return
	}
	h.retainedReplyBytes += uint64(size) - uint64(resources.reply[slot])
	resources.reply[slot] = size
}

func (h *VolumeHandler) credential(ctx context.Context, req *authoritypb.Request) (volumeserver.SessionCredential, error) {
	var cred volumeserver.SessionCredential
	if len(req.GetEpoch()) != len(cred.Epoch) || req.GetSession() == nil || len(req.GetSession().GetId()) != len(cred.ID) || len(req.GetSession().GetResumeSecret()) != len(cred.Secret) {
		return cred, syscall.EINVAL
	}
	copy(cred.Epoch[:], req.GetEpoch())
	copy(cred.ID[:], req.GetSession().GetId())
	copy(cred.Secret[:], req.GetSession().GetResumeSecret())
	cred.Generation = req.GetSession().GetGeneration()
	peer, ok := PeerIdentity(ctx)
	if !ok {
		return cred, syscall.EPERM
	}
	cred.Peer = volumeserver.PeerIdentity(peer)
	return cred, nil
}

func capability(raw []byte) (xfsstore.Capability, error) {
	var cap xfsstore.Capability
	if len(raw) != len(cap) {
		return cap, syscall.EINVAL
	}
	copy(cap[:], raw)
	return cap, nil
}

// item resolves an object capability that this session actually holds. A
// capability is a volume-epoch bearer token; scoping resolution to the issuing
// session is what keeps one session from reclaiming another session's objects.
func (h *VolumeHandler) item(id volumeserver.SessionID, raw []byte) (xfsstore.Capability, error) {
	cap, err := capability(raw)
	if err != nil {
		return cap, err
	}
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		return xfsstore.Capability{}, volumeserver.ErrSessionExpired
	}
	if cap == resources.root {
		return cap, nil
	}
	if _, held := resources.items[cap]; !held {
		return xfsstore.Capability{}, xfsstore.ErrStaleObject
	}
	return cap, nil
}

// open resolves an open-handle capability that this session actually holds.
func (h *VolumeHandler) open(id volumeserver.SessionID, raw []byte) (xfsstore.Capability, error) {
	cap, err := capability(raw)
	if err != nil {
		return cap, err
	}
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		return xfsstore.Capability{}, volumeserver.ErrSessionExpired
	}
	if _, held := resources.opens[cap]; !held {
		return xfsstore.Capability{}, xfsstore.ErrStaleOpen
	}
	return cap, nil
}

func openFlags(flags *authoritypb.OpenFlags) xfsstore.OpenFlags {
	if flags == nil {
		return xfsstore.OpenFlags{}
	}
	return xfsstore.OpenFlags{Read: flags.GetRead(), Write: flags.GetWrite(), Append: flags.GetAppend(), Truncate: flags.GetTruncate(), Sync: flags.GetSync(), DataSync: flags.GetDataSync()}
}

func itemProto(item xfsstore.Capability, attr xfsstore.Attr) *authoritypb.Item {
	return &authoritypb.Item{Token: item[:], Attr: attrProto(attr)}
}
func attrProto(attr xfsstore.Attr) *authoritypb.Attr {
	return &authoritypb.Attr{Kind: attrKindProto(attr.Kind), Inode: attr.Ino, Size: attr.Size, Blocks: attr.Blocks, Mode: modeToProtocol(attr.Mode), Uid: attr.UID, Gid: attr.GID, Nlink: attr.Nlink, AtimeNs: attr.ATimeNS, MtimeNs: attr.MTimeNS, CtimeNs: attr.CTimeNS, BirthTimeNs: attr.BirthTimeNS}
}

// attrKindProto and xattrMode translate between two independently numbered
// enumerations. They are written out so that renumbering either side is a
// compile-time or test failure rather than a silent reinterpretation.
func attrKindProto(kind xfsstore.Kind) authoritypb.Attr_Kind {
	switch kind {
	case xfsstore.KindRegular:
		return authoritypb.Attr_REGULAR
	case xfsstore.KindDirectory:
		return authoritypb.Attr_DIRECTORY
	case xfsstore.KindSymlink:
		return authoritypb.Attr_SYMLINK
	default:
		return authoritypb.Attr_KIND_UNSPECIFIED
	}
}

func xattrMode(mode authoritypb.SetXattrRequest_Mode) (xfsstore.XattrMode, bool) {
	switch mode {
	case authoritypb.SetXattrRequest_UPSERT:
		return xfsstore.XattrUpsert, true
	case authoritypb.SetXattrRequest_CREATE:
		return xfsstore.XattrCreate, true
	case authoritypb.SetXattrRequest_REPLACE:
		return xfsstore.XattrReplace, true
	default:
		return 0, false
	}
}

func modeFromProtocol(mode uint32) (fs.FileMode, bool) {
	if mode&^0o7777 != 0 {
		return 0, false
	}
	result := fs.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		result |= fs.ModeSetuid
	}
	if mode&0o2000 != 0 {
		result |= fs.ModeSetgid
	}
	if mode&0o1000 != 0 {
		result |= fs.ModeSticky
	}
	return result, true
}

func modeToProtocol(mode fs.FileMode) uint32 {
	result := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		result |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		result |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		result |= 0o1000
	}
	return result
}

func (h *VolumeHandler) getattr(id volumeserver.SessionID, req *authoritypb.GetAttrRequest) (xfsstore.Attr, error) {
	if len(req.GetHandle()) != 0 {
		handle, err := h.open(id, req.GetHandle())
		if err != nil {
			return xfsstore.Attr{}, err
		}
		return h.Store.GetattrOpen(handle)
	}
	item, err := h.item(id, req.GetItem())
	if err != nil {
		return xfsstore.Attr{}, err
	}
	return h.Store.Getattr(item)
}

func (h *VolumeHandler) getLock(requestID uint64, cred volumeserver.SessionCredential, request *authoritypb.GetLockRequest) *authoritypb.Response {
	lock, err := h.lock(cred, request.GetLock())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	held, conflict, err := h.Runtime.Locks().Get(lock)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	resp := h.success(requestID)
	reply := &authoritypb.GetLockReply{Conflict: conflict}
	if conflict {
		reply.Held = lockProto(held)
	}
	resp.Body = &authoritypb.Response_GetLock{GetLock: reply}
	return resp
}

func (h *VolumeHandler) setLock(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential, request *authoritypb.SetLockRequest) *authoritypb.Response {
	return h.mutate(ctx, req, cred, func() *authoritypb.Response {
		lock, err := h.lock(cred, request.GetLock())
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		if request.GetUnlock() {
			err = h.Runtime.Locks().Unlock(lock.Object, lock.Owner, lock.Range)
		} else if request.GetWait() {
			err = h.Runtime.Locks().Wait(ctx, lock)
		} else {
			err = h.Runtime.Locks().Set(lock)
		}
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		return h.success(0)
	})
}

func (h *VolumeHandler) lock(cred volumeserver.SessionCredential, spec *authoritypb.LockSpec) (volumeserver.Lock, error) {
	if spec == nil || spec.GetRange() == nil {
		return volumeserver.Lock{}, syscall.EINVAL
	}
	item, err := h.item(cred.ID, spec.GetItem())
	if err != nil {
		return volumeserver.Lock{}, err
	}
	identity, err := h.Store.Identity(item)
	if err != nil {
		return volumeserver.Lock{}, err
	}
	type_ := volumeserver.LockRead
	if spec.GetWrite() {
		type_ = volumeserver.LockWrite
	}
	return volumeserver.Lock{Object: identity, Owner: volumeserver.LockOwner{Session: cred.ID, Kernel: spec.GetOwner(), Flock: spec.GetFlock()}, Type: type_, Range: volumeserver.LockRange{Start: spec.GetRange().GetStart(), End: spec.GetRange().GetEnd()}}, nil
}
func lockProto(lock volumeserver.Lock) *authoritypb.LockSpec {
	// item is a request capability. The runtime's inode identity is deliberately
	// not exposed as a token-shaped value in a conflict response.
	return &authoritypb.LockSpec{Owner: lock.Owner.Kernel, Write: lock.Type == volumeserver.LockWrite, Range: &authoritypb.LockRange{Start: lock.Range.Start, End: lock.Range.End}, Flock: lock.Owner.Flock}
}

func (h *VolumeHandler) unlockOpenOwner(cred volumeserver.SessionCredential, handle xfsstore.Capability, owner uint64, flock bool) error {
	identity, err := h.Store.IdentityOpen(handle)
	if err != nil {
		return err
	}
	return h.Runtime.Locks().Unlock(identity, volumeserver.LockOwner{Session: cred.ID, Kernel: owner, Flock: flock}, volumeserver.ToEOF(0))
}

func (h *VolumeHandler) success(requestID uint64) *authoritypb.Response {
	return &authoritypb.Response{RequestId: requestID, Epoch: h.Epoch()}
}

func (h *VolumeHandler) errorResponse(requestID uint64, err error, uncertain bool) *authoritypb.Response {
	h.recordStorageFailure(err)
	if uncertainFailure(err) {
		uncertain = true
	}
	errno := wireErrno(err)
	switch {
	case errors.Is(err, volumeserver.ErrEpochMismatch), errors.Is(err, volumeserver.ErrSessionExpired), errors.Is(err, volumeserver.ErrSessionFenced):
		errno = errnos.ESTALE
	case errors.Is(err, volumeserver.ErrSequenceGap), errors.Is(err, volumeserver.ErrRequestMismatch), errors.Is(err, volumeserver.ErrSlotRange):
		errno = errnos.EINVAL
	case errors.Is(err, volumeserver.ErrAdmission):
		errno = errnos.EAGAIN
	case errors.Is(err, errInternal):
		errno = errnos.EIO
	case errors.Is(err, volumeserver.ErrLockConflict):
		errno = errnos.EAGAIN
	case errors.Is(err, xfsstore.ErrStaleObject), errors.Is(err, xfsstore.ErrStaleOpen):
		errno = errnos.ESTALE
	case errors.Is(err, xfsstore.ErrFenced):
		errno = errnos.EIO
	case errors.Is(err, xfsstore.ErrOutcomeUncertain) && errno == errnos.OK:
		errno = errnos.EIO
	}
	resp := h.success(requestID)
	resp.Errno, resp.Uncertain = errno, uncertain
	if errno == errnos.EIO {
		// EIO alone cannot say whether the filesystem is gone or the authority
		// merely failed to recognise one of its own errors. The client needs
		// that difference: one requires a remount, the other does not.
		resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_INTERNAL
		if storageFailure(err) {
			resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_STORAGE
		}
	}
	return resp
}

// storageFailure reports whether an error came from the authoritative store
// itself rather than from this handler's own logic.
func storageFailure(err error) bool {
	return errors.Is(err, syscall.EIO) || errors.Is(err, xfsstore.ErrFenced) || errors.Is(err, xfsstore.ErrOutcomeUncertain)
}

func uncertainFailure(err error) bool {
	return errors.Is(err, syscall.EIO) || errors.Is(err, xfsstore.ErrOutcomeUncertain)
}

func (h *VolumeHandler) recordStorageFailure(err error) {
	if h.Store == nil || !errors.Is(err, syscall.EIO) {
		return
	}
	h.Store.Fence(err)
	if h.OnStorageFailure != nil {
		h.storageFailureOnce.Do(func() { h.OnStorageFailure(err) })
	}
}

func wireErrno(err error) int32 {
	var errno syscall.Errno
	if errors.As(err, &errno) && errno > 0 {
		return int32(errno)
	}
	return errnos.Of(err)
}

func (h *VolumeHandler) startSessionResources(id volumeserver.SessionID, root xfsstore.Capability, slots uint32) error {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	if h.resources == nil {
		h.resources = make(map[volumeserver.SessionID]*sessionResources)
	}
	if _, exists := h.resources[id]; exists {
		return volumeserver.ErrAdmission
	}
	h.resources[id] = &sessionResources{
		root:  root,
		items: make(map[xfsstore.Capability]struct{}),
		opens: make(map[xfsstore.Capability]struct{}),
		reply: make([]uint32, slots),
	}
	return nil
}

// add inserts a capability and keeps the worker-wide counter in step with the
// set in one place, so the two can never diverge and no clamp is needed when
// they are taken apart again.
func trackCapability(set map[xfsstore.Capability]struct{}, cap xfsstore.Capability, total *uint32) {
	if _, exists := set[cap]; exists {
		return
	}
	set[cap] = struct{}{}
	*total++
}

func untrackCapability(set map[xfsstore.Capability]struct{}, cap xfsstore.Capability, total *uint32) {
	if _, exists := set[cap]; !exists {
		return
	}
	delete(set, cap)
	*total--
}

func (h *VolumeHandler) trackItem(id volumeserver.SessionID, item xfsstore.Capability) error {
	h.resourcesMu.Lock()
	resources := h.resources[id]
	var err error
	switch {
	case resources == nil || resources.ended:
		err = volumeserver.ErrSessionExpired
	case uint32(len(resources.items)) >= h.MaxItemsPerSession || h.totalItems >= h.MaxItems:
		err = volumeserver.ErrAdmission
	default:
		trackCapability(resources.items, item, &h.totalItems)
	}
	h.resourcesMu.Unlock()
	if err != nil {
		h.forgetItem(item)
	}
	return err
}

func (h *VolumeHandler) trackItemAndOpen(id volumeserver.SessionID, item, handle xfsstore.Capability) error {
	h.resourcesMu.Lock()
	resources := h.resources[id]
	var err error
	switch {
	case resources == nil || resources.ended:
		err = volumeserver.ErrSessionExpired
	case uint32(len(resources.items)) >= h.MaxItemsPerSession || h.totalItems >= h.MaxItems ||
		uint32(len(resources.opens)) >= h.MaxOpensPerSession || h.totalOpens >= h.MaxOpens:
		err = volumeserver.ErrAdmission
	default:
		trackCapability(resources.items, item, &h.totalItems)
		trackCapability(resources.opens, handle, &h.totalOpens)
	}
	h.resourcesMu.Unlock()
	if err != nil {
		h.closeOpen(handle)
		h.forgetItem(item)
	}
	return err
}

func (h *VolumeHandler) untrackItem(id volumeserver.SessionID, item xfsstore.Capability) {
	h.resourcesMu.Lock()
	if resources := h.resources[id]; resources != nil {
		untrackCapability(resources.items, item, &h.totalItems)
	}
	h.resourcesMu.Unlock()
}

func (h *VolumeHandler) trackOpen(id volumeserver.SessionID, handle xfsstore.Capability) error {
	h.resourcesMu.Lock()
	resources := h.resources[id]
	var err error
	switch {
	case resources == nil || resources.ended:
		err = volumeserver.ErrSessionExpired
	case uint32(len(resources.opens)) >= h.MaxOpensPerSession || h.totalOpens >= h.MaxOpens:
		err = volumeserver.ErrAdmission
	default:
		trackCapability(resources.opens, handle, &h.totalOpens)
	}
	h.resourcesMu.Unlock()
	if err != nil {
		h.closeOpen(handle)
	}
	return err
}

func (h *VolumeHandler) untrackOpen(id volumeserver.SessionID, handle xfsstore.Capability) {
	h.resourcesMu.Lock()
	if resources := h.resources[id]; resources != nil {
		untrackCapability(resources.opens, handle, &h.totalOpens)
	}
	h.resourcesMu.Unlock()
}

func (h *VolumeHandler) closeSessionResources(id volumeserver.SessionID) {
	h.resourcesMu.Lock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		h.resourcesMu.Unlock()
		return
	}
	resources.ended = true
	handles := make([]xfsstore.Capability, 0, len(resources.opens))
	for handle := range resources.opens {
		handles = append(handles, handle)
	}
	items := make([]xfsstore.Capability, 0, len(resources.items))
	for item := range resources.items {
		items = append(items, item)
	}
	// Every insertion incremented these counters exactly once, so the totals
	// are the sum of the live sets and the subtraction is exact.
	h.totalOpens -= uint32(len(handles))
	h.totalItems -= uint32(len(items))
	for _, size := range resources.reply {
		h.retainedReplyBytes -= uint64(size)
	}
	resources.opens = nil
	resources.items = nil
	resources.reply = nil
	h.resourcesMu.Unlock()
	for _, handle := range handles {
		h.closeOpen(handle)
	}
	for _, item := range items {
		h.forgetItem(item)
	}
	h.resourcesMu.Lock()
	if h.resources[id] == resources {
		delete(h.resources, id)
	}
	h.resourcesMu.Unlock()
}

func (h *VolumeHandler) closeOpen(handle xfsstore.Capability) {
	if h.Store == nil {
		return
	}
	if err := h.Store.CloseOpen(handle); err != nil && !errors.Is(err, xfsstore.ErrStaleOpen) && !errors.Is(err, xfsstore.ErrClosed) {
		h.recordStorageFailure(err)
	}
}

func (h *VolumeHandler) forgetItem(item xfsstore.Capability) {
	if h.Store == nil {
		return
	}
	if err := h.Store.Forget(item); err != nil && !errors.Is(err, xfsstore.ErrStaleObject) && !errors.Is(err, xfsstore.ErrClosed) {
		h.recordStorageFailure(err)
	}
}
