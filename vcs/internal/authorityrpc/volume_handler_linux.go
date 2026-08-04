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
	"google.golang.org/protobuf/proto"
)

var errInternal = errors.New("authorityrpc: internal handler failure")

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
	// OnStorageFailure is called once after an EIO fences the store. Production
	// uses it to terminate this epoch instead of remaining deceptively ready.
	OnStorageFailure func(error)

	cleanupOnce        sync.Once
	storageFailureOnce sync.Once
	resourcesMu        sync.Mutex
	resources          map[volumeserver.SessionID]*sessionResources
	totalItems         uint32
	totalOpens         uint32
}

type sessionResources struct {
	ended bool
	items map[xfsstore.Capability]struct{}
	opens map[xfsstore.Capability]struct{}
}

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
		if err == nil {
			err = syscall.EPERM
		}
		return h.errorResponse(req.GetRequestId(), err, false)
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
	case *authoritypb.Request_Cancel:
		return h.success(req.GetRequestId())
	case *authoritypb.Request_Detach:
		if err := h.Runtime.Detach(cred); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_Lookup:
		parent, err := capability(body.Lookup.GetParent())
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
		attr, err := h.getattr(body.GetAttr)
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
				item, err = capability(set.GetItem())
				if err != nil {
					return h.errorResponse(0, err, false)
				}
			}
			if len(set.GetHandle()) != 0 {
				handle, err = capability(set.GetHandle())
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
				} else if item != (xfsstore.Capability{}) {
					err = h.Store.TruncateObject(item, set.GetSize())
				} else {
					err = syscall.EINVAL
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
			parent, err := capability(body.Create.GetParent())
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
			parent, err := capability(body.Mkdir.GetParent())
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
			parent, err := capability(body.Unlink.GetParent())
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
			oldParent, err := capability(body.Rename.GetOldParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			newParent, err := capability(body.Rename.GetNewParent())
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
			source, err := capability(body.Link.GetExistingItem())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			parent, err := capability(body.Link.GetNewParent())
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
			parent, err := capability(body.Symlink.GetParent())
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
		item, err := capability(body.Readlink.GetItem())
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
			item, err := capability(body.Open.GetItem())
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
			handle, err := capability(body.Close.GetHandle())
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
		handle, err := capability(body.Flush.GetHandle())
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
		handle, err := capability(body.Read.GetHandle())
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
			handle, err := capability(body.Write.GetHandle())
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
			if err != nil && n == 0 {
				return h.errorResponse(0, err, false)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Count: uint32(n), AssignedOffset: uint64(assigned)}}
			if err != nil {
				h.recordStorageFailure(err)
				resp.Errno = wireErrno(err)
				if errors.Is(err, syscall.EIO) {
					resp.Uncertain = true
				}
			}
			return resp
		})
	case *authoritypb.Request_Fsync:
		handle, err := capability(body.Fsync.GetHandle())
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
			handle, err := capability(body.ReadDir.GetHandle())
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
			for i, entry := range entries {
				attr, err := h.Store.StatOpenDirChild(handle, entry.Name)
				if err != nil {
					return h.errorResponse(0, syscall.ESTALE, false)
				}
				result.Entries = append(result.Entries, &authoritypb.Dirent{Name: []byte(entry.Name), Attr: attrProto(attr), NextCookie: encodeCookie(cookie + uint64(i) + 1)})
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
		item, err := capability(body.Reclaim.GetItem())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.Store.Forget(item); err != nil && !errors.Is(err, xfsstore.ErrStaleObject) {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		h.untrackItem(cred.ID, item)
		return h.success(req.GetRequestId())
	case *authoritypb.Request_GetXattr:
		item, err := capability(body.GetXattr.GetItem())
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
			item, err := capability(body.SetXattr.GetItem())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			mode := xfsstore.XattrMode(body.SetXattr.GetMode())
			if err := h.Store.SetXattr(item, string(body.SetXattr.GetName()), body.SetXattr.GetValue(), mode); err != nil {
				return h.errorResponse(0, err, false)
			}
			return h.success(0)
		})
	case *authoritypb.Request_RemoveXattr:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			item, err := capability(body.RemoveXattr.GetItem())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := h.Store.RemoveXattr(item, string(body.RemoveXattr.GetName())); err != nil {
				return h.errorResponse(0, err, false)
			}
			return h.success(0)
		})
	case *authoritypb.Request_ListXattr:
		item, err := capability(body.ListXattr.GetItem())
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
	resp := h.success(requestID)
	if h.MaxFrame == 0 || h.MaxRead == 0 || h.MaxWrite == 0 || h.MaxInFlight == 0 {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	resp.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{ProtocolMajor: ProtocolMajor, Features: append([]string(nil), requiredHelloFeatures...), MaxFrameBytes: h.MaxFrame, MaxReadBytes: h.MaxRead, MaxWriteBytes: h.MaxWrite, MaxInFlight: h.MaxInFlight}}
	return resp
}

func (h *VolumeHandler) attach(ctx context.Context, requestID uint64, attach *authoritypb.AttachRequest) *authoritypb.Response {
	if h.Store == nil || h.Runtime == nil || h.Authorizer == nil || attach.GetVolumeId() != h.Runtime.VolumeID() {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	if !h.validResourceLimits() {
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
	if err := h.startSessionResources(cred.ID); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	root, err := h.Store.Root()
	if err != nil {
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
	id := volumeserver.MutationID{Slot: mutation.GetSlot(), Sequence: mutation.GetSequence(), Hash: hash}
	out, err := h.Runtime.ExecuteMutation(ctx, cred, id, func(context.Context) volumeserver.Outcome {
		resp := apply()
		resp.RequestId = 0
		resp.Epoch = nil
		encoded, encodeErr := proto.MarshalOptions{Deterministic: true}.Marshal(resp)
		if encodeErr != nil {
			return volumeserver.Outcome{Errno: errnos.EIO}
		}
		if uint64(len(encoded)) > uint64(h.MaxFrame) {
			resp = h.errorResponse(0, syscall.EOVERFLOW, true)
			resp.RequestId = 0
			resp.Epoch = nil
			encoded, encodeErr = proto.MarshalOptions{Deterministic: true}.Marshal(resp)
			if encodeErr != nil || uint64(len(encoded)) > uint64(h.MaxFrame) {
				return volumeserver.Outcome{Errno: errnos.EIO}
			}
		}
		return volumeserver.Outcome{Errno: resp.GetErrno(), Reply: encoded}
	})
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	resp := new(authoritypb.Response)
	if err := proto.Unmarshal(out.Reply, resp); err != nil {
		return h.errorResponse(req.GetRequestId(), errInternal, true)
	}
	epoch := h.Runtime.Epoch()
	resp.RequestId, resp.Epoch, resp.Errno = req.GetRequestId(), epoch[:], out.Errno
	return resp
}

func requestRequiresWrite(req *authoritypb.Request) bool {
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Create, *authoritypb.Request_Mkdir,
		*authoritypb.Request_Unlink, *authoritypb.Request_Rename,
		*authoritypb.Request_Link, *authoritypb.Request_Symlink,
		*authoritypb.Request_Write, *authoritypb.Request_SetAttr,
		*authoritypb.Request_SetXattr, *authoritypb.Request_RemoveXattr:
		return true
	case *authoritypb.Request_Open:
		flags := body.Open.GetFlags()
		return flags != nil && (flags.GetWrite() || flags.GetAppend() || flags.GetTruncate())
	case *authoritypb.Request_SetLock:
		return !body.SetLock.GetUnlock() && body.SetLock.GetLock() != nil && body.SetLock.GetLock().GetWrite()
	default:
		return false
	}
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
	return &authoritypb.Attr{Kind: authoritypb.Attr_Kind(attr.Kind), Inode: attr.Ino, Size: attr.Size, Blocks: attr.Blocks, Mode: modeToProtocol(attr.Mode), Uid: attr.UID, Gid: attr.GID, Nlink: attr.Nlink, AtimeNs: attr.ATimeNS, MtimeNs: attr.MTimeNS, CtimeNs: attr.CTimeNS, BirthTimeNs: attr.BirthTimeNS}
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

func (h *VolumeHandler) getattr(req *authoritypb.GetAttrRequest) (xfsstore.Attr, error) {
	if len(req.GetHandle()) != 0 {
		handle, err := capability(req.GetHandle())
		if err != nil {
			return xfsstore.Attr{}, err
		}
		return h.Store.GetattrOpen(handle)
	}
	item, err := capability(req.GetItem())
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
	item, err := capability(spec.GetItem())
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
	epoch := h.Runtime
	var raw []byte
	if epoch != nil {
		value := epoch.Epoch()
		raw = append([]byte(nil), value[:]...)
	}
	return &authoritypb.Response{RequestId: requestID, Epoch: raw}
}
func (h *VolumeHandler) errorResponse(requestID uint64, err error, uncertain bool) *authoritypb.Response {
	h.recordStorageFailure(err)
	if errors.Is(err, syscall.EIO) || errors.Is(err, xfsstore.ErrOutcomeUncertain) {
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
	return resp
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

func (h *VolumeHandler) startSessionResources(id volumeserver.SessionID) error {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	if h.resources == nil {
		h.resources = make(map[volumeserver.SessionID]*sessionResources)
	}
	if _, exists := h.resources[id]; exists {
		return volumeserver.ErrAdmission
	}
	h.resources[id] = &sessionResources{items: make(map[xfsstore.Capability]struct{}), opens: make(map[xfsstore.Capability]struct{})}
	return nil
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
		if _, exists := resources.items[item]; !exists {
			resources.items[item] = struct{}{}
			h.totalItems++
		}
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
		resources.items[item] = struct{}{}
		resources.opens[handle] = struct{}{}
		h.totalItems++
		h.totalOpens++
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
		if _, exists := resources.items[item]; exists {
			delete(resources.items, item)
			if h.totalItems > 0 {
				h.totalItems--
			}
		}
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
		if _, exists := resources.opens[handle]; !exists {
			resources.opens[handle] = struct{}{}
			h.totalOpens++
		}
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
		if _, exists := resources.opens[handle]; exists {
			delete(resources.opens, handle)
			if h.totalOpens > 0 {
				h.totalOpens--
			}
		}
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
	if count := uint32(len(handles)); count <= h.totalOpens {
		h.totalOpens -= count
	} else {
		h.totalOpens = 0
	}
	if count := uint32(len(items)); count <= h.totalItems {
		h.totalItems -= count
	} else {
		h.totalItems = 0
	}
	resources.opens = nil
	resources.items = nil
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
