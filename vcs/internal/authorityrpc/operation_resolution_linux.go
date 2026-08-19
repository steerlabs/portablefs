//go:build linux

package authorityrpc

import (
	"errors"
	"io/fs"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// operationResolutionContext owns every immutable capability fact and
// namespace answer used by one mutation. If namespace bindings change while
// lease admission waits, the caller discards this context and resolves again.
type operationResolutionContext struct {
	h          *VolumeHandler
	id         volumeserver.SessionID
	items      map[string]sourceResolvedIdentity
	opens      map[string]sourceResolvedIdentity
	namespaces map[namespaceResolutionKey]namespaceResolution
}

type sourceResolvedIdentity struct {
	cap        xfsstore.Capability
	identity   [16]byte
	coordinate visibilityCoordinate
}

type namespaceResolutionKey struct {
	parent xfsstore.Capability
	name   string
}

type namespaceResolution struct {
	coordinate visibilityCoordinate
	size       int64
	found      bool
}

func newOperationResolutionContext(h *VolumeHandler, id volumeserver.SessionID) *operationResolutionContext {
	return &operationResolutionContext{
		h: h, id: id, items: make(map[string]sourceResolvedIdentity), opens: make(map[string]sourceResolvedIdentity),
		namespaces: make(map[namespaceResolutionKey]namespaceResolution),
	}
}

func (r *operationResolutionContext) item(raw []byte) (sourceResolvedIdentity, error) {
	if resolved, ok := r.items[string(raw)]; ok {
		return resolved, nil
	}
	capability, err := r.h.item(r.id, raw)
	if err != nil {
		return sourceResolvedIdentity{}, err
	}
	stored, err := r.h.Store.CoordinateItem(capability)
	if err != nil {
		return sourceResolvedIdentity{}, err
	}
	coordinate := objectCoordinate(stored)
	if coordinate.identity == ([16]byte{}) || coordinate.ino == 0 {
		return sourceResolvedIdentity{}, syscall.EIO
	}
	resolved := sourceResolvedIdentity{cap: capability, identity: coordinate.identity, coordinate: coordinate}
	r.items[string(raw)] = resolved
	return resolved, nil
}

func (r *operationResolutionContext) open(raw []byte) (sourceResolvedIdentity, error) {
	if resolved, ok := r.opens[string(raw)]; ok {
		return resolved, nil
	}
	capability, err := r.h.open(r.id, raw)
	if err != nil {
		return sourceResolvedIdentity{}, err
	}
	stored, err := r.h.Store.CoordinateOpen(capability)
	if err != nil {
		return sourceResolvedIdentity{}, err
	}
	coordinate := objectCoordinate(stored)
	if coordinate.identity == ([16]byte{}) || coordinate.ino == 0 {
		return sourceResolvedIdentity{}, syscall.EIO
	}
	resolved := sourceResolvedIdentity{cap: capability, identity: coordinate.identity, coordinate: coordinate}
	r.opens[string(raw)] = resolved
	return resolved, nil
}

func (r *operationResolutionContext) invalidateNamespaceBindings() {
	clear(r.namespaces)
}

func (r *operationResolutionContext) namespace(parent xfsstore.Capability, name []byte) (namespaceResolution, error) {
	if err := namespaceName(name); err != nil {
		return namespaceResolution{}, err
	}
	key := namespaceResolutionKey{parent: parent, name: string(name)}
	if resolved, ok := r.namespaces[key]; ok {
		return resolved, nil
	}
	item, attr, err := r.h.Store.Lookup(parent, string(name))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		resolved := namespaceResolution{}
		r.namespaces[key] = resolved
		return resolved, nil
	}
	if err != nil {
		return namespaceResolution{}, err
	}
	stored, coordinateErr := r.h.Store.CoordinateItem(item)
	forgetErr := r.h.Store.Forget(item)
	if coordinateErr != nil {
		return namespaceResolution{}, coordinateErr
	}
	if forgetErr != nil {
		return namespaceResolution{}, forgetErr
	}
	coordinate := objectCoordinate(stored)
	if coordinate.identity == ([16]byte{}) || coordinate.ino == 0 || coordinate != attrCoordinate(coordinate.identity, attr) {
		return namespaceResolution{}, syscall.EIO
	}
	resolved := namespaceResolution{coordinate: coordinate, size: attr.Size, found: true}
	r.namespaces[key] = resolved
	return resolved, nil
}
