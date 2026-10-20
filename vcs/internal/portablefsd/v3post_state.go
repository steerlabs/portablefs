package portablefsd

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

// PostState roles, mirroring the authority's wire constants.
const (
	v3PostStateRoleTarget      uint32 = 0x0001
	v3PostStateRoleParent      uint32 = 0x0002
	v3PostStateRoleOldParent   uint32 = 0x0004
	v3PostStateRoleNewParent   uint32 = 0x0008
	v3PostStateRoleRemoved     uint32 = 0x0010
	v3PostStateRoleOverwritten uint32 = 0x0020
	v3PostStateRoleSource      uint32 = 0x0040
	v3PostStateRoleDestination uint32 = 0x0080
	v3PostStateRoleCreated     uint32 = 0x0100
	v3PostStateRoleExchanged   uint32 = 0x0200

	v3PostStateKnownRoles = v3PostStateRoleTarget | v3PostStateRoleParent | v3PostStateRoleOldParent |
		v3PostStateRoleNewParent | v3PostStateRoleRemoved | v3PostStateRoleOverwritten |
		v3PostStateRoleSource | v3PostStateRoleDestination | v3PostStateRoleCreated | v3PostStateRoleExchanged
	v3PostStateRoleMoved = v3PostStateRoleSource | v3PostStateRoleDestination
)

// v3Observation is one validated attribute sample of one stable identity: its
// actual object version, inside the enclosing storage snapshot.
type v3Observation struct {
	identity [16]byte
	attr     *authoritypb.Attr
	version  uint64
	roles    uint32
}

// v3NameEffect is the authoritative post-binding of one touched coordinate:
// bound to identity, or proved absent.
type v3NameEffect struct {
	parent   *v3ItemRecord
	name     string
	bound    bool
	identity [16]byte
}

// v3MutationEffect is one whole validated mutation result. Every affected
// identity and touched coordinate is applied in one data-plane transaction,
// ordered by the PostState snapshot, never by PARENT.object_version.
type v3MutationEffect struct {
	snapshot         uint64
	objects          []v3Observation
	names            []v3NameEffect
	namesComplete    bool
	permissionTarget *v3ItemRecord
	mkdir            *v3ItemRecord
	mkdirWitness     *v3MkdirWitness
}

// v3ReadStamp validates the coherent storage stamp of one read sample: an
// actual object version within its snapshot, 0 < v <= s.
func v3ReadStamp(version, snapshot uint64) error {
	if version == 0 || snapshot == 0 || version > snapshot {
		return fmt.Errorf("authority read stamp version %d snapshot %d is not 0 < v <= s", version, snapshot)
	}
	return nil
}

// v3PostState validates the operation-independent mutation envelope and
// returns its objects with their exact role multiset: canonical unique
// identities, one to four objects, known nonzero roles, attributes present,
// and 0 < object_version <= snapshot = visibility sequence.
func v3PostState(state *authoritypb.PostState) ([]*authoritypb.ObjectPostState, []uint32, error) {
	if state == nil || state.GetSnapshotSequence() == 0 || state.GetVisibilitySequence() != state.GetSnapshotSequence() ||
		len(state.GetObjects()) < 1 || len(state.GetObjects()) > 4 {
		return nil, nil, errors.New("mutation post-state envelope is missing or malformed")
	}
	roles := make([]uint32, 0, len(state.GetObjects()))
	var previous []byte
	for _, object := range state.GetObjects() {
		if object == nil || len(object.GetStableIdentity()) != 16 || bytes.Equal(object.GetStableIdentity(), make([]byte, 16)) ||
			object.GetObjectVersion() == 0 || object.GetObjectVersion() > state.GetSnapshotSequence() ||
			object.GetAttr() == nil || object.GetAttr().GetInode() == 0 || !validAuthorityKind(object.GetAttr().GetKind()) ||
			object.GetRoles() == 0 || object.GetRoles()&^v3PostStateKnownRoles != 0 ||
			previous != nil && bytes.Compare(previous, object.GetStableIdentity()) >= 0 {
			return nil, nil, errors.New("mutation post-state carried a malformed or noncanonical object")
		}
		previous = object.GetStableIdentity()
		roles = append(roles, object.GetRoles())
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return state.GetObjects(), roles, nil
}

func v3RolesEqual(got []uint32, want ...uint32) bool {
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func v3ObjectIdentity(object *authoritypb.ObjectPostState) [16]byte {
	return [16]byte(object.GetStableIdentity())
}

func newV3MutationEffect(state *authoritypb.PostState, objects []*authoritypb.ObjectPostState) *v3MutationEffect {
	effect := &v3MutationEffect{snapshot: state.GetSnapshotSequence(), objects: make([]v3Observation, len(objects))}
	for index, object := range objects {
		effect.objects[index] = v3Observation{identity: v3ObjectIdentity(object), attr: object.GetAttr(), version: object.GetObjectVersion(), roles: object.GetRoles()}
	}
	return effect
}

// v3OperandObject requires an object naming exactly the record an operation
// was addressed to, with that record's immutable inode and kind.
func v3OperandObject(object *authoritypb.ObjectPostState, record *v3ItemRecord, role string) error {
	if v3ObjectIdentity(object) != record.item.StableIdentity {
		return fmt.Errorf("mutation post-state %s is not the operation's %s", role, role)
	}
	if object.GetAttr().GetInode() != record.inode || object.GetAttr().GetKind() != record.kind {
		return fmt.Errorf("mutation post-state %s changed its inode or kind", role)
	}
	return nil
}

// v3ReplyItemAgrees binds a returned Item to the PostState object for its
// identity: the same attributes, the same actual version, and the enclosing
// snapshot.
func v3ReplyItemAgrees(item *authoritypb.Item, object *authoritypb.ObjectPostState, snapshot uint64) error {
	if item == nil || !bytes.Equal(item.GetStableIdentity(), object.GetStableIdentity()) ||
		!proto.Equal(item.GetAttr(), object.GetAttr()) ||
		item.GetObjectVersion() != object.GetObjectVersion() || item.GetSnapshotSequence() != snapshot {
		return errors.New("mutation reply item disagrees with its post-state object")
	}
	return nil
}

// v3TargetEffect validates WRITE, SETATTR, and REMOVE_XATTR: exactly one
// TARGET, the operation's own item. It changes no name.
func v3TargetEffect(state *authoritypb.PostState, item *v3ItemRecord) (*v3MutationEffect, *authoritypb.ObjectPostState, error) {
	objects, roles, err := v3PostState(state)
	if err != nil {
		return nil, nil, err
	}
	if !v3RolesEqual(roles, v3PostStateRoleTarget) {
		return nil, nil, errors.New("mutation post-state is not exactly one target")
	}
	if err := v3OperandObject(objects[0], item, "target"); err != nil {
		return nil, nil, err
	}
	return newV3MutationEffect(state, objects), objects[0], nil
}

// v3BindingEffect validates CREATE, MKDIR, SYMLINK, and LINK: the operation's
// PARENT plus one bound object (CREATED, or TARGET for an existing-file CREATE
// and for LINK) whose returned Item agrees with it. The coordinate becomes
// bound to that identity.
func v3BindingEffect(
	state *authoritypb.PostState,
	parent *v3ItemRecord,
	name []byte,
	item *authoritypb.Item,
	kind authoritypb.Attr_Kind,
	boundRoles ...uint32,
) (*v3MutationEffect, error) {
	objects, roles, err := v3PostState(state)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, bound := range boundRoles {
		allowed = allowed || v3RolesEqual(roles, v3PostStateRoleParent, bound)
	}
	if !allowed {
		return nil, errors.New("mutation post-state roles do not match the namespace operation")
	}
	var bound *authoritypb.ObjectPostState
	for _, object := range objects {
		if object.GetRoles() == v3PostStateRoleParent {
			if err := v3OperandObject(object, parent, "parent"); err != nil {
				return nil, err
			}
			continue
		}
		bound = object
	}
	if bound.GetAttr().GetKind() != kind {
		return nil, errors.New("mutation post-state bound an object of the wrong kind")
	}
	if err := v3ReplyItemAgrees(item, bound, state.GetSnapshotSequence()); err != nil {
		return nil, err
	}
	effect := newV3MutationEffect(state, objects)
	effect.namesComplete = true
	effect.names = []v3NameEffect{{parent: parent, name: string(name), bound: true, identity: v3ObjectIdentity(bound)}}
	return effect, nil
}

// v3RemoveEffect validates UNLINK/RMDIR: the operation's PARENT and the
// REMOVED object, whose kind matches the request. The coordinate becomes
// absent; a still-held removed inode keeps its record and receives its attrs.
func v3RemoveEffect(state *authoritypb.PostState, parent *v3ItemRecord, name []byte, directory bool) (*v3MutationEffect, error) {
	objects, roles, err := v3PostState(state)
	if err != nil {
		return nil, err
	}
	if !v3RolesEqual(roles, v3PostStateRoleParent, v3PostStateRoleRemoved) {
		return nil, errors.New("removal post-state is not exactly its parent and removed object")
	}
	for _, object := range objects {
		if object.GetRoles() == v3PostStateRoleParent {
			if err := v3OperandObject(object, parent, "parent"); err != nil {
				return nil, err
			}
		} else if (object.GetAttr().GetKind() == authoritypb.Attr_DIRECTORY) != directory {
			return nil, errors.New("removal post-state removed an object of the wrong kind")
		}
	}
	effect := newV3MutationEffect(state, objects)
	effect.namesComplete = true
	effect.names = []v3NameEffect{{parent: parent, name: string(name)}}
	return effect, nil
}

// v3RenameEffect validates a non-exchange RENAME against its exact operands
// and the reply's authoritative post-bindings: the moved object is the new
// name's post identity, the parents are the operation's (merged when they are
// one directory), an OVERWRITTEN victim is distinct, and the old name is
// either absent or, for the same-inode no-op, still bound to the moved
// object. Absence of the old name is never inferred.
func v3RenameEffect(
	state *authoritypb.PostState,
	from *v3ItemRecord, fromName []byte,
	to *v3ItemRecord, toName []byte,
	moved, old v3PublicationIdentity, oldBound bool,
) (*v3MutationEffect, error) {
	objects, roles, err := v3PostState(state)
	if err != nil {
		return nil, err
	}
	sameParent := from.item.StableIdentity == to.item.StableIdentity
	var allowed bool
	if sameParent {
		allowed = v3RolesEqual(roles, v3PostStateRoleMoved, v3PostStateRoleOldParent|v3PostStateRoleNewParent) ||
			v3RolesEqual(roles, v3PostStateRoleMoved, v3PostStateRoleOverwritten, v3PostStateRoleOldParent|v3PostStateRoleNewParent)
	} else {
		allowed = v3RolesEqual(roles, v3PostStateRoleMoved, v3PostStateRoleOldParent, v3PostStateRoleNewParent) ||
			v3RolesEqual(roles, v3PostStateRoleMoved, v3PostStateRoleOverwritten, v3PostStateRoleOldParent, v3PostStateRoleNewParent)
	}
	if !allowed {
		return nil, errors.New("rename post-state roles do not match a non-exchange rename")
	}
	if oldBound && old != moved {
		return nil, errors.New("rename reported a different object at the old name without an exchange")
	}
	for _, object := range objects {
		identity := v3PublicationIdentity(v3ObjectIdentity(object))
		switch object.GetRoles() {
		case v3PostStateRoleMoved:
			if identity != moved {
				return nil, errors.New("rename post-state moved object is not the new name's post identity")
			}
		case v3PostStateRoleOverwritten:
			if identity == moved || identity == v3PublicationIdentity(from.item.StableIdentity) ||
				identity == v3PublicationIdentity(to.item.StableIdentity) {
				return nil, errors.New("rename post-state overwrote an operand")
			}
		case v3PostStateRoleOldParent | v3PostStateRoleNewParent, v3PostStateRoleOldParent:
			if err := v3OperandObject(object, from, "old parent"); err != nil {
				return nil, err
			}
		case v3PostStateRoleNewParent:
			if err := v3OperandObject(object, to, "new parent"); err != nil {
				return nil, err
			}
		}
	}
	effect := newV3MutationEffect(state, objects)
	effect.namesComplete = true
	effect.names = []v3NameEffect{
		{parent: from, name: string(fromName), bound: oldBound, identity: [16]byte(moved)},
		{parent: to, name: string(toName), bound: true, identity: [16]byte(moved)},
	}
	return effect, nil
}
