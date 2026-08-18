//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

const (
	postStateRoleTarget      uint32 = 0x0001
	postStateRoleParent      uint32 = 0x0002
	postStateRoleOldParent   uint32 = 0x0004
	postStateRoleNewParent   uint32 = 0x0008
	postStateRoleRemoved     uint32 = 0x0010
	postStateRoleOverwritten uint32 = 0x0020
	postStateRoleSource      uint32 = 0x0040
	postStateRoleDestination uint32 = 0x0080
	postStateRoleCreated     uint32 = 0x0100
	postStateRoleExchanged   uint32 = 0x0200
	postStateKnownRoles             = postStateRoleTarget | postStateRoleParent | postStateRoleOldParent |
		postStateRoleNewParent | postStateRoleRemoved | postStateRoleOverwritten | postStateRoleSource |
		postStateRoleDestination | postStateRoleCreated | postStateRoleExchanged
)

func validateMutationPostState(state *authoritypb.PostState) error {
	if state == nil || state.GetVisibilitySequence() == 0 || state.GetSnapshotSequence() != state.GetVisibilitySequence() ||
		len(state.GetObjects()) < 1 || len(state.GetObjects()) > 4 {
		return errors.New("fusev3: malformed mutation post-state envelope")
	}
	var previous []byte
	for _, object := range state.GetObjects() {
		if object == nil || len(object.GetStableIdentity()) != 16 || object.GetObjectVersion() == 0 ||
			object.GetObjectVersion() > state.GetSnapshotSequence() || object.GetAttr() == nil ||
			object.GetRoles() == 0 || object.GetRoles()&^postStateKnownRoles != 0 ||
			previous != nil && bytes.Compare(previous, object.GetStableIdentity()) >= 0 {
			return errors.New("fusev3: malformed object in mutation post-state")
		}
		previous = object.GetStableIdentity()
	}
	return nil
}

func postStateRoles(state *authoritypb.PostState) []uint32 {
	result := make([]uint32, 0, len(state.GetObjects()))
	for _, object := range state.GetObjects() {
		result = append(result, object.GetRoles())
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func samePostStateRoles(got []uint32, want ...uint32) bool {
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

func validateMutationPostStateForOpcode(opcode uint32, state *authoritypb.PostState) error {
	if err := validateMutationPostState(state); err != nil {
		return err
	}
	got := postStateRoles(state)
	valid := false
	switch opcode {
	case 4, 14, 21, 24, 43, fuse.PFS_WRITE_OPCODE, fuse.PFS_FALLOCATE_OPCODE: // setattr, open(O_TRUNC), xattrs, fallocate, private write/fallocate
		valid = samePostStateRoles(got, postStateRoleTarget)
	case fuse.PFS_COPY_FILE_RANGE_OPCODE:
		valid = samePostStateRoles(got, postStateRoleSource|postStateRoleDestination) ||
			samePostStateRoles(got, postStateRoleSource, postStateRoleDestination)
	case 6, 8, 9, 51: // symlink, regular mknod, mkdir, tmpfile
		valid = samePostStateRoles(got, postStateRoleCreated, postStateRoleParent)
	case 35: // create-new or open-existing with O_TRUNC
		valid = samePostStateRoles(got, postStateRoleTarget, postStateRoleParent) ||
			samePostStateRoles(got, postStateRoleCreated, postStateRoleParent)
	case 13: // link
		valid = samePostStateRoles(got, postStateRoleTarget, postStateRoleParent)
	case 10, 11: // unlink, rmdir
		valid = samePostStateRoles(got, postStateRoleRemoved, postStateRoleParent)
	case 12, 45: // rename, rename2
		valid = validateRenamePostStateRoles(got)
	}
	if !valid {
		return errors.New("fusev3: mutation post-state does not match the opcode object/role set")
	}
	return nil
}

// removedPostStateIdentity returns the exact object an unlink/rmdir removed,
// while also binding the response to the parent on which the operation ran.
// A source mount is not required to have cached the name before mutating it;
// in that case the authority's ordered post-state is the only exact identity
// available after the successful operation.
func removedPostStateIdentity(state *authoritypb.PostState, parent publicationIdentity) (publicationIdentity, error) {
	if err := validateMutationPostStateForOpcode(10, state); err != nil {
		return publicationIdentity{}, err
	}
	var removed publicationIdentity
	parentFound := false
	for _, object := range state.GetObjects() {
		identity, ok := publicationIdentityFromBytes(object.GetStableIdentity())
		if !ok {
			return publicationIdentity{}, errors.New("fusev3: removal post-state carried an invalid stable identity")
		}
		switch object.GetRoles() {
		case postStateRoleRemoved:
			removed = identity
		case postStateRoleParent:
			parentFound = identity == parent
		}
	}
	if removed == (publicationIdentity{}) || !parentFound {
		return publicationIdentity{}, errors.New("fusev3: removal post-state did not match its source parent and removed object")
	}
	return removed, nil
}

func validateRenamePostStateRoles(got []uint32) bool {
	const moved = postStateRoleSource | postStateRoleDestination
	const exchanged = moved | postStateRoleExchanged
	for _, want := range [][]uint32{
		{moved, postStateRoleOldParent | postStateRoleNewParent},
		{moved, postStateRoleOldParent, postStateRoleNewParent},
		{moved, postStateRoleOverwritten, postStateRoleOldParent | postStateRoleNewParent},
		{moved, postStateRoleOverwritten, postStateRoleOldParent, postStateRoleNewParent},
		{exchanged, exchanged, postStateRoleOldParent | postStateRoleNewParent},
		{exchanged, exchanged, postStateRoleOldParent, postStateRoleNewParent},
	} {
		if samePostStateRoles(got, want...) {
			return true
		}
	}
	return false
}

func postStateObject(state *authoritypb.PostState, identity []byte, requiredRoles uint32) *authoritypb.ObjectPostState {
	for _, object := range state.GetObjects() {
		if bytes.Equal(object.GetStableIdentity(), identity) && object.GetRoles()&requiredRoles == requiredRoles {
			return object
		}
	}
	return nil
}

type expectedPostStateObject struct {
	identity publicationIdentity
	roles    uint32
}

func expectedPostStateItem(item interface{ GetStableIdentity() []byte }, roles uint32) (expectedPostStateObject, error) {
	identity, ok := publicationIdentityFromItem(item)
	if !ok {
		return expectedPostStateObject{}, errors.New("fusev3: exact post-state operand has an invalid stable identity")
	}
	return expectedPostStateObject{identity: identity, roles: roles}, nil
}

func expectedPostStateRecord(record *inodeRecord, roles uint32) (expectedPostStateObject, error) {
	if record == nil || record.graft || record.reclaimed || record.identity == (publicationIdentity{}) {
		return expectedPostStateObject{}, errors.New("fusev3: exact post-state operand is not a canonical live record")
	}
	return expectedPostStateObject{identity: record.identity, roles: roles}, nil
}

func expectPostStateItem(ctx context.Context, item interface{ GetStableIdentity() []byte }, roles uint32) error {
	object, err := expectedPostStateItem(item, roles)
	if err != nil {
		return err
	}
	return expectPostState(ctx, object)
}

func expectPostStateRecord(ctx context.Context, record *inodeRecord, roles uint32) error {
	object, err := expectedPostStateRecord(record, roles)
	if err != nil {
		return err
	}
	return expectPostState(ctx, object)
}

func expectPostStateIdentity(ctx context.Context, identity publicationIdentity, roles uint32) error {
	return expectPostState(ctx, expectedPostStateObject{identity: identity, roles: roles})
}

// expectPostState records the complete operation-derived identity/role set.
// The authority envelope is checked against this map after the callback has
// finished constructing all canonical records and before any reply bytes can
// be finalized. Opcode-only role validation cannot detect two live operands
// whose identities were swapped.
func expectPostState(ctx context.Context, objects ...expectedPostStateObject) error {
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		return errors.New("fusev3: exact post-state expectation escaped its reply lifecycle")
	}
	if publication.expectedPostState == nil {
		publication.expectedPostState = make(map[publicationIdentity]uint32, len(objects))
	}
	for _, object := range objects {
		if object.identity == (publicationIdentity{}) || object.roles == 0 || object.roles&^postStateKnownRoles != 0 {
			return errors.New("fusev3: exact post-state expectation has an invalid live operand")
		}
		publication.expectedPostState[object.identity] |= object.roles
	}
	return nil
}

func validateExpectedPostState(publication *replyPublication) error {
	if publication == nil || len(publication.expectedPostState) == 0 {
		return nil
	}
	state := publication.postState
	if state == nil {
		if publication.needsPostVFS {
			return errors.New("fusev3: applied mutation omitted its exact post-state")
		}
		return nil
	}
	if len(state.GetObjects()) != len(publication.expectedPostState) {
		return errors.New("fusev3: mutation post-state identity count does not match its operands")
	}
	for _, object := range state.GetObjects() {
		identity, ok := publicationIdentityFromBytes(object.GetStableIdentity())
		if !ok || publication.expectedPostState[identity] != object.GetRoles() {
			return errors.New("fusev3: mutation post-state identity/role set does not match its operands")
		}
	}
	return nil
}

func responsePostAttr(response *authoritypb.Response, requiredRoles uint32) *authoritypb.Attr {
	if response == nil || validateMutationPostState(response.GetPostState()) != nil {
		return nil
	}
	for _, object := range response.GetPostState().GetObjects() {
		if object.GetRoles()&requiredRoles == requiredRoles {
			return object.GetAttr()
		}
	}
	return nil
}
