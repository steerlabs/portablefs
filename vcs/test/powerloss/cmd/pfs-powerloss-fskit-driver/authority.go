package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/test/powerloss"
)

// writeKillSUIDGID is the stock FUSE_WRITE_KILL_SUIDGID bit portablefsd sets
// on every FSKit WRITE.
const writeKillSUIDGID uint32 = 1 << 2

// authorityVolume issues each workload mutation as the exact FSKit-profile
// request portablefsd sends for the corresponding FSKit callback, on a session
// attached and activated with FRONTEND_PROFILE_FSKIT_EXCLUSIVE. Nothing sits
// between it and the real authority handler: no daemon cache, no extension,
// no kernel. That is the point of the instrument - the durability claim under
// test belongs to the handler, and only the handler is in the path.
type authorityVolume struct {
	client   *authorityrpc.Client
	maxWrite uint32
	// items holds the capability each workload label was acquired as; the
	// root is the empty label.
	items map[string]*authoritypb.Item
	// handles holds the read/write description CREATE returned per file.
	handles map[string][]byte
	// acquired lists every item capability the session obtained, including
	// LINK's, so Release can return all of them.
	acquired [][]byte
}

func newAuthorityVolume(client *authorityrpc.Client) (*authorityVolume, error) {
	root := client.Root()
	if root == nil || len(root.GetToken()) == 0 {
		return nil, errors.New("the activated session carries no root capability")
	}
	_, maxWrite := client.IOLimits()
	return &authorityVolume{
		client: client, maxWrite: maxWrite,
		items:   map[string]*authoritypb.Item{"": root},
		handles: map[string][]byte{},
	}, nil
}

// mutate sends one mutation and admits only the complete success shape as an
// acknowledgement: no errno, no uncertainty or failure class, and a recorded
// replay outcome. Anything else is a failed step, never a partial claim.
func (v *authorityVolume) mutate(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	response, err := v.client.CallMutation(ctx, request)
	if err != nil {
		return nil, err
	}
	switch {
	case response.GetErrno() != 0:
		return nil, fmt.Errorf("the authority refused it: %w", syscall.Errno(response.GetErrno()))
	case response.GetUncertain() || response.GetSessionTerminal():
		return nil, errors.New("the authority reported an uncertain or session-terminal outcome")
	case response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED:
		return nil, fmt.Errorf("the authority reported failure class %s with a success errno", response.GetFailure())
	case response.GetMutation() == nil:
		return nil, errors.New("the success reply carries no recorded replay outcome, so it is not an acknowledgement a Mac could rely on")
	}
	return response, nil
}

func (v *authorityVolume) item(t target) (*authoritypb.Item, error) {
	item, exists := v.items[t.label]
	if !exists {
		return nil, fmt.Errorf("no capability is held for object %q", t.label)
	}
	return item, nil
}

func (v *authorityVolume) adopt(label string, item *authoritypb.Item) (observed, error) {
	if item == nil || len(item.GetToken()) == 0 || len(item.GetStableIdentity()) == 0 || item.GetAttr() == nil {
		return observed{}, errors.New("the success reply omitted the created item")
	}
	v.items[label] = item
	v.acquired = append(v.acquired, item.GetToken())
	return fromAttr(item.GetAttr())
}

func (v *authorityVolume) Mkdir(ctx context.Context, parent target, name string, mode uint32, created string) (observed, error) {
	directory, err := v.item(parent)
	if err != nil {
		return observed{}, err
	}
	response, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{
		Parent: directory.GetToken(), Name: []byte(name), Mode: mode,
	}}})
	if err != nil {
		return observed{}, err
	}
	return v.adopt(created, response.GetMkdir().GetItem())
}

func (v *authorityVolume) Create(ctx context.Context, parent target, name string, mode uint32, created string) (observed, error) {
	directory, err := v.item(parent)
	if err != nil {
		return observed{}, err
	}
	response, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: directory.GetToken(), Name: []byte(name), Mode: mode,
		Flags: &authoritypb.OpenFlags{Read: true, Write: true}, Exclusive: true,
	}}})
	if err != nil {
		return observed{}, err
	}
	if len(response.GetCreate().GetHandle()) == 0 {
		return observed{}, errors.New("the CREATE reply omitted its open description")
	}
	got, err := v.adopt(created, response.GetCreate().GetItem())
	if err != nil {
		return observed{}, err
	}
	v.handles[created] = response.GetCreate().GetHandle()
	return got, nil
}

// Write is portablefsd's direct positioned WRITE: no append intent, no
// per-call sync flags and no delegation fields, because the FSKit profile
// makes every acknowledged WRITE durable on its own.
func (v *authorityVolume) Write(ctx context.Context, file target, offset int64, data []byte) (observed, error) {
	handle, exists := v.handles[file.label]
	if !exists {
		return observed{}, fmt.Errorf("no open description is held for %q", file.label)
	}
	if offset < 0 || len(data) == 0 || uint64(len(data)) > uint64(v.maxWrite) {
		return observed{}, fmt.Errorf("a %d-byte write does not fit the negotiated %d-byte limit", len(data), v.maxWrite)
	}
	response, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
		Handle: handle, Position: uint64(offset), Size: uint32(len(data)), Data: data, WriteFlags: writeKillSUIDGID,
	}}})
	if err != nil {
		return observed{}, err
	}
	reply := response.GetWrite()
	if reply.GetError() != 0 || reply.GetCommittedSize() != uint64(len(data)) || reply.GetAssignedOffset() != uint64(offset) || reply.GetPostAttr() == nil {
		return observed{}, fmt.Errorf("the WRITE reply did not commit exactly [%d, %d): error %d, committed %d at %d",
			offset, offset+int64(len(data)), reply.GetError(), reply.GetCommittedSize(), reply.GetAssignedOffset())
	}
	return fromAttr(reply.GetPostAttr())
}

// setAttr sends one SETATTR and returns the target's attributes from the
// reply's PostState, which is where an FSKit SETATTR reports them.
func (v *authorityVolume) setAttr(ctx context.Context, item *authoritypb.Item, set *authoritypb.SetAttrRequest) (observed, error) {
	set.Item = item.GetToken()
	response, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: set}})
	if err != nil {
		return observed{}, err
	}
	for _, object := range response.GetPostState().GetObjects() {
		if bytes.Equal(object.GetStableIdentity(), item.GetStableIdentity()) && object.GetAttr() != nil {
			return fromAttr(object.GetAttr())
		}
	}
	return observed{}, errors.New("the SETATTR reply's PostState does not describe its target")
}

func (v *authorityVolume) Truncate(ctx context.Context, file target, size int64, throughHandle bool) (observed, error) {
	item, err := v.item(file)
	if err != nil {
		return observed{}, err
	}
	set := &authoritypb.SetAttrRequest{Size: &size}
	if throughHandle {
		handle, exists := v.handles[file.label]
		if !exists {
			return observed{}, fmt.Errorf("no open description is held for %q", file.label)
		}
		set.Handle = handle
	}
	return v.setAttr(ctx, item, set)
}

func (v *authorityVolume) Chmod(ctx context.Context, object target, mode uint32) (observed, error) {
	item, err := v.item(object)
	if err != nil {
		return observed{}, err
	}
	return v.setAttr(ctx, item, &authoritypb.SetAttrRequest{Mode: &mode})
}

func (v *authorityVolume) SetTimes(ctx context.Context, object target, atimeNs, mtimeNs int64) (observed, error) {
	item, err := v.item(object)
	if err != nil {
		return observed{}, err
	}
	return v.setAttr(ctx, item, &authoritypb.SetAttrRequest{AtimeNs: &atimeNs, MtimeNs: &mtimeNs})
}

func (v *authorityVolume) Link(ctx context.Context, object, parent target, name string) (observed, error) {
	item, err := v.item(object)
	if err != nil {
		return observed{}, err
	}
	directory, err := v.item(parent)
	if err != nil {
		return observed{}, err
	}
	response, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{
		ExistingItem: item.GetToken(), NewParent: directory.GetToken(), NewName: []byte(name),
	}}})
	if err != nil {
		return observed{}, err
	}
	linked := response.GetLink().GetItem()
	if linked == nil || len(linked.GetToken()) == 0 || linked.GetAttr() == nil {
		return observed{}, errors.New("the LINK reply omitted its item")
	}
	if !bytes.Equal(linked.GetStableIdentity(), item.GetStableIdentity()) {
		return observed{}, errors.New("the LINK reply names a different object than the one linked")
	}
	v.acquired = append(v.acquired, linked.GetToken())
	return fromAttr(linked.GetAttr())
}

func (v *authorityVolume) Symlink(ctx context.Context, parent target, name, linkTarget, created string) (observed, error) {
	directory, err := v.item(parent)
	if err != nil {
		return observed{}, err
	}
	response, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{
		Parent: directory.GetToken(), Name: []byte(name), Target: []byte(linkTarget),
	}}})
	if err != nil {
		return observed{}, err
	}
	return v.adopt(created, response.GetLookup().GetItem())
}

func (v *authorityVolume) Rename(ctx context.Context, oldParent target, oldName string, newParent target, newName string) error {
	from, err := v.item(oldParent)
	if err != nil {
		return err
	}
	to, err := v.item(newParent)
	if err != nil {
		return err
	}
	response, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
		OldParent: from.GetToken(), OldName: []byte(oldName), NewParent: to.GetToken(), NewName: []byte(newName),
	}}})
	if err != nil {
		return err
	}
	if len(response.GetRename().GetNewPostIdentity()) == 0 {
		return errors.New("the RENAME reply omitted the moved object's identity")
	}
	return nil
}

func (v *authorityVolume) Unlink(ctx context.Context, parent target, name string, directory bool) error {
	from, err := v.item(parent)
	if err != nil {
		return err
	}
	_, err = v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{
		Parent: from.GetToken(), Name: []byte(name), Directory: directory,
	}}})
	return err
}

// Release mirrors portablefsd's release owner: open descriptions retire in one
// CLOSE_BATCH - the FSKit profile has no individual CLOSE - and then every
// item capability retires in one batched Reclaim.
func (v *authorityVolume) Release(ctx context.Context) error {
	labels := make([]string, 0, len(v.handles))
	for label := range v.handles {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	if len(labels) != 0 {
		batch := &authoritypb.CloseBatchRequest{}
		for _, label := range labels {
			batch.Closes = append(batch.Closes, &authoritypb.CloseRequest{Handle: v.handles[label]})
		}
		response, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_CloseBatch{CloseBatch: batch}})
		if err != nil {
			return fmt.Errorf("CLOSE_BATCH of %d descriptions: %w", len(labels), err)
		}
		results := response.GetCloseBatch().GetResults()
		if len(results) != len(labels) {
			return fmt.Errorf("CLOSE_BATCH of %d descriptions returned %d results", len(labels), len(results))
		}
		for index, result := range results {
			if result.GetErrno() != 0 || result.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED {
				return fmt.Errorf("CLOSE_BATCH refused the description of %q: errno %d, failure %s", labels[index], result.GetErrno(), result.GetFailure())
			}
		}
		v.handles = map[string][]byte{}
	}
	var tokens [][]byte
	seen := map[string]bool{}
	for _, token := range v.acquired {
		if !seen[string(token)] {
			seen[string(token)] = true
			tokens = append(tokens, token)
		}
	}
	if len(tokens) != 0 {
		if _, err := v.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: tokens}}}); err != nil {
			return fmt.Errorf("Reclaim of %d capabilities: %w", len(tokens), err)
		}
		v.acquired = nil
	}
	return nil
}

func fromAttr(attr *authoritypb.Attr) (observed, error) {
	got := observed{
		mode: attr.GetMode() & 0o7777, size: attr.GetSize(), links: attr.GetNlink(),
		atimeNs: attr.GetAtimeNs(), mtimeNs: attr.GetMtimeNs(),
	}
	switch attr.GetKind() {
	case authoritypb.Attr_REGULAR:
		got.kind = powerloss.ObjectFile
	case authoritypb.Attr_DIRECTORY:
		got.kind = powerloss.ObjectDirectory
	case authoritypb.Attr_SYMLINK:
		got.kind = powerloss.ObjectSymlink
	default:
		return observed{}, fmt.Errorf("the authority reported an object of unknown kind %s", attr.GetKind())
	}
	return got, nil
}
