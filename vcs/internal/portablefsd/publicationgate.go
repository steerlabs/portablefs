package portablefsd

import "github.com/steerlabs/portablefs/vcs/internal/pfslocal"

// FSKit reserves inode values 0, 1, and 2 for invalid, parent-of-root, and
// root. The Swift adapter exposes every durable pfslocal item ID through the
// checked successor mapping (root 1 -> 2), so kernel-side identity proofs must
// apply the exact same boundary translation.
func fskitItemID(itemID uint64) (uint64, bool) {
	if itemID == 0 || itemID == ^uint64(0) {
		return 0, false
	}
	return itemID + 1, true
}

// frontendRequestPublishes is the Go-side copy of the frozen pfslocal
// publication classification. These requests may install namespace,
// metadata, xattr, or content state in a frontend cache and therefore require
// a logical operation ID and one post-callback acknowledgement.
func frontendRequestPublishes(body any) bool {
	switch body.(type) {
	case *pfslocal.LookupRequest,
		*pfslocal.EnumerateEntriesRequest,
		*pfslocal.GetAttrRequest,
		*pfslocal.SetAttrRequest,
		*pfslocal.ReadRequest,
		*pfslocal.WriteRequest,
		*pfslocal.CreateRequest,
		*pfslocal.MkdirRequest,
		*pfslocal.RemoveRequest,
		*pfslocal.RenameRequest,
		*pfslocal.SymlinkRequest,
		*pfslocal.ReadlinkRequest,
		*pfslocal.HardLinkRequest,
		*pfslocal.XattrGetRequest,
		*pfslocal.XattrSetRequest,
		*pfslocal.XattrListRequest,
		*pfslocal.XattrRemoveRequest:
		return true
	default:
		return false
	}
}
