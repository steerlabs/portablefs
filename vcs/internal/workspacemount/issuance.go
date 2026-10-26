package workspacemount

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

// inspectGrant adds refusal constraints; it never authenticates or authorizes a
// grant. The existing Manager/authority signature and single-use checks remain
// mandatory at Attach. Inspecting here prevents a valid grant for another
// guest's renewal scope/epoch from being installed under this guest identity.
func inspectGrant[T any](token string, limit int) (T, error) {
	var zero T
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" || len(token) > limit {
		return zero, errors.New("invalid workspace initial grant")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, errors.New("invalid workspace initial grant")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return zero, errors.New("invalid workspace initial grant")
	}
	value, err := hostctl.DecodeBounded[T](payload, limit)
	if err != nil {
		return zero, errors.New("invalid workspace initial grant")
	}
	return value, nil
}
func validateHostedScope(p *pb.Provision, guest, incarnation, spki []byte, epoch uint64) error {
	h := p.HostedEnrollment
	if h == nil {
		return nil
	}
	grant, err := inspectGrant[volumecap.Claims](string(p.Capability), 65536)
	if err != nil {
		return err
	}
	product, err := inspectGrant[productauth.Claims](grant.ProductAuthorization, 8192)
	if err != nil {
		return err
	}
	peer := sha256.Sum256(spki)
	expectedPeer := base64.RawURLEncoding.EncodeToString(peer[:])
	expectedScope := RenewalScope(&pb.IdentityReply{GuestUuid: guest, IdentityIncarnation: incarnation})
	if grant.VolumeID != p.Mount.VolumeId || grant.PeerSPKI != expectedPeer || grant.AuthorityID != p.ServerName || grant.AuthorityGeneration != h.AuthorityGeneration || grant.MountEnrollmentID != h.EnrollmentId || grant.SessionID != "" || grant.Sequence != 0 || grant.Expires != int64(h.AuthorizationDeadlineUnix) ||
		product.VolumeID != p.Mount.VolumeId || product.PeerSPKI != expectedPeer || product.RenewalScope != expectedScope || product.RenewalEpoch != epoch {
		return errors.New("initial grant does not bind the guest key, volume, scope, epoch and authority")
	}
	return nil
}
