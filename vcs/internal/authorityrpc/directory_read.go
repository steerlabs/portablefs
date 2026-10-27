package authorityrpc

import (
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func validDirectoryReadRequest(open *authoritypb.OpenRequest) bool {
	f := open.GetFlags()
	return f.GetRead() && !f.GetWrite() && !f.GetAppend() && !f.GetTruncate() && !f.GetSync() && !f.GetDataSync() && !open.GetWriteIntent() && !open.GetCacheCapable()
}

func validDirectoryReadProof(response *authoritypb.Response) bool {
	open := response.GetOpen()
	p := open.GetDirectoryReadProof()
	return p != nil && response.GetErrno() == 0 && !response.GetUncertain() &&
		response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED &&
		validCoherenceIdentity(open.GetHandle()) && validCoherenceIdentity(p.GetStableIdentity()) &&
		p.GetIncarnation() != 0 && p.GetObjectVersion() != 0 && p.GetObjectVersion() <= p.GetSnapshotSequence() &&
		p.GetSnapshotSequence() == response.GetVolumeVersion() && open.GetDelegation() == nil && !open.GetCacheCapable()
}

// Request/reply binding is checked before replay ownership can be surrendered.
// The mount additionally binds the returned identity and incarnation to its
// exact Item and subscription cut; stable identity alone never admits an open.
func validateDirectoryReadResult(request *authoritypb.Request, response *authoritypb.Response) error {
	requested := request.GetOpen().GetReusableDirectoryReadIncarnation() != 0
	returned := response.GetOpen().GetDirectoryReadProof() != nil
	if returned && (!requested || !validDirectoryReadProof(response) || response.GetOpen().GetDirectoryReadProof().GetIncarnation() != request.GetOpen().GetReusableDirectoryReadIncarnation()) {
		return fmt.Errorf("%w: unrequested or invalid directory read proof", ErrTransportBinding)
	}
	if requested && response.GetErrno() == 0 && !response.GetUncertain() && !returned {
		return fmt.Errorf("%w: reusable directory open omitted its proof", ErrTransportBinding)
	}
	return nil
}
