//go:build linux

package authorityrpc

import (
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"syscall"
	"testing"
)

// Historical lease fields remain decodable, but no frontend can execute them
// in protocol 7. This replaces tests of removed v6 grant/discharge machinery.
func TestProtocol7RefusesHistoricalLeaseHandlers(t *testing.T) {
	requests := []*authoritypb.Request{
		{Body: &authoritypb.Request_NextLeaseEvent{NextLeaseEvent: &authoritypb.NextLeaseEventRequest{}}},
		{Body: &authoritypb.Request_RenewLeases{RenewLeases: &authoritypb.RenewLeasesRequest{}}},
		{Body: &authoritypb.Request_AcknowledgeLeaseEvent{AcknowledgeLeaseEvent: &authoritypb.AcknowledgeLeaseEventRequest{}}},
		{Body: &authoritypb.Request_AcknowledgeSourceLeaseDischarge{AcknowledgeSourceLeaseDischarge: &authoritypb.AcknowledgeSourceLeaseDischargeRequest{}}},
	}
	h, ctx, cred, _ := resourceAdmissionRequestHarness(t, &resourceAdmissionFaultStore{}, 8, 8)
	for _, req := range requests {
		req.RequestId = 1
		req.Epoch = cred.Epoch[:]
		req.Session = &authoritypb.SessionProof{Id: cred.ID[:], ResumeSecret: cred.Secret[:], Generation: cred.Generation}
		response := h.Handle(ctx, req)
		if response.GetErrno() != int32(syscall.EOPNOTSUPP) || len(response.GetLeaseGrants()) != 0 || response.GetSourceLeaseDischarge() != nil {
			t.Fatalf("%T was honoured: %v", req.GetBody(), response)
		}
		if requestAllowedForFrontend(req, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR) {
			t.Fatalf("FSKit admitted %T", req.GetBody())
		}
	}
}
