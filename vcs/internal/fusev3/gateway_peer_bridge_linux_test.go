//go:build linux

package fusev3

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// GatewayPeerFixture is the integration fixture, re-exported for the external
// test package in this directory.
//
// The files gateway cannot be imported from package fusev3 at any strength:
// readonlyfs depends on mountv3, and mountv3 depends on this package, so a
// readonlyfs import here is an import cycle even from a test file. The test
// that qualifies the gateway against a real kernel mount therefore lives in
// package fusev3_test, which can import both. This type is the only thing that
// crosses that line: it exists so that test can drive the same fixture every
// other privileged test in this package drives, rather than reconstructing the
// authority, the XFS volume, and the mount from exported API and drifting from
// it. Nothing here adds capability -- every method forwards.
type GatewayPeerFixture struct {
	f *integrationFixture

	attachProfile atomic.Int32
}

// NewGatewayPeerFixture starts one authority over real XFS with mounts kernel
// FUSE mounts of it, and begins recording the frontend profile of every attach
// that arrives from now on -- which is every attach except the mounts', whose
// sessions are already established when this returns.
func NewGatewayPeerFixture(t *testing.T, mounts int) *GatewayPeerFixture {
	t.Helper()
	// Routes must stay empty: readonlyfs declares the empty rule set's revision,
	// and the authority refuses a participant whose revision is not the active
	// one.
	peer := &GatewayPeerFixture{f: newIntegrationFixture(t, integrationConfig{Mounts: mounts})}
	peer.attachProfile.Store(int32(authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED))
	peer.f.counter.setBeforeHandle(func(request *authoritypb.Request) {
		if attach := request.GetAttach(); attach != nil {
			peer.attachProfile.Store(int32(attach.GetFrontendProfile()))
		}
	})
	t.Cleanup(func() { peer.f.counter.setBeforeHandle(nil) })
	return peer
}

// AuthorityAddress is the dial target of the running authority.
func (p *GatewayPeerFixture) AuthorityAddress() string { return p.f.listener.Addr().String() }

// VolumeID is the volume every participant must declare.
func (p *GatewayPeerFixture) VolumeID() string { return integrationVolumeID }

// AuthorityCAPEM, ClientCertificatePEM, ClientPrivateKeyPEM and ServerName are
// the identity material a participant configured from a control-plane grant
// receives, rather than the assembled *tls.Config a mount binary builds.
func (p *GatewayPeerFixture) AuthorityCAPEM() []byte {
	return p.f.credentials.AuthorityCAPEM
}

func (p *GatewayPeerFixture) ClientCertificatePEM() []byte {
	return p.f.credentials.ClientCertificatePEM
}

func (p *GatewayPeerFixture) ClientPrivateKeyPEM() []byte {
	return p.f.credentials.ClientPrivateKeyPEM
}

func (p *GatewayPeerFixture) ServerName() string { return p.f.credentials.ServerName }

// Capability is the access token the fixture's authorizer accepts.
func (p *GatewayPeerFixture) Capability() []byte { return []byte("test-capability") }

// Join builds a host path to a volume object as seen through mount i.
func (p *GatewayPeerFixture) Join(i int, elements ...string) string {
	return p.f.join(i, elements...)
}

// RepairBudget is the per-phase budget every mount in this fixture declared. A
// frontend that does not discharge inside it is fenced, so it is the scale a
// claim about obstruction has to be measured against.
func (p *GatewayPeerFixture) RepairBudget() time.Duration { return integrationRepairBudget }

// LastAttachProfile is the frontend profile of the most recent attach the
// authority handled.
func (p *GatewayPeerFixture) LastAttachProfile() authoritypb.FrontendProfile {
	return authoritypb.FrontendProfile(p.attachProfile.Load())
}

// SyncRepairProfile names the profile a non-caching frontend declares.
func SyncRepairProfile() authoritypb.FrontendProfile {
	return authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR
}

// ActiveParticipants is the number of sessions currently in the volume's
// durable visibility membership.
func (p *GatewayPeerFixture) ActiveParticipants() int { return p.f.membership.activeCount() }

// FencedSessions is how many sessions the authority has fenced. Recall-budget
// exhaustion has no error return and no metric; this call is its only evidence.
func (p *GatewayPeerFixture) FencedSessions() int { return len(p.f.fencer.fenced()) }

// MountFatal is the terminal cause mount i's frontend recorded, or nil.
func (p *GatewayPeerFixture) MountFatal(i int) error { return p.f.mounts[i].fatalError() }

// Diagnostics describes every mount session, for failure messages.
func (p *GatewayPeerFixture) Diagnostics() string { return p.f.sessionDiagnostics() }
