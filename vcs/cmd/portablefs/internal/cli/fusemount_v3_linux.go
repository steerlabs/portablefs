//go:build linux

package cli

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/mountlog"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
)

// fuseV3Config is everything the v3 engine needs to attach and mount. The
// caller owns mountpoint validation, lifecycle records, and teardown.
type fuseV3Config struct {
	addr            string
	token           string
	transport       dataPlaneTransport
	identity        *clientTLSIdentity
	volumeID        string
	mountPath       string
	mountInstanceID string
	// backingRoot is the per-machine tree that serves the volume's declared
	// machine-local routes; used only when the adopted rule set is non-empty.
	backingRoot            string
	requireMountEnrollment bool
	// onRevoked observes this mount's self-revocation. It is handed to the
	// engine at construction because a strict mount can revoke before
	// MountVolume returns, and the supervisor's whole job here is to persist a
	// verdict it might otherwise never hear.
	onRevoked func(mountRevocation)
}

// fuseRevocation translates the engine's report into the platform-neutral
// verdict the supervisor persists. The withdrawal failures are folded into the
// detail sentence because they are the operator-facing consequence: a
// revocation whose kernel state could not be withdrawn leaves a dead FUSE mount
// installed in this namespace, which no amount of status reporting removes.
func fuseRevocation(report fusev3.RevocationReport) mountRevocation {
	detail := report.Cause
	if !report.KernelStateWithdrawn {
		detail += " [kernel state not withdrawn: the revoked FUSE mount is still installed"
		if len(report.Withdrawal) > 0 {
			detail += "; " + strings.Join(report.Withdrawal, "; ")
		}
		detail += "]"
	}
	return mountRevocation{
		reason:               report.Reason,
		detail:               detail,
		kernelStateWithdrawn: report.KernelStateWithdrawn,
	}
}

// fuseV3Mount is one live fusev3 kernel mount plus the routing it was
// admitted with.
type fuseV3Mount struct {
	renewalMu   sync.Mutex
	managed     bool
	checkPermit func(mountenrollment.Permit) bool
	mount       *fusev3.Mount
	client      *authorityrpc.Client
	// routes is the volume-declared route set this mount serves and the
	// declaration revision the authority pinned the attach to. Never
	// per-machine: the v3 attach protocol admits only the volume's topology.
	routes  mountRoutes
	backing string
}

func (m *fuseV3Mount) Unmount() error { return m.mount.Unmount() }
func (m *fuseV3Mount) Wait()          { m.mount.Wait() }
func (m *fuseV3Mount) Close() error   { return m.mount.Close() }
func (m *fuseV3Mount) WritebackStats() *mountlog.WritebackStats {
	s := m.mount.WritebackStats()
	return &mountlog.WritebackStats{
		DirtyBytes: s.DirtyBytes, DirtyEntries: s.DirtyEntries,
		RetainedBytes: s.RetainedBytes, RetainedEntries: s.RetainedEntries,
		PendingAdmissions: s.PendingAdmissions, FlushingIdentities: s.FlushingIdentities,
		ScheduledIdentities: s.ScheduledIdentities, TrackedIdentities: s.TrackedIdentities,
		BufferIdentities: s.BufferIdentities, PendingCloses: s.PendingCloses,
		DurabilityLag: s.DurabilityLag, LossSequence: s.LossSequence,
	}
}
func (m *fuseV3Mount) AuthorizationSessionID() string {
	id := m.client.AuthorizationSessionID()
	empty := true
	for _, value := range id {
		empty = empty && value == 0
	}
	if empty {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(id[:])
}
func (m *fuseV3Mount) AuthorizationDeadline() time.Time { return m.client.AuthorizationDeadline() }
func (m *fuseV3Mount) InitialAuthorizationDeadline() time.Time {
	return m.client.InitialAuthorizationDeadline()
}
func (m *fuseV3Mount) Reauthorize(ctx context.Context, token string, sequence uint64, certificatePEM []byte) (time.Time, error) {
	m.renewalMu.Lock()
	defer m.renewalMu.Unlock()
	permitted := func() bool {
		if !m.managed {
			return true
		}
		p, ok := mountenrollment.PermitFromContext(ctx)
		return ok && m.checkPermit != nil && m.checkPermit(p)
	}
	if !permitted() {
		return time.Time{}, errors.New("managed reauthorization requires current generation/serial permit")
	}
	session, changed, err := m.mount.CurrentAuthorizationSession()
	if err != nil {
		return time.Time{}, err
	}
	if session.AuthorizationSessionID() != m.client.AuthorizationSessionID() {
		return time.Time{}, fmt.Errorf("reauthorization session changed: %w", mountenrollment.ErrDefinitiveDenial)
	}
	deadline, err := m.client.ReauthorizeWithCertificate(ctx, []byte(token), sequence, certificatePEM, time.Now())
	if err != nil {
		return deadline, err
	}
	select {
	case <-changed:
		return deadline, mountenrollment.ErrSessionChangedInstallation
	default:
	}
	if !permitted() {
		return deadline, mountenrollment.ErrPermitClosedInstallation
	}
	return deadline, nil
}

// mountFUSEv3 attaches the authority under the exact declared transport and
// installs the fusev3 kernel mount. One attach, one capability: routing is
// adopted from the attach refusal when the volume declares it (see
// mountv3.AttachWithRoutes), never read over a second session.
//
// authorityAttached stays true even when later startup fails. That distinction
// keeps a Manager enrollment alive when cleanup is ambiguous, while a failure
// before attach can close an enrollment that was never handed to a session.
// startupClean is decided at the failed attach or kernel-startup boundary before
// callers add diagnostics; later error-tree members cannot certify release.
func mountFUSEv3(ctx context.Context, cfg fuseV3Config) (_ *fuseV3Mount, authorityAttached, startupClean bool, _ error) {
	tlsCfg, err := cfg.transport.tlsConfig()
	if err != nil {
		return nil, false, false, fmt.Errorf("data-plane transport: %w", err)
	}
	if tlsCfg == nil {
		// Refused earlier by flag validation; kept as a structural guard so the
		// dial below can never run without endpoint verification.
		return nil, false, false, fmt.Errorf("v3 authority sessions require mutually authenticated TLS; %q cannot carry one", cfg.transport.Mode)
	}
	tlsCfg.Certificates = []tls.Certificate{cfg.identity.certificate}
	preKernelAbsence, err := mountv3.PreKernelMountAbsenceObserver(cfg.mountPath, cfg.mountInstanceID)
	if err != nil {
		return nil, false, false, fmt.Errorf("bind pre-kernel mount-absence observer: %w", err)
	}
	attach := authorityrpc.ClientConfig{
		Purpose:         authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX,
		Address:         cfg.addr, TLS: tlsCfg, VolumeID: cfg.volumeID,
		AccessToken: []byte(cfg.token), ReplaySlots: mountv3.ReplaySlots,
		MaxFrame: mountv3.MaxFrame, DialTimeout: mountv3.DialTimeout,
		CancelDrainTimeout: mountv3.CancelDrainTimeout, MaxInFlight: mountv3.MaxInFlight,
		RequireMountEnrollmentReauthorization: cfg.requireMountEnrollment,
		ObservePreKernelMountAbsence:          preKernelAbsence,
	}
	client, rules, err := mountv3.AttachWithRoutes(ctx, attach, true)
	if err != nil {
		// A routing refusal names both revisions and the volume's declaration.
		// It is surfaced exactly as it arrived: the operator is told what the
		// volume routes and what this mount asked for, and retrying in a loop
		// against a volume that is being reconfigured is not an answer.
		var failure *authorityrpc.AttachError
		// Missing classification is cleanup debt, never evidence of no ownership.
		retained, clean := true, false
		if errors.As(err, &failure) {
			retained = failure.Disposition != authorityrpc.AttachNotCommitted && failure.Disposition != authorityrpc.AttachReleased
			clean = failure.Disposition == authorityrpc.AttachReleased
		}
		return nil, retained, clean, err
	}
	backing := ""
	if !rules.Empty() {
		backing = cfg.backingRoot
	}
	transport := mountv3.NewTransport(client)
	mount, err := fusev3.MountVolume(context.Background(), ctx, cfg.mountPath, transport, fusev3.Config{
		// The mount core derives "portablefs:<mountInstanceID>", the same
		// instance-bound kernel source mount_identity_linux.go verifies.
		MountInstanceID: cfg.mountInstanceID, RequestTimeout: mountv3.RequestTimeout,
		// The published record, local renewal socket, and Manager enrollment
		// all belong to this exact session. Replacement requires fresh owner
		// authorization, after this mount proves its own withdrawal.
		RequireRemountOnEpochChange: true,
		MaxBackground:               mountv3.MaxInFlight, MaxInFlight: mountv3.MaxInFlight, ReclaimQueue: mountv3.ReclaimQueue,
		PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid()),
		NameCacheCapacity: mountv3.NameCacheCapacity, WithdrawalTimeout: mountv3.WithdrawalTimeout,
		Routes: rules, LocalBacking: backing,
		OnRevoked: func(report fusev3.RevocationReport) {
			if cfg.onRevoked != nil {
				cfg.onRevoked(fuseRevocation(report))
			}
		},
	})
	if err != nil {
		// MountVolume owns the ACTIVE session as soon as it is called. Its
		// failed-startup path supplies the same exact source-bound absence proof
		// and closes the client, so a second release here would be a second
		// lifecycle transition rather than cleanup.
		return nil, true, fusev3.FailedStartupClean(err), fmt.Errorf("mount %s: %w", cfg.mountPath, err)
	}
	return &fuseV3Mount{
		mount:  mount,
		client: client,
		routes: mountRoutes{
			rules:    rules,
			revision: rules.RevisionHex(),
			declared: !rules.Empty(),
		},
		backing: backing,
	}, true, false, nil
}
