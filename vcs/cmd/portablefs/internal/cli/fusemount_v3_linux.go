//go:build linux

package cli

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
)

// The Linux mount engine: one strict fusev3 session against the
// v3 XFS authority. This replaces the legacy clientcore FUSE engine for
// `portablefs mount`; the lifecycle contract around it — canonical state
// root, mount records, locks, exact unmount — is unchanged and lives in
// runMountForeground.
//
// One honest asymmetry with the legacy engine: fusev3 owns its kernel-mount
// edge (go-fuse resolves the fusermount helper itself), so the host-facts
// mechanism the record carries governs the exact UNMOUNT — direct umount(2)
// or the validated root-managed helper — rather than selecting how the mount
// syscall is issued. The recorded kernel identity checks are unchanged, so
// unmount still refuses anything but the exact recorded mount.

// fuseV3Config is everything the v3 engine needs to attach and mount. The
// caller owns mountpoint validation, lifecycle records, and teardown.
type fuseV3Config struct {
	addr            string
	token           string
	transport       dataPlaneTransport
	identity        *clientTLSIdentity
	coherence       string
	volumeID        string
	mountPath       string
	mountInstanceID string
	// backingRoot is the per-machine tree that serves the volume's declared
	// machine-local routes; used only when the adopted rule set is non-empty.
	backingRoot string
	// noLocalDirs refuses a volume that declares machine-local routes instead
	// of serving them (adopt=false in the attach protocol).
	noLocalDirs            bool
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
	mount  *fusev3.Mount
	client *authorityrpc.Client
	// routes is the volume-declared route set this mount serves and the
	// declaration revision the authority pinned the attach to. Never
	// per-machine: the v3 attach protocol admits only the volume's topology.
	routes  mountRoutes
	backing string
}

func (m *fuseV3Mount) Unmount() error { return m.mount.Unmount() }
func (m *fuseV3Mount) Wait()          { m.mount.Wait() }
func (m *fuseV3Mount) Close() error   { return m.mount.Close() }
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
func (m *fuseV3Mount) InitialAuthorizationDeadline() time.Time {
	return m.client.InitialAuthorizationDeadline()
}
func (m *fuseV3Mount) Reauthorize(ctx context.Context, token string, sequence uint64, certificatePEM []byte) (time.Time, error) {
	return m.client.ReauthorizeWithCertificate(ctx, []byte(token), sequence, certificatePEM, time.Now())
}

// mountFUSEv3 attaches the authority under the exact declared transport and
// installs the fusev3 kernel mount. One attach, one capability: routing is
// adopted from the attach refusal when the volume declares it (see
// mountv3.AttachWithRoutes), never read over a second session.
//
// authorityAttached stays true even when later startup fails. That distinction
// keeps a Manager enrollment alive when cleanup is ambiguous, while a failure
// before attach can close an enrollment that was never handed to a session.
func mountFUSEv3(cfg fuseV3Config) (_ *fuseV3Mount, authorityAttached bool, _ error) {
	profile, wireProfile, err := mountv3.Profile(cfg.coherence)
	if err != nil {
		return nil, false, err
	}
	tlsCfg, err := cfg.transport.tlsConfig()
	if err != nil {
		return nil, false, fmt.Errorf("data-plane transport: %w", err)
	}
	if tlsCfg == nil {
		// Refused earlier by flag validation; kept as a structural guard so the
		// dial below can never run without endpoint verification.
		return nil, false, fmt.Errorf("v3 authority sessions require mutually authenticated TLS; %q cannot carry one", cfg.transport.Mode)
	}
	tlsCfg.Certificates = []tls.Certificate{cfg.identity.certificate}
	preKernelAbsence, err := mountv3.PreKernelMountAbsenceObserver(cfg.mountPath, cfg.mountInstanceID)
	if err != nil {
		return nil, false, fmt.Errorf("bind pre-kernel mount-absence observer: %w", err)
	}
	attach := authorityrpc.ClientConfig{
		Address: cfg.addr, TLS: tlsCfg, VolumeID: cfg.volumeID,
		AccessToken: []byte(cfg.token), ReplaySlots: mountv3.ReplaySlots,
		MaxFrame: mountv3.MaxFrame, DialTimeout: mountv3.DialTimeout,
		CancelDrainTimeout: mountv3.CancelDrainTimeout, MaxInFlight: mountv3.MaxInFlight,
		RequireMountEnrollmentReauthorization: cfg.requireMountEnrollment,
		// The two numbers a strict mount declares are the two the authority
		// needs to size the barrier: how much cached state this frontend can be
		// holding, and how long it may take to withdraw it.
		CoherenceProfile: wireProfile, CachedNameCapacity: mountv3.CachedNameCapacity, RepairBudget: mountv3.RepairBudget,
		ObservePreKernelMountAbsence: preKernelAbsence,
	}
	// How this frontend's kernel makes a cached binding unservable. It is
	// declared rather than inferred because the authority cannot observe a
	// remote kernel. The strict Linux answer is load-bearing: its private
	// reverse notification expires one exact binding under dcache locks without
	// taking the parent inode's i_rwsem. A stock parent-lock implementation is
	// refused rather than translated into synthetic application EINTR.
	attach.NamespaceRepair = authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION
	client, rules, err := mountv3.AttachWithRoutes(context.Background(), attach, !cfg.noLocalDirs)
	if err != nil {
		// A routing refusal names both revisions and the volume's declaration.
		// It is surfaced exactly as it arrived: the operator is told what the
		// volume routes and what this mount asked for, and retrying in a loop
		// against a volume that is being reconfigured is not an answer.
		return nil, false, err
	}
	backing := ""
	if !rules.Empty() {
		backing = cfg.backingRoot
	}
	transport := mountv3.NewTransport(client)
	mount, err := fusev3.MountVolume(context.Background(), cfg.mountPath, transport, fusev3.Config{
		// The mount core derives "portablefs:<mountInstanceID>", the same
		// instance-bound kernel source mount_identity_linux.go verifies.
		MountInstanceID: cfg.mountInstanceID, RequestTimeout: mountv3.RequestTimeout,
		MaxBackground: mountv3.MaxInFlight, MaxInFlight: mountv3.MaxInFlight, ReclaimQueue: mountv3.ReclaimQueue,
		PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid()),
		Coherence: profile, CachedNameCapacity: mountv3.CachedNameCapacity, RepairBudget: mountv3.RepairBudget,
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
		return nil, true, fmt.Errorf("mount %s: %w", cfg.mountPath, err)
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
	}, true, nil
}

func failedFUSEStartupClean(err error) bool {
	return fusev3.FailedStartupClean(err)
}
