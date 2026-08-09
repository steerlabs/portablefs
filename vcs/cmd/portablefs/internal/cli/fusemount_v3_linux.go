//go:build linux

package cli

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
)

// The Linux mount engine: one strict (or uncached) fusev3 session against the
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
func mountFUSEv3(cfg fuseV3Config) (*fuseV3Mount, error) {
	profile, wireProfile, err := mountv3.Profile(cfg.coherence)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := cfg.transport.tlsConfig()
	if err != nil {
		return nil, fmt.Errorf("data-plane transport: %w", err)
	}
	if tlsCfg == nil {
		// Refused earlier by flag validation; kept as a structural guard so the
		// dial below can never run without endpoint verification.
		return nil, fmt.Errorf("v3 authority sessions require mutually authenticated TLS; %q cannot carry one", cfg.transport.Mode)
	}
	tlsCfg.Certificates = []tls.Certificate{cfg.identity.certificate}
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
	}
	// How this frontend's kernel makes a cached binding unservable. It is
	// declared rather than inferred because the authority cannot observe a
	// remote kernel, and on Linux FUSE the answer is load-bearing: making a
	// binding unservable takes the parent directory's i_rwsem for write, which
	// is the same lock a namespace syscall holds across the whole authority
	// round trip. Saying so is what lets the authority tell a provably closed
	// repair cycle apart from an ordinary slow lock, and fence one participant
	// immediately instead of stalling the volume for a whole repair budget.
	if profile == fusev3.CoherenceStrict {
		attach.NamespaceRepair = authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE
	}
	client, rules, err := mountv3.AttachWithRoutes(context.Background(), attach, !cfg.noLocalDirs)
	if err != nil {
		// A routing refusal names both revisions and the volume's declaration.
		// It is surfaced exactly as it arrived: the operator is told what the
		// volume routes and what this mount asked for, and retrying in a loop
		// against a volume that is being reconfigured is not an answer.
		return nil, err
	}
	backing := ""
	if !rules.Empty() {
		backing = cfg.backingRoot
	}
	transport, err := mountv3.NewTransport(client, profile)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	mount, err := fusev3.MountVolume(context.Background(), cfg.mountPath, transport, fusev3.Config{
		// The kernel source is "portablefs:<mountInstanceID>": the same
		// instance-bound identity the legacy engine records, so the exact-mount
		// classification in mount_identity_linux.go holds for both engines.
		FSName: "portablefs:" + cfg.mountInstanceID, RequestTimeout: mountv3.RequestTimeout,
		MaxBackground: mountv3.MaxInFlight, MaxInFlight: mountv3.MaxInFlight, ReclaimQueue: mountv3.ReclaimQueue,
		PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid()),
		Coherence: profile, CachedNameCapacity: mountv3.CachedNameCapacity, RepairBudget: mountv3.RepairBudget,
		Routes: rules, LocalBacking: backing,
	})
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("mount %s: %w", cfg.mountPath, err)
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
	}, nil
}
