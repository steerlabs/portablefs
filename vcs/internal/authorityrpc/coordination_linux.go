//go:build linux

package authorityrpc

import (
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// CoordinationConfig is the complete construction input for one volume's
// protocol-6 coordination. Every field is a safety property of the deployment,
// so none of them has a default a caller may inherit silently.
type CoordinationConfig struct {
	Store  *xfsstore.Volume
	Fencer volumeserver.SessionFencer
	Locks  *volumeserver.LockTable
	// Membership is the durable mount record. MountLifecycle is its only owner;
	// the visibility coordinator composes on top of it rather than writing it a
	// second time.
	Membership volumeserver.DurableVisibilityMembership
	Prior      volumeserver.PriorEpochDisposition
	ClockSkew  time.Duration

	MaxCachedNameCapacity uint64
	MaxRepairBudget       time.Duration

	CacheLeaseTTL            time.Duration
	MaxCacheLeasesPerSession uint32
	MaxCacheLeases           uint64

	Now       func() time.Time
	OnBarrier func(time.Duration, int)
}

// Coordination is a volume's complete protocol-6 coordination assembly.
//
// The four coordinators are one unit, not four independent options. The route
// controller needs the same durable mount lifecycle that admits mounts and the
// same lease table that owns cache authority, and an authority that has some of
// them is not a protocol-6 authority at all - it is one that refuses every
// route change or admits mounts nothing can recall. Assembling them here, once,
// is what keeps a test fixture and production from disagreeing about which
// parts a working authority has.
type Coordination struct {
	Store      *xfsstore.Volume
	Lifecycle  *volumeserver.MountLifecycle
	Visibility *volumeserver.VisibilityCoordinator
	Leases     *volumeserver.LeaseCoordinator
	Routes     *RoutesController
}

// NewCoordination assembles the volume's coordination and activates the routing
// revision the volume declares. A volume with no loaded revision cannot tell an
// agreeing mount from a disagreeing one, so a declaration that will not parse
// fails construction rather than admitting mounts against a topology this
// volume does not run.
func NewCoordination(cfg CoordinationConfig) (*Coordination, error) {
	if cfg.Store == nil || cfg.Fencer == nil || cfg.Locks == nil || cfg.Membership == nil {
		return nil, errors.New("authorityrpc: coordination needs the volume store, session fencer, epoch lock table, and durable membership")
	}
	lifecycle, err := volumeserver.NewMountLifecycle(volumeserver.MountLifecycleConfig{
		Membership: cfg.Membership, Prior: cfg.Prior, Now: cfg.Now, ClockSkew: cfg.ClockSkew,
	})
	if err != nil {
		return nil, err
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: cfg.Prior, ExternalMembership: true, Fencer: cfg.Fencer,
		MaxCachedNameCapacity: cfg.MaxCachedNameCapacity, MaxRepairBudget: cfg.MaxRepairBudget,
		MaxClockSkew: cfg.ClockSkew, Now: cfg.Now, OnBarrier: cfg.OnBarrier,
	})
	if err != nil {
		return nil, err
	}
	leases, err := volumeserver.NewLeaseCoordinator(volumeserver.LeaseConfig{
		TTL: cfg.CacheLeaseTTL, RecallBudget: cfg.MaxRepairBudget, StartupGrace: volumeserver.Protocol6MaxLeaseTTL,
		PriorGrantsFenced: cfg.Prior == volumeserver.PriorEpochStrictMountsFenced,
		MaxPerHolder:      cfg.MaxCacheLeasesPerSession, MaxTotal: cfg.MaxCacheLeases,
		Now: cfg.Now, Fencer: cfg.Fencer, OnRecall: cfg.OnBarrier,
	})
	if err != nil {
		return nil, err
	}
	routes, err := newRoutesController(cfg.Store, lifecycle, leases, cfg.Locks)
	if err != nil {
		return nil, err
	}
	if err := routes.Load(); err != nil {
		return nil, fmt.Errorf("load machine-local routing declaration: %w", err)
	}
	return &Coordination{
		Store: cfg.Store, Lifecycle: lifecycle, Visibility: visibility, Leases: leases, Routes: routes,
	}, nil
}

// Bind installs this assembly on a handler. It is the only way the four
// coordinators reach one, so a handler can never be given a partial set.
func (c *Coordination) Bind(h *VolumeHandler) {
	h.Lifecycle, h.Visibility, h.Leases, h.Routes = c.Lifecycle, c.Visibility, c.Leases, c.Routes
}
