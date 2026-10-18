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
// protocol-8 coordination. Every field is a safety property of the deployment,
// so none of them has a default a caller may inherit silently.
type CoordinationConfig struct {
	Store  *xfsstore.Volume
	Fencer volumeserver.SessionFencer
	Locks  *volumeserver.LockTable
	// Membership is the durable mount record. MountLifecycle is its only owner;
	// the writer registry never writes a second membership record.
	Membership volumeserver.DurableMountMembership
	Prior      volumeserver.PriorEpochDisposition
	ClockSkew  time.Duration

	ContinuousNow func() (time.Duration, error)
	Now           func() time.Time
}

// Coordination is a volume's complete protocol-8 coordination assembly.
//
// Linux caching, exclusive Mac writing and durable topology have separate owners.
type Coordination struct {
	Store     *xfsstore.Volume
	Lifecycle *volumeserver.MountLifecycle
	Writers   *volumeserver.WriterRegistry
	Coherence *volumeserver.CoherenceCoordinator
	Routes    *RoutesController
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
	writerPrior, priorLinux := cfg.Prior, false
	if typed, ok := cfg.Membership.(interface {
		PriorCacheState() (volumeserver.PriorEpochDisposition, bool)
	}); ok {
		writerPrior, priorLinux = typed.PriorCacheState()
	}
	writers, err := volumeserver.NewWriterRegistry(volumeserver.WriterRegistryConfig{
		Fencer: cfg.Fencer, Prior: writerPrior, ContinuousNow: cfg.ContinuousNow,
	})
	if err != nil {
		return nil, err
	}
	routes, err := newRoutesController(cfg.Store, lifecycle, cfg.Locks)
	if err != nil {
		return nil, err
	}
	if err := routes.Load(); err != nil {
		return nil, fmt.Errorf("load machine-local routing declaration: %w", err)
	}
	return &Coordination{
		Coherence: volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{PriorLinuxCaches: priorLinux}), Store: cfg.Store, Lifecycle: lifecycle, Writers: writers, Routes: routes,
	}, nil
}

// Bind installs the volume assembly on its handler.
func (c *Coordination) Bind(h *VolumeHandler) {
	h.Lifecycle, h.Writers, h.Routes = c.Lifecycle, c.Writers, c.Routes
	h.Coherence = c.Coherence
	h.initCoherence()
}
