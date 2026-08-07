// Package mountv3 is the v3 mount attach engine shared by `portablefs mount`
// and the standalone portablefs-mount-v3 binary. Both frontends speak to the
// same authority with the same declared contract, so the numbers a strict
// mount declares, the one-capability attach flow, and the transport that joins
// an authorityrpc session to the fusev3 frontend live here exactly once.
//
// The package is deliberately small: fusev3 owns the kernel mapping,
// authorityrpc owns the wire, and the caller owns credentials, lifecycle
// records, and teardown. What is shared is the part where disagreement
// between the two binaries would be a product bug — two mounts of the same
// volume must declare identical barrier obligations and adopt routing through
// the identical refusal protocol.
package mountv3

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// The transport and declaration defaults every v3 frontend starts from.
//
// The first group are transport bounds: they negotiate downward against the
// authority's advertised limits and are private to this client. The second
// group is different in kind — CachedNameCapacity and RepairBudget are
// DECLARED to the authority, which sizes its visibility barrier from them, so
// two frontends that disagreed here would be admitted with different
// obligations for the same product behavior.
const (
	ReplaySlots  uint32 = 128
	MaxInFlight         = 128
	MaxFrame     uint32 = 4 << 20
	ReclaimQueue        = 4096

	// CachedNameCapacity is how many directory bindings a strict mount may
	// leave resident in its kernel.
	CachedNameCapacity = 1 << 16
)

const (
	DialTimeout        = 10 * time.Second
	CancelDrainTimeout = 10 * time.Second
	RequestTimeout     = 45 * time.Second
	// RepairBudget is the per-phase deadline a strict mount commits to before
	// revoking itself; the authority fences the mount on the same number.
	RepairBudget = 15 * time.Second
)

// AttachWithRoutes attaches one mount and returns the routing it was admitted
// with.
//
// # Why there is no second session
//
// The routing declaration lives in the volume, and the revision derived from
// it has to be on the attach request -- so a mount that has never seen the
// volume appears to need a session in order to learn what it must say to get
// one. Reading it over a separate bootstrap session is not a way out of that
// circle, it is a way to break the mount: a volume capability is single-use,
// its nonce spent the moment a token is accepted, so a bootstrap that
// SUCCEEDED would consume the capability and the real attach would be refused.
// A mount is issued one capability and one is what it must need.
//
// The authority breaks the circle on the refusal itself: a routing
// disagreement at attach carries the volume's active canonical rules, and a
// refusal for that reason does not spend the capability. So the flow is one
// attach, and at most one more:
//
//  1. attach with the routing this mount believes is active -- the empty rule
//     set, which is also exactly what a volume with no declaration runs, so the
//     common case is a single attach with no retry and no extra round trip;
//  2. on a routing refusal, adopt the declaration the refusal carries, check
//     that it hashes to the revision the authority calls active, and attach
//     again with the same capability;
//  3. a second refusal is a real disagreement -- the volume's routing changed
//     between the two attaches, or the authority is inconsistent -- and is
//     surfaced verbatim rather than retried, because a loop here would spin
//     against a volume that is being reconfigured.
//
// adopt=false is the caller's "no machine-local routes" posture: a volume
// that declares routes is then refused outright rather than served with its
// topology ignored.
func AttachWithRoutes(ctx context.Context, attach authorityrpc.ClientConfig, adopt bool) (*authorityrpc.Client, localroutes.RuleSet, error) {
	rules := localroutes.RuleSet{}
	attach.RoutesRevision = rules.Revision()
	client, err := dialOnce(ctx, attach)
	if err == nil {
		return client, rules, nil
	}
	var mismatch *authorityrpc.RoutesMismatchError
	if !errors.As(err, &mismatch) {
		return nil, rules, fmt.Errorf("attach authority: %w", err)
	}
	if !adopt {
		return nil, rules, fmt.Errorf("this volume declares machine-local routes in %s and this mount was told not to serve them (no-local-dirs); drop the option or reconcile the declaration: %w",
			localroutes.ConfigPath, err)
	}
	if len(mismatch.Canonical) == 0 {
		// Nothing to adopt. Reporting the refusal as it arrived is the only
		// honest answer: this mount cannot construct a topology it was not told.
		return nil, rules, fmt.Errorf("attach authority: %w", err)
	}
	adopted, parseErr := localroutes.Parse(mismatch.Canonical)
	if parseErr != nil {
		return nil, rules, fmt.Errorf("the volume's active %s declaration could not be compiled: %w", localroutes.ConfigPath, parseErr)
	}
	if adopted.Revision() != mismatch.Active {
		// The rules and the revision on one refusal have to agree, or this mount
		// would attach claiming a topology it did not derive from what it was
		// handed. Echoing the authority's own number back would make the check
		// that admits it vacuous.
		return nil, rules, fmt.Errorf("the authority's active %s rules hash to %x but it reports %x as active; refusing to attach against a routing declaration that does not describe itself",
			localroutes.ConfigPath, adopted.Revision(), mismatch.Active)
	}
	attach.RoutesRevision = adopted.Revision()
	client, err = dialOnce(ctx, attach)
	if err != nil {
		return nil, adopted, fmt.Errorf("attach authority with the volume's active routing (%s): %w", strings.Join(adopted.Patterns(), " "), err)
	}
	return client, adopted, nil
}

// dialOnce makes one attach attempt. The TLS configuration is cloned per
// attempt because a dial takes ownership of the one it is given.
func dialOnce(ctx context.Context, attach authorityrpc.ClientConfig) (*authorityrpc.Client, error) {
	if attach.TLS != nil {
		attach.TLS = attach.TLS.Clone()
	}
	return authorityrpc.DialClient(ctx, attach)
}
