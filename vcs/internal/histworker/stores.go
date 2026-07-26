package histworker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/histstore"
)

// DomainStores is the immutable failure-domain → store map of one worker.
type DomainStores struct {
	byDomain map[string]histstore.Store
	ordered  []string
}

// OpenStores builds every configured store (no network I/O).
func OpenStores(configs []StoreConfig) (*DomainStores, error) {
	out := &DomainStores{byDomain: map[string]histstore.Store{}}
	for _, cfg := range configs {
		var (
			store histstore.Store
			err   error
		)
		switch cfg.Kind {
		case "fs":
			store, err = histstore.NewFSStore(histstore.FSConfig{
				Domain: cfg.FailureDomain, RootDir: cfg.RootDir, Prefix: cfg.Prefix,
			})
		case "s3":
			store, err = histstore.NewS3Store(histstore.S3Config{
				Domain: cfg.FailureDomain, Endpoint: cfg.Endpoint, Region: cfg.Region,
				Bucket: cfg.Bucket, Prefix: cfg.Prefix, PathStyle: cfg.PathStyle,
				AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey,
				OperationTimeout: time.Duration(cfg.OperationTimeoutMs) * time.Millisecond,
			})
		default:
			err = fmt.Errorf("histworker: store kind %q", cfg.Kind)
		}
		if err != nil {
			_ = out.Close()
			return nil, err
		}
		if _, dup := out.byDomain[store.Domain()]; dup {
			return nil, fmt.Errorf("histworker: duplicate failure domain %q", store.Domain())
		}
		out.byDomain[store.Domain()] = store
		out.ordered = append(out.ordered, store.Domain())
	}
	if len(out.ordered) == 0 {
		return nil, fmt.Errorf("histworker: no stores configured")
	}
	return out, nil
}

// NewDomainStores wraps prebuilt stores (tests).
func NewDomainStores(stores ...histstore.Store) (*DomainStores, error) {
	out := &DomainStores{byDomain: map[string]histstore.Store{}}
	for _, s := range stores {
		if s == nil {
			return nil, fmt.Errorf("histworker: nil store")
		}
		if _, dup := out.byDomain[s.Domain()]; dup {
			return nil, fmt.Errorf("histworker: duplicate failure domain %q", s.Domain())
		}
		out.byDomain[s.Domain()] = s
		out.ordered = append(out.ordered, s.Domain())
	}
	if len(out.ordered) == 0 {
		return nil, fmt.Errorf("histworker: no stores configured")
	}
	return out, nil
}

// Get returns the store of one failure domain.
func (d *DomainStores) Get(domain string) (histstore.Store, bool) {
	s, ok := d.byDomain[domain]
	return s, ok
}

// Domains lists configured domains in declaration order.
func (d *DomainStores) Domains() []string {
	return append([]string(nil), d.ordered...)
}

// SweepTemps reclaims stale crash-orphaned temporary uploads from backends
// that expose such a maintenance surface. S3 PUTs are atomic at object
// visibility and therefore need no equivalent local-temp sweep.
func (d *DomainStores) SweepTemps(ctx context.Context, minAge time.Duration) (int, error) {
	total := 0
	var errs []error
	for domain, store := range d.byDomain {
		sweeper, ok := store.(interface {
			SweepTemps(context.Context, time.Duration) (int, error)
		})
		if !ok {
			continue
		}
		removed, err := sweeper.SweepTemps(ctx, minAge)
		total += removed
		if err != nil {
			errs = append(errs, fmt.Errorf("histworker: sweep store %s temps: %w", domain, err))
		}
	}
	return total, errors.Join(errs...)
}

// Close releases backend resources. It is idempotent at the process level:
// callers invoke it once after every worker loop and health handler stop.
func (d *DomainStores) Close() error {
	var errs []error
	for domain, store := range d.byDomain {
		closer, ok := store.(interface{ Close() error })
		if !ok {
			continue
		}
		if err := closer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("histworker: close store %s: %w", domain, err))
		}
	}
	return errors.Join(errs...)
}

// RequireAll proves every required domain is configured, unique, and (with
// the expected epoch) admissible under this deployment's policy pin.
// minDomains is the deployment's replication floor (Config.MinFailureDomains):
// a policy naming fewer distinct domains is refused as operator work, never
// written under.
func (d *DomainStores) RequireAll(policy ReplicationPolicy, expectedEpoch int64, minDomains int) error {
	epoch, err := policy.Epoch()
	if err != nil {
		return err
	}
	if epoch != expectedEpoch {
		return fmt.Errorf("%w: cut policy epoch %d, deployment expects %d",
			ErrPolicyMismatch, epoch, expectedEpoch)
	}
	if len(policy.RequiredFailureDomains) == 0 {
		return fmt.Errorf("%w: policy names no failure domains", ErrPolicyMismatch)
	}
	if minDomains < 1 {
		minDomains = 1
	}
	if len(policy.RequiredFailureDomains) < minDomains {
		return fmt.Errorf("%w: policy names %d failure domains, below the deployment's replication floor of %d",
			ErrPolicyMismatch, len(policy.RequiredFailureDomains), minDomains)
	}
	seen := map[string]bool{}
	for _, domain := range policy.RequiredFailureDomains {
		if seen[domain] {
			return fmt.Errorf("%w: policy repeats failure domain %q", ErrPolicyMismatch, domain)
		}
		seen[domain] = true
		if _, ok := d.byDomain[domain]; !ok {
			return fmt.Errorf("%w: no store configured for required failure domain %q",
				ErrPolicyMismatch, domain)
		}
	}
	return nil
}
