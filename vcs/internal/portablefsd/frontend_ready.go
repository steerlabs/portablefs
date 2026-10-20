package portablefsd

import (
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// The socket and paired release checks authenticate the peer; this label only
// distinguishes shipping frontend witnesses from daemon control self-probes.
const shippingFSKitFrontendClientName = "portablefskit"

var errFrontendNotReady = errors.New("FSKit frontend is not ready")

func (a *attach) registerFrontendWitness(c *frontendConn) bool {
	if c == nil || c.origin == 0 || c.helloClientName != shippingFSKitFrontendClientName || c.connectionClosed.Load() {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.detached || a.v3Config == nil || c.connectionClosed.Load() {
		return false
	}
	if a.frontendWitnesses == nil {
		a.frontendWitnesses = make(map[*frontendConn]struct{})
	}
	a.frontendWitnesses[c] = struct{}{}
	return true
}
func (a *attach) removeFrontendWitness(c *frontendConn) {
	a.mu.Lock()
	delete(a.frontendWitnesses, c)
	a.mu.Unlock()
}
func (a *attach) retireFrontendWitnessesLocked() { a.frontendWitnesses = nil }

// requireFrontendReady observes the kernel identity without accessing the
// mounted namespace. Recheck all serving witnesses after the observation.
func (a *attach) requireFrontendReady() error {
	present, err := hostFSKitKernelOps().present(a.mountPath, a.ref)
	if err != nil {
		return fmt.Errorf("observe frontend kernel identity: %w", err)
	}
	return a.requireFrontendWitnesses(present)
}
func (a *attach) requireFrontendWitnesses(kernelPresent bool) error {
	a.mu.RLock()
	ready := kernelPresent && !a.detached && !a.detachBarrier && !a.credentialPending && !a.coherenceFailFrozen && a.lastErr == "" && a.currentStateLocked() == pfslocal.AttachStateAttached
	d, b := a.v3Data, a.v3Coherence
	if ready && d != nil && b != nil {
		b.mu.Lock()
		ready = b.subscribed && b.terminal == nil && !b.detaching && b.frontendOrigin != 0
		witnessed := false
		for c := range a.frontendWitnesses {
			if c.origin == b.frontendOrigin && !c.connectionClosed.Load() {
				witnessed = true
				break
			}
		}
		ready = ready && witnessed
		if ready {
			d.mu.Lock()
			ready = d.cacheAdmissionLocked() == v3CacheHit
			d.mu.Unlock()
		}
		b.mu.Unlock()
	} else {
		ready = false
	}
	a.mu.RUnlock()
	if d != nil {
		_ = d.endOnClockFault()
	}
	if !ready {
		return fmt.Errorf("%w: attach %s", errFrontendNotReady, a.ref)
	}
	return nil
}
