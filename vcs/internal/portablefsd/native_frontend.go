package portablefsd

import (
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// nativeFSKitFrontendClientName is the frozen Hello identity emitted by the
// shipping Swift FSKit frontend. A daemon control self-probe deliberately uses
// a different name and can therefore never manufacture a native mount-ready
// witness. Hello.ClientVersion is the Swift protocol-client revision (currently
// "1"), not the paired PortableFS release identity, so it is intentionally not
// compared with the daemon version. The signed app-group socket authorizes the
// peer; the host/CLI separately prove the sealed paired daemon release before
// creating the attach.
const nativeFSKitFrontendClientName = "portablefskit"

var (
	errNativeFrontendWrongPolicy = errors.New("attach does not use native FSKit revocation")
	errNativeFrontendNotReady    = errors.New("native FSKit frontend is not connected")
)

// registerNativeFrontendWitness records one exact, successfully resolved
// portablefskit connection. v3Config is immutable after attach construction;
// all witness membership and terminal-state checks share attach.mu.
func (a *attach) registerNativeFrontendWitness(c *frontendConn) bool {
	if c == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.detached || a.v3Config == nil ||
		a.v3Config.cachePolicy != v3CachePolicyFSKit {
		return false
	}
	if a.nativeFrontendWitnesses == nil {
		a.nativeFrontendWitnesses = make(map[*frontendConn]struct{})
	}
	a.nativeFrontendWitnesses[c] = struct{}{}
	return true
}

func (a *attach) removeNativeFrontendWitness(c *frontendConn) {
	if c == nil {
		return
	}
	a.mu.Lock()
	delete(a.nativeFrontendWitnesses, c)
	a.mu.Unlock()
}

// retireNativeFrontendWitnessesLocked is the attach-terminal transition. The
// caller holds a.mu, so readiness cannot observe `detached` together with an
// old connection set even transiently.
func (a *attach) retireNativeFrontendWitnessesLocked() {
	a.nativeFrontendWitnesses = nil
}

// requireNativeFrontendReady attests that this exact native-policy attach has
// at least one currently live shipping FSKit connection which completed Hello
// and Resolve. It performs no mounted-path I/O and grants no legacy descriptor
// repair channel.
func (a *attach) requireNativeFrontendReady() error {
	a.mu.RLock()
	wrongPolicy := a.v3Config == nil ||
		a.v3Config.cachePolicy != v3CachePolicyFSKit
	notReady := a.detached || a.detachPrepared || a.detachForce ||
		a.detachBarrier || a.detachFailFrozen || a.credentialPending ||
		a.coherenceFailFrozen || a.coherenceRepairGaveUp ||
		a.coherenceRepairs != 0 || a.lastErr != "" ||
		a.state != pfslocal.AttachStateAttached ||
		a.currentStateLocked() != pfslocal.AttachStateAttached ||
		len(a.nativeFrontendWitnesses) == 0
	dataPlane := a.v3Data
	a.mu.RUnlock()
	if wrongPolicy {
		return fmt.Errorf("%w: attach %s", errNativeFrontendWrongPolicy, a.ref)
	}
	if notReady || dataPlane == nil || dataPlane.terminalError() != nil {
		return fmt.Errorf("%w: attach %s", errNativeFrontendNotReady, a.ref)
	}
	return nil
}
