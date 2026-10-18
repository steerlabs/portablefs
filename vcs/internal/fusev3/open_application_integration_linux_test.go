//go:build linux

package fusev3

import (
	"os"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// A truncating allocating mutation must return an application cut for the
// grant it reports. Otherwise the authority cannot separate application from
// the peer withdrawal that may itself require this holder's CONTROL receipt.
func TestTruncatingOpenCarriesItsGrantApplicationCut(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	path := f.join(0, "application-cut")
	mustWrite(t, path, []byte("before"), 0600)
	f.waitForDelegationReleases(t)
	holder := mustOpenFile(t, path, os.O_WRONLY, 0)
	defer holder.Close()
	cuts := make(chan uint64, 1)
	f.transports[0].setAfterMutation(func(req *authoritypb.Request, response *authoritypb.Response, err error) {
		if req.GetOpen().GetFlags().GetTruncate() && err == nil && response.GetErrno() == 0 {
			cuts <- response.GetAppliedSequence()
		}
	})
	defer f.transports[0].setAfterMutation(nil)
	truncated, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
	if truncated != nil {
		defer truncated.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	select {
	case cut := <-cuts:
		if cut == 0 {
			t.Fatal("truncating OPEN omitted its grant's application receipt")
		}
	default:
		t.Fatal("truncating OPEN completed without its authority outcome")
	}
}
