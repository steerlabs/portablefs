//go:build linux

package mountv3

import (
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
)

func TestProfileAcceptsOnlyStrictCoherence(t *testing.T) {
	frontend, wire, err := Profile("strict")
	if err != nil || frontend != fusev3.CoherenceStrict || wire != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
		t.Fatalf("strict profile = (%v, %v, %v)", frontend, wire, err)
	}
	for _, retired := range []string{"", "uncached", "eventual"} {
		frontend, wire, err := Profile(retired)
		if err == nil || frontend != 0 || wire != authoritypb.CoherenceProfile_COHERENCE_PROFILE_UNSPECIFIED || !strings.Contains(err.Error(), "must be strict") {
			t.Fatalf("Profile(%q) = (%v, %v, %v), want an explicit strict-only refusal", retired, frontend, wire, err)
		}
	}
}
