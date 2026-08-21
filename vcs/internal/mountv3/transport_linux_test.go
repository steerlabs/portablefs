//go:build linux

package mountv3

import (
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
)

func TestProfileAcceptsOnlyStrictCoherence(t *testing.T) {
	frontend, err := Profile("strict")
	if err != nil || frontend != fusev3.CoherenceStrict {
		t.Fatalf("strict profile = (%v, %v)", frontend, err)
	}
	for _, retired := range []string{"", "uncached", "eventual"} {
		frontend, err := Profile(retired)
		if err == nil || frontend != 0 || !strings.Contains(err.Error(), "must be strict") {
			t.Fatalf("Profile(%q) = (%v, %v), want an explicit strict-only refusal", retired, frontend, err)
		}
	}
}
