package cli

import (
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
)

func TestFSKitCachePolicyRequiresAnExactQualifiedBuildAndOS(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		qualification string
		want          string
	}{
		{"macOS 26 release", "26.0", "", portablefsd.V3CachePolicyMacOS26},
		{"macOS 26 ignores native stamp", "26.6.1", sdk27QualificationStamp, portablefsd.V3CachePolicyMacOS26},
		{"macOS 27 qualification build", "27.0", sdk27QualificationStamp, portablefsd.V3CachePolicyFSKit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fskitCachePolicyForProductVersion(
				tt.version,
				tt.qualification,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("policy = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFSKitCachePolicyRejectsUnsupportedOrUnknownVersions(t *testing.T) {
	for _, version := range []string{"", "beta", "25.7", "28.0", "0"} {
		t.Run(version, func(t *testing.T) {
			if _, err := fskitCachePolicyForProductVersion(
				version,
				sdk27QualificationStamp,
			); err == nil {
				t.Fatalf("version %q was accepted", version)
			} else if !strings.Contains(err.Error(), "macOS") {
				t.Fatalf("error %q does not identify macOS eligibility", err)
			}
		})
	}
}

func TestFSKitCachePolicyRefusesUnqualifiedMacOS27Build(t *testing.T) {
	for _, qualification := range []string{"", "enabled", "sdk27"} {
		t.Run(qualification, func(t *testing.T) {
			if _, err := fskitCachePolicyForProductVersion(
				"27.0",
				qualification,
			); err == nil {
				t.Fatalf("qualification %q admitted the native policy", qualification)
			} else if !strings.Contains(err.Error(), "not admitted by this build") {
				t.Fatalf("unexpected gate error: %v", err)
			}
		})
	}
}
