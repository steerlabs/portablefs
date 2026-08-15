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

func TestFSKitCachePolicyRefusesEveryProductionMacOSBeforeAttach(t *testing.T) {
	for _, version := range []string{"26.0", "26.6.1", "27.0"} {
		t.Run(version, func(t *testing.T) {
			if _, err := fskitCachePolicyForProductVersion(version, ""); err == nil {
				t.Fatalf("production macOS %s was admitted", version)
			} else if !strings.Contains(err.Error(), "protocol 5") ||
				!strings.Contains(err.Error(), "no authority attach was attempted") {
				t.Fatalf("production refusal = %q", err)
			}
		})
	}
}

func TestFSKitCachePolicyNeverTreatsTheMacOS27StampAsMacOS26Proof(t *testing.T) {
	if _, err := fskitCachePolicyForProductVersion("26.6.1", sdk27QualificationStamp); err == nil {
		t.Fatal("native macOS 27 qualification stamp admitted legacy macOS 26")
	} else if !strings.Contains(err.Error(), "source post-mutation attributes") {
		t.Fatalf("macOS 26 refusal omitted its exact source gap: %v", err)
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
			} else if !strings.Contains(err.Error(), "cannot mount PortableFS protocol 5") {
				t.Fatalf("unexpected gate error: %v", err)
			}
		})
	}
}
