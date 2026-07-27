package cli

import (
	"fmt"
	"os/exec"
	"runtime"
)

// strategyProbe abstracts the host checks strategy selection depends on, so
// the platform matrix is table-testable.
type strategyProbe struct {
	goos     string
	lookPath func(string) (string, error)
}

func hostStrategyProbe() strategyProbe {
	return strategyProbe{
		goos:     runtime.GOOS,
		lookPath: exec.LookPath,
	}
}

func (p strategyProbe) fusermountAvailable() bool {
	if _, err := p.lookPath("fusermount3"); err == nil {
		return true
	}
	_, err := p.lookPath("fusermount")
	return err == nil
}

// resolveStrategy picks the ONE mount transport per platform: FSKit on
// macOS, FUSE on Linux. There are deliberately no fallback transports — a
// host that cannot serve its platform's strategy fails with specific
// guidance instead of degrading to a weaker consistency model.
func resolveStrategy(explicit string, p strategyProbe) (string, error) {
	switch explicit {
	case "", "auto":
		switch p.goos {
		case "darwin":
			return "fskit", nil
		case "linux":
			if !p.fusermountAvailable() {
				return "", fmt.Errorf("FUSE is not available: fusermount3/fusermount not found in PATH (install the fuse3 package, e.g. `apt install fuse3`)")
			}
			return "fuse", nil
		default:
			return "", fmt.Errorf("mounting is not supported on %s (supported: darwin via FSKit, linux via FUSE)", p.goos)
		}
	case "fskit":
		if p.goos != "darwin" {
			return "", fmt.Errorf("--strategy fskit is the macOS FSKit mount and requires darwin")
		}
		return "fskit", nil
	case "fuse":
		if p.goos != "linux" {
			return "", fmt.Errorf("--strategy fuse is the Linux FUSE mount and requires linux (macOS mounts use fskit)")
		}
		if !p.fusermountAvailable() {
			return "", fmt.Errorf("--strategy fuse: fusermount3/fusermount not found in PATH (install the fuse3 package)")
		}
		return "fuse", nil
	default:
		return "", fmt.Errorf("unknown --strategy %q (valid: auto, fskit, fuse)", explicit)
	}
}
