//go:build darwin

package mounthost

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"golang.org/x/sys/unix"
)

// fskitAppBundles are the app bundles that can carry a "pfs" FSKit
// extension, in preference order: the released app, then the development
// harness. An FSKit module is an app extension and ships only inside a
// bundle, so their absence from the locations LaunchServices scans is the
// most likely explanation for a host that cannot mount.
var fskitAppBundles = []string{"PortableFS.app", "PortableFSKitDev.app"}

// appSearchRoots are the application domains LaunchServices scans. A bundle
// installed outside them can still be registered, which is exactly why their
// emptiness is reported as a likely cause and never as a verdict.
func appSearchRoots() ([]string, error) {
	roots := []string{"/Applications"}
	home, err := accountpath.Home()
	if err != nil {
		return roots, err
	}
	return append(roots, filepath.Join(home, "Applications")), nil
}

func check(t Transport) Facts {
	if t != FSKit {
		return unsupported("darwin")
	}

	f := Facts{Transport: FSKit}

	version, err := unix.Sysctl("kern.osproductversion")
	switch {
	case err != nil:
		f.Details = append(f.Details, detail("macos", "unknown: "+err.Error()))
	default:
		f.Details = append(f.Details, detail("macos", version))
		if major, ok := majorVersion(version); ok && major < MinimumMacOSMajor {
			f.State = Blocked
			f.Issue = IssueMacOSTooOld
			f.Summary = fmt.Sprintf(
				"macOS %s is older than %d, which the PortableFS FSKit extension requires",
				version, MinimumMacOSMajor,
			)
			return f
		}
	}

	roots, homeErr := appSearchRoots()
	if homeErr != nil {
		f.Details = append(f.Details, detail("account_home", "unknown: "+homeErr.Error()))
	}
	bundles := installedAppBundles(roots)
	if len(bundles) == 0 {
		f.State = Unverified
		f.Issue = IssueFSKitAppNotFound
		f.Summary = "no PortableFS app bundle found in " + strings.Join(roots, " or ") +
			"; the FSKit extension ships inside that bundle"
		if homeErr != nil {
			f.Summary += "; the canonical per-account Applications directory could not be resolved"
		}
		f.Details = append(f.Details, detail("app", "none found"))
		return f
	}
	for _, bundle := range bundles {
		f.Details = append(f.Details, detail("app", bundle))
	}

	// Everything observable is in place. Enablement itself is deliberately
	// not claimed: macOS exposes no reliable way to ask whether a
	// third-party FSKit extension is enabled. FSClient.fetchInstalledExtensions
	// reports only Apple's own modules, the PlugInKit election is a separate
	// mechanism FSKit does not consult, and the enablement plist is private
	// and goes stale. A mount is the only authority.
	f.State = Unverified
	f.Summary = "macOS exposes no reliable query for third-party FSKit extension enablement; a mount is the only proof"
	return f
}

// installedAppBundles returns the app bundles found in the standard
// application domains.
func installedAppBundles(roots []string) []string {
	var found []string
	for _, root := range roots {
		for _, name := range fskitAppBundles {
			path := filepath.Join(root, name)
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				found = append(found, path)
			}
		}
	}
	return found
}

// majorVersion parses the leading integer of a macOS product version.
func majorVersion(version string) (int, bool) {
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0, false
	}
	return n, true
}
