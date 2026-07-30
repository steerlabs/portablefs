// Package mounthost reports current, non-mutating facts about a host's mount
// transport.
//
// It exists because that question had three different answers in three
// different places (transport selection, the doctor command, and the mount
// error path), which is how a host could be told to install a package it
// already had, or told an extension was disabled while it was serving a live
// mount.
//
// Three rules keep those answers from diverging again:
//
//  1. Nothing is cached. Every input is mutable within a session — the user
//     enables a system extension, installs a package, or the process enters a
//     different namespace — so a cached verdict is a wrong verdict waiting to
//     be printed.
//  2. Nothing is executed. Facts come from the filesystem, /proc and sysctl,
//     never from a subprocess.
//  3. Nothing is guessed. When a platform cannot answer a question — macOS
//     exposes no reliable way to ask whether a third-party FSKit extension is
//     enabled — the answer is [Unknown], never an optimistic or pessimistic
//     invention. A mount is the only authority on whether a mount works.
package mounthost

import "fmt"

// Transport is the single mount transport a platform supports. There is
// deliberately one per platform and no fallback between them: a host that
// cannot serve its transport fails with specific guidance rather than
// degrading to a weaker consistency model.
type Transport string

const (
	// FSKit is the macOS transport, served by the PortableFS FSKit extension.
	FSKit Transport = "fskit"
	// FUSE is the Linux transport, served through /dev/fuse.
	FUSE Transport = "fuse"
)

// State is the strongest honest statement supported by the evidence.
//
// Check only returns Blocked or Unverified. Verified is reserved for a caller
// that has independently observed a live, usable mount; installed packages,
// capabilities and extension inventory are never proof.
type State string

const (
	// Verified means a live mount has answered a filesystem operation.
	Verified State = "verified"
	// Blocked means a specific precondition was observed to be missing.
	// [Facts.Issue] identifies which one.
	Blocked State = "blocked"
	// Unverified means no definite blocker was observed, but no live mount
	// proved the transport. This is a normal result, not an error.
	Unverified State = "unverified"
)

// Issue is a stable machine-readable identifier for a host condition.
// Consumers map it to an action: the installer to an installation step, the
// CLI to guidance. Codes may be added; an existing code never changes
// meaning.
type Issue string

const (
	// IssueNone is the absence of an identified condition.
	IssueNone Issue = ""

	// IssueUnsupportedOS is a platform with no PortableFS mount transport.
	IssueUnsupportedOS Issue = "unsupported-os"

	// IssueFUSEDeviceMissing is /dev/fuse not existing: the kernel module is
	// not loaded, or a container was created without the device. It cannot
	// be repaired from inside a running container.
	IssueFUSEDeviceMissing Issue = "fuse-device-missing"
	// IssueFUSEDeviceDenied is /dev/fuse existing but not openable by this
	// process and no helper being available to try on the process's behalf.
	IssueFUSEDeviceDenied Issue = "fuse-device-denied"
	// IssueFUSEDeviceUnavailable is a /dev/fuse node whose kernel device is
	// unavailable (ENODEV/ENXIO).
	IssueFUSEDeviceUnavailable Issue = "fuse-device-unavailable"
	// IssueFUSEMountUnavailable is a usable /dev/fuse with neither of the two
	// ways to issue the mount: no fusermount helper on PATH for an
	// unprivileged process, and no CAP_SYS_ADMIN for a direct mount.
	IssueFUSEMountUnavailable Issue = "fuse-mount-unavailable"

	// IssueMacOSTooOld is a macOS release older than the FSKit APIs the
	// extension is built against.
	IssueMacOSTooOld Issue = "macos-too-old"
	// IssueFSKitAppNotFound means no app bundle was found in the standard
	// application domains. It is inventory evidence, not a blocker: a bundle
	// outside those domains may already be registered.
	IssueFSKitAppNotFound Issue = "fskit-app-not-found"
)

// MinimumMacOSMajor is the macOS major version the FSKit extension targets.
// The extension uses macOS 26 FSVolume.Operations APIs, so an older host
// cannot serve a mount regardless of what is installed.
const MinimumMacOSMajor = 26

// Facts is one uncached observation of this host.
//
// State and Issue are the machine contract; Summary and Details are
// human-readable diagnostics and must not be parsed.
type Facts struct {
	Transport Transport `json:"transport"`
	State     State     `json:"state"`
	Issue     Issue     `json:"issue,omitempty"`
	// MountMechanism is the one deterministic primitive selected for this
	// observation: "direct" or "helper". HelperPath is populated only for
	// the latter and is persisted by the mount owner for exact unmount.
	MountMechanism string `json:"mountMechanism,omitempty"`
	HelperPath     string `json:"helperPath,omitempty"`
	// Summary is one line stating what was observed, in the present tense.
	Summary string `json:"summary"`
	// Details is ordered supporting evidence, most relevant first.
	Details []Detail `json:"details,omitempty"`
}

// Detail is one piece of evidence behind a [Facts].
type Detail struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func detail(key, value string) Detail { return Detail{Key: key, Value: value} }

// Check observes this host for the given transport. It never mutates the
// host, never runs a subprocess, and never caches: two calls a second apart
// can legitimately differ, which is the point.
func Check(t Transport) Facts { return check(t) }

// SelectTransport resolves the mount transport for a platform. It is pure:
// the choice depends only on the operating system and an explicit override,
// never on what happens to be installed. Host capability is a separate
// question with a separate answer ([Check]) so that a missing package can
// never be mistaken for an unsupported platform.
func SelectTransport(explicit, goos string) (Transport, error) {
	switch explicit {
	case "", "auto":
		switch goos {
		case "darwin":
			return FSKit, nil
		case "linux":
			return FUSE, nil
		default:
			return "", fmt.Errorf("mounting is not supported on %s (supported: darwin via FSKit, linux via FUSE)", goos)
		}
	case string(FSKit):
		if goos != "darwin" {
			return "", fmt.Errorf("--strategy fskit is the macOS FSKit mount and requires darwin")
		}
		return FSKit, nil
	case string(FUSE):
		if goos != "linux" {
			return "", fmt.Errorf("--strategy fuse is the Linux FUSE mount and requires linux (macOS mounts use fskit)")
		}
		return FUSE, nil
	default:
		return "", fmt.Errorf("unknown --strategy %q (valid: auto, fskit, fuse)", explicit)
	}
}

// unsupported is the shared answer for a platform with no transport.
func unsupported(goos string) Facts {
	return Facts{
		State:   Blocked,
		Issue:   IssueUnsupportedOS,
		Summary: fmt.Sprintf("%s has no PortableFS mount transport", goos),
	}
}
