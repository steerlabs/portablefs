package cli

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
)

const mountCheckSchemaVersion = 1

type mountCheckEnvelope struct {
	SchemaVersion int              `json:"schemaVersion"`
	Facts         *mounthost.Facts `json:"facts,omitempty"`
	// KernelProbe is present only for --probe-mount, and only when a real
	// throwaway mount completed the kernel INIT handshake.
	KernelProbe any              `json:"kernelProbe,omitempty"`
	Error       *mountCheckError `json:"error,omitempty"`
}

// errUnprobableTransport is the refusal for --probe-mount on a transport this
// CLI cannot install by itself.
func errUnprobableTransport(transport mounthost.Transport) error {
	return fmt.Errorf("--probe-mount is available only for the fuse transport; %s installs its mount through the system extension", transport)
}

type mountCheckError struct {
	Kind    string          `json:"kind"`
	Code    mounthost.Issue `json:"code,omitempty"`
	Message string          `json:"message"`
}

// observeMountHost keeps deterministic transport selection, mutable host
// facts, and authoritative mount verification as three explicit inputs.
func observeMountHost(
	goos, explicit string,
	check func(mounthost.Transport) mounthost.Facts,
	liveMount func(mounthost.Transport) (string, bool, error),
) (mounthost.Facts, error) {
	transport, err := mounthost.SelectTransport(explicit, goos)
	if err != nil {
		return mounthost.Facts{}, err
	}
	facts := check(transport)
	path, live, err := liveMount(transport)
	if err != nil {
		return mounthost.Facts{}, fmt.Errorf("inventory recorded mounts: %w", err)
	}
	if live {
		facts.State = mounthost.Verified
		facts.Issue = mounthost.IssueNone
		facts.Summary = fmt.Sprintf("a live %s mount at %s has exact process and kernel identity", transport, path)
		facts.Details = append([]mounthost.Detail{{Key: "verified_mount", Value: path}}, facts.Details...)
	}
	return facts, nil
}

func (e *cmdEnv) verifiedMount(transport mounthost.Transport) (string, bool, error) {
	stateDir, err := e.mountStateDir()
	if err != nil {
		return "", false, err
	}
	states, err := listMountStates(stateDir)
	if err != nil {
		return "", false, err
	}
	for _, state := range states {
		if state.Strategy != string(transport) {
			continue
		}
		present, err := recordedKernelMountPresent(&state)
		if err != nil {
			return "", false, fmt.Errorf("validate mount state for %s: %w", state.MountPath, err)
		}
		if present && mountProcessMatches(&state) {
			return state.MountPath, true, nil
		}
	}
	return "", false, nil
}

func mountHostBlockedError(facts mounthost.Facts) error {
	guidance := mountHostGuidance(facts.Issue)
	if guidance == "" {
		return fmt.Errorf("%s (%s)", facts.Summary, facts.Issue)
	}
	return fmt.Errorf("%s (%s); %s", facts.Summary, facts.Issue, guidance)
}

func mountHostGuidance(issue mounthost.Issue) string {
	switch issue {
	case mounthost.IssueFUSEDeviceMissing:
		return "make /dev/fuse available to this environment, then retry"
	case mounthost.IssueFUSEDeviceDenied:
		return "allow this process or the FUSE helper to open /dev/fuse, then retry"
	case mounthost.IssueFUSEDeviceUnavailable:
		return "make the kernel FUSE device available, then retry"
	case mounthost.IssueFUSEMountUnavailable:
		return "grant CAP_SYS_ADMIN in this mount namespace or install fusermount3/fusermount, then retry"
	case mounthost.IssueMacOSTooOld:
		return fmt.Sprintf("use macOS %d or newer", mounthost.MinimumMacOSMajor)
	case mounthost.IssueUnsupportedOS:
		return "use macOS with FSKit or Linux with FUSE"
	default:
		return ""
	}
}

func cmdMountCheck(e *cmdEnv, args []string) int {
	fs := newFlagSet("mount-check")
	var common commonOpts
	var strategy string
	addCommonFlags(fs, &common)
	var probeMount bool
	fs.StringVar(&strategy, "strategy", "auto", "mount strategy: auto (fskit on macOS, fuse on Linux), fskit, or fuse")
	fs.BoolVar(&probeMount, "probe-mount", false, "install one real throwaway FUSE mount, complete the kernel INIT handshake, and unmount")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		if argsRequestJSON(args) {
			_ = e.printJSON(mountCheckEnvelope{
				SchemaVersion: mountCheckSchemaVersion,
				Error:         &mountCheckError{Kind: "usage", Message: err.Error()},
			})
			return 2
		}
		return e.handleParseError("mount-check", err)
	}
	if len(positionals) != 0 {
		if common.jsonOut {
			_ = e.printJSON(mountCheckEnvelope{
				SchemaVersion: mountCheckSchemaVersion,
				Error:         &mountCheckError{Kind: "usage", Message: "expected no arguments"},
			})
			return 2
		}
		return e.usageError("mount-check", fmt.Errorf("expected no arguments"))
	}
	facts, err := observeMountHost(runtime.GOOS, strategy, mounthost.Check, e.verifiedMount)
	if err != nil {
		if common.jsonOut {
			_ = e.printJSON(mountCheckEnvelope{
				SchemaVersion: mountCheckSchemaVersion,
				Error:         &mountCheckError{Kind: "strategy", Message: err.Error()},
			})
			return 2
		}
		return e.fail("mount-check", err)
	}
	var probe any
	if probeMount {
		if facts.State == mounthost.Blocked {
			// A blocked host has already named the missing primitive. Mounting
			// anyway would replace that specific diagnosis with a mount error.
			return e.reportMountCheck(common.jsonOut, facts, nil)
		}
		observed, probeErr := probeMountTransport(facts.Transport)
		if probeErr != nil {
			if common.jsonOut {
				_ = e.printJSON(mountCheckEnvelope{
					SchemaVersion: mountCheckSchemaVersion,
					Error:         &mountCheckError{Kind: "probe", Message: probeErr.Error()},
				})
				return 1
			}
			return e.fail("mount-check", probeErr)
		}
		probe = observed
		// A completed INIT handshake is a live mount answering this client, so
		// it is proof of the transport rather than evidence about the host.
		facts.State = mounthost.Verified
		facts.Issue = mounthost.IssueNone
		facts.Summary = fmt.Sprintf("a throwaway %s mount completed the kernel INIT handshake with this client", facts.Transport)
		facts.Details = append([]mounthost.Detail{{Key: "kernel_init_probe", Value: "completed"}}, facts.Details...)
	}
	return e.reportMountCheck(common.jsonOut, facts, probe)
}

func (e *cmdEnv) reportMountCheck(jsonOut bool, facts mounthost.Facts, probe any) int {
	if jsonOut {
		envelope := mountCheckEnvelope{SchemaVersion: mountCheckSchemaVersion, KernelProbe: probe}
		if facts.State == mounthost.Blocked {
			envelope.Error = &mountCheckError{
				Kind:    "blocked",
				Code:    facts.Issue,
				Message: facts.Summary,
			}
		} else {
			envelope.Facts = &facts
		}
		if rc := e.printJSON(envelope); rc != 0 {
			return rc
		}
	} else {
		fmt.Fprintf(e.stdout, "%s  %s: %s\n", strings.ToUpper(string(facts.State)), facts.Transport, facts.Summary)
		for _, evidence := range facts.Details {
			fmt.Fprintf(e.stdout, "            %s: %s\n", evidence.Key, evidence.Value)
		}
		if guidance := mountHostGuidance(facts.Issue); facts.State == mounthost.Blocked && guidance != "" {
			fmt.Fprintf(e.stdout, "            fix: %s\n", guidance)
		}
	}
	if facts.State == mounthost.Blocked {
		return 1
	}
	return 0
}

func argsRequestJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--json" || strings.HasPrefix(arg, "--json=") {
			return true
		}
	}
	return false
}
