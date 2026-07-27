package cli

import (
	"context"
	"fmt"
	"time"
)

// activationProgress renders one activation poll for progress lines:
// conversion state, cut state, attempt count, and last error, e.g.
// "final_cut, cut materializing, attempt 3". The top-level cutState/
// attemptCount/lastError fields are additive; older servers without them
// render exactly as before (nested conversion/cut states only).
func activationProgress(status *journalActivationResponse) string {
	progress := status.State
	if status.Conversion != nil {
		progress = status.Conversion.State
	}
	switch {
	case status.CutState != "":
		progress = fmt.Sprintf("%s, cut %s", progress, status.CutState)
	case status.Cut != nil:
		progress = fmt.Sprintf("%s, cut %s", progress, status.Cut.State)
	}
	if status.AttemptCount > 0 {
		progress = fmt.Sprintf("%s, attempt %d", progress, status.AttemptCount)
	}
	if status.LastError != "" {
		progress = fmt.Sprintf("%s, last error: %s", progress, status.LastError)
	}
	return progress
}

// activationFailed reports a terminal activation failure: the overall state
// "failed", or the server marking the cut itself "failed" — terminal even
// while the overall state still reads converting, so polling must stop
// immediately. detail carries the server's error (": ..." or empty).
func activationFailed(status *journalActivationResponse) (detail string, failed bool) {
	if status.State != "failed" && status.CutState != "failed" {
		return "", false
	}
	switch {
	case status.LastError != "":
		detail = ": " + status.LastError
	case status.Conversion != nil && len(status.Conversion.LastError) > 0:
		detail = ": " + string(status.Conversion.LastError)
	case status.Cut != nil && len(status.Cut.LastError) > 0:
		detail = ": " + string(status.Cut.LastError)
	}
	return detail, true
}

// cmdActivate drives journal activation for a base-authored branch: the
// server converts the committed manifest head into the immutable PFT2 base
// and flips the branch into managed journal service (the mode mounting
// requires). Adopt runs this automatically; the explicit command exists for
// volumes adopted before activation shipped and for interrupted activations.
func cmdActivate(e *cmdEnv, args []string) int {
	fs := newFlagSet("activate")
	var o commonOpts
	addCommonFlags(fs, &o)
	branch := fs.String("branch", "main", "branch to activate")
	timeout := fs.Duration("timeout", 15*time.Minute, "how long to wait for activation to converge")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("activate", err)
	}
	if len(positionals) != 1 {
		return e.usageError("activate", fmt.Errorf("expected exactly one volume id"))
	}
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("activate", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("activate", err)
	}
	api := e.apiClient(s.apiURL, s.apiToken)
	ctx := context.Background()
	volumeID := positionals[0]

	deadline := time.Now().Add(*timeout)
	sleep := e.sleeper()
	lastProgress := ""
	for {
		status, err := api.activateJournal(ctx, volumeID, *branch)
		if err != nil {
			return e.fail("activate", err)
		}
		if status.State == "active" {
			if o.jsonOut {
				return e.printJSON(map[string]any{
					"volumeId":   volumeID,
					"branch":     *branch,
					"state":      status.State,
					"branchMode": status.BranchMode,
				})
			}
			fmt.Fprintf(e.stdout, "journal active: %s@%s (branch mode %s)\n", volumeID, *branch, status.BranchMode)
			fmt.Fprintf(e.stdout, "\nmount it:  portablefs mount %s <path>\n", volumeID)
			return 0
		}
		if detail, failed := activationFailed(status); failed {
			return e.fail("activate", fmt.Errorf("activation failed%s (re-run to retry)", detail))
		}
		progress := activationProgress(status)
		if progress != lastProgress && !o.jsonOut {
			fmt.Fprintf(e.stderr, "activating journal (%s) ...\n", progress)
			lastProgress = progress
		}
		if time.Now().After(deadline) {
			return e.fail("activate", fmt.Errorf("activation did not converge within %s (%s); the server keeps working — re-run to keep waiting", *timeout, progress))
		}
		sleep(2 * time.Second)
	}
}
