package cli

import (
	"bufio"
	"context"
	"fmt"
	"strings"
)

// cmdRm retires (deletes) a volume through DELETE /v1/volumes/:id. Retirement
// is immediate and irreversible at the API surface: the volume disappears from
// listings and every per-volume route, and existing live mounts lose access as
// their leases expire (nothing is force-detached). Because that is a
// destructive one-way door, rm never acts silently: interactive callers must
// type the volume id back, and non-interactive callers must pass --yes.
func cmdRm(e *cmdEnv, args []string) int {
	fs := newFlagSet("rm")
	var o commonOpts
	addCommonFlags(fs, &o)
	yes := fs.Bool("yes", false, "skip the interactive confirmation")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("rm", err)
	}
	if len(positionals) != 1 {
		return e.usageError("rm", fmt.Errorf("expected exactly one volume id"))
	}
	volumeID := positionals[0]
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("rm", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("rm", err)
	}

	if !*yes {
		if !e.stdinIsTerminal() {
			return e.usageError("rm", fmt.Errorf("stdin is not an interactive terminal, so the volume id cannot be confirmed; pass --yes to retire %s", volumeID))
		}
		if !e.confirmRetirement(volumeID) {
			return e.fail("rm", fmt.Errorf("confirmation did not match %q; nothing was retired", volumeID))
		}
	}

	receipt, err := e.apiClient(s.apiURL, s.apiToken).retireVolume(context.Background(), volumeID)
	if err != nil {
		if httpStatus(err) == 404 {
			// The non-enumerating 404: unknown, foreign, and already-retired
			// volumes are deliberately indistinguishable server-side.
			return e.fail("rm", fmt.Errorf("volume %q not found — it may already be retired or belong to another tenant (list volumes: portablefs ls)", volumeID))
		}
		return e.fail("rm", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{
			"volumeId":  receipt.VolumeID,
			"retiredAt": receipt.RetiredAt,
		})
	}
	fmt.Fprintf(e.stdout, "retired volume %s at %s\n", receipt.VolumeID, receipt.RetiredAt)
	fmt.Fprintln(e.stdout, "existing mounts will detach shortly as their leases expire")
	return 0
}

// confirmRetirement prints what retirement does and requires the exact volume
// id to be typed back. Only ever called on an interactive terminal.
func (e *cmdEnv) confirmRetirement(volumeID string) bool {
	fmt.Fprintf(e.stdout, "retire volume %s\n\n", volumeID)
	fmt.Fprintf(e.stdout, "  - it disappears from listings and every API surface immediately\n")
	fmt.Fprintf(e.stdout, "  - existing live mounts lose access as their leases expire\n")
	fmt.Fprintf(e.stdout, "  - this cannot be undone\n\n")
	fmt.Fprintf(e.stdout, "type the volume id to confirm: ")
	line, err := bufio.NewReader(e.stdinReader()).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.TrimSpace(line) == volumeID
}
