package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// cmdInternalRootProbe is a one-shot child boundary for filesystem I/O that
// may wedge in a userspace filesystem. The parent owns, deadlines, kills, and
// reaps this process; UI/status inventory never runs this probe.
func cmdInternalRootProbe(e *cmdEnv, args []string) int {
	fs := newFlagSet("internal-root-probe")
	path := fs.String("path", "", "mount root")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("internal-root-probe", err)
	}
	if len(positionals) != 0 || *path == "" {
		return e.usageError("internal-root-probe", fmt.Errorf("expected --path"))
	}
	root, err := os.Open(*path)
	if err != nil {
		return e.fail("internal-root-probe", err)
	}
	defer root.Close()
	if _, err := root.Stat(); err != nil {
		return e.fail("internal-root-probe", err)
	}
	if _, err := root.Readdirnames(1); err != nil && err != io.EOF {
		return e.fail("internal-root-probe", err)
	}
	return 0
}

func probeFSKitRootOnce(mountPath string, timeout time.Duration) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate root-probe executable: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "internal-root-probe", "--path", mountPath)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("root probe exceeded %s: %w", timeout, ctx.Err())
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("root probe: %w (%s)", err, detail)
		}
		return fmt.Errorf("root probe: %w", err)
	}
	return nil
}
