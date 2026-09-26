package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

type mountLossResult struct {
	MountPath string `json:"mountPath"`
	mountLossSnapshot
}

// cmdMountLoss is an identity-bound live observation, not a durability barrier.
// Callers retaining a root descriptor use it to cover publication before OPEN.
func cmdMountLoss(e *cmdEnv, args []string) int {
	fs := newFlagSet("mount-loss")
	var common commonOpts
	var instance string
	addCommonFlags(fs, &common)
	fs.StringVar(&instance, "mount-instance", "", "exact mount instance from the verified kernel mount")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("mount-loss", err)
	}
	if len(positionals) != 1 || !mountid.ValidMountInstance(instance) {
		return e.usageError("mount-loss", fmt.Errorf("requires <mountPath> and a valid --mount-instance"))
	}
	mountPath, err := canonicalMountPath(positionals[0])
	if err != nil {
		return e.fail("mount-loss", err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("mount-loss", err)
	}
	state, err := readMountState(stateDir, mountPath)
	if err != nil {
		return e.fail("mount-loss", err)
	}
	if state == nil || state.Strategy != "fuse" || state.MountInstanceID != instance || e.classifyMount(state) != "live" {
		return e.fail("mount-loss", fmt.Errorf("no exact live Linux mount is recorded at %s", mountPath))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := readFuseMountLoss(ctx, state, instance)
	if err != nil {
		return e.fail("mount-loss", err)
	}
	result := mountLossResult{MountPath: mountPath, mountLossSnapshot: snapshot}
	if common.jsonOut {
		return e.printJSON(result)
	}
	fmt.Fprintf(e.stdout, "%s  instance=%s  loss-sequence=%s\n", mountPath, snapshot.MountInstanceID, snapshot.LossSequence)
	return 0
}
