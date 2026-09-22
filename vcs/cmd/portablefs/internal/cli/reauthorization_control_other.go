//go:build !linux

package cli

import (
	"context"
	"errors"
	"time"
)

func startFuseReauthorizationControl(fuseReauthorizationHandler, fuseLossSnapshotHandler) (fuseReauthorizationControl, error) {
	return nil, errors.New("FUSE reauthorization requires Linux")
}

func reauthorizeFuseMount(context.Context, *mountState, string, uint64, []byte) (time.Time, error) {
	return time.Time{}, errors.New("FUSE reauthorization requires Linux")
}

func validReauthorizationControlAddress(string) bool { return false }

func readFuseMountLoss(context.Context, *mountState, string) (mountLossSnapshot, error) {
	return mountLossSnapshot{}, errors.New("live FUSE loss snapshots require Linux")
}
