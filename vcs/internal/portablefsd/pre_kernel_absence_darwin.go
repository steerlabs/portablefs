//go:build darwin

package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

func hostPreKernelFSKitMountAbsenceObserver(mountPath, attachRef string) (authorityrpc.PreKernelMountAbsenceObserver, error) {
	return func(ctx context.Context) (*authoritypb.MountAbsenceProof, error) {
		if ctx == nil {
			return nil, errors.New("portablefsd: pre-kernel FSKit observation requires a context")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mounts, err := fskitKernelMounts()
		if err != nil {
			return nil, err
		}
		proof, err := plannedFSKitMountAbsenceProof(mounts, mountPath, attachRef, time.Now())
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("portablefsd: pre-kernel FSKit observation outlived its owner: %w", err)
		}
		return proof, nil
	}, nil
}
