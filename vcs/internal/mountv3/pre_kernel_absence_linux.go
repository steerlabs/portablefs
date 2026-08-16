//go:build linux

package mountv3

import (
	"context"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

// PreKernelMountAbsenceObserver binds authority cleanup to the same random
// mount-source identity that MountVolume will publish. The returned callback
// performs a fresh mountinfo observation every time cleanup needs evidence;
// construction itself never snapshots a verdict that could go stale.
func PreKernelMountAbsenceObserver(mountpoint, mountInstanceID string) (authorityrpc.PreKernelMountAbsenceObserver, error) {
	if mountpoint == "" || !mountid.ValidMountInstance(mountInstanceID) {
		return nil, errors.New("mountv3: exact mountpoint and valid mount-instance identity are required for pre-kernel cleanup")
	}
	fsName := "portablefs:" + mountInstanceID
	return func(ctx context.Context) (*authoritypb.MountAbsenceProof, error) {
		if ctx == nil {
			return nil, errors.New("mountv3: pre-kernel mount-absence observation requires a context")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		proof, err := fusev3.ObservePlannedKernelMountAbsent(fsName, mountpoint)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("mountv3: pre-kernel mount-absence observation outlived its owner: %w", err)
		}
		return &authoritypb.MountAbsenceProof{
			ObservedUnixNanos: proof.ObservedUnixNanos,
			Observation:       append([]byte(nil), proof.Observation...),
			Component:         proof.Component,
		}, nil
	}, nil
}
