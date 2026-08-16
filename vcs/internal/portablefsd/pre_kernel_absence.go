package portablefsd

import (
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

type fskitKernelMount struct {
	path   string
	fsType string
	source string
}

// plannedFSKitMountAbsenceProof classifies a complete getfsstat snapshot by
// the attempt-unique FSKit resource URL, not by the target path alone. A
// filesystem can be mounted over the target concurrently without becoming
// this attempt; conversely, this attempt's source appearing anywhere is enough
// to refuse a clean release.
func plannedFSKitMountAbsenceProof(mounts []fskitKernelMount, mountPath, attachRef string, observed time.Time) (*authoritypb.MountAbsenceProof, error) {
	if mountPath == "" || !mountid.ValidAttachRef(attachRef) {
		return nil, errors.New("portablefsd: exact mount path and attach identity are required for pre-kernel cleanup")
	}
	if observed.IsZero() {
		return nil, errors.New("portablefsd: pre-kernel mount observation has no timestamp")
	}
	if len(mounts) == 0 {
		return nil, errors.New("portablefsd: getfsstat returned no mount records; absence cannot be established")
	}
	wantSource := fskitidentity.ResourcePrefix + attachRef
	for _, mount := range mounts {
		if mount.source != wantSource {
			continue
		}
		return nil, fmt.Errorf(
			"portablefsd: planned FSKit source %s is already installed as %s at %s",
			wantSource, mount.fsType, mount.path,
		)
	}
	return &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: observed.UnixNano(),
		Observation: []byte(fmt.Sprintf(
			"getfsstat(MNT_NOWAIT) mount-source=%s mountpoint=%s present=false records=%d stage=startup",
			wantSource, mountPath, len(mounts),
		)),
		Component: v3DetachProofComponent,
	}, nil
}
