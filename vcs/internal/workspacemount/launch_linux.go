//go:build linux

package workspacemount

import (
	"encoding/json"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"io"
)

// Launch is private inherited-pipe material. Never serialize it to a log or to
// either inventory; in particular PrivateKey belongs only to the volume child.
type Launch struct {
	Binding                     workspaceadmission.Binding
	ClockBinding                [16]byte
	Provision                   *pb.Provision
	PrivateKey                  []byte
	StateDirectory, BackingRoot string
	TargetDevice, TargetInode   uint64
}
type ChildReady struct {
	Socket string `json:"socket"`
}

type Reconciliation struct {
	NeverSpawned   bool
	ExitedProcess  string
	Desired        *Desired
	StateDirectory string
}

func ReadLaunch(r io.Reader) (Launch, error) {
	var c Launch
	d := json.NewDecoder(io.LimitReader(r, 2<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid workspace launch handoff")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("trailing workspace launch handoff")
	}
	return c, nil
}
