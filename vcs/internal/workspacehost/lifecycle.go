package workspacehost

import (
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
)

// Lifecycle v1 is a separately versioned, read/idle-quiesce boundary. A
// quiesced reply is not VM/process termination or singleton-release proof.
// The future installer must authenticate the outgoing release first.
type LifecycleRequest struct {
	Version   int    `json:"lifecycleVersion"`
	Operation string `json:"operation"`
}
type LifecycleReply struct {
	Version            int    `json:"lifecycleVersion"`
	IdentitySchema     int    `json:"identitySchema"`
	OperationalVersion int    `json:"operationalVersion"`
	State              string `json:"state"`
	ExecutionPresent   bool   `json:"executionPresent"`
	DesiredRunning     bool   `json:"desiredRunning"`
}

func DecodeLifecycle(raw []byte) (LifecycleRequest, error) {
	r, err := hostctl.DecodeExact[LifecycleRequest](raw)
	if err != nil {
		return r, err
	}
	if r.Version != 1 || r.Operation != "identity" && r.Operation != "inventory" && r.Operation != "quiesce" {
		return r, errors.New("invalid workspace lifecycle request")
	}
	return r, nil
}
