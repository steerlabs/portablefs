//go:build linux

package mountv3

import (
	"context"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
)

// RecoverEpoch creates a new epoch-scoped mount transport. The fuse frontend's
// stable facade publishes the returned value only after staling the old open
// handles and accounting for buffered loss.
func (t *Transport) RecoverEpoch(ctx context.Context) (fusev3.RPC, error) {
	client, err := t.Client.RecoverEpoch(ctx)
	if err != nil {
		return nil, err
	}
	return NewTransport(client), nil
}
