//go:build linux

package workspacemount

import (
	"bytes"
	"context"
	"errors"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func TestOvertakenUmountCannotEscalateClosedMount(t *testing.T) {
	id := &pb.MountID{AuthorityId: bytes.Repeat([]byte{1}, 32), VolumeId: "test", Incarnation: bytes.Repeat([]byte{2}, 16)}
	for _, serving := range []bool{false, true} {
		d := &Driver{}
		d.serving.Store(serving)
		// No Host is installed: a cancelled intent must reach no terminal
		// transition, kernel effect or lifecycle operation.
		m := &Manager{mounts: map[string]*Driver{control.MountKey(id): d}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.Run(ctx, &pb.MountJob{Mount: id, Operation: "umount"}, nil); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if d.removals[0] != nil || d.removals[1] != nil || d.serving.Load() != serving {
			t.Fatal("overtaken Umount changed kernel ownership")
		}
	}
}
