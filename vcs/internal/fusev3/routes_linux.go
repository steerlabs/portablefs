//go:build linux

package fusev3

import (
	"bytes"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// LocalDirsPath is the in-volume route declaration. It is ordinary authority
// data -- an ordinary file, read through an ordinary read -- which is precisely
// why a change to it is a change to the volume's namespace and not something
// this mount may apply to itself.
const LocalDirsPath = localroutes.ConfigPath

// The declaration itself is never read from here.
//
// A mount learns the volume's routing from the authority's attach refusal,
// which carries the active canonical rules precisely so that a mount which has
// never seen the volume has somewhere to start. Reading the file over a session
// of its own was the previous design and it was wrong in a way worth recording:
// a volume capability is single-use, so the session that succeeded in reading
// the declaration spent the credential the real mount needed, and every default
// mount failed. There is one capability, so there is one attach that may
// succeed.

// ActivateRoutes compiles the rule set this mount will serve, and therefore the
// revision it declares at attach.
//
// The volume's declaration is the ONLY input. A machine-local addition would be
// exactly the topology skew this whole mechanism exists to refuse: one machine
// hiding a directory every other machine believes is shared, with the volume's
// copy silently diverging from what that machine actually writes. Routing is a
// property of the workspace, so it is declared once, in the workspace, and the
// revision the authority pins a mount to is the digest of that declaration and
// of nothing a command line can add.
func ActivateRoutes(declaration []byte) (localroutes.RuleSet, error) {
	rules, err := localroutes.Parse(declaration)
	if err != nil {
		return localroutes.RuleSet{}, fmt.Errorf("fusev3: %s: %w", LocalDirsPath, err)
	}
	return rules, nil
}

// routesEventChange reports whether a visibility event announces a route
// declaration this mount did not attach with.
//
// The authority sends the change on both phases of the barrier and this answers
// on the first one it sees. Acting at PREPARE is deliberate: PREPARE is the
// point at which the new topology is not yet visible anywhere, so a mount that
// stops there has served nothing under the old rules that the new rules
// contradict.
func routesEventChange(mounted [32]byte, event *authoritypb.VisibilityEvent) error {
	revision := event.GetRoutes().GetRevision()
	if len(revision) == 0 || bytes.Equal(revision, mounted[:]) {
		return nil
	}
	return routesChangeCause(mounted[:], revision)
}

// routesChangeCause is the message a mount self-revokes with when the volume's
// route declaration moves under it.
//
// Route topology cannot change live and this is the fail-closed answer, not a
// missing feature. A mount that hot-swapped its routes would have to decide, for
// every path that changed sides, what happens to the data already written on the
// losing side: content written to machine-local backing under a rule that no
// longer exists is invisible to the volume, and content written to the volume
// under a rule that now exists is shadowed by backing that does not hold it.
// Neither outcome is expressible as a filesystem operation, so the mount stops
// being a filesystem instead of silently becoming a wrong one.
func routesChangeCause(mounted, announced []byte) error {
	return fmt.Errorf("fusev3: the volume's %s declaration changed from revision %x to %x; machine-local route topology is fixed for the life of a mount, so this mount has revoked itself -- unmount and mount again to serve the new routes",
		LocalDirsPath, mounted, announced)
}
