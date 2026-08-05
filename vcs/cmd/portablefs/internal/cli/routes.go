package cli

import "github.com/steerlabs/portablefs/vcs/internal/localroutes"

// mountRoutes is what one mount serves and what it answers for. The two are
// deliberately separate fields, because they are separate facts.
type mountRoutes struct {
	// rules is the route set this mount actually serves.
	rules localroutes.RuleSet
	// revision is EXACTLY the volume declaration's revision — the hash of
	// localroutes.Parse(<declaration bytes>) and of nothing else. It is the
	// value the authority pins the attach to, so it must describe what the
	// VOLUME declares, identically on every machine.
	revision string
	// declared reports that the volume publishes a declaration at all.
	declared bool
	// perMachine reports that rules came from this machine's own routing
	// rather than from the volume. A v3 mount never sets it: --local-dir is
	// refused unconditionally, so every route this mount serves is the
	// volume's.
	perMachine bool
}
