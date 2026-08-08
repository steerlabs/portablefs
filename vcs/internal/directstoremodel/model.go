package directstoremodel

import (
	"fmt"
	"math/bits"
	"slices"
)

// Mask is a replica set. The Phase 0 bound has four replicas because one
// three-voter configuration plus one replacement learner is the smallest
// system that exercises a real membership change.
type Mask uint8

const noLeader int8 = -1

// Parameters expose the values inside the executable model's fixed topology.
// The topology bound comes directly from the exploration design: three
// voters, one tolerated AZ failure, one replacement learner, and one declared
// AZ per machine. validateParameters rejects a different topology instead of
// silently pretending the finite proof covers it.
type Parameters struct {
	ReplicaAZ           []string
	OldVoters           Mask
	NewVoters           Mask
	ToleratedAZFailures int
}

// DefaultParameters returns the Phase 0 design point. Nothing in the checker
// assumes that quorum size or durable-copy count is the literal number two;
// both are derived from these parameters.
func DefaultParameters() Parameters {
	return Parameters{
		ReplicaAZ:           []string{"az-a", "az-b", "az-c", "az-d"},
		OldVoters:           maskOf(0, 1, 2),
		NewVoters:           maskOf(1, 2, 3),
		ToleratedAZFailures: 1,
	}
}

func maskOf(nodes ...int) Mask {
	var out Mask
	for _, node := range nodes {
		out |= 1 << node
	}
	return out
}

func (m Mask) has(node int) bool { return m&(1<<node) != 0 }

func (m Mask) count() int { return bits.OnesCount8(uint8(m)) }

func majority(voters Mask) int { return voters.count()/2 + 1 }

// ConfigPhase is the active committed membership rule.
type ConfigPhase uint8

const (
	OldConfig ConfigPhase = iota
	JointConfig
	NewConfig
)

func (p ConfigPhase) String() string {
	switch p {
	case OldConfig:
		return "old"
	case JointConfig:
		return "joint"
	case NewConfig:
		return "new"
	default:
		return fmt.Sprintf("config(%d)", p)
	}
}

// HasQuorum implements stable-majority and joint-consensus voting. Joint
// consensus is deliberately an AND, never a majority of the union.
func HasQuorum(p Parameters, phase ConfigPhase, votes Mask) bool {
	switch phase {
	case OldConfig:
		return (votes & p.OldVoters).count() >= majority(p.OldVoters)
	case JointConfig:
		return (votes&p.OldVoters).count() >= majority(p.OldVoters) &&
			(votes&p.NewVoters).count() >= majority(p.NewVoters)
	case NewConfig:
		return (votes & p.NewVoters).count() >= majority(p.NewVoters)
	default:
		return false
	}
}

func voterUnion(p Parameters, phase ConfigPhase) Mask {
	switch phase {
	case OldConfig:
		return p.OldVoters
	case JointConfig:
		return p.OldVoters | p.NewVoters
	case NewConfig:
		return p.NewVoters
	default:
		return 0
	}
}

func quorumMasks(p Parameters, phase ConfigPhase) []Mask {
	limit := 1 << len(p.ReplicaAZ)
	var out []Mask
	for raw := 1; raw < limit; raw++ {
		mask := Mask(raw)
		if mask&^voterUnion(p, phase) == 0 && HasQuorum(p, phase, mask) {
			out = append(out, mask)
		}
	}
	return out
}

// RequiredDurableAZCopies is derived from the declared crash fault: after any
// ToleratedAZFailures complete AZ losses, at least one copy must remain.
func RequiredDurableAZCopies(p Parameters) int { return p.ToleratedAZFailures + 1 }

func distinctAZCopies(p Parameters, copies Mask) int {
	seen := map[string]struct{}{}
	for node, az := range p.ReplicaAZ {
		if copies.has(node) {
			seen[az] = struct{}{}
		}
	}
	return len(seen)
}

// Violation includes a shortest counterexample trace because a safety check
// that only returns false is not useful to the Phase 1 fault harness.
type Violation struct {
	Property string
	Detail   string
	Trace    []string
}

func (v *Violation) Error() string {
	return fmt.Sprintf("%s: %s\ntrace:\n  %s", v.Property, v.Detail, joinTrace(v.Trace))
}

func joinTrace(trace []string) string {
	if len(trace) == 0 {
		return "<initial state>"
	}
	out := trace[0]
	for _, step := range trace[1:] {
		out += "\n  " + step
	}
	return out
}

// Exploration reports the complete finite state graph visited by a checker.
type Exploration struct {
	States      int
	Transitions int
	Violation   *Violation
	Coverage    []string
}

func sortedCoverage(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	slices.Sort(out)
	return out
}

func validateParameters(p Parameters) error {
	if len(p.ReplicaAZ) != 4 {
		return fmt.Errorf("replica count %d does not match the bounded three-voter plus one-learner model", len(p.ReplicaAZ))
	}
	all := Mask((1 << len(p.ReplicaAZ)) - 1)
	if p.OldVoters == 0 || p.NewVoters == 0 || p.OldVoters&^all != 0 || p.NewVoters&^all != 0 {
		return fmt.Errorf("voter masks are empty or outside the replica set")
	}
	if p.OldVoters.count() != 2*p.ToleratedAZFailures+1 || p.NewVoters.count() != 2*p.ToleratedAZFailures+1 {
		return fmt.Errorf("each stable configuration must have 2f+1 voters")
	}
	if (p.NewVoters&^p.OldVoters).count() != 1 || (p.OldVoters&^p.NewVoters).count() != 1 {
		return fmt.Errorf("the bounded membership model replaces exactly one voter with one learner")
	}
	seen := map[string]bool{}
	for _, az := range p.ReplicaAZ {
		if az == "" || seen[az] {
			return fmt.Errorf("replica AZs must be non-empty and distinct in the Phase 0 placement bound")
		}
		seen[az] = true
	}
	return nil
}

func onlyNode(mask Mask) int {
	for node := 0; node < 8; node++ {
		if mask.has(node) {
			return node
		}
	}
	return -1
}
