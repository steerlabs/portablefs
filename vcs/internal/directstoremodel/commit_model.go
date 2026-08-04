package directstoremodel

import "fmt"

type rootValue uint8

// One index and two distinct roots are the smallest bound that can falsify
// committed-root uniqueness; additional values cannot produce a new form of
// this safety violation.
const modeledIndex = 1

const (
	noRoot rootValue = iota
	rootX
	rootY
)

func (r rootValue) String() string {
	switch r {
	case rootX:
		return "root-x"
	case rootY:
		return "root-y"
	default:
		return "none"
	}
}

type commitState struct {
	Accepted  [4]rootValue
	Committed uint8
	CertX     Mask
	CertY     Mask
}

type commitOptions struct {
	AllowCommittedOverwrite bool
}

type commitTransition struct {
	name string
	next commitState
}

type commitParentStep struct {
	prior  commitState
	action string
	has    bool
}

// ExploreCommitUniqueness checks that no two roots can be committed at one
// index. The finite model permits arbitrary overwrites of uncommitted tails.
// Once a quorum certificate exists, its replicas become witnesses: quorum
// intersection forces every competing quorum to contain at least one witness
// that refuses the overwrite.
func ExploreCommitUniqueness(p Parameters) Exploration {
	return exploreCommitUniqueness(p, commitOptions{})
}

func exploreCommitUniqueness(p Parameters, options commitOptions) Exploration {
	if err := validateParameters(p); err != nil {
		return Exploration{Violation: &Violation{Property: "parameters", Detail: err.Error()}}
	}
	initial := commitState{}
	queue := []commitState{initial}
	parents := map[commitState]commitParentStep{initial: {}}
	transitions := 0
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for _, transition := range commitTransitions(p, state, options) {
			transitions++
			if _, ok := parents[transition.next]; ok {
				continue
			}
			parents[transition.next] = commitParentStep{prior: state, action: transition.name, has: true}
			if state := transition.next; state.Committed == (1<<rootX)|(1<<rootY) {
				return Exploration{
					States: len(parents), Transitions: transitions,
					Violation: &Violation{
						Property: "two-committed-roots-at-one-index",
						Detail:   fmt.Sprintf("root-x certificate %03b and root-y certificate %03b", state.CertX, state.CertY),
						Trace:    commitTrace(parents, state),
					},
				}
			}
			queue = append(queue, transition.next)
		}
	}
	return Exploration{States: len(parents), Transitions: transitions}
}

func commitTransitions(p Parameters, state commitState, options commitOptions) []commitTransition {
	var out []commitTransition
	for node := range state.Accepted {
		if !p.OldVoters.has(node) {
			continue
		}
		for _, root := range []rootValue{rootX, rootY} {
			if state.Accepted[node] == root {
				continue
			}
			locked := state.CertX.has(node) || state.CertY.has(node)
			if locked && !options.AllowCommittedOverwrite {
				continue
			}
			next := state
			next.Accepted[node] = root
			out = append(out, commitTransition{
				fmt.Sprintf("persist %s at index %d on replica %d", root, modeledIndex, node), next,
			})
		}
	}
	for _, root := range []rootValue{rootX, rootY} {
		if state.Committed&(1<<root) != 0 {
			continue
		}
		var accepted Mask
		for node, got := range state.Accepted {
			if p.OldVoters.has(node) && got == root {
				accepted |= 1 << node
			}
		}
		for _, cert := range quorumMasks(p, OldConfig) {
			if cert&^accepted != 0 {
				continue
			}
			next := state
			next.Committed |= 1 << root
			if root == rootX {
				next.CertX = cert
			} else {
				next.CertY = cert
			}
			out = append(out, commitTransition{
				fmt.Sprintf("commit %s at index %d with certificate %03b", root, modeledIndex, cert), next,
			})
		}
	}
	return out
}

func commitTrace(parents map[commitState]commitParentStep, state commitState) []string {
	var reverse []string
	for {
		step := parents[state]
		if !step.has {
			break
		}
		reverse = append(reverse, step.action)
		state = step.prior
	}
	trace := make([]string, len(reverse))
	for i := range reverse {
		trace[len(reverse)-1-i] = reverse[i]
	}
	return trace
}

// CheckQuorumIntersection exhaustively enumerates the stable and joint quorum
// sets used by the model. Adjacent membership phases must intersect; direct
// old-to-new intersection is deliberately not relied upon.
func CheckQuorumIntersection(p Parameters) *Violation {
	if err := validateParameters(p); err != nil {
		return &Violation{Property: "parameters", Detail: err.Error()}
	}
	type pair struct {
		left  ConfigPhase
		right ConfigPhase
	}
	checks := []pair{
		{OldConfig, OldConfig},
		{OldConfig, JointConfig},
		{JointConfig, JointConfig},
		{JointConfig, NewConfig},
		{NewConfig, NewConfig},
	}
	for _, check := range checks {
		for _, left := range quorumMasks(p, check.left) {
			for _, right := range quorumMasks(p, check.right) {
				if left&right == 0 {
					return &Violation{
						Property: "quorum-intersection",
						Detail: fmt.Sprintf("%s quorum %04b does not intersect %s quorum %04b",
							check.left, left, check.right, right),
					}
				}
			}
		}
	}
	return nil
}
