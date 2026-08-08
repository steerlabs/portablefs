package directstoremodel

import "fmt"

type mutationStage uint8

const (
	mutationNothing mutationStage = iota
	mutationObjects
	mutationStateCommit
	mutationEntry
	mutationCommitIndex
	mutationInstalled
)

func (s mutationStage) String() string {
	switch s {
	case mutationNothing:
		return "nothing"
	case mutationObjects:
		return "objects"
	case mutationStateCommit:
		return "state-commit"
	case mutationEntry:
		return "consensus-entry"
	case mutationCommitIndex:
		return "commit-index"
	case mutationInstalled:
		return "root-installed"
	default:
		return fmt.Sprintf("mutation-stage(%d)", s)
	}
}

type mutationReplica struct {
	Alive   bool
	Stable  mutationStage
	Pending mutationStage
}

type replyState uint8

const (
	replyNone replyState = iota
	replyInFlight
	replyLost
	replyDelivered
)

type exactOutcome uint8

const (
	outcomeNone exactOutcome = iota
	outcomeOriginal
)

type mutationState struct {
	Replicas [4]mutationReplica
	Leader   int8
	Acks     Mask

	Committed      bool
	CommitCert     Mask
	CommitLeader   int8
	CommitOutcome  exactOutcome
	LogicalApplies uint8

	Reply         replyState
	ReplyAttempts uint8
	ReplyOutcome  exactOutcome
}

type mutationOptions struct {
	DropQuorumRequirement bool
}

type mutationTransition struct {
	name string
	next mutationState
}

type mutationParentStep struct {
	prior  mutationState
	action string
	has    bool
}

func initialMutationState(p Parameters) mutationState {
	state := mutationState{Leader: int8(onlyNode(p.OldVoters)), CommitLeader: noLeader}
	for i := range state.Replicas {
		state.Replicas[i].Alive = p.OldVoters.has(i)
	}
	return state
}

// ExploreMutation exhaustively explores all local persistence interleavings,
// leader crashes/restarts, elections, append-response loss (an acknowledgement
// can simply remain undelivered), commit/apply crashes, one lost success reply,
// and its exact retry. Two reply attempts are the smallest bound that contains
// both a lost first reply and a successful exact retry.
func ExploreMutation(p Parameters) Exploration {
	return exploreMutation(p, mutationOptions{})
}

func exploreMutation(p Parameters, options mutationOptions) Exploration {
	if err := validateParameters(p); err != nil {
		return Exploration{Violation: &Violation{Property: "parameters", Detail: err.Error()}}
	}
	initial := initialMutationState(p)
	queue := []mutationState{initial}
	parents := map[mutationState]mutationParentStep{initial: {}}
	coverage := map[string]bool{}
	transitions := 0

	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for _, transition := range mutationTransitions(p, state, options) {
			transitions++
			if _, ok := parents[transition.next]; ok {
				continue
			}
			parents[transition.next] = mutationParentStep{prior: state, action: transition.name, has: true}
			trace := mutationTrace(parents, transition.next)
			if violation := checkMutationInvariants(p, transition.next); violation != nil {
				violation.Trace = trace
				return Exploration{
					States: len(parents), Transitions: transitions,
					Violation: violation, Coverage: sortedCoverage(coverage),
				}
			}
			if transition.next.Reply == replyLost {
				coverage["exact-reply.success:lost"] = true
			}
			if transition.next.Reply == replyDelivered && transition.next.ReplyAttempts == 2 {
				coverage["exact-reply.success:retry-delivered"] = true
			}
			queue = append(queue, transition.next)
		}
	}
	return Exploration{
		States: len(parents), Transitions: transitions,
		Coverage: sortedCoverage(coverage),
	}
}

func mutationTrace(parents map[mutationState]mutationParentStep, state mutationState) []string {
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

func mutationTransitions(p Parameters, state mutationState, options mutationOptions) []mutationTransition {
	var out []mutationTransition
	leader := int(state.Leader)

	for node := range state.Replicas {
		if !p.OldVoters.has(node) {
			continue
		}
		replica := state.Replicas[node]
		if !replica.Alive {
			next := state
			next.Replicas[node].Alive = true
			out = append(out, mutationTransition{fmt.Sprintf("restart replica %d", node), next})
			continue
		}

		// A crash before completion loses only the in-flight write. Every
		// completed stage remains exactly as durable as it was before death.
		next := state
		next.Replicas[node].Alive = false
		next.Replicas[node].Pending = mutationNothing
		if leader == node {
			next.Leader = noLeader
			next.Acks = 0
			if next.Reply == replyInFlight {
				next.Reply = replyLost
			}
		}
		out = append(out, mutationTransition{fmt.Sprintf("crash replica %d", node), next})

		if replica.Pending != mutationNothing {
			next = state
			completed := replica.Pending
			next.Replicas[node].Pending = mutationNothing
			next.Replicas[node].Stable = completed
			if completed == mutationCommitIndex && !state.Committed {
				next.Committed = true
				next.CommitCert = state.Acks
				next.CommitLeader = int8(node)
				next.CommitOutcome = outcomeOriginal
				next.LogicalApplies = 1
			}
			out = append(out, mutationTransition{
				fmt.Sprintf("complete %s on replica %d", completed, node), next,
			})
			continue
		}

		switch replica.Stable {
		case mutationNothing, mutationObjects, mutationStateCommit:
			next = state
			next.Replicas[node].Pending = replica.Stable + 1
			out = append(out, mutationTransition{
				fmt.Sprintf("begin %s on replica %d", replica.Stable+1, node), next,
			})
		case mutationEntry:
			if state.Committed {
				next = state
				next.Replicas[node].Pending = mutationCommitIndex
				out = append(out, mutationTransition{
					fmt.Sprintf("begin commit-index on replica %d", node), next,
				})
			}
		case mutationCommitIndex:
			next = state
			next.Replicas[node].Pending = mutationInstalled
			out = append(out, mutationTransition{
				fmt.Sprintf("begin root-install on replica %d", node), next,
			})
		}
	}

	if leader >= 0 && state.Replicas[leader].Alive {
		for node, replica := range state.Replicas {
			if p.OldVoters.has(node) && replica.Alive && replica.Stable >= mutationEntry && !state.Acks.has(node) {
				next := state
				next.Acks |= 1 << node
				out = append(out, mutationTransition{
					fmt.Sprintf("deliver append response replica %d to leader %d", node, leader), next,
				})
			}
		}

		leaderReplica := state.Replicas[leader]
		if !state.Committed && leaderReplica.Stable == mutationEntry && leaderReplica.Pending == mutationNothing {
			allowed := HasQuorum(p, OldConfig, state.Acks) && state.Acks.has(leader)
			if options.DropQuorumRequirement {
				allowed = state.Acks.has(leader)
			}
			if allowed {
				next := state
				next.Replicas[leader].Pending = mutationCommitIndex
				out = append(out, mutationTransition{"begin leader commit-index", next})
			}
		}

		if state.Committed && leaderReplica.Stable >= mutationInstalled &&
			(state.Reply == replyNone || state.Reply == replyLost) && state.ReplyAttempts < 2 {
			next := state
			next.Reply = replyInFlight
			next.ReplyAttempts++
			next.ReplyOutcome = state.CommitOutcome
			name := "emit success reply"
			if state.Reply == replyLost {
				name = "retry exact identity and emit stored success reply"
			}
			out = append(out, mutationTransition{name, next})
		}
	}

	if state.Reply == replyInFlight {
		next := state
		next.Reply = replyLost
		out = append(out, mutationTransition{"drop success reply", next})
		next = state
		next.Reply = replyDelivered
		out = append(out, mutationTransition{"deliver success reply", next})
	}

	if state.Leader == noLeader {
		alive := Mask(0)
		for node, replica := range state.Replicas {
			if p.OldVoters.has(node) && replica.Alive {
				alive |= 1 << node
			}
		}
		for candidate, replica := range state.Replicas {
			if !replica.Alive || !p.OldVoters.has(candidate) {
				continue
			}
			for _, votes := range quorumMasks(p, OldConfig) {
				if votes&^alive != 0 || !votes.has(candidate) {
					continue
				}
				// For this one-index model, a voter holding a committed
				// entry rejects a candidate that lacks it. Commit/election
				// quorum intersection therefore derives leader completeness.
				eligible := true
				if state.Committed && replica.Stable < mutationEntry {
					for voter := range state.Replicas {
						if votes.has(voter) && state.CommitCert.has(voter) {
							eligible = false
						}
					}
				}
				if !eligible {
					continue
				}
				next := state
				next.Leader = int8(candidate)
				next.Acks = 0
				out = append(out, mutationTransition{
					fmt.Sprintf("elect replica %d with voters %03b", candidate, votes), next,
				})
			}
		}
	}
	return out
}

func checkMutationInvariants(p Parameters, state mutationState) *Violation {
	for node, replica := range state.Replicas {
		if state.Acks.has(node) && replica.Stable < mutationEntry {
			return &Violation{Property: "vote-before-durability", Detail: fmt.Sprintf("replica %d acknowledged at stage %s", node, replica.Stable)}
		}
		if replica.Stable >= mutationInstalled && !state.Committed {
			return &Violation{Property: "uncommitted-root-visible", Detail: fmt.Sprintf("replica %d installed an uncommitted root", node)}
		}
	}
	if state.Committed {
		if !HasQuorum(p, OldConfig, state.CommitCert) {
			return &Violation{Property: "commit-without-quorum", Detail: fmt.Sprintf("certificate %03b is not a quorum", state.CommitCert)}
		}
		if state.CommitLeader < 0 || !state.CommitCert.has(int(state.CommitLeader)) {
			return &Violation{Property: "leader-not-durable-at-commit", Detail: fmt.Sprintf("leader %d absent from certificate %03b", state.CommitLeader, state.CommitCert)}
		}
		if state.CommitOutcome == outcomeNone || state.LogicalApplies != 1 {
			return &Violation{Property: "exact-outcome-not-committed", Detail: fmt.Sprintf("outcome=%d logical applies=%d", state.CommitOutcome, state.LogicalApplies)}
		}
	}
	if state.Reply != replyNone {
		if !state.Committed {
			return &Violation{Property: "success-before-commit", Detail: "a success reply exists without a committed entry"}
		}
		leader := int(state.Leader)
		if state.Reply == replyInFlight && (leader < 0 || state.Replicas[leader].Stable < mutationInstalled) {
			return &Violation{Property: "success-before-root-install", Detail: "the emitting leader has not durably installed the root"}
		}
		if state.ReplyOutcome != state.CommitOutcome || state.LogicalApplies != 1 {
			return &Violation{Property: "exact-retry-changed-outcome", Detail: fmt.Sprintf("reply outcome=%d committed outcome=%d logical applies=%d", state.ReplyOutcome, state.CommitOutcome, state.LogicalApplies)}
		}
		copies := Mask(0)
		for node, replica := range state.Replicas {
			if replica.Stable >= mutationStateCommit {
				copies |= 1 << node
			}
		}
		if distinctAZCopies(p, copies) < RequiredDurableAZCopies(p) {
			return &Violation{
				Property: "success-with-insufficient-az-copies",
				Detail: fmt.Sprintf("copies %03b span %d AZs; need %d", copies,
					distinctAZCopies(p, copies), RequiredDurableAZCopies(p)),
			}
		}
	}
	return nil
}
