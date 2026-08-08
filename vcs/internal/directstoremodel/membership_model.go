package directstoremodel

import "fmt"

type snapshotStage uint8

const (
	snapshotNothing snapshotStage = iota
	snapshotObjects
	snapshotStateCommit
	snapshotConsensusMetadata
	snapshotInstalled
)

func (s snapshotStage) String() string {
	switch s {
	case snapshotNothing:
		return "nothing"
	case snapshotObjects:
		return "snapshot-objects"
	case snapshotStateCommit:
		return "snapshot-state-commit"
	case snapshotConsensusMetadata:
		return "snapshot-consensus-metadata"
	case snapshotInstalled:
		return "snapshot-installed"
	default:
		return fmt.Sprintf("snapshot-stage(%d)", s)
	}
}

type configChange uint8

const (
	noConfigChange configChange = iota
	jointChange
	finalChange
)

func (c configChange) String() string {
	switch c {
	case jointChange:
		return "joint"
	case finalChange:
		return "final"
	default:
		return "none"
	}
}

type membershipState struct {
	Alive  Mask
	Leader int8

	Snapshot        snapshotStage
	SnapshotPending snapshotStage

	Phase                ConfigPhase
	Change               configChange
	EntryAcks            Mask
	EntryPending         int8
	ChangeCommitPending  bool
	ChangeCommitted      bool
	ChangeInstallPending bool
}

type membershipTransition struct {
	name string
	next membershipState
}

type membershipParentStep struct {
	prior  membershipState
	action string
	has    bool
}

// ExploreMembership exhaustively explores learner snapshot installation,
// old -> joint -> new membership, and leader loss during every phase. The
// model never counts the learner as a voter or full copy until its snapshot
// root and applied index are durably installed.
func ExploreMembership(p Parameters) Exploration {
	if err := validateParameters(p); err != nil {
		return Exploration{Violation: &Violation{Property: "parameters", Detail: err.Error()}}
	}
	initial := membershipState{
		Alive: p.OldVoters | p.NewVoters, Leader: int8(onlyNode(p.OldVoters)),
		Phase: OldConfig, EntryPending: noLeader,
	}
	queue := []membershipState{initial}
	parents := map[membershipState]membershipParentStep{initial: {}}
	transitions := 0
	coverage := map[string]bool{}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for _, transition := range membershipTransitions(p, state) {
			transitions++
			if _, ok := parents[transition.next]; ok {
				continue
			}
			parents[transition.next] = membershipParentStep{prior: state, action: transition.name, has: true}
			trace := membershipTrace(parents, transition.next)
			if violation := checkMembershipInvariants(p, transition.next); violation != nil {
				violation.Trace = trace
				return Exploration{States: len(parents), Transitions: transitions, Violation: violation, Coverage: sortedCoverage(coverage)}
			}
			if transition.next.Snapshot == snapshotInstalled {
				coverage["snapshot-installation"] = true
			}
			if transition.next.Phase == JointConfig {
				coverage["membership-joint"] = true
			}
			if transition.next.Phase == NewConfig {
				coverage["membership-final"] = true
			}
			queue = append(queue, transition.next)
		}
	}
	return Exploration{States: len(parents), Transitions: transitions, Coverage: sortedCoverage(coverage)}
}

func effectiveConfig(state membershipState) ConfigPhase {
	if state.ChangeCommitted {
		if state.Change == jointChange {
			return JointConfig
		}
		if state.Change == finalChange {
			return NewConfig
		}
	}
	return state.Phase
}

func membershipTransitions(p Parameters, state membershipState) []membershipTransition {
	var out []membershipTransition
	learner := onlyNode(p.NewVoters &^ p.OldVoters)

	for node := range p.ReplicaAZ {
		if state.Alive.has(node) {
			next := state
			next.Alive &^= 1 << node
			if int(state.Leader) == node {
				next.Leader = noLeader
				next.ChangeCommitPending = false
				next.ChangeInstallPending = false
			}
			if int(state.EntryPending) == node {
				next.EntryPending = noLeader
			}
			if node == learner {
				next.SnapshotPending = snapshotNothing
			}
			out = append(out, membershipTransition{fmt.Sprintf("crash replica %d", node), next})
		} else {
			next := state
			next.Alive |= 1 << node
			out = append(out, membershipTransition{fmt.Sprintf("restart replica %d", node), next})
		}
	}

	if state.Leader >= 0 && state.Alive.has(learner) && state.Snapshot < snapshotInstalled {
		if state.SnapshotPending == snapshotNothing {
			next := state
			next.SnapshotPending = state.Snapshot + 1
			out = append(out, membershipTransition{fmt.Sprintf("begin %s", state.Snapshot+1), next})
		} else {
			next := state
			next.Snapshot = state.SnapshotPending
			next.SnapshotPending = snapshotNothing
			out = append(out, membershipTransition{fmt.Sprintf("complete %s", next.Snapshot), next})
		}
	}

	if state.Change == noConfigChange && state.Leader >= 0 {
		switch state.Phase {
		case OldConfig:
			if state.Snapshot == snapshotInstalled {
				next := state
				next.Change = jointChange
				next.EntryPending = noLeader
				out = append(out, membershipTransition{"propose joint configuration", next})
			}
		case JointConfig:
			next := state
			next.Change = finalChange
			next.EntryPending = noLeader
			out = append(out, membershipTransition{"propose final configuration", next})
		}
	}

	if state.Change != noConfigChange {
		if state.EntryPending == noLeader {
			if state.Leader >= 0 {
				for node := range p.ReplicaAZ {
					if !state.Alive.has(node) || state.EntryAcks.has(node) {
						continue
					}
					next := state
					next.EntryPending = int8(node)
					out = append(out, membershipTransition{
						fmt.Sprintf("begin %s config entry sync on replica %d", state.Change, node), next,
					})
				}
			}
		} else {
			node := int(state.EntryPending)
			if state.Alive.has(node) {
				next := state
				next.EntryAcks |= 1 << node
				next.EntryPending = noLeader
				out = append(out, membershipTransition{
					fmt.Sprintf("complete %s config entry sync on replica %d", state.Change, node), next,
				})
			}
		}

		leader := int(state.Leader)
		if leader >= 0 && state.Alive.has(leader) && !state.ChangeCommitted {
			commitPhase := OldConfig
			if state.Change == finalChange {
				commitPhase = JointConfig
			}
			if !state.ChangeCommitPending && state.EntryAcks.has(leader) && HasQuorum(p, commitPhase, state.EntryAcks) {
				next := state
				next.ChangeCommitPending = true
				out = append(out, membershipTransition{fmt.Sprintf("begin %s config commit-index", state.Change), next})
			}
			if state.ChangeCommitPending {
				next := state
				next.ChangeCommitPending = false
				next.ChangeCommitted = true
				out = append(out, membershipTransition{fmt.Sprintf("complete %s config commit-index", state.Change), next})
			}
		}

		if state.ChangeCommitted && state.Leader >= 0 {
			if !state.ChangeInstallPending {
				next := state
				next.ChangeInstallPending = true
				out = append(out, membershipTransition{fmt.Sprintf("begin %s config install", state.Change), next})
			} else {
				next := state
				if state.Change == jointChange {
					next.Phase = JointConfig
				} else {
					next.Phase = NewConfig
				}
				next.Change = noConfigChange
				next.EntryAcks = 0
				next.EntryPending = noLeader
				next.ChangeCommitted = false
				next.ChangeInstallPending = false
				out = append(out, membershipTransition{fmt.Sprintf("complete %s config install", state.Change), next})
			}
		}
	}

	if state.Leader == noLeader {
		phase := effectiveConfig(state)
		for candidate := range p.ReplicaAZ {
			if !state.Alive.has(candidate) || !voterUnion(p, phase).has(candidate) {
				continue
			}
			for _, voters := range quorumMasks(p, phase) {
				if !voters.has(candidate) || voters&^state.Alive != 0 {
					continue
				}
				next := state
				next.Leader = int8(candidate)
				out = append(out, membershipTransition{
					fmt.Sprintf("elect replica %d under %s config with voters %04b", candidate, phase, voters), next,
				})
			}
		}
	}
	return out
}

func checkMembershipInvariants(p Parameters, state membershipState) *Violation {
	learnerMask := p.NewVoters &^ p.OldVoters
	if learnerMask.count() != 1 {
		return &Violation{Property: "model-bound", Detail: "membership model requires exactly one replacement learner"}
	}
	if state.Change != noConfigChange && state.Phase == OldConfig && state.Snapshot < snapshotInstalled {
		return &Violation{Property: "learner-promoted-before-snapshot", Detail: "joint configuration began before the learner installed a verified snapshot"}
	}
	if state.Phase == NewConfig && state.Snapshot < snapshotInstalled {
		return &Violation{Property: "new-voter-without-full-copy", Detail: "new configuration contains an incomplete replica"}
	}
	if state.ChangeCommitted {
		phase := OldConfig
		if state.Change == finalChange {
			phase = JointConfig
		}
		if !HasQuorum(p, phase, state.EntryAcks) {
			return &Violation{Property: "membership-commit-without-quorum", Detail: fmt.Sprintf("%s certificate %04b fails %s quorum", state.Change, state.EntryAcks, phase)}
		}
	}

	fullCopies := p.OldVoters
	if state.Snapshot == snapshotInstalled {
		fullCopies |= learnerMask
	}
	phase := effectiveConfig(state)
	for _, cert := range quorumMasks(p, phase) {
		if cert&^fullCopies != 0 {
			return &Violation{Property: "quorum-counts-incomplete-copy", Detail: fmt.Sprintf("%s quorum %04b includes a replica without installed state", phase, cert)}
		}
		if distinctAZCopies(p, cert) < RequiredDurableAZCopies(p) {
			return &Violation{Property: "membership-quorum-insufficient-az-copies", Detail: fmt.Sprintf("%s quorum %04b spans too few AZs", phase, cert)}
		}
	}
	return nil
}

func membershipTrace(parents map[membershipState]membershipParentStep, state membershipState) []string {
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
