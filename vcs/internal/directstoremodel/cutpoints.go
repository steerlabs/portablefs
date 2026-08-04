// Package directstoremodel is the executable Phase 0 safety specification for
// the proposed replicated readable store. It models the boundary between a
// crash-consensus component and materialized replica storage; it is not a
// consensus implementation or a serving-path prototype.
package directstoremodel

// CutKind distinguishes stable-storage boundaries from messages whose loss is
// semantically important. The fault harness must crash before and after every
// persistence cut and must independently drop every message cut.
type CutKind string

const (
	PersistenceCut CutKind = "persistence"
	MessageCut     CutKind = "message"
)

// Scenario identifies the operation whose local state is crossing a cut.
type Scenario string

const (
	ElectionScenario    Scenario = "election"
	MutationScenario    Scenario = "mutation"
	SnapshotScenario    Scenario = "snapshot"
	JointConfigScenario Scenario = "membership_joint"
	FinalConfigScenario Scenario = "membership_final"
	ExactReplyScenario  Scenario = "exact_reply"
)

// DurableFact is a local, restart-visible fact. Names are intentionally
// operation-scoped: the same physical transaction API may establish several
// facts atomically, but the harness must prove that no crash state exists
// between facts it claims are atomic.
type DurableFact string

const (
	FactTermVote          DurableFact = "term_and_vote"
	FactObjects           DurableFact = "materialized_object_closure"
	FactStateCommit       DurableFact = "state_commit_and_exact_outcome"
	FactConsensusEntry    DurableFact = "consensus_entry_and_hard_state"
	FactCommitIndex       DurableFact = "committed_index"
	FactRootInstalled     DurableFact = "visible_root_and_applied_index"
	FactSnapshotObjects   DurableFact = "snapshot_object_closure"
	FactSnapshotCommit    DurableFact = "snapshot_state_commit"
	FactSnapshotConsensus DurableFact = "consensus_snapshot_metadata"
	FactSnapshotInstalled DurableFact = "snapshot_root_and_applied_index"
	FactConfigEntry       DurableFact = "configuration_entry_and_hard_state"
	FactConfigCommit      DurableFact = "configuration_commit_index"
	FactConfigInstalled   DurableFact = "installed_configuration"
)

// CutPoint is the machine-readable contract consumed by the Phase 1 fault
// harness. IDs are stable test identities. BeforeFacts must be durable before
// the event can start; AfterFacts become durable atomically when it completes.
// A persistence cut is injected twice: immediately before completion and
// immediately after completion, on every actor named in Actors.
type CutPoint struct {
	ID          string
	Kind        CutKind
	Scenario    Scenario
	Actors      []string
	BeforeFacts []DurableFact
	AfterFacts  []DurableFact
}

// CrashSide is the side of a stable-storage completion at which the process
// is killed. Before must recover without AfterFacts; After must recover with
// all AfterFacts.
type CrashSide string

const (
	CrashBefore CrashSide = "before"
	CrashAfter  CrashSide = "after"
)

// PersistenceFaultCase is one concrete harness injection. CutIndex addresses
// PersistenceCutPoints without copying it; actor and side make the required
// cross product explicit and machine-readable.
type PersistenceFaultCase struct {
	ID       string
	CutIndex int
	Actor    string
	Side     CrashSide
}

// PersistenceFaultCases expands the authoritative cut table into every
// required actor × before/after injection. Harnesses should iterate this
// function rather than inventing a list from prose.
func PersistenceFaultCases() []PersistenceFaultCase {
	var out []PersistenceFaultCase
	for cutIndex, cut := range PersistenceCutPoints {
		for _, actor := range cut.Actors {
			for _, side := range []CrashSide{CrashBefore, CrashAfter} {
				out = append(out, PersistenceFaultCase{
					ID:       cut.ID + "." + actor + "." + string(side),
					CutIndex: cutIndex,
					Actor:    actor,
					Side:     side,
				})
			}
		}
	}
	return out
}

// PersistenceCutPoints is the complete Phase 0 enumeration of local durable
// boundaries. Consensus configuration entries carry no filesystem objects,
// so their first durable event is the configuration log entry. Snapshot
// installation has its own object and descriptor boundaries because a learner
// cannot vote merely because it has received bytes.
var PersistenceCutPoints = []CutPoint{
	{
		ID: "election.candidate.term-vote-sync", Kind: PersistenceCut,
		Scenario: ElectionScenario, Actors: []string{"candidate"},
		AfterFacts: []DurableFact{FactTermVote},
	},
	{
		ID: "election.voter.term-vote-sync", Kind: PersistenceCut,
		Scenario: ElectionScenario, Actors: []string{"voter"},
		AfterFacts: []DurableFact{FactTermVote},
	},
	{
		ID: "mutation.leader.object-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"leader"},
		AfterFacts: []DurableFact{FactObjects},
	},
	{
		ID: "mutation.leader.state-commit-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"leader"},
		BeforeFacts: []DurableFact{FactObjects},
		AfterFacts:  []DurableFact{FactStateCommit},
	},
	{
		ID: "mutation.leader.consensus-entry-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"leader"},
		BeforeFacts: []DurableFact{FactObjects, FactStateCommit},
		AfterFacts:  []DurableFact{FactConsensusEntry},
	},
	{
		ID: "mutation.follower.object-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"follower"},
		AfterFacts: []DurableFact{FactObjects},
	},
	{
		ID: "mutation.follower.state-commit-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"follower"},
		BeforeFacts: []DurableFact{FactObjects},
		AfterFacts:  []DurableFact{FactStateCommit},
	},
	{
		ID: "mutation.follower.consensus-entry-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"follower"},
		BeforeFacts: []DurableFact{FactObjects, FactStateCommit},
		AfterFacts:  []DurableFact{FactConsensusEntry},
	},
	{
		ID: "mutation.leader.commit-index-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"leader"},
		BeforeFacts: []DurableFact{FactObjects, FactStateCommit, FactConsensusEntry},
		AfterFacts:  []DurableFact{FactCommitIndex},
	},
	{
		ID: "mutation.follower.commit-index-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"follower"},
		BeforeFacts: []DurableFact{FactObjects, FactStateCommit, FactConsensusEntry},
		AfterFacts:  []DurableFact{FactCommitIndex},
	},
	{
		ID: "mutation.leader.root-install-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"leader"},
		BeforeFacts: []DurableFact{FactObjects, FactStateCommit, FactConsensusEntry, FactCommitIndex},
		AfterFacts:  []DurableFact{FactRootInstalled},
	},
	{
		ID: "mutation.follower.root-install-sync", Kind: PersistenceCut,
		Scenario: MutationScenario, Actors: []string{"follower"},
		BeforeFacts: []DurableFact{FactObjects, FactStateCommit, FactConsensusEntry, FactCommitIndex},
		AfterFacts:  []DurableFact{FactRootInstalled},
	},
	{
		ID: "snapshot.receiver.object-sync", Kind: PersistenceCut,
		Scenario: SnapshotScenario, Actors: []string{"snapshot_receiver"},
		AfterFacts: []DurableFact{FactSnapshotObjects},
	},
	{
		ID: "snapshot.receiver.state-commit-sync", Kind: PersistenceCut,
		Scenario: SnapshotScenario, Actors: []string{"snapshot_receiver"},
		BeforeFacts: []DurableFact{FactSnapshotObjects},
		AfterFacts:  []DurableFact{FactSnapshotCommit},
	},
	{
		ID: "snapshot.receiver.consensus-snapshot-sync", Kind: PersistenceCut,
		Scenario: SnapshotScenario, Actors: []string{"snapshot_receiver"},
		BeforeFacts: []DurableFact{FactSnapshotObjects, FactSnapshotCommit},
		AfterFacts:  []DurableFact{FactSnapshotConsensus},
	},
	{
		ID: "snapshot.receiver.root-install-sync", Kind: PersistenceCut,
		Scenario: SnapshotScenario, Actors: []string{"snapshot_receiver"},
		BeforeFacts: []DurableFact{FactSnapshotObjects, FactSnapshotCommit, FactSnapshotConsensus},
		AfterFacts:  []DurableFact{FactSnapshotInstalled},
	},
	{
		ID: "membership.joint.leader.entry-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"leader"},
		AfterFacts: []DurableFact{FactConfigEntry},
	},
	{
		ID: "membership.joint.follower.entry-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"follower"},
		AfterFacts: []DurableFact{FactConfigEntry},
	},
	{
		ID: "membership.joint.learner.entry-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"learner"},
		AfterFacts: []DurableFact{FactConfigEntry},
	},
	{
		ID: "membership.joint.leader.commit-index-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"leader"},
		BeforeFacts: []DurableFact{FactConfigEntry},
		AfterFacts:  []DurableFact{FactConfigCommit},
	},
	{
		ID: "membership.joint.follower.commit-index-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"follower"},
		BeforeFacts: []DurableFact{FactConfigEntry},
		AfterFacts:  []DurableFact{FactConfigCommit},
	},
	{
		ID: "membership.joint.learner.commit-index-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"learner"},
		BeforeFacts: []DurableFact{FactConfigEntry},
		AfterFacts:  []DurableFact{FactConfigCommit},
	},
	{
		ID: "membership.joint.leader.config-install-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"leader"},
		BeforeFacts: []DurableFact{FactConfigEntry, FactConfigCommit},
		AfterFacts:  []DurableFact{FactConfigInstalled},
	},
	{
		ID: "membership.joint.follower.config-install-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"follower"},
		BeforeFacts: []DurableFact{FactConfigEntry, FactConfigCommit},
		AfterFacts:  []DurableFact{FactConfigInstalled},
	},
	{
		ID: "membership.joint.learner.config-install-sync", Kind: PersistenceCut,
		Scenario: JointConfigScenario, Actors: []string{"learner"},
		BeforeFacts: []DurableFact{FactConfigEntry, FactConfigCommit},
		AfterFacts:  []DurableFact{FactConfigInstalled},
	},
	{
		ID: "membership.final.leader.entry-sync", Kind: PersistenceCut,
		Scenario: FinalConfigScenario, Actors: []string{"leader"},
		AfterFacts: []DurableFact{FactConfigEntry},
	},
	{
		ID: "membership.final.follower.entry-sync", Kind: PersistenceCut,
		Scenario: FinalConfigScenario, Actors: []string{"follower"},
		AfterFacts: []DurableFact{FactConfigEntry},
	},
	{
		ID: "membership.final.leader.commit-index-sync", Kind: PersistenceCut,
		Scenario: FinalConfigScenario, Actors: []string{"leader"},
		BeforeFacts: []DurableFact{FactConfigEntry},
		AfterFacts:  []DurableFact{FactConfigCommit},
	},
	{
		ID: "membership.final.follower.commit-index-sync", Kind: PersistenceCut,
		Scenario: FinalConfigScenario, Actors: []string{"follower"},
		BeforeFacts: []DurableFact{FactConfigEntry},
		AfterFacts:  []DurableFact{FactConfigCommit},
	},
	{
		ID: "membership.final.leader.config-install-sync", Kind: PersistenceCut,
		Scenario: FinalConfigScenario, Actors: []string{"leader"},
		BeforeFacts: []DurableFact{FactConfigEntry, FactConfigCommit},
		AfterFacts:  []DurableFact{FactConfigInstalled},
	},
	{
		ID: "membership.final.follower.config-install-sync", Kind: PersistenceCut,
		Scenario: FinalConfigScenario, Actors: []string{"follower"},
		BeforeFacts: []DurableFact{FactConfigEntry, FactConfigCommit},
		AfterFacts:  []DurableFact{FactConfigInstalled},
	},
}

// MessageCutPoints completes the failure schedule around the durable table.
// These events do not create durable facts; withholding a delivery explores a
// delayed message, and Drop=true explores permanent loss. In particular,
// success-reply loss is distinct from a crash at root installation.
var MessageCutPoints = []CutPoint{
	{ID: "election.request-vote", Kind: MessageCut, Scenario: ElectionScenario, Actors: []string{"candidate", "voter"}},
	{ID: "election.vote-response", Kind: MessageCut, Scenario: ElectionScenario, Actors: []string{"voter", "candidate"}},
	{ID: "mutation.proposal", Kind: MessageCut, Scenario: MutationScenario, Actors: []string{"leader", "follower"}},
	{
		ID: "mutation.append-response", Kind: MessageCut, Scenario: MutationScenario,
		Actors:      []string{"follower", "leader"},
		BeforeFacts: []DurableFact{FactObjects, FactStateCommit, FactConsensusEntry},
	},
	{
		ID: "mutation.commit-notice", Kind: MessageCut, Scenario: MutationScenario,
		Actors: []string{"leader", "follower"}, BeforeFacts: []DurableFact{FactCommitIndex},
	},
	{ID: "snapshot.object-chunk", Kind: MessageCut, Scenario: SnapshotScenario, Actors: []string{"snapshot_sender", "snapshot_receiver"}},
	{
		ID: "snapshot.install-response", Kind: MessageCut, Scenario: SnapshotScenario,
		Actors: []string{"snapshot_receiver", "leader"}, BeforeFacts: []DurableFact{FactSnapshotInstalled},
	},
	{
		ID: "membership.joint.append-response", Kind: MessageCut, Scenario: JointConfigScenario,
		Actors: []string{"follower", "leader"}, BeforeFacts: []DurableFact{FactConfigEntry},
	},
	{
		ID: "membership.final.append-response", Kind: MessageCut, Scenario: FinalConfigScenario,
		Actors: []string{"follower", "leader"}, BeforeFacts: []DurableFact{FactConfigEntry},
	},
	{
		ID: "exact-reply.success", Kind: MessageCut, Scenario: ExactReplyScenario,
		Actors: []string{"leader", "client"}, BeforeFacts: []DurableFact{FactRootInstalled},
	},
}
