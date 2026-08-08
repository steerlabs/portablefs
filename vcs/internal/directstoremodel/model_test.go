package directstoremodel

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPersistenceCutPointTableIsCompleteAndCrashAtomic(t *testing.T) {
	// This exact list is intentional: adding a persistent transition to a
	// model without adding its harness identity here fails the test.
	wantIDs := []string{
		"election.candidate.term-vote-sync",
		"election.voter.term-vote-sync",
		"membership.final.follower.commit-index-sync",
		"membership.final.follower.config-install-sync",
		"membership.final.follower.entry-sync",
		"membership.final.leader.commit-index-sync",
		"membership.final.leader.config-install-sync",
		"membership.final.leader.entry-sync",
		"membership.joint.follower.commit-index-sync",
		"membership.joint.follower.config-install-sync",
		"membership.joint.follower.entry-sync",
		"membership.joint.leader.commit-index-sync",
		"membership.joint.leader.config-install-sync",
		"membership.joint.leader.entry-sync",
		"membership.joint.learner.commit-index-sync",
		"membership.joint.learner.config-install-sync",
		"membership.joint.learner.entry-sync",
		"mutation.follower.commit-index-sync",
		"mutation.follower.consensus-entry-sync",
		"mutation.follower.object-sync",
		"mutation.follower.root-install-sync",
		"mutation.follower.state-commit-sync",
		"mutation.leader.commit-index-sync",
		"mutation.leader.consensus-entry-sync",
		"mutation.leader.object-sync",
		"mutation.leader.root-install-sync",
		"mutation.leader.state-commit-sync",
		"snapshot.receiver.consensus-snapshot-sync",
		"snapshot.receiver.object-sync",
		"snapshot.receiver.root-install-sync",
		"snapshot.receiver.state-commit-sync",
	}
	gotIDs := make([]string, 0, len(PersistenceCutPoints))
	seen := map[string]bool{}
	coveredScenarios := map[Scenario]bool{}
	for _, cut := range PersistenceCutPoints {
		if cut.ID == "" || seen[cut.ID] {
			t.Fatalf("persistence cut point has empty or duplicate ID %q", cut.ID)
		}
		seen[cut.ID] = true
		gotIDs = append(gotIDs, cut.ID)
		coveredScenarios[cut.Scenario] = true
		if cut.Kind != PersistenceCut {
			t.Fatalf("%s has kind %q", cut.ID, cut.Kind)
		}
		if len(cut.Actors) == 0 || len(cut.AfterFacts) == 0 {
			t.Fatalf("%s has no actor or durable effect", cut.ID)
		}
		for _, after := range cut.AfterFacts {
			if slices.Contains(cut.BeforeFacts, after) {
				t.Fatalf("%s establishes already-required fact %q", cut.ID, after)
			}
		}

		// Executable crash contract. Before completion a crash discards the
		// pending facts. After completion the same crash retains all facts.
		beforeCrash := newLocalPersistence(cut.BeforeFacts)
		beforeCrash.begin(cut)
		beforeCrash.crash()
		for _, fact := range cut.AfterFacts {
			if beforeCrash.has(fact) {
				t.Fatalf("%s survived a crash before completion with fact %q", cut.ID, fact)
			}
		}

		afterCrash := newLocalPersistence(cut.BeforeFacts)
		afterCrash.begin(cut)
		afterCrash.complete()
		afterCrash.crash()
		for _, fact := range cut.AfterFacts {
			if !afterCrash.has(fact) {
				t.Fatalf("%s lost fact %q after completed persistence", cut.ID, fact)
			}
		}
	}
	slices.Sort(gotIDs)
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("persistence cut-point table changed without updating the exhaustive contract\ngot:  %q\nwant: %q", gotIDs, wantIDs)
	}
	for _, scenario := range []Scenario{ElectionScenario, MutationScenario, SnapshotScenario, JointConfigScenario, FinalConfigScenario} {
		if !coveredScenarios[scenario] {
			t.Fatalf("scenario %q has no persistence cut", scenario)
		}
	}
}

func TestPersistenceFaultCasesExpandEveryActorBeforeAndAfter(t *testing.T) {
	wantCount := 0
	for _, cut := range PersistenceCutPoints {
		wantCount += 2 * len(cut.Actors)
	}
	cases := PersistenceFaultCases()
	if len(cases) != wantCount {
		t.Fatalf("expanded %d fault cases, want %d", len(cases), wantCount)
	}
	seen := map[string]bool{}
	for _, fault := range cases {
		if fault.CutIndex < 0 || fault.CutIndex >= len(PersistenceCutPoints) {
			t.Fatalf("fault case has invalid cut index: %+v", fault)
		}
		if fault.Side != CrashBefore && fault.Side != CrashAfter {
			t.Fatalf("fault case has invalid side: %+v", fault)
		}
		if fault.Actor == "" || seen[fault.ID] {
			t.Fatalf("fault case has empty actor or duplicate ID: %+v", fault)
		}
		seen[fault.ID] = true
	}
}

type localPersistence struct {
	stable  map[DurableFact]bool
	pending []DurableFact
}

func newLocalPersistence(facts []DurableFact) *localPersistence {
	state := &localPersistence{stable: map[DurableFact]bool{}}
	for _, fact := range facts {
		state.stable[fact] = true
	}
	return state
}

func (s *localPersistence) begin(cut CutPoint) {
	for _, required := range cut.BeforeFacts {
		if !s.stable[required] {
			panic(fmt.Sprintf("cut %s began without %s", cut.ID, required))
		}
	}
	s.pending = append([]DurableFact(nil), cut.AfterFacts...)
}

func (s *localPersistence) complete() {
	for _, fact := range s.pending {
		s.stable[fact] = true
	}
	s.pending = nil
}

func (s *localPersistence) crash() { s.pending = nil }

func (s *localPersistence) has(fact DurableFact) bool { return s.stable[fact] }

func TestMessageCutPointTableIncludesExactLostReply(t *testing.T) {
	seen := map[string]bool{}
	for _, cut := range MessageCutPoints {
		if cut.Kind != MessageCut || cut.ID == "" || seen[cut.ID] {
			t.Fatalf("invalid message cut point %+v", cut)
		}
		seen[cut.ID] = true
	}
	if !seen["mutation.append-response"] || !seen["exact-reply.success"] {
		t.Fatal("message cuts must include the persistence vote and exact success reply")
	}
}

func TestExecutableSafetyModel(t *testing.T) {
	p := DefaultParameters()
	if got := RequiredDurableAZCopies(p); got != 2 {
		t.Fatalf("f+1 durable copy derivation produced %d, want 2", got)
	}
	if got := majority(p.OldVoters); got != 2 {
		t.Fatalf("floor(n/2)+1 quorum derivation produced %d, want 2", got)
	}
	if violation := CheckQuorumIntersection(p); violation != nil {
		t.Fatal(violation)
	}

	mutation := ExploreMutation(p)
	if mutation.Violation != nil {
		t.Fatal(mutation.Violation)
	}
	for _, want := range []string{"exact-reply.success:lost", "exact-reply.success:retry-delivered"} {
		if !slices.Contains(mutation.Coverage, want) {
			t.Fatalf("mutation exploration did not cover %s; coverage=%v", want, mutation.Coverage)
		}
	}

	commits := ExploreCommitUniqueness(p)
	if commits.Violation != nil {
		t.Fatal(commits.Violation)
	}

	membership := ExploreMembership(p)
	if membership.Violation != nil {
		t.Fatal(membership.Violation)
	}
	for _, want := range []string{"snapshot-installation", "membership-joint", "membership-final"} {
		if !slices.Contains(membership.Coverage, want) {
			t.Fatalf("membership exploration did not cover %s; coverage=%v", want, membership.Coverage)
		}
	}

	t.Logf("mutation: %d states, %d transitions", mutation.States, mutation.Transitions)
	t.Logf("commit uniqueness: %d states, %d transitions", commits.States, commits.Transitions)
	t.Logf("membership/snapshot: %d states, %d transitions", membership.States, membership.Transitions)
}

func TestNegativeControlDroppedQuorumIsReported(t *testing.T) {
	report := exploreMutation(DefaultParameters(), mutationOptions{DropQuorumRequirement: true})
	if report.Violation == nil {
		t.Fatal("checker accepted the deliberately broken one-replica commit rule")
	}
	if report.Violation.Property != "commit-without-quorum" && report.Violation.Property != "success-with-insufficient-az-copies" {
		t.Fatalf("broken quorum failed for the wrong reason: %v", report.Violation)
	}
	if !traceContains(report.Violation.Trace, "deliver append response replica 0") ||
		!traceContains(report.Violation.Trace, "complete commit-index") {
		t.Fatalf("counterexample does not demonstrate a one-replica commit: %v", report.Violation)
	}
	t.Logf("expected counterexample:\n%s", report.Violation)
}

func TestNegativeControlDuplicateCommitIsReported(t *testing.T) {
	report := exploreCommitUniqueness(DefaultParameters(), commitOptions{AllowCommittedOverwrite: true})
	if report.Violation == nil {
		t.Fatal("checker accepted deliberately overwriting a committed quorum witness")
	}
	if report.Violation.Property != "two-committed-roots-at-one-index" {
		t.Fatalf("duplicate commit failed for the wrong reason: %v", report.Violation)
	}
	if !traceContains(report.Violation.Trace, "commit root-x") || !traceContains(report.Violation.Trace, "commit root-y") {
		t.Fatalf("counterexample does not contain both commits: %v", report.Violation)
	}
	t.Logf("expected counterexample:\n%s", report.Violation)
}

func traceContains(trace []string, fragment string) bool {
	for _, step := range trace {
		if strings.Contains(step, fragment) {
			return true
		}
	}
	return false
}
