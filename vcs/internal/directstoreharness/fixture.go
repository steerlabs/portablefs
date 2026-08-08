package directstoreharness

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	pointLeaderObject        = "mutation.leader.object-sync"
	pointLeaderStateCommit   = "mutation.leader.state-commit-sync"
	pointLeaderEntry         = "mutation.leader.consensus-entry-sync"
	pointFollowerObject      = "mutation.follower.object-sync"
	pointFollowerStateCommit = "mutation.follower.state-commit-sync"
	pointFollowerEntry       = "mutation.follower.consensus-entry-sync"
	pointLeaderCommit        = "mutation.leader.commit-index-sync"
	pointFollowerCommit      = "mutation.follower.commit-index-sync"
	pointLeaderApply         = "mutation.leader.root-install-sync"
	pointFollowerApply       = "mutation.follower.root-install-sync"
	pointProposal            = "mutation.proposal"
	pointAppendResponse      = "mutation.append-response"
	pointCommitNotice        = "mutation.commit-notice"
	pointSuccessReply        = "exact-reply.success"
)

type FixtureDefect uint8

const (
	FixtureCorrect FixtureDefect = iota
	FixtureAcknowledgeBeforeQuorum
	FixtureTwoCommitsAtOneIndex
	FixtureStaleFollowerRead
)

type fixtureState struct {
	Index  uint64
	Parent Digest
	Root   Digest
	ID     ExactID
	Value  uint64
}

func newFixtureState(index uint64, parent Digest, operation Mutation) fixtureState {
	state := fixtureState{Index: index, Parent: parent, ID: operation.ID, Value: operation.Value}
	payload := make([]byte, 0, 32+8+4+8+8)
	payload = append(payload, parent[:]...)
	payload = binary.LittleEndian.AppendUint64(payload, index)
	payload = binary.LittleEndian.AppendUint32(payload, operation.ID.Client)
	payload = binary.LittleEndian.AppendUint64(payload, operation.ID.Sequence)
	payload = binary.LittleEndian.AppendUint64(payload, operation.Value)
	state.Root = digestBytes(payload)
	return state
}

func encodeFixtureState(state fixtureState) []byte {
	payload := make([]byte, 0, 1+8+32+32+4+8+8)
	payload = append(payload, 1)
	payload = binary.LittleEndian.AppendUint64(payload, state.Index)
	payload = append(payload, state.Parent[:]...)
	payload = append(payload, state.Root[:]...)
	payload = binary.LittleEndian.AppendUint32(payload, state.ID.Client)
	payload = binary.LittleEndian.AppendUint64(payload, state.ID.Sequence)
	payload = binary.LittleEndian.AppendUint64(payload, state.Value)
	return payload
}

func decodeFixtureState(payload []byte) (fixtureState, error) {
	const size = 1 + 8 + 32 + 32 + 4 + 8 + 8
	if len(payload) != size || payload[0] != 1 {
		return fixtureState{}, ErrChecksum
	}
	state := fixtureState{Index: binary.LittleEndian.Uint64(payload[1:9])}
	offset := 9
	copy(state.Parent[:], payload[offset:offset+32])
	offset += 32
	copy(state.Root[:], payload[offset:offset+32])
	offset += 32
	state.ID.Client = binary.LittleEndian.Uint32(payload[offset : offset+4])
	offset += 4
	state.ID.Sequence = binary.LittleEndian.Uint64(payload[offset : offset+8])
	offset += 8
	state.Value = binary.LittleEndian.Uint64(payload[offset : offset+8])
	want := newFixtureState(state.Index, state.Parent, Mutation{ID: state.ID, Value: state.Value})
	if want.Root != state.Root {
		return fixtureState{}, ErrChecksum
	}
	return state, nil
}

func fixtureSlot(index uint64) uint64 { return index & 1 }

func fixturePath(kind string, index uint64) string {
	return fmt.Sprintf("%s/%d", kind, fixtureSlot(index))
}

type fixtureReplica struct {
	healthy bool
	state   fixtureState
}

type Fixture struct {
	env     *Environment
	defect  FixtureDefect
	nodes   [ReplicaCount]fixtureReplica
	leader  NodeID
	commits []CommitAudit
	applies []ApplyAudit
}

func NewFixture(env *Environment, defect FixtureDefect) *Fixture {
	fixture := &Fixture{env: env, defect: defect, leader: 0}
	for node := range ReplicaCount {
		fixture.nodes[node].healthy = true
	}
	return fixture
}

func (f *Fixture) Mutate(operation Mutation) MutationReply {
	if !f.ready(f.leader) || !f.hasReadQuorum(f.leader) {
		f.electLeader()
	}
	if !f.ready(f.leader) || !f.hasReadQuorum(f.leader) {
		return MutationReply{Status: MutationUnavailable, ID: operation.ID}
	}
	leader := f.leader
	current := f.nodes[leader].state
	if current.ID == operation.ID && current.Index != 0 {
		if current.Value != operation.Value {
			return MutationReply{Status: MutationIntegrityFailure, ID: operation.ID}
		}
		if f.appliedCopies(current) < 2 {
			return MutationReply{Status: MutationUnavailable, ID: operation.ID}
		}
		return f.sendReply(leader, current)
	}
	if operation.ID.Client == current.ID.Client && operation.ID.Sequence <= current.ID.Sequence {
		return MutationReply{Status: MutationIntegrityFailure, ID: operation.ID}
	}
	state := newFixtureState(current.Index+1, current.Root, operation)
	if status := f.prepare(leader, state, true); status != MutationSuccess {
		return MutationReply{Status: status, ID: operation.ID}
	}

	if f.defect == FixtureAcknowledgeBeforeQuorum {
		certificate := uint8(1 << leader)
		if !f.commitAndInstall(leader, state, certificate, true) {
			return MutationReply{Status: MutationUnknown, ID: operation.ID}
		}
		return f.sendReply(leader, state)
	}

	votes := uint8(1 << leader)
	for raw := range ReplicaCount {
		follower := NodeID(raw)
		if follower == leader || !f.ready(follower) {
			continue
		}
		if copies, err := f.env.Send(leader, follower, pointProposal, state.Index, encodeFixtureState(state)); err != nil || copies == 0 {
			f.reloadIfCrashed(leader)
			f.reloadIfCrashed(follower)
			continue
		}
		if status := f.prepare(follower, state, false); status != MutationSuccess {
			continue
		}
		if copies, err := f.env.Send(follower, leader, pointAppendResponse, state.Index, state.Root[:]); copies > 0 {
			votes |= 1 << follower
			if err != nil {
				f.reloadIfCrashed(follower)
				f.reloadIfCrashed(leader)
			}
		}
	}
	if bitsSet(votes) < 2 || votes&(1<<leader) == 0 || !f.ready(leader) {
		return MutationReply{Status: MutationUnavailable, ID: operation.ID}
	}
	if !f.commitAndInstall(leader, state, votes, true) {
		return MutationReply{Status: MutationUnknown, ID: operation.ID}
	}
	for raw := range ReplicaCount {
		follower := NodeID(raw)
		if follower == leader || votes&(1<<follower) == 0 || !f.ready(follower) {
			continue
		}
		copies, _ := f.env.Send(leader, follower, pointCommitNotice, state.Index, state.Root[:])
		for range copies {
			_ = f.commitAndInstall(follower, state, votes, false)
		}
	}

	if f.defect == FixtureTwoCommitsAtOneIndex {
		f.plantConflictingCommit(state)
	}
	if f.appliedCopies(state) < 2 || !f.ready(leader) || f.nodes[leader].state.Root != state.Root {
		return MutationReply{Status: MutationUnknown, ID: operation.ID}
	}
	return f.sendReply(leader, state)
}

func (f *Fixture) prepare(node NodeID, state fixtureState, leader bool) MutationStatus {
	payload := encodeFixtureState(state)
	objectPoint, commitPoint, entryPoint := pointFollowerObject, pointFollowerStateCommit, pointFollowerEntry
	if leader {
		objectPoint, commitPoint, entryPoint = pointLeaderObject, pointLeaderStateCommit, pointLeaderEntry
	}
	for _, step := range []struct {
		point string
		path  string
	}{
		{objectPoint, fixturePath("object", state.Index)},
		{commitPoint, fixturePath("state", state.Index)},
		{entryPoint, fixturePath("entry", state.Index)},
	} {
		if err := f.env.Persist(node, step.point, step.path, payload); err != nil {
			f.reloadIfCrashed(node)
			switch {
			case errors.Is(err, ErrNoSpace):
				return MutationNoSpace
			case errors.Is(err, ErrChecksum):
				f.nodes[node].healthy = false
				return MutationIntegrityFailure
			default:
				return MutationUnknown
			}
		}
	}
	return MutationSuccess
}

func (f *Fixture) commitAndInstall(node NodeID, state fixtureState, certificate uint8, leader bool) bool {
	commitPoint, applyPoint := pointFollowerCommit, pointFollowerApply
	if leader {
		commitPoint, applyPoint = pointLeaderCommit, pointLeaderApply
	}
	payload := encodeFixtureState(state)
	if err := f.env.Persist(node, commitPoint, "meta/commit", payload); err != nil {
		f.reloadIfCrashed(node)
		return false
	}
	if leader {
		commit := CommitAudit{Index: state.Index, Root: state.Root, Operation: state.ID, Certificate: certificate, Leader: node}
		f.commits = append(f.commits, commit)
		f.env.emit(TraceEvent{Kind: EventCommit, Node: node, Index: state.Index, Point: commitPoint, Detail: fmt.Sprintf("certificate=%03b", certificate), Digest: state.Root})
	}
	if err := f.env.Persist(node, applyPoint, "meta/root", payload); err != nil {
		f.reloadIfCrashed(node)
		return false
	}
	prior := f.nodes[node].state
	f.nodes[node].healthy = true
	f.nodes[node].state = state
	if prior.Index != state.Index || prior.Root != state.Root {
		apply := ApplyAudit{Node: node, Index: state.Index, Root: state.Root, Operation: state.ID}
		f.applies = append(f.applies, apply)
		f.env.emit(TraceEvent{Kind: EventApply, Node: node, Index: state.Index, Point: applyPoint, Digest: state.Root})
	}
	return true
}

func (f *Fixture) sendReply(leader NodeID, state fixtureState) MutationReply {
	copies, _ := f.env.Send(leader, ClientNode, pointSuccessReply, state.Index, encodeFixtureState(state))
	if copies == 0 {
		return MutationReply{Status: MutationUnknown, ID: state.ID}
	}
	f.env.emit(TraceEvent{Kind: EventReply, Node: leader, Peer: ClientNode, Index: state.Index, Point: pointSuccessReply, Detail: fmt.Sprintf("copies=%d", copies), Digest: state.Root})
	return MutationReply{Status: MutationSuccess, ID: state.ID, Index: state.Index, Value: state.Value, Root: state.Root}
}

func (f *Fixture) LinearizableRead(minimumIndex uint64) ReadReply {
	if f.defect == FixtureStaleFollowerRead {
		candidate := f.lowestAppliedReplica()
		state := f.nodes[candidate].state
		f.env.emit(TraceEvent{Kind: EventRead, Node: candidate, Index: state.Index, Detail: "unfenced", Digest: state.Root})
		return ReadReply{Status: ReadSuccess, Index: state.Index, Value: state.Value, Node: candidate}
	}
	if !f.ready(f.leader) {
		f.electLeader()
	}
	if !f.ready(f.leader) || !f.hasReadQuorum(f.leader) {
		return ReadReply{Status: ReadUnavailable}
	}
	state := f.nodes[f.leader].state
	if state.Index < minimumIndex {
		return ReadReply{Status: ReadUnavailable}
	}
	f.env.emit(TraceEvent{Kind: EventRead, Node: f.leader, Index: state.Index, Detail: "quorum-fenced", Digest: state.Root})
	return ReadReply{Status: ReadSuccess, Index: state.Index, Value: state.Value, Node: f.leader}
}

func (f *Fixture) Recover() error {
	for raw := range ReplicaCount {
		node := NodeID(raw)
		f.env.Restart(node)
		f.reload(node)
	}
	type candidateKey struct {
		index uint64
		root  Digest
	}
	type candidate struct {
		state fixtureState
		mask  uint8
	}
	candidates := make(map[candidateKey]candidate, ReplicaCount*2)
	for raw := range ReplicaCount {
		node := NodeID(raw)
		if !f.env.Alive(node) {
			continue
		}
		for slot := range uint64(2) {
			payload, err := f.env.Read(node, fmt.Sprintf("entry/%d", slot))
			if err != nil || payload == nil {
				continue
			}
			state, err := decodeFixtureState(payload)
			if err != nil {
				continue
			}
			key := candidateKey{index: state.Index, root: state.Root}
			entry := candidates[key]
			entry.state = state
			entry.mask |= 1 << node
			candidates[key] = entry
		}
	}
	var chosen candidate
	for _, entry := range candidates {
		if bitsSet(entry.mask) >= 2 && entry.state.Index > chosen.state.Index {
			chosen = entry
		}
	}
	if chosen.state.Index != 0 {
		for raw := range ReplicaCount {
			node := NodeID(raw)
			if chosen.mask&(1<<node) != 0 && f.ready(node) {
				f.leader = node
				break
			}
		}
		commit := CommitAudit{
			Index: chosen.state.Index, Root: chosen.state.Root, Operation: chosen.state.ID,
			Certificate: chosen.mask, Leader: f.leader,
		}
		f.commits = append(f.commits, commit)
		f.env.emit(TraceEvent{Kind: EventCommit, Node: f.leader, Index: chosen.state.Index, Point: "recovery.commit", Detail: fmt.Sprintf("certificate=%03b", chosen.mask), Digest: chosen.state.Root})
		for raw := range ReplicaCount {
			node := NodeID(raw)
			if !f.env.Alive(node) || (f.ready(node) && f.nodes[node].state.Index == chosen.state.Index && f.nodes[node].state.Root == chosen.state.Root) {
				continue
			}
			if status := f.prepare(node, chosen.state, node == f.leader); status != MutationSuccess {
				continue
			}
			_ = f.commitAndInstall(node, chosen.state, chosen.mask, false)
		}
	}
	f.electLeader()
	if !f.ready(f.leader) {
		return ErrProcessKilled
	}
	return nil
}

func (f *Fixture) Audit() AuditSnapshot {
	snapshot := AuditSnapshot{
		Replicas: make([]ReplicaAudit, 0, ReplicaCount),
		Commits:  append([]CommitAudit(nil), f.commits...),
		Applies:  append([]ApplyAudit(nil), f.applies...),
	}
	f.commits = f.commits[:0]
	f.applies = f.applies[:0]
	for raw := range ReplicaCount {
		node := NodeID(raw)
		state := f.nodes[node].state
		snapshot.Replicas = append(snapshot.Replicas, ReplicaAudit{
			Node: node, Alive: f.ready(node), CommitIndex: state.Index,
			AppliedIndex: state.Index, Value: state.Value, Root: state.Root,
		})
	}
	return snapshot
}

func (f *Fixture) ready(node NodeID) bool {
	return node < ReplicaCount && f.env.Alive(node) && f.nodes[node].healthy
}

func (f *Fixture) reloadIfCrashed(node NodeID) {
	if node < ReplicaCount && !f.env.Alive(node) {
		f.nodes[node] = fixtureReplica{}
	}
}

func (f *Fixture) reload(node NodeID) {
	f.nodes[node] = fixtureReplica{healthy: true}
	payload, err := f.env.Read(node, "meta/root")
	if err != nil {
		f.nodes[node].healthy = false
		return
	}
	if payload == nil {
		return
	}
	state, err := decodeFixtureState(payload)
	if err != nil {
		f.nodes[node].healthy = false
		return
	}
	object, err := f.env.Read(node, fixturePath("object", state.Index))
	if err != nil || object == nil {
		f.nodes[node].healthy = false
		return
	}
	objectState, err := decodeFixtureState(object)
	if err != nil || objectState.Root != state.Root {
		f.nodes[node].healthy = false
		return
	}
	f.nodes[node].state = state
}

func (f *Fixture) electLeader() {
	best := NodeID(ReplicaCount)
	var bestIndex uint64
	for raw := range ReplicaCount {
		node := NodeID(raw)
		if !f.ready(node) || !f.hasReadQuorum(node) {
			continue
		}
		index := f.nodes[node].state.Index
		if best == NodeID(ReplicaCount) || index > bestIndex || index == bestIndex && node < best {
			best, bestIndex = node, index
		}
	}
	if best < ReplicaCount {
		f.leader = best
	}
}

func (f *Fixture) hasReadQuorum(candidate NodeID) bool {
	votes := 0
	for raw := range ReplicaCount {
		node := NodeID(raw)
		if !f.ready(node) {
			continue
		}
		if node == candidate || !f.env.Partitioned(candidate, node) && !f.env.Partitioned(node, candidate) {
			votes++
		}
	}
	return votes >= 2
}

func (f *Fixture) appliedCopies(state fixtureState) int {
	copies := 0
	for node := range f.nodes {
		if f.ready(NodeID(node)) && f.nodes[node].state.Index == state.Index && f.nodes[node].state.Root == state.Root {
			copies++
		}
	}
	return copies
}

func (f *Fixture) lowestAppliedReplica() NodeID {
	best := NodeID(ReplicaCount)
	for raw := range ReplicaCount {
		node := NodeID(raw)
		if f.ready(node) && (best == ReplicaCount || f.nodes[node].state.Index < f.nodes[best].state.Index) {
			best = node
		}
	}
	if best == ReplicaCount {
		return f.leader
	}
	return best
}

func (f *Fixture) plantConflictingCommit(committed fixtureState) {
	alternative := newFixtureState(committed.Index, committed.Parent, Mutation{
		ID:    ExactID{Client: committed.ID.Client + 1, Sequence: committed.ID.Sequence},
		Value: committed.Value ^ 0x8000000000000000,
	})
	certificate := uint8(0b110)
	f.commits = append(f.commits, CommitAudit{
		Index: alternative.Index, Root: alternative.Root, Operation: alternative.ID,
		Certificate: certificate, Leader: 1,
	})
	f.env.emit(TraceEvent{Kind: EventCommit, Node: 1, Index: alternative.Index, Point: "planted.double-commit", Detail: "certificate=110", Digest: alternative.Root})
}

func bitsSet(mask uint8) int {
	count := 0
	for mask != 0 {
		mask &= mask - 1
		count++
	}
	return count
}
