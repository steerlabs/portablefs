package directstoreharness

import "fmt"

type referenceModel struct {
	index uint64
	value uint64
}

type checker struct {
	seed          uint64
	operation     uint64
	model         referenceModel
	commitRoots   []Digest
	lastApplied   [ReplicaCount]uint64
	lastApplyRoot [ReplicaCount]Digest
}

func newChecker(seed uint64) *checker {
	return &checker{seed: seed, commitRoots: make([]Digest, 1, 1024)}
}

func (c *checker) setOperation(operation uint64) { c.operation = operation }

func (c *checker) observe(snapshot AuditSnapshot) *Violation {
	for _, commit := range snapshot.Commits {
		if bitsSet(commit.Certificate) < 2 {
			return c.violation("commit-without-quorum", fmt.Sprintf("index %d certificate %03b has fewer than two voters", commit.Index, commit.Certificate))
		}
		if commit.Leader >= ReplicaCount || commit.Certificate&(1<<commit.Leader) == 0 {
			return c.violation("leader-not-in-commit-certificate", fmt.Sprintf("index %d leader %s certificate %03b", commit.Index, commit.Leader, commit.Certificate))
		}
		if commit.Index > uint64(len(c.commitRoots)) {
			return c.violation("commit-index-gap", fmt.Sprintf("commit index %d follows ledger length %d", commit.Index, len(c.commitRoots)-1))
		}
		if commit.Index == uint64(len(c.commitRoots)) {
			c.commitRoots = append(c.commitRoots, Digest{})
		}
		prior := c.commitRoots[commit.Index]
		if prior != (Digest{}) && prior != commit.Root {
			return c.violation("two-commits-at-one-index", fmt.Sprintf("index %d committed roots %s and %s", commit.Index, prior, commit.Root))
		}
		c.commitRoots[commit.Index] = commit.Root
	}
	for _, apply := range snapshot.Applies {
		if apply.Node >= ReplicaCount {
			return c.violation("invalid-apply-node", fmt.Sprintf("apply at index %d names %s", apply.Index, apply.Node))
		}
		last := c.lastApplied[apply.Node]
		if apply.Index < last {
			return c.violation("apply-index-regression", fmt.Sprintf("%s applied index %d after %d", apply.Node, apply.Index, last))
		}
		if apply.Index == last && last != 0 {
			property := "double-apply"
			if c.lastApplyRoot[apply.Node] != apply.Root {
				property = "two-roots-applied-at-one-index"
			}
			return c.violation(property, fmt.Sprintf("%s applied index %d more than once", apply.Node, apply.Index))
		}
		c.lastApplied[apply.Node] = apply.Index
		c.lastApplyRoot[apply.Node] = apply.Root
	}
	return nil
}

func (c *checker) acknowledge(operation Mutation, reply MutationReply, snapshot AuditSnapshot) *Violation {
	if reply.ID != operation.ID || reply.Value != operation.Value {
		return c.violation("wrong-exact-outcome", fmt.Sprintf("operation %+v=%d replied %+v=%d", operation.ID, operation.Value, reply.ID, reply.Value))
	}
	if reply.Index == 0 || reply.Index >= uint64(len(c.commitRoots)) || c.commitRoots[reply.Index] != reply.Root {
		return c.violation("acknowledgement-before-commit", fmt.Sprintf("reply index %d root %s has no matching committed fact", reply.Index, reply.Root))
	}
	copies := 0
	for _, replica := range snapshot.Replicas {
		if replica.AppliedIndex == reply.Index && replica.Root == reply.Root {
			copies++
		}
	}
	if copies < 2 {
		return c.violation("acknowledgement-without-two-full-copies", fmt.Sprintf("reply index %d root %s has %d applied durable copies; replicas=%+v", reply.Index, reply.Root, copies, snapshot.Replicas))
	}
	if reply.Index <= c.model.index {
		return c.violation("acknowledgement-index-regression", fmt.Sprintf("reply index %d follows model index %d", reply.Index, c.model.index))
	}
	c.model = referenceModel{index: reply.Index, value: operation.Value}
	return nil
}

func (c *checker) read(reply ReadReply) *Violation {
	if reply.Status != ReadSuccess {
		return c.violation("linearizable-read-unavailable", fmt.Sprintf("read after recovery returned status %d", reply.Status))
	}
	if reply.Index < c.model.index {
		return c.violation("stale-linearizable-read", fmt.Sprintf("%s returned index %d below acknowledged index %d", reply.Node, reply.Index, c.model.index))
	}
	if reply.Value != c.model.value {
		return c.violation("wrong-linearizable-read-value", fmt.Sprintf("%s returned value %d at index %d; model value is %d at index %d", reply.Node, reply.Value, reply.Index, c.model.value, c.model.index))
	}
	return nil
}

func (c *checker) optionalRead(reply ReadReply) *Violation {
	if reply.Status != ReadSuccess {
		return nil
	}
	return c.read(reply)
}

func (c *checker) violation(property, detail string) *Violation {
	return &Violation{Property: property, Detail: detail, Seed: c.seed, Operation: c.operation}
}
