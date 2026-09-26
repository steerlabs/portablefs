package volumeserver

import "fmt"

// ValidateTargets proves storage preparation stays inside its acquired turn.
func (d MutationDependencies) ValidateTargets(targets []VisibilityTarget) error {
	if !d.valid() || validateVisibilityTargets(targets) != nil || !d.covers(targets) {
		return ErrVisibilityTargets
	}
	return nil
}

// ValidateMutationCompletion proves the committed post-state stays inside the
// prepared footprint. Both protocol 7 and Mac repair use this pure invariant.
func ValidateMutationCompletion(complete, prepared []VisibilityTarget) error {
	if err := validateVisibilityTargets(complete); err != nil {
		return ErrVisibilityTargets
	}
	exactCount := 0
	for _, target := range complete {
		if target.Scope == VisibilityNamespace {
			continue
		}
		exactCount++
		if target.ExactPostState == nil || target.ExactPostState.ObjectVersion == 0 {
			return fmt.Errorf("%w: completion inode target omitted exact committed attributes", ErrVisibilityTargets)
		}
	}
	if exactCount > 4 {
		return fmt.Errorf("%w: completion exceeded the four-object exact repair bound", ErrVisibilityTargets)
	}
	// Fan-out chooses its audience from the PREPARE targets. A COMPLETE target
	// outside that set would be a repair instruction addressed to mounts that
	// were never asked to close publication for it, so it is an invariant
	// violation rather than a case to widen the audience for.
	if !visibilityTargetsCovered(complete, prepared) {
		return fmt.Errorf("%w: completion named a coordinate prepare did not", ErrVisibilityTargets)
	}
	completeKeys := visibilityTargetKeySet(complete)
	for _, target := range complete {
		if target.Scope != VisibilityAttributes {
			continue
		}
		for _, preparedTarget := range prepared {
			if preparedTarget.Scope != VisibilityNamespace || preparedTarget.ParentIdentity != target.Identity {
				continue
			}
			if _, ok := completeKeys[string(preparedTarget.key())]; !ok {
				return fmt.Errorf("%w: parent attributes completed without a prepared namespace dependency", ErrVisibilityTargets)
			}
		}
	}
	return nil
}
