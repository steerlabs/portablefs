package volumeserver

import "fmt"

// ValidateTargets proves storage preparation stays inside its acquired turn.
func (d MutationDependencies) ValidateTargets(targets []MutationTarget) error {
	if !d.valid() || validateMutationTargets(targets) != nil || !d.covers(targets) {
		return ErrMutationTargets
	}
	return nil
}

// ValidateMutationCompletion proves the committed post-state stays inside the
// prepared footprint, including every dependency named in the Linux change log.
func ValidateMutationCompletion(complete, prepared []MutationTarget) error {
	if err := validateMutationTargets(complete); err != nil {
		return ErrMutationTargets
	}
	exactCount := 0
	for _, target := range complete {
		if target.Scope == MutationNamespace {
			continue
		}
		exactCount++
		if target.ExactPostState == nil || target.ExactPostState.ObjectVersion == 0 {
			return fmt.Errorf("%w: completion inode target omitted exact committed attributes", ErrMutationTargets)
		}
	}
	if exactCount > 4 {
		return fmt.Errorf("%w: completion exceeded the four-object outcome bound", ErrMutationTargets)
	}
	// Completion cannot widen the dependencies after storage apply. Other
	// operations may already be using coordinates outside the acquired turn.
	if !mutationTargetsCovered(complete, prepared) {
		return fmt.Errorf("%w: completion named a coordinate prepare did not", ErrMutationTargets)
	}
	completeKeys := mutationTargetKeySet(complete)
	for _, target := range complete {
		if target.Scope != MutationAttributes {
			continue
		}
		for _, preparedTarget := range prepared {
			if preparedTarget.Scope != MutationNamespace || preparedTarget.ParentIdentity != target.Identity {
				continue
			}
			if _, ok := completeKeys[string(preparedTarget.key())]; !ok {
				return fmt.Errorf("%w: parent attributes completed without a prepared namespace dependency", ErrMutationTargets)
			}
		}
	}
	return nil
}
