package apphost

import (
	"errors"
	"fmt"
	"testing"
)

func TestLaunchCompletionAmbiguitySurvivesContextWrapping(t *testing.T) {
	err := fmt.Errorf("wake exact host: %w", ErrLaunchCompletionAmbiguous)
	if !errors.Is(err, ErrLaunchCompletionAmbiguous) {
		t.Fatalf("wrapped ambiguity = %v", err)
	}
	if errors.Is(errors.New("launch rejected"), ErrLaunchCompletionAmbiguous) {
		t.Fatal("ordinary rejection classified as ambiguous")
	}
}
