//go:build linux

package soak

import (
	"sync"
	"testing"
	"time"
)

func TestSerializedWorkloadCommandStartAllowsOnlyOneForkAtATime(t *testing.T) {
	firstEntered := make(chan struct{})
	allowFirst := make(chan struct{})
	secondEntered := make(chan struct{})
	var callers sync.WaitGroup
	callers.Add(2)

	go func() {
		defer callers.Done()
		if err := serializedWorkloadCommandStart(func() error {
			close(firstEntered)
			<-allowFirst
			return nil
		}); err != nil {
			t.Errorf("first start: %v", err)
		}
	}()
	<-firstEntered
	go func() {
		defer callers.Done()
		if err := serializedWorkloadCommandStart(func() error {
			close(secondEntered)
			return nil
		}); err != nil {
			t.Errorf("second start: %v", err)
		}
	}()

	select {
	case <-secondEntered:
		t.Fatal("second process launch entered while the first was still in progress")
	case <-time.After(50 * time.Millisecond):
	}
	close(allowFirst)
	callers.Wait()
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second process launch did not proceed after the first completed")
	}
}
