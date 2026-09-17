//go:build linux

package soak

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestWorkloadCommandEntersDirectoryAfterExec(t *testing.T) {
	command := newWorkloadCommand(context.Background(), "/mounted/worktree", "git", "status", "--short")
	if command.Dir != "/" {
		t.Fatalf("pre-exec working directory = %q, want host root", command.Dir)
	}
	want := []string{"/usr/bin/env", "-C", "/mounted/worktree", "git", "status", "--short"}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("launcher arguments = %q, want %q", command.Args, want)
	}
}

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
