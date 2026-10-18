//go:build linux

package authorityrpc

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A select evaluates Done only after the gate has observed a conflicting
// permit and released its state mutex. This observes a wait, not a launch.
type admissionWaitContext struct {
	context.Context
	waiting chan struct{}
	resume  <-chan struct{}
	once    sync.Once
}

func newAdmissionWaitContext(ctx context.Context) *admissionWaitContext {
	return &admissionWaitContext{Context: ctx, waiting: make(chan struct{})}
}
func (c *admissionWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	if c.resume != nil {
		<-c.resume
	}
	return c.Context.Done()
}
func admissionReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("admission schedule stuck")
		var zero T
		return zero
	}
}
