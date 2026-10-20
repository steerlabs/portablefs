//go:build linux

package main

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

type supervisedTestMount struct {
	attempts, finalizations int
	attempt                 func() error
	cleanupErr              error
	serving, owners         bool
}

func (m *supervisedTestMount) UnmountKernel() error {
	m.attempts++
	return m.attempt()
}
func (m *supervisedTestMount) Close() error {
	m.finalizations++
	if m.cleanupErr == nil {
		m.serving, m.owners = false, false
	}
	return m.cleanupErr
}

func TestSupervisorRequiresAnotherExplicitSignalAfterEachRefusal(t *testing.T) {
	for _, refusal := range []error{syscall.EBUSY, syscall.EPERM, errors.New("fusermount helper exited 42")} {
		t.Run(refusal.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				done := make(chan struct{})
				requests := make(chan os.Signal)
				failed := make(chan error)
				var reports []error
				m := &supervisedTestMount{serving: true, owners: true, attempt: func() error { return refusal }}
				result := make(chan error, 1)
				go func() {
					result <- superviseMount(m, done, requests, failed, func(err error) { reports = append(reports, err) })
				}()
				for want, signal := range []os.Signal{syscall.SIGTERM, syscall.SIGINT} {
					requests <- signal
					synctest.Wait()
					// Only the test clock advances; no event authorizes a new attempt.
					<-time.After(24 * time.Hour)
					synctest.Wait()
					if m.attempts != want+1 || m.finalizations != 0 || !m.serving || !m.owners {
						t.Fatalf("refusal changed ownership or retried: %+v", m)
					}
					if len(reports) != want+1 || !errors.Is(reports[want], refusal) {
						t.Fatalf("actual refusal lost: %v", reports)
					}
					if !errors.Is(refusal, syscall.EBUSY) && strings.Contains(reports[want].Error(), "busy") {
						t.Fatalf("other error mislabeled busy: %v", reports[want])
					}
				}
				renewalErr := errors.New("authorization renewal ended")
				failed <- renewalErr
				synctest.Wait()
				if m.attempts != 2 || m.finalizations != 0 || !m.serving || !m.owners {
					t.Fatalf("renewal failure manufactured an unmount: %+v", m)
				}
				close(done)
				if err := <-result; !errors.Is(err, renewalErr) {
					t.Fatalf("terminal result = %v", err)
				}
				if m.finalizations != 1 {
					t.Fatalf("finalizations = %d", m.finalizations)
				}
			})
		})
	}
}

func TestSupervisorCannotLoseConnectionCompletionRacingARefusal(t *testing.T) {
	for _, duringAttempt := range []bool{true, false} {
		t.Run(map[bool]string{true: "during attempt", false: "after refusal"}[duringAttempt], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				done := make(chan struct{})
				requests := make(chan os.Signal)
				cleanupErr := errors.New("exact mount identity changed")
				m := &supervisedTestMount{serving: true, owners: true, cleanupErr: cleanupErr}
				m.attempt = func() error {
					if duringAttempt {
						close(done)
					}
					return syscall.EBUSY
				}
				var reports []error
				result := make(chan error, 1)
				go func() {
					result <- superviseMount(m, done, requests, nil, func(err error) { reports = append(reports, err) })
				}()
				requests <- syscall.SIGTERM
				synctest.Wait()
				if !duringAttempt {
					close(done)
				}
				if err := <-result; !errors.Is(err, cleanupErr) {
					t.Fatalf("failed finalization certified success: %v", err)
				}
				if m.attempts != 1 || m.finalizations != 1 || !m.owners || len(reports) != 1 || !errors.Is(reports[0], syscall.EBUSY) {
					t.Fatalf("attempt/finalization result lost: %+v, %v", m, reports)
				}
			})
		})
	}
}
