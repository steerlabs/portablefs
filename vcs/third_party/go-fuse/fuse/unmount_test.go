//go:build go1.25

package fuse

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"testing/synctest"
)

func TestNormalUnmountMakesOneAttemptAndPreservesTheError(t *testing.T) {
	for _, refusal := range []error{syscall.EBUSY, syscall.EPERM, errors.New("helper failure")} {
		t.Run(refusal.Error(), func(t *testing.T) {
			server := &Server{mountPoint: "/owned", opts: &MountOptions{}}
			attempts := 0
			for want := 1; want <= 2; want++ {
				err := server.unmount(func(path string, opts *MountOptions) error {
					attempts++
					if path != "/owned" || opts != server.opts {
						t.Fatal("unmount changed its target")
					}
					return refusal
				})
				if err != refusal || attempts != want || server.mountPoint != "/owned" {
					t.Fatalf("attempts = %d, err = %v, target = %q", attempts, err, server.mountPoint)
				}
			}
		})
	}
}

func TestNormalUnmountJoinsWorkersOnlyAfterSuccess(t *testing.T) {
	// This nested module retains go 1.21; synctest requires modern timer semantics.
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",asynctimerchan=0")
	synctest.Test(t, func(t *testing.T) {
		server := &Server{mountPoint: "/owned"}
		server.loops.Add(1)
		attempted := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			result <- server.unmount(func(string, *MountOptions) error {
				close(attempted)
				return nil
			})
		}()
		<-attempted
		synctest.Wait()
		select {
		case <-result:
			t.Fatal("successful unmount returned before its workers exited")
		default:
		}
		if server.mountPoint != "/owned" {
			t.Fatal("target cleared before workers exited")
		}
		server.loops.Done()
		if err := <-result; err != nil || server.mountPoint != "" {
			t.Fatalf("joined unmount = %v, target = %q", err, server.mountPoint)
		}
		if err := server.unmount(func(string, *MountOptions) error {
			t.Fatal("already unmounted server made another attempt")
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
