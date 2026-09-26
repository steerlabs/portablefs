//go:build linux

package soak

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSoakGitLock(t *testing.T) {
	if isolateSoak(t, 90*time.Second) {
		return
	}
	f := newFixture(t)
	mustMkdir(t, filepath.Join(f.a, ".git"))
	f.measure(t, "git-lock-exclusive-create-100-races", func() error {
		for i := 0; i < 100; i++ {
			type opened struct {
				root string
				file *os.File
				err  error
			}
			ready := make(chan struct{})
			results := make(chan opened, 2)
			for _, root := range []string{f.a, f.b} {
				go func(root string) {
					<-ready
					h, err := os.OpenFile(filepath.Join(root, ".git/index.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					results <- opened{root, h, err}
				}(root)
			}
			close(ready)
			var winner opened
			wins := 0
			for n := 0; n < 2; n++ {
				r := <-results
				if r.err == nil {
					winner = r
					wins++
				} else if !errors.Is(r.err, syscall.EEXIST) {
					return fmt.Errorf("lock race %d: %w", i, r.err)
				}
			}
			if wins != 1 {
				return fmt.Errorf("lock race %d had %d winners", i, wins)
			}
			payload := []byte(fmt.Sprintf("index iteration %d", i))
			_, err := winner.file.Write(payload)
			if err = errors.Join(err, winner.file.Close()); err != nil {
				return err
			}
			if err := os.Rename(filepath.Join(winner.root, ".git/index.lock"), filepath.Join(winner.root, ".git/index")); err != nil {
				return err
			}
			for _, root := range []string{f.a, f.b} {
				got, err := os.ReadFile(filepath.Join(root, ".git/index"))
				if err != nil {
					return err
				}
				if string(got) != string(payload) {
					return fmt.Errorf("index publication %d returned %q", i, got)
				}
			}
		}
		f.barrier(t)
		return nil
	})
}
