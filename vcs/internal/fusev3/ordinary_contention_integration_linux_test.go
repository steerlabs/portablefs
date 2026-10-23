//go:build linux

package fusev3

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestOrdinaryAtomicSaveWithLocalReader(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{})
	name := f.join(0, "document")
	mustWrite(t, name, bytes.Repeat([]byte("0"), 4096), 0600)
	stop := make(chan struct{})
	readers := make(chan error, 2)
	for mount := range 2 {
		go func() {
			for {
				select {
				case <-stop:
					readers <- nil
					return
				default:
				}
				data, err := os.ReadFile(f.join(mount, "document"))
				if err != nil {
					readers <- err
					return
				}
				if len(data) != 4096 || !bytes.Equal(data, bytes.Repeat(data[:1], 4096)) {
					readers <- fmt.Errorf("torn atomic save: %d bytes", len(data))
					return
				}
			}
		}()
	}
	defer close(stop)
	for round := range 500 {
		file, err := os.OpenFile(f.join(0, "temporary"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.Write(bytes.Repeat([]byte{byte(round%10 + '0')}, 4096))
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("save %d: %v, close %v", round, err, closeErr)
		}
		if err := os.Rename(f.join(0, "temporary"), name); err != nil {
			t.Fatalf("save %d: %v", round, err)
		}
		select {
		case err := <-readers:
			t.Fatalf("reader stopped: %v", err)
		default:
		}
	}
	for mount := range 2 {
		if _, err := os.ReadDir(f.mountPath(mount)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrdinaryThreeInPlaceWriters(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{})
	mustWrite(t, f.join(0, "overwrite"), []byte("initial"), 0600)
	start := make(chan struct{})
	done := make(chan error, 3)
	for writer := range 3 {
		go func() {
			<-start
			for round := range 200 {
				file, err := os.OpenFile(f.join(writer/2, "overwrite"), os.O_WRONLY|os.O_TRUNC, 0)
				if err != nil {
					done <- fmt.Errorf("writer %d open %d: %w", writer, round, err)
					return
				}
				_, err = file.Write(bytes.Repeat([]byte{byte('a' + writer)}, 4096))
				if err == nil {
					err = file.Sync()
				}
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					done <- fmt.Errorf("writer %d round %d: %v, close %v", writer, round, err, closeErr)
					return
				}
			}
			done <- nil
		}()
	}
	close(start)
	for range 3 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("in-place writers stalled: %s", f.sessionDiagnostics())
		}
	}
	for mount := range 2 {
		if _, err := os.ReadDir(f.mountPath(mount)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrdinaryItemPressurePreservesExistingAccess(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{MaxItemsPerSession: 64, MaxItems: 96, NameCacheCapacity: 64})
	for i := range 80 {
		file, err := os.OpenFile(f.join(0, fmt.Sprintf("item-%03d", i)), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			if !errors.Is(err, syscall.ENFILE) {
				t.Fatal(err)
			}
			break
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		_, _ = os.Stat(f.join(1, fmt.Sprintf("item-%03d", i)))
	}
	for mount := range 2 {
		if _, err := os.ReadDir(f.mountPath(mount)); err != nil {
			t.Fatalf("mount %d lost existing directory access at item saturation: %v", mount, err)
		}
	}
}

func TestOrdinaryQuotaExhaustionIsLocal(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{})
	file := mustOpenFile(t, f.join(0, "fill"), os.O_CREATE|os.O_WRONLY, 0600)
	defer file.Close()
	block := bytes.Repeat([]byte{0x5a}, 1<<20)
	var fillErr error
	for range 2048 {
		if _, fillErr = file.Write(block); fillErr != nil {
			break
		}
	}
	if fillErr == nil {
		fillErr = file.Sync()
	}
	if !errors.Is(fillErr, syscall.EDQUOT) && !errors.Is(fillErr, syscall.ENOSPC) {
		t.Fatalf("quota writer error = %v, want EDQUOT or ENOSPC", fillErr)
	}
	if err := f.store.Health(); err != nil {
		t.Fatalf("quota fenced authority: %v", err)
	}
	if err := file.Truncate(0); err != nil {
		t.Fatalf("free quota through existing descriptor: %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("sync after freeing quota: %v", err)
	}
	for mount := range 2 {
		if _, err := os.ReadDir(f.mountPath(mount)); err != nil {
			t.Fatalf("quota killed mount %d: %v", mount, err)
		}
	}
	if err := file.Close(); err != nil && !errors.Is(err, syscall.EDQUOT) && !errors.Is(err, syscall.ENOSPC) {
		t.Fatal(err)
	}
	if err := os.Remove(f.join(1, "fill")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, f.join(1, "after-quota"), []byte("recovered"), 0600)
}
