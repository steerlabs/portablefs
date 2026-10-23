//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenGuestIdentitiesKeepsClassifiedRefusalAvailable(t *testing.T) {
	for _, shape := range []string{"fresh", "corrupt", "lost", "unexpected"} {
		t.Run(shape, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "identities")
			if shape == "unexpected" {
				if err := os.WriteFile(directory, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if shape != "fresh" {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "volume.json"), []byte("retained test record"), 0600); err != nil {
					t.Fatal(err)
				}
				if shape == "corrupt" {
					if err := os.WriteFile(filepath.Join(directory, "guest.json"), []byte("corrupt"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				identities, err := openGuestIdentities(directory)
				if shape == "unexpected" {
					if err == nil || identities != nil {
						t.Fatal("unexpected startup error suppressed", err)
					}
					continue
				}
				if err != nil {
					t.Fatal("classified refusal killed service", err)
				}
				if shape == "fresh" {
					if identities == nil {
						t.Fatal("fresh identity unavailable")
					}
					if err := identities.Close(); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if identities != nil {
					identities.Close()
					t.Fatal("refused identity reopened")
				}
				raw, err := os.ReadFile(filepath.Join(directory, "guest.json"))
				if shape == "lost" {
					if !os.IsNotExist(err) {
						t.Fatal("lost identity rewritten", err)
					}
				} else if err != nil || !bytes.Equal(raw, []byte("corrupt")) {
					t.Fatal("corrupt identity rewritten", err)
				}
				raw, err = os.ReadFile(filepath.Join(directory, "volume.json"))
				if err != nil || !bytes.Equal(raw, []byte("retained test record")) {
					t.Fatal("retained scope rewritten", err)
				}
			}
		})
	}
}
