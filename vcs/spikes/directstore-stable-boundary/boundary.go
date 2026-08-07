// Package stableboundary is a disposable spike for the direct-store
// persistence ordering. It is not a proposed storage format or engine.
package stableboundary

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Event names the semantic cuts and externally visible actions in the spike.
type Event string

const (
	BeforeObjectSync      Event = "before-object-sync"
	AfterObjectSync       Event = "after-object-sync"
	BeforeStateCommitSync Event = "before-state-commit-sync"
	AfterStateCommitSync  Event = "after-state-commit-sync"
	BeforeRaftSync        Event = "before-raft-sync"
	AfterRaftSync         Event = "after-raft-sync"
	BeforeAppendResponse  Event = "before-append-response"
	AppendResponse        Event = "event-append-response"
	AfterAppendResponse   Event = "after-append-response"
	BeforeInstallSync     Event = "before-install-sync"
	AfterInstallSync      Event = "after-install-sync"
	BeforeClientReply     Event = "before-client-reply"
	ClientReply           Event = "event-client-reply"
	AfterClientReply      Event = "after-client-reply"
)

// OrderingPoints is the complete semantic crash list for this spike. It is
// derived from O -> S -> L -> A -> I -> P; physical torn-write cut points
// belong to the Phase 1 fault harness.
var OrderingPoints = []Event{
	BeforeObjectSync,
	AfterObjectSync,
	BeforeStateCommitSync,
	AfterStateCommitSync,
	BeforeRaftSync,
	AfterRaftSync,
	BeforeAppendResponse,
	AfterAppendResponse,
	BeforeInstallSync,
	AfterInstallSync,
	BeforeClientReply,
	AfterClientReply,
}

// Bundle is one canonical materialized proposal used by the spike.
type Bundle struct {
	Index   uint64
	Object  []byte
	Outcome []byte
}

type stateCommit struct {
	Index        uint64 `json:"index"`
	ObjectDigest string `json:"object_digest"`
	Outcome      []byte `json:"outcome"`
}

type raftRecord struct {
	Index             uint64 `json:"index"`
	StateCommitDigest string `json:"state_commit_digest"`
}

type installRecord struct {
	Index             uint64 `json:"index"`
	StateCommitDigest string `json:"state_commit_digest"`
}

type records struct {
	objectName  string
	state       []byte
	stateName   string
	raft        []byte
	raftName    string
	install     []byte
	installName string
}

// Inspection describes the durable dependency chain found during recovery.
type Inspection struct {
	ObjectStable      bool
	StateCommitStable bool
	RaftStable        bool
	Prepared          bool
	Installed         bool
}

// PrepareLayout creates and stabilizes the directories used by the spike.
func PrepareLayout(root string) error {
	for _, name := range []string{"objects", "state", "raft", "installed"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			return fmt.Errorf("create %s directory: %w", name, err)
		}
	}
	if err := syncDirectory(root); err != nil {
		return fmt.Errorf("stabilize spike layout: %w", err)
	}
	return nil
}

// Persist executes the object-before-record order. observe is called at every
// semantic cut and action; tests use it to stop the process without sleeps.
func Persist(root string, bundle Bundle, observe func(Event)) error {
	r, err := buildRecords(bundle)
	if err != nil {
		return err
	}
	if err := writeDurableAtomic(
		filepath.Join(root, "objects"), r.objectName, bundle.Object,
		BeforeObjectSync, AfterObjectSync, observe,
	); err != nil {
		return fmt.Errorf("persist object: %w", err)
	}
	if err := writeDurableAtomic(
		filepath.Join(root, "state"), r.stateName, r.state,
		BeforeStateCommitSync, AfterStateCommitSync, observe,
	); err != nil {
		return fmt.Errorf("persist state commit: %w", err)
	}
	if err := writeDurableAtomic(
		filepath.Join(root, "raft"), r.raftName, r.raft,
		BeforeRaftSync, AfterRaftSync, observe,
	); err != nil {
		return fmt.Errorf("persist raft record: %w", err)
	}
	emit(observe, BeforeAppendResponse)
	emit(observe, AppendResponse)
	emit(observe, AfterAppendResponse)
	if err := writeDurableAtomic(
		filepath.Join(root, "installed"), r.installName, r.install,
		BeforeInstallSync, AfterInstallSync, observe,
	); err != nil {
		return fmt.Errorf("persist installed root: %w", err)
	}
	emit(observe, BeforeClientReply)
	emit(observe, ClientReply)
	emit(observe, AfterClientReply)
	return nil
}

// Inspect reopens one bundle and validates every dependency before declaring
// it prepared or installed. A durable record with a missing dependency is
// corruption, not a recoverable commit.
func Inspect(root string, bundle Bundle) (Inspection, error) {
	r, err := buildRecords(bundle)
	if err != nil {
		return Inspection{}, err
	}
	var got Inspection
	objectPresent, err := readExact(filepath.Join(root, "objects", r.objectName), bundle.Object)
	if err != nil {
		return got, fmt.Errorf("inspect object: %w", err)
	}
	got.ObjectStable = objectPresent

	statePresent, err := readExact(filepath.Join(root, "state", r.stateName), r.state)
	if err != nil {
		return got, fmt.Errorf("inspect state commit: %w", err)
	}
	got.StateCommitStable = statePresent
	if statePresent && !objectPresent {
		return got, errors.New("state commit references a missing materialized object")
	}

	raftPresent, err := readExact(filepath.Join(root, "raft", r.raftName), r.raft)
	if err != nil {
		return got, fmt.Errorf("inspect raft record: %w", err)
	}
	got.RaftStable = raftPresent
	if raftPresent && !statePresent {
		return got, errors.New("raft record references a missing state commit")
	}
	got.Prepared = objectPresent && statePresent && raftPresent

	installPresent, err := readExact(filepath.Join(root, "installed", r.installName), r.install)
	if err != nil {
		return got, fmt.Errorf("inspect installed root: %w", err)
	}
	if installPresent && !got.Prepared {
		return got, errors.New("installed root references an incomplete prepared bundle")
	}
	got.Installed = installPresent
	return got, nil
}

func buildRecords(bundle Bundle) (records, error) {
	if bundle.Index == 0 {
		return records{}, errors.New("bundle index must be non-zero")
	}
	objectDigest := sha256.Sum256(bundle.Object)
	stateBytes, err := json.Marshal(stateCommit{
		Index:        bundle.Index,
		ObjectDigest: hex.EncodeToString(objectDigest[:]),
		Outcome:      bundle.Outcome,
	})
	if err != nil {
		return records{}, fmt.Errorf("encode state commit: %w", err)
	}
	stateDigest := sha256.Sum256(stateBytes)
	stateName := hex.EncodeToString(stateDigest[:])
	raftBytes, err := json.Marshal(raftRecord{
		Index:             bundle.Index,
		StateCommitDigest: stateName,
	})
	if err != nil {
		return records{}, fmt.Errorf("encode raft record: %w", err)
	}
	installBytes, err := json.Marshal(installRecord{
		Index:             bundle.Index,
		StateCommitDigest: stateName,
	})
	if err != nil {
		return records{}, fmt.Errorf("encode install record: %w", err)
	}
	return records{
		objectName:  hex.EncodeToString(objectDigest[:]),
		state:       stateBytes,
		stateName:   stateName,
		raft:        raftBytes,
		raftName:    fmt.Sprintf("%d.json", bundle.Index),
		install:     installBytes,
		installName: fmt.Sprintf("%d.json", bundle.Index),
	}, nil
}

func writeDurableAtomic(
	dir string,
	name string,
	data []byte,
	before Event,
	after Event,
	observe func(Event),
) error {
	finalPath := filepath.Join(dir, name)
	temporaryPath := finalPath + ".tmp"
	f, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	written, err := f.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	emit(observe, before)
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close synced file: %w", err)
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return fmt.Errorf("install file: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync containing directory: %w", err)
	}
	emit(observe, after)
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readExact(path string, want []byte) (bool, error) {
	got, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(got, want) {
		return false, fmt.Errorf("%s is present but corrupt", path)
	}
	return true, nil
}

func emit(observe func(Event), event Event) {
	if observe != nil {
		observe(event)
	}
}
