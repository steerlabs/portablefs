// Command treehashcheck computes the Go tree hash of a manifest-entries JSON
// file, for cross-checking against the TS implementation.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/steerlabs/portablefs/vcs/internal/treehash"
)

type blobJSON struct {
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	Compression string `json:"compression"`
	Packed      bool   `json:"packed"`
}
type chunkJSON struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
}
type entryJSON struct {
	Path       string      `json:"path"`
	Kind       string      `json:"kind"`
	Mode       uint32      `json:"mode"`
	Size       int64       `json:"size"`
	Executable bool        `json:"executable"`
	UID        uint32      `json:"uid"`
	GID        uint32      `json:"gid"`
	Blob       *blobJSON   `json:"blob"`
	Chunks     []chunkJSON `json:"chunks"`
	LinkTarget string      `json:"linkTarget"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: treehashcheck <entries.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var ej []entryJSON
	if err := json.Unmarshal(data, &ej); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	entries := make([]treehash.Entry, 0, len(ej))
	for _, e := range ej {
		te := treehash.Entry{Path: e.Path, Kind: e.Kind, Mode: e.Mode, Size: e.Size, Executable: e.Executable, LinkTarget: e.LinkTarget, UID: e.UID, GID: e.GID}
		if e.Blob != nil {
			te.Blob = &treehash.Blob{Digest: e.Blob.Digest, Size: e.Blob.Size, Compression: e.Blob.Compression, Packed: e.Blob.Packed}
		}
		for _, c := range e.Chunks {
			te.Chunks = append(te.Chunks, treehash.Chunk{Digest: c.Digest, Size: c.Size, Offset: c.Offset})
		}
		entries = append(entries, te)
	}
	if os.Getenv("DEBUG") == "1" {
		for _, e := range entries {
			fmt.Printf("%d|%s\n", treehash.ShardID(e.Path), treehash.ComparableKey(e))
		}
		return
	}
	fmt.Println("GO_HASH=" + treehash.Compute(entries))
}
