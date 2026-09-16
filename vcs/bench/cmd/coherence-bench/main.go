// Command coherence-bench runs the coherence-v2 baseline workloads against
// POSIX paths. The privileged integration test uses the same package while it
// owns the PortableFS Authority request meter.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/steerlabs/portablefs/vcs/bench/coherencebench"
)

func main() {
	mode := flag.String("mode", "install", "workload: install, git-prepare, git-cold, git-warm, or peer")
	root := flag.String("root", "", "primary path; install and git-prepare require an empty existing directory")
	peer := flag.String("peer", "", "peer view of the same directory for peer mode")
	files := flag.Int("files", 40000, "file count")
	directories := flag.Int("directories", 2000, "install directory count")
	workers := flag.Int("workers", 1, "install worker count")
	flag.Parse()
	if *root == "" {
		fatalf("-root is required")
	}
	var result coherencebench.WorkloadResult
	var err error
	switch *mode {
	case "install":
		result, err = coherencebench.Install(*root, *files, *directories, *workers)
	case "git-prepare":
		err = coherencebench.PrepareGit(*root, *files)
		result = coherencebench.WorkloadResult{Scenario: "git-prepare", Files: *files}
	case "git-cold":
		result, err = coherencebench.GitStatus(*root, "cold", *files)
	case "git-warm":
		result, err = coherencebench.GitStatus(*root, "warm", *files)
	case "peer":
		if *peer == "" {
			fatalf("-peer is required for peer mode")
		}
		result, err = coherencebench.PeerWriteRead(*root, *peer, *files)
	default:
		fatalf("unknown -mode %q", *mode)
	}
	if err != nil {
		fatalf("%s: %v", *mode, err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fatalf("encode result: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "coherence-bench: "+format+"\n", args...)
	os.Exit(1)
}
