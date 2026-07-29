// Command pfsbench is the PortableFS benchmark harness. It provisions a
// throwaway local stack (a disk-backed workfs authority served over loopback
// fsproto) and runs coding-agent-shaped workloads against it, comparing to a
// local temp directory baseline.
//
// Modes:
//
//	pfsbench serve  -wal <path> [-addr 127.0.0.1:0] [-addrfile <path>]
//	    Run a standalone authority until killed. Used by the torture test
//	    (kill -9 + restart on the same WAL) and by external FUSE mounts.
//
//	pfsbench run    -transport local|core|fuse [flags] -out <file.json>
//	    Run workloads W1..W5 and write JSON results.
//	      local: against a temp directory (the baseline).
//	      core:  against an in-process authority via the clientcore volume
//	             (loopback fsproto; no kernel, no FUSE requirement). Each
//	             logical filesystem op mirrors what the FUSE frontend issues.
//	      fuse:  against a real kernel mount (Linux-only: requires /dev/fuse
//	             plus -mount-bin pointing at the built bench/cmd/benchmount).
//	             PFSBENCH_MOUNT_ONLY=skip skips instead of failing when FUSE
//	             is unavailable.
//
//	pfsbench report -dir <results-dir>
//	    Print a markdown table across all JSON results in a directory.
//
// Workloads (deterministic seeds, fixed size distributions):
//
//	W1 metadata-walk : create files across dirs, lstat-walk cold + warm (git status proxy)
//	W2 small-file storm : npm-ci-like small file writes, time-to-visible + time-to-durable,
//	                      plus an ENOENT probe storm (npm probes many missing paths)
//	W3 append : sequential appends to one log file
//	W4 grep : walk + read every file's bytes (content scan)
//	W5 sequential : one large file written then cold-read
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "wbstorm":
		cmdWBStorm(os.Args[2:])
	case "wbrecover":
		cmdWBRecover(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pfsbench <serve|run|report|wbstorm|wbrecover> [flags]")
	os.Exit(2)
}
