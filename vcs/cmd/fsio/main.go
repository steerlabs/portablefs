// Command fsio drives the custom VCS filesystem protocol (no FUSE) — for
// scripting, smoke tests, and delegation coordination.
//
//	fsio write    <host:port> <path> <data>
//	fsio read     <host:port> <path>
//	fsio checkout <host:port> <path> <owner>
//	fsio checkin  <host:port> <path> <owner>
package main

import (
	"fmt"
	"os"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fsio write|read <host:port> <path> [data] | fsio checkout|checkin <host:port> <path> <owner>")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 4 {
		usage()
	}
	cmd, addr, path := os.Args[1], os.Args[2], os.Args[3]
	c, err := fsproto.Dial(addr, 2)
	must(err)
	defer c.Close()

	switch cmd {
	case "write":
		if len(os.Args) < 5 {
			usage()
		}
		if _, st, err := c.Create(path, 0o644); err != nil || st != fsproto.OK {
			fail("create", st, err)
		}
		if _, st, err := c.Write(path, 0, []byte(os.Args[4]), 0o644); err != nil || st != fsproto.OK {
			fail("write", st, err)
		}
		fmt.Println("wrote", path)
	case "read":
		data, st, err := c.Read(path, 0, 1<<20)
		if err != nil || st != fsproto.OK {
			fail("read", st, err)
		}
		os.Stdout.Write(data)
	case "checkout":
		if len(os.Args) < 5 {
			usage()
		}
		ok, heldBy, err := c.Checkout(path, os.Args[4])
		must(err)
		if !ok {
			fmt.Fprintf(os.Stderr, "checkout denied: %s held by %s\n", path, heldBy)
			os.Exit(1)
		}
		fmt.Printf("checked out %s for %s\n", path, os.Args[4])
	case "checkin":
		if len(os.Args) < 5 {
			usage()
		}
		must(c.Checkin(path, os.Args[4]))
		fmt.Printf("checked in %s\n", path)
	case "readdir":
		ents, _, st, err := c.Readdir(path)
		if err != nil || st != fsproto.OK {
			fail("readdir", st, err)
		}
		for _, e := range ents {
			fmt.Printf("%s\t%s\t%d\n", e.Name, e.Attr.Kind, e.Attr.Size)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fsio:", err)
		os.Exit(1)
	}
}

func fail(op string, st int32, err error) {
	fmt.Fprintf(os.Stderr, "fsio %s: status=%d err=%v\n", op, st, err)
	os.Exit(1)
}
