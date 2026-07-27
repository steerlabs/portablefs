// Command nfsio is a tiny userspace NFSv3 client for reading or writing a single
// file against a running VCS — handy for scripting and failover demos without a
// kernel mount (no sudo).
//
//	nfsio write <host:port> <path> <data>
//	nfsio read  <host:port> <path>
package main

import (
	"fmt"
	"os"

	nfsclient "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
)

func main() {
	if len(os.Args) < 4 || (os.Args[1] == "write" && len(os.Args) < 5) {
		fmt.Fprintln(os.Stderr, "usage: nfsio write <host:port> <path> <data> | nfsio read <host:port> <path>")
		os.Exit(2)
	}
	cmd, addr, path := os.Args[1], os.Args[2], os.Args[3]
	target := mount(addr)

	switch cmd {
	case "write":
		f, err := target.OpenFile(path, 0o644)
		must(err)
		_, err = f.Write([]byte(os.Args[4]))
		must(err)
		must(f.Close())
		fmt.Println("wrote", path)
	case "read":
		f, err := target.Open(path)
		must(err)
		buf := make([]byte, 1<<16)
		n, _ := f.Read(buf)
		_ = f.Close()
		os.Stdout.Write(buf[:n])
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		os.Exit(2)
	}
}

func mount(addr string) *nfsclient.Target {
	c, err := rpc.DialTCP("tcp", addr, false)
	must(err)
	t, err := (&nfsclient.Mount{Client: c}).Mount("/", rpc.AuthNull)
	must(err)
	return t
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "nfsio:", err)
		os.Exit(1)
	}
}
