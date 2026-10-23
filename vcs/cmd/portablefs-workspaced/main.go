// portablefs-workspaced owns the VM-bound control stream and protected mounts.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "portablefs-workspaced:", err)
		os.Exit(1)
	}
}
