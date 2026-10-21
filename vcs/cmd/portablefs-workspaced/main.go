// portablefs-workspaced owns the VM-bound guest control stream. Mount creation
// remains unavailable until the real daemon suspension boundary is integrated.
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
