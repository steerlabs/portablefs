// portablefs-workspaced is reserved for the guest-only workspace supervisor.
// Stage 1a deliberately has no vsock listener or mount driver to activate.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "portablefs-workspaced: unavailable: workspace control and suspension models only; guest transport and mount integration pending")
	os.Exit(1)
}
