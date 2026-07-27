// Command portablefs is the unified PortableFS CLI: login, create volumes, mount
// them live on this machine, snapshot/branch/fork them for parallel agent runs,
// and run server-side exec/grep against committed branch state.
//
// A PortableFS volume is a place in the network, not a folder on one machine:
// the same live volume mounts from a laptop, a server, and an agent sandbox at
// once, with continuous checkpoints and cheap forks.
//
//	portablefs help
package main

import (
	"os"

	"github.com/steerlabs/portablefs/vcs/cmd/portablefs/internal/cli"
)

// version is stamped by release builds: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	os.Exit(cli.Main(os.Args[1:], version))
}
