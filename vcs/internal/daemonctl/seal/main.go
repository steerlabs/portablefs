// Command seal emits the protocol metadata sealed into the daemon service.
package main

import (
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"os"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "seal takes no arguments")
		os.Exit(1)
	}
	data, err := daemonctl.EncodeSealedProtocols(daemonctl.SealedProtocols{IdentitySchema: daemonctl.IdentitySchemaVersion, ControlProtocol: daemonctl.ControlProtocolVersion, PFSLocalMajor: pfslocal.ProtocolMajor, PFSLocalMinor: pfslocal.ProtocolMinor})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
