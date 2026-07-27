package main

import (
	"os"

	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
)

var version = "dev"

func main() {
	os.Exit(portablefsd.Main(version))
}
