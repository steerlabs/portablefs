package main

import (
	"os"

	"github.com/trendup-ai/portablefs/vcs/internal/portablefsd"
)

var version = "dev"

func main() {
	os.Exit(portablefsd.Main(version))
}
