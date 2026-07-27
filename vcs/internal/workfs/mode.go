package workfs

import (
	"os"

	"github.com/steerlabs/portablefs/vcs/internal/modebits"
)

const modeUnixFileModeBits = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

func modeFromUnix(mode uint32) os.FileMode { return modebits.FromUnix(mode) }

func modeToUnix(mode os.FileMode) uint32 { return modebits.ToUnix(mode) }
