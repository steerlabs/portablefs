//go:build !linux

package main

import "log"

func main() {
	log.Fatal("portablefs-mount-v3 requires Linux FUSE; there is no weaker production fallback")
}
