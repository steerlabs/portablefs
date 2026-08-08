//go:build !linux

package main

import "errors"

func run() error { return errors.New("portablefs-authority requires Linux and authoritative XFS") }
