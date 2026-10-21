//go:build !linux

package main

import "fmt"

func run([]string) error { return fmt.Errorf("Linux guest required") }
