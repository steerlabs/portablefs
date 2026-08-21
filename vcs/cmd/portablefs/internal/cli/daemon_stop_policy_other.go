//go:build !darwin

package cli

func daemonStopPolicy() error { return nil }
