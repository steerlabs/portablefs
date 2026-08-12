//go:build !darwin

package portablefsd

func prepareRuntimeConfig(*Config) error { return nil }
