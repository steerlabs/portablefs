//go:build !darwin

package cli

import "fmt"

func authenticateDaemonRelease(string, string) (daemonRelease, error) {
	return daemonRelease{}, fmt.Errorf("authenticated FSKit daemon releases require macOS")
}

func connectInstalledPortablefsd(fskitConfig) (*fsdControl, error) {
	return nil, fmt.Errorf("authenticated FSKit daemon releases require macOS")
}
