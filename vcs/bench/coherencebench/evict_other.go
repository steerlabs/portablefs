//go:build !linux

package coherencebench

import "fmt"

// EvictFilePages is implemented only on Linux, where the privileged baseline
// runs. Keeping the stub lets the command and repository build on Darwin.
func EvictFilePages(string) error {
	return fmt.Errorf("file-page eviction is supported only on Linux")
}
