package cli

import (
	"fmt"
	"strconv"
	"strings"
)

func validateFSKitProductVersion(productVersion string) error {
	majorText, _, _ := strings.Cut(strings.TrimSpace(productVersion), ".")
	major, err := strconv.Atoi(majorText)
	if err != nil || (major != 26 && major != 27) {
		return fmt.Errorf("macOS %q is unsupported; PortableFS requires macOS 26 or 27", productVersion)
	}
	return nil
}
