package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
)

const sdk27QualificationStamp = "sdk27-live-qualification-only"

// nativeFSKitPolicyQualification is deliberately empty in ordinary and
// release builds. The SDK-27 signed development lane stamps the exact value
// above with -ldflags -X only while running the live qualification matrix.
// An OS version is not evidence that the installed extension implements every
// repair family in fskit-native-revocation-v1.
var nativeFSKitPolicyQualification = ""

// fskitCachePolicyForProductVersion selects the exact cache contract an FSKit
// mount declares to portablefsd and the authority. macOS 26 and ordinary
// macOS 27 builds use the bounded synchronous-VFS-repair policy. The separately
// signed SDK-27 lane selects native revocation only when its exact build stamp
// proves that the matching adapter is present; OS version alone never selects
// an implementation the installed extension may not contain.
func fskitCachePolicyForProductVersion(
	productVersion string,
	nativeQualification string,
) (string, error) {
	majorText, _, _ := strings.Cut(strings.TrimSpace(productVersion), ".")
	major, err := strconv.Atoi(majorText)
	if err != nil || major <= 0 {
		return "", fmt.Errorf("read macOS product version: unsupported value %q", productVersion)
	}
	switch major {
	case 26:
		return portablefsd.V3CachePolicyMacOS26, nil
	case 27:
		if nativeQualification == sdk27QualificationStamp {
			return portablefsd.V3CachePolicyFSKit, nil
		}
		return portablefsd.V3CachePolicyMacOS26, nil
	default:
		return "", fmt.Errorf("macOS %s has no qualified PortableFS FSKit cache policy in this build", productVersion)
	}
}
