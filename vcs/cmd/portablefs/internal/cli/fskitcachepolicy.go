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

// fskitCachePolicyForProductVersion selects the one cache contract implemented
// by this exact frontend build on this exact OS generation. macOS 26 uses the
// frozen synchronous-VFS-repair contract. macOS 27 remains production-gated;
// only the separately signed live-qualification build may ask for the native
// policy. Later OS generations are refused until independently qualified.
// There is no probe-based fallback between policy names.
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
		if nativeQualification != sdk27QualificationStamp {
			return "", fmt.Errorf("macOS 27 native FSKit mounting is not admitted by this build: the SDK-27 adapter has not completed the namespace and attribute coherence gates")
		}
		return portablefsd.V3CachePolicyFSKit, nil
	default:
		return "", fmt.Errorf("macOS %s has no qualified PortableFS FSKit cache policy in this build", productVersion)
	}
}
