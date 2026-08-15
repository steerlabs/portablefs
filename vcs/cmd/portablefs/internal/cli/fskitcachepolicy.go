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

// fskitCachePolicyForProductVersion is the pre-daemon, pre-authority admission
// gate for an FSKit mount. No currently documented FSKit version has the
// complete primitives protocol 5 requires: legacy macOS 26 callbacks cannot
// publish all source post-mutation attributes, and neither macOS 26 nor 27 can
// invalidate peer namespace/attribute state exactly. Shipping builds therefore
// refuse every macOS version here. Only the separately signed macOS 27 live-
// qualification artifact may select its native data-cache policy, and that is
// a test lane rather than a compatibility fallback.
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
		return "", fmt.Errorf("macOS 26 FSKit cannot mount PortableFS protocol 5: legacy mutation callbacks cannot publish complete source post-mutation attributes and FSKit exposes no exact peer namespace or attribute invalidation; no authority attach was attempted")
	case 27:
		if nativeQualification != sdk27QualificationStamp {
			return "", fmt.Errorf("macOS 27 FSKit cannot mount PortableFS protocol 5 in production: FSKit exposes no exact peer namespace or attribute invalidation; no authority attach was attempted")
		}
		return portablefsd.V3CachePolicyFSKit, nil
	default:
		return "", fmt.Errorf("macOS %s has no qualified PortableFS FSKit cache policy in this build", productVersion)
	}
}
