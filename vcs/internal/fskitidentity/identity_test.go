package fskitidentity

import "testing"

func TestCurrentIdentityIncludesEveryFSKitAxis(t *testing.T) {
	identity := Current()
	if identity.SchemaVersion != IdentitySchemaVersion ||
		identity.FSType != FSType ||
		identity.ResourceScheme != ResourceScheme ||
		identity.AppGroup != AppGroup {
		t.Fatalf("identity = %+v", identity)
	}
	if ResourcePrefix != ResourceScheme+"://" {
		t.Fatalf("resource prefix = %q", ResourcePrefix)
	}
}
