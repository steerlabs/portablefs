package appgroupcontainer

import "testing"

func TestValidateResolvedPathRequiresCanonicalAbsoluteNonRootPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		ok   bool
	}{
		{name: "canonical", path: "/Users/test/Library/Group Containers/TEAM.pfs", ok: true},
		{name: "relative", path: "Library/Group Containers/TEAM.pfs"},
		{name: "root", path: "/"},
		{name: "parent traversal", path: "/Users/test/../other"},
		{name: "duplicate separator", path: "/Users//test/group"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateResolvedPath("TEAM.pfs", test.path)
			if test.ok {
				if err != nil || got != test.path {
					t.Fatalf("path = %q, err = %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("unsafe path %q was accepted as %q", test.path, got)
			}
		})
	}
}
