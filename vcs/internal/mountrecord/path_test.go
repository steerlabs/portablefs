package mountrecord

import "testing"

func TestKeyIsStableAndPathSpecific(t *testing.T) {
	const want = "037c3efbeab2bdc9"
	if got := Key("/tmp/work"); got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
	if Key("/tmp/work") == Key("/tmp/other") {
		t.Fatal("different mount paths produced the same test key")
	}
}
