package clientcore

import "testing"

func TestLocalNodeAuthorityIdentityIsExactAndImmutable(t *testing.T) {
	n := NewNodeState(1234, false)
	if n.MatchesAuthorityIno(44) {
		t.Fatal("unbound local node matched an authority inode")
	}
	if !n.RecordAuthorityIno(44) {
		t.Fatal("first proven authority binding was rejected")
	}
	if !n.MatchesAuthorityIno(44) {
		t.Fatal("proven authority binding did not match")
	}
	if n.MatchesAuthorityIno(45) {
		t.Fatal("node matched a different authority inode")
	}
	if n.RecordAuthorityIno(45) {
		t.Fatal("instantiated node accepted an authority identity change")
	}
	if !n.MatchesAuthorityIno(44) {
		t.Fatal("failed identity change damaged the original binding")
	}
}

func TestAuthorityBornNodeStartsBound(t *testing.T) {
	n := NewNodeState(77, true)
	if !n.MatchesAuthorityIno(77) {
		t.Fatal("authority-born node did not match its inode")
	}
}
