package cellhost

import (
	"encoding/hex"
	"strings"
	"testing"
)

// testNonce carries hex letters on purpose: the acceptance rule is exact
// lowercase-hex equality, and a digits-only nonce could not show that.
func testNonce() string { return strings.Repeat("a1b2c3d4", 8) }

func provenQuiesce() QuiesceProof {
	return QuiesceProof{
		VolumeID:            testVolumeID,
		AuthorityEpoch:      7,
		WireSessionEpochHex: hex.EncodeToString([]byte("fedcba9876543210")),
		Nonce:               testNonce(),
		MembershipEmpty:     true,
		WrittenUnix:         1_760_000_000,
	}
}

// TestQuiesceProofProvesOnlyWhatItSays states the acceptance rule once, in a
// test, so no caller can weaken it by accident: right volume, right epoch,
// right nonce, and an actual claim of emptiness.
func TestQuiesceProofProvesOnlyWhatItSays(t *testing.T) {
	if !provenQuiesce().Proves(testVolumeID, 7, testNonce()) {
		t.Fatal("a complete proof was rejected")
	}
	for name, check := range map[string]bool{
		"other volume":    provenQuiesce().Proves("22222222-2222-4222-8222-222222222223", 7, testNonce()),
		"invalid volume":  provenQuiesce().Proves("not-a-uuid", 7, testNonce()),
		"other epoch":     provenQuiesce().Proves(testVolumeID, 8, testNonce()),
		"zero epoch":      provenQuiesce().Proves(testVolumeID, 0, testNonce()),
		"other nonce":     provenQuiesce().Proves(testVolumeID, 7, hex.EncodeToString(make([]byte, 32))),
		"short nonce":     provenQuiesce().Proves(testVolumeID, 7, hex.EncodeToString(make([]byte, 8))),
		"unset nonce":     provenQuiesce().Proves(testVolumeID, 7, ""),
		"uppercase nonce": provenQuiesce().Proves(testVolumeID, 7, strings.ToUpper(testNonce())),
	} {
		if check {
			t.Fatalf("%s: a proof that does not answer this request was accepted", name)
		}
	}
	// A stale proof from an earlier attempt answers an earlier nonce, and the
	// only thing that makes it stale is the nonce.
	stale := provenQuiesce()
	stale.Nonce = hex.EncodeToString(make([]byte, 32))
	if stale.Proves(testVolumeID, 7, testNonce()) {
		t.Fatal("a stale proof from an earlier attempt was accepted")
	}
	// The authority can also report that the membership is not empty; that is
	// an answer, not a proof.
	populated := provenQuiesce()
	populated.MembershipEmpty = false
	if populated.Proves(testVolumeID, 7, testNonce()) {
		t.Fatal("a proof that reports a non-empty membership was accepted")
	}
}

func TestQuiesceFieldValidatorsRefuseAnythingButExactHex(t *testing.T) {
	if !validQuiesceNonce(testNonce()) || !validWireSessionEpoch(provenQuiesce().WireSessionEpochHex) {
		t.Fatal("well-formed quiesce fields were rejected")
	}
	for _, nonce := range []string{"", "zz", strings.ToUpper(testNonce()), testNonce() + "00", testNonce()[:62]} {
		if validQuiesceNonce(nonce) {
			t.Fatalf("nonce %q was accepted", nonce)
		}
	}
	for _, epoch := range []string{"", "zz", hex.EncodeToString(make([]byte, 15)), hex.EncodeToString(make([]byte, 17))} {
		if validWireSessionEpoch(epoch) {
			t.Fatalf("wire session epoch %q was accepted", epoch)
		}
	}
}
